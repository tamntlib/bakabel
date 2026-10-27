"""Causal lifecycle controls: owned socket FDs, threads and owned children only.

Socket permission packets are protocol controls, NOT real fanotify evidence.
"""
import errno
import os
from pathlib import Path
import signal
import socket
import threading
import time
import unittest
from unittest.mock import patch
import native_permission_fixture as m


class PermissionLifetimeTests(unittest.TestCase):
    def gate(self, classify, seconds=.1):
        front, back=socket.socketpair(socket.AF_UNIX,socket.SOCK_DGRAM)
        self.addCleanup(front.close); self.addCleanup(back.close)
        back.settimeout(2)
        gate=m.PermissionGate.from_fd(os.dup(front.fileno()),classify,hold_seconds=seconds)
        self.addCleanup(self.close_gate,gate)
        return gate,back

    def close_gate(self,gate):
        try:os.fstat(gate.fd)
        except OSError:return
        gate.close()

    def event(self):
        return {'fd':os.open(__file__,os.O_RDONLY),'pid':os.getpid(),'mask':m.OPEN_PERM}

    def send(self,peer,event):
        peer.send(m.METADATA.pack(24,3,0,24,event['mask'],event['fd'],event['pid']))

    def assert_closed(self,fd):
        with self.assertRaises(OSError):os.fstat(fd)

    def test_EK001_close_retains_authority_until_classifier_quiesces(self):
        entered=threading.Event(); resume=threading.Event()
        def classify(event):
            entered.set(); resume.wait(5); os.fstat(event['fd']); return 'allow'
        gate,peer=self.gate(classify)
        event=self.event(); group=gate.fd
        gate.start(); self.send(peer,event); self.assertTrue(entered.wait(1))
        try:
            with self.assertRaisesRegex(TimeoutError,'quiesc'):
                gate.close()
            os.fstat(group); os.fstat(event['fd'])
            self.assertTrue(gate.thread.is_alive())
            peer.settimeout(.1)
            self.assertEqual(peer.recv(8),m.permission_response(event['fd'],False))
        finally:
            resume.set(); gate.thread.join(2); self.close_gate(gate)
        self.assertFalse(gate.thread.is_alive()); self.assert_closed(group)
        self.assert_closed(event['fd'])
        # Force only our own unrelated descriptor into the released number.
        a,b=socket.socketpair(socket.AF_UNIX,socket.SOCK_DGRAM)
        try:
            if a.fileno()!=group:os.dup2(a.fileno(),group)
            b.settimeout(.05)
            with self.assertRaises(socket.timeout):b.recv(8)
        finally:
            if a.fileno()!=group:os.close(group)
            a.close();b.close()


    def test_EK002_canceled_close_and_expire_release_every_owned_fd(self):
        for operation in ('close','expire'):
            with self.subTest(operation=operation):
                gate,peer=self.gate(lambda e:'hold');event=self.event();group=gate.fd
                gate.dispatch([event])
                try:
                    with patch.object(m.os,'write',side_effect=OSError(errno.ENOENT,'canceled')):
                        if operation=='close':gate.close()
                        else:gate.expire(now=time.monotonic()+1)
                    self.assertIsNone(gate.held);self.assert_closed(event['fd'])
                    gate.close();self.assert_closed(group)
                finally:
                    self.close_gate(gate)
                    try:os.close(event['fd'])
                    except OSError:pass

    def test_EK002_non_cancellation_error_preserved_after_quiescent_owned_cleanup(self):
        import run_hosted_native_faults as runner
        gate,peer=self.gate(lambda e:'hold');event=self.event();group=gate.fd
        gate.dispatch([event]);probe=runner.NativeFaultProbe.__new__(runner.NativeFaultProbe)
        probe.gate=gate;probe.result={};order=[]
        def cleanup():
            self.assert_closed(group);self.assert_closed(event['fd']);order.append('owned')
        try:
            with patch.object(m.os,'write',side_effect=OSError(errno.EIO,'response failed')), \
                    patch.object(runner.FaultProbe,'cleanup',side_effect=cleanup):
                with self.assertRaises(OSError) as caught:probe.cleanup()
            self.assertEqual(caught.exception.errno,errno.EIO);self.assertEqual(order,['owned'])
            self.assertIsNone(gate.held)
        finally:
            self.close_gate(gate)
            try:os.close(event['fd'])
            except OSError:pass


    def test_EK002_response_failure_never_retries_a_released_event_fd(self):
        gate,peer=self.gate(lambda e:'allow');event=self.event()
        with patch.object(m.os,'write',side_effect=OSError(errno.EIO,'failed')) as write:
            with self.assertRaises(OSError):gate.dispatch([event])
        self.assertEqual(write.call_count,1);self.assert_closed(event['fd'])


    def test_EK005_overflow_after_received_event_retires_transport_and_wakes_waiter(self):
        gate,peer=self.gate(lambda e:'allow');event=self.event();group=gate.fd
        gate.start()
        peer.send(m.METADATA.pack(24,3,0,24,m.OPEN_PERM,event['fd'],event['pid'])+
                  m.METADATA.pack(24,3,0,24,0x4000,-1,0))
        gate.thread.join(1)
        try:
            self.assertFalse(gate.thread.is_alive());self.assertTrue(gate.hit.is_set())
            self.assert_closed(event['fd']);self.assert_closed(group)
            start=time.monotonic()
            with self.assertRaises(TimeoutError):gate.await_hold(.5)
            self.assertLess(time.monotonic()-start,.1)
            self.assertIn('permission-transport-failed',gate.errors)
        finally:
            self.close_gate(gate)
            try:os.close(event['fd'])
            except OSError:pass

    def test_EK005_watchdog_includes_classification_and_preserves_inflight_fd(self):
        entered=threading.Event();resume=threading.Event();classification=[]
        def classify(event):
            entered.set();resume.wait(2);os.fstat(event['fd']);classification.append('valid-fd');return 'allow'
        gate,peer=self.gate(classify,.05);event=self.event()
        gate.start();start=time.monotonic();self.send(peer,event);self.assertTrue(entered.wait(1))
        try:
            peer.settimeout(.2)
            self.assertEqual(peer.recv(8),m.permission_response(event['fd'],False))
            self.assertLess(time.monotonic()-start,.2)
            os.fstat(event['fd']) # Deny may not recycle a descriptor in use by classify.
            self.assertTrue(gate.hit.is_set())
            with self.assertRaises(TimeoutError):gate.await_hold(.5)
        finally:
            resume.set();gate.close()
        self.assertEqual(classification,['valid-fd']);self.assert_closed(event['fd'])
        peer.settimeout(.05)
        with self.assertRaises(socket.timeout):peer.recv(8) # No late allow/second response.

    def test_EK005_select_failure_denies_hold_and_wakes_waiter(self):
        gate,peer=self.gate(lambda e:'hold');event=self.event();group=gate.fd
        gate.dispatch([event]);gate.hit.clear()
        with patch.object(m.select,'select',side_effect=OSError(errno.EIO,'transport failed')):
            gate.start();gate.thread.join(1)
        try:
            self.assertEqual(peer.recv(8),m.permission_response(event['fd'],False))
            self.assertTrue(gate.hit.is_set());self.assert_closed(event['fd']);self.assert_closed(group)
            self.assertIn('permission-transport-failed',gate.errors)
        finally:self.close_gate(gate)


    def test_EK001_stale_answer_cannot_write_or_close_a_recycled_event_fd(self):
        gate,peer=self.gate(lambda e:'hold');event=self.event();gate.dispatch([event])
        held=gate.current_hold();gate.release(False);peer.recv(8)
        recycled=os.open(__file__,os.O_RDONLY)
        try:
            if recycled!=event['fd']:os.dup2(recycled,event['fd'])
            with self.assertRaises(RuntimeError):gate.answer(held,True)
            os.fstat(event['fd'])
            peer.settimeout(.05)
            with self.assertRaises(socket.timeout):peer.recv(8)
        finally:
            for fd in set((recycled,event['fd'])):
                try:os.close(fd)
                except OSError:pass


    def test_EK005_queued_batch_events_share_receipt_deadline(self):
        entered=threading.Event();resume=threading.Event();seen=[]
        def classify(event):
            seen.append(event['fd']);entered.set();resume.wait(2);return 'hold'
        gate,peer=self.gate(classify,.05);events=[self.event(),self.event()]
        gate.start();peer.send(b''.join(m.METADATA.pack(24,3,0,24,e['mask'],e['fd'],e['pid']) for e in events))
        self.assertTrue(entered.wait(1));peer.settimeout(.2)
        try:
            packets={peer.recv(8),peer.recv(8)}
            self.assertEqual(packets,{m.permission_response(e['fd'],False) for e in events})
            os.fstat(events[0]['fd']);self.assert_closed(events[1]['fd'])
        finally:resume.set();gate.close()
        self.assertEqual(seen,[events[0]['fd']]);self.assert_closed(events[0]['fd'])

    def test_EK005_read_failure_retires_authority_without_waiting_outer_timeout(self):
        gate,peer=self.gate(lambda e:'hold');event=self.event();group=gate.fd
        gate.dispatch([event]);gate.hit.clear()
        with patch.object(m.select,'select',return_value=([group],[],[])), \
                patch.object(m.os,'read',side_effect=OSError(errno.EIO,'read failed')):
            gate.start();gate.thread.join(1)
        self.assertTrue(gate.hit.is_set());self.assert_closed(group);self.assert_closed(event['fd'])
        self.assertEqual(peer.recv(8),m.permission_response(event['fd'],False))

    def test_EK002_blocked_cleanup_retains_gate_and_never_runs_owned_teardown(self):
        import run_hosted_native_faults as runner
        from unittest.mock import Mock
        probe=runner.NativeFaultProbe.__new__(runner.NativeFaultProbe)
        probe.gate=Mock();probe.gate.retired=False;probe.gate.close.side_effect=TimeoutError('not quiescent')
        probe.result={}
        with patch.object(runner.FaultProbe,'cleanup') as cleanup:
            with self.assertRaises(TimeoutError):probe.cleanup()
            cleanup.assert_not_called()

    def test_EK001_concurrent_release_expire_close_answer_exactly_once(self):
        for _ in range(20):
            gate,peer=self.gate(lambda e:'hold',1);event=self.event();gate.dispatch([event])
            barrier=threading.Barrier(4);errors=[]
            def run(operation):
                barrier.wait()
                try:operation()
                except TimeoutError:pass # Another operation retired the hold.
                except Exception as exc:errors.append(exc)
            threads=[threading.Thread(target=run,args=(fn,)) for fn in
                (lambda:gate.release(False),lambda:gate.expire(time.monotonic()+2),gate.close)]
            for thread in threads:thread.start()
            barrier.wait()
            for thread in threads:thread.join(2);self.assertFalse(thread.is_alive())
            self.assertEqual(errors,[]);self.assertIsNone(gate.held);self.assertEqual(gate.pending,{})
            self.assert_closed(event['fd']);self.assert_closed(gate.fd)
            self.assertEqual(peer.recv(8),m.permission_response(event['fd'],False))
            peer.settimeout(.01)
            with self.assertRaises(socket.timeout):peer.recv(8)


class ReaderCleanupTests(unittest.TestCase):
    def test_EK003_timeout_detaches_and_resumes_before_tracer_returns(self):
        import hosted_f14_reader as reader
        r,w=os.pipe();done_r,done_w=os.pipe();pid=os.fork()
        if pid==0:
            os.close(w);os.close(done_r);os.read(r,1);os.write(done_w,b'done');os._exit(0)
        os.close(r);os.close(done_w);pidfd=os.pidfd_open(pid)
        try:
            with self.assertRaises(TimeoutError):
                reader.trace_exit(pid,lambda:None,lambda:None,inject=False,seconds=.1)
            status=Path(f'/proc/{pid}/status').read_text()
            tracer=next(line.split(':')[1].strip() for line in status.splitlines() if line.startswith('TracerPid:'))
            self.assertEqual(tracer,'0',status)
            os.write(w,b'x')
            import select
            self.assertTrue(select.select([done_r],[],[],1)[0]);self.assertEqual(os.read(done_r,4),b'done')
            found,status=os.waitpid(pid,0);self.assertEqual(found,pid);self.assertTrue(os.WIFEXITED(status))
        finally:
            try:signal.pidfd_send_signal(pidfd,signal.SIGKILL)
            except ProcessLookupError:pass
            # Kill only this owned incarnation and drain only its statuses.
            import ctypes
            libc=ctypes.CDLL(None,use_errno=True);end=time.monotonic()+2
            while time.monotonic()<end:
                try:found,status=os.waitpid(pid,os.WNOHANG|0x40000000)
                except ChildProcessError:break
                if found and (os.WIFEXITED(status) or os.WIFSIGNALED(status)):break
                if found and os.WIFSTOPPED(status):libc.ptrace(7,pid,None,None)
                time.sleep(.001)
            os.close(pidfd);os.close(w);os.close(done_r)


    def test_EK003_multithread_timeout_detaches_all_owned_tasks(self):
        import hosted_f14_reader as reader
        from test_hosted_f14 import cleanup_owned_child
        r,w=os.pipe();ready_r,ready_w=os.pipe();done_r,done_w=os.pipe();pid=os.fork()
        if pid==0:
            os.close(w);os.close(ready_r);os.close(done_r)
            def wait_input():os.read(r,1);os.write(done_w,b'x')
            workers=[threading.Thread(target=wait_input) for _ in range(3)]
            for thread in workers:thread.start()
            os.write(ready_w,b'x')
            for thread in workers:thread.join()
            os._exit(0)
        pidfd=os.pidfd_open(pid);os.close(r);os.close(ready_w);os.close(done_w)
        try:
            self.assertEqual(os.read(ready_r,1),b'x')
            with self.assertRaises(TimeoutError):reader.trace_exit(pid,lambda:None,lambda:None,inject=False,seconds=.1)
            for task in Path(f'/proc/{pid}/task').iterdir():
                status=(task/'status').read_text()
                tracer=next(line.split(':')[1].strip() for line in status.splitlines() if line.startswith('TracerPid:'))
                self.assertEqual(tracer,'0',status)
            os.write(w,b'xxx')
            import select
            data=b'';end=time.monotonic()+1
            while len(data)<3 and time.monotonic()<end:
                if select.select([done_r],[],[],.1)[0]:data+=os.read(done_r,3)
            self.assertEqual(data,b'xxx')
            _,status=os.waitpid(pid,0);self.assertTrue(os.WIFEXITED(status))
        finally:
            cleanup_owned_child(pid,pidfd);os.close(w);os.close(ready_r);os.close(done_r)


    def test_EK003_detach_failure_is_reported_not_swallowed(self):
        import ctypes
        import hosted_f14_reader as reader
        from test_hosted_f14 import cleanup_owned_child
        r,w=os.pipe();pid=os.fork()
        if pid==0:os.close(w);os.read(r,1);os._exit(0)
        pidfd=os.pidfd_open(pid);os.close(r)
        libc=ctypes.CDLL(None,use_errno=True)
        libc.ptrace.restype=ctypes.c_long
        libc.ptrace.argtypes=[ctypes.c_uint,ctypes.c_int,ctypes.c_void_p,ctypes.c_void_p]
        class Ptrace:
            def __call__(self,request,tid,addr,data):
                if request==17:ctypes.set_errno(errno.EIO);return -1
                return libc.ptrace(request,tid,addr,data)
        class Libc:ptrace=Ptrace()
        try:
            with patch.object(reader.ctypes,'CDLL',return_value=Libc()):
                with self.assertRaisesRegex(RuntimeError,'could not detach'):
                    reader.trace_exit(pid,lambda:None,lambda:None,inject=False,seconds=.1)
        finally:
            # Failure injection leaves only OUR stopped child: undo it before
            # pidfd cleanup. Never fake a successful kernel detach.
            libc.ptrace(17,pid,None,None)
            cleanup_owned_child(pid,pidfd);os.close(w)


    def test_EK003_cleanup_verifies_the_actual_tracer_thread_not_group_pid(self):
        import ctypes
        import hosted_f14_reader as reader
        from test_hosted_f14 import cleanup_owned_child
        r,w=os.pipe();pid=os.fork()
        if pid==0:os.close(w);os.read(r,1);os._exit(0)
        pidfd=os.pidfd_open(pid);os.close(r);observed=[]
        libc=ctypes.CDLL(None,use_errno=True)
        libc.ptrace.restype=ctypes.c_long
        libc.ptrace.argtypes=[ctypes.c_uint,ctypes.c_int,ctypes.c_void_p,ctypes.c_void_p]
        class Ptrace:
            def __call__(self,request,tid,addr,data):
                if request==17:ctypes.set_errno(errno.EIO);return -1
                return libc.ptrace(request,tid,addr,data)
        class Libc:ptrace=Ptrace()
        def trace():
            try:
                with patch.object(reader.ctypes,'CDLL',return_value=Libc()):
                    reader.trace_exit(pid,lambda:None,lambda:None,inject=False,seconds=.1)
            except Exception as exc:observed.append(exc)
            finally:libc.ptrace(17,pid,None,None) # Same tracer thread performs real detach.
        thread=threading.Thread(target=trace)
        try:
            thread.start();thread.join(2);self.assertFalse(thread.is_alive())
            self.assertEqual(len(observed),1);self.assertIsInstance(observed[0],RuntimeError)
            self.assertIn('could not detach',str(observed[0]))
        finally:cleanup_owned_child(pid,pidfd);os.close(w)


class TestCleanupOwnershipTests(unittest.TestCase):
    def test_EK004_existing_owned_child_tests_never_signal_a_numeric_pid(self):
        import test_hosted_f14 as f14
        original_fork=os.fork;owned={};attempts=[]
        def fork():
            pid=original_fork()
            if pid>0:owned[pid]=os.pidfd_open(pid)
            return pid
        def guarded_kill(pid,sig):
            attempts.append(pid)
            if pid not in owned:raise AssertionError('unowned cleanup signal')
            return signal.pidfd_send_signal(owned[pid],sig)
        try:
            with patch.object(os,'fork',side_effect=fork),patch.object(os,'kill',side_effect=guarded_kill):
                suite=unittest.defaultTestLoader.loadTestsFromTestCase(f14.ReaderTracerTests)
                result=unittest.TestResult();suite.run(result)
            self.assertEqual(result.errors,[]);self.assertEqual(result.failures,[])
            self.assertEqual(attempts,[],'numeric PID signals after terminal wait permit PID reuse')
        finally:
            for fd in owned.values():os.close(fd)


if __name__=='__main__':unittest.main()
