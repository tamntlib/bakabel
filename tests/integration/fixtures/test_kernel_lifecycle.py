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
                with self.assertRaises(TimeoutError) as caught:
                    reader.trace_exit(pid,lambda:None,lambda:None,inject=False,seconds=.1)
            self.assertTrue(caught.exception.f14_cleanup_failed)
            self.assertIn('F14 owned reader cleanup could not detach/resume',caught.exception.__notes__)
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
            self.assertEqual(len(observed),1);self.assertIsInstance(observed[0],TimeoutError)
            self.assertTrue(observed[0].f14_cleanup_failed)
            self.assertIn('F14 owned reader cleanup could not detach/resume',observed[0].__notes__)
        finally:cleanup_owned_child(pid,pidfd);os.close(w)


class ReaderGroupExitTests(unittest.TestCase):
    """Real unprivileged children; terminal status, never ESRCH, is proof.

    The supervisor pins the child before tracing. It checks attachment while
    the native tracer is STILL alive, then joins that exact thread and verifies
    its /proc task disappeared before pidfd-only fallback cleanup. Stop on the
    first failure, after proving no residue; no retry-to-green.
    """
    def snapshot(self):
        tasks=Path('/proc/self/task')
        return (set(Path('/proc/self/fd').iterdir()),set(tasks.iterdir()),
                {int(x) for task in tasks.iterdir() for x in (task/'children').read_text().split()})

    def trial(self,inject,fail_validation=False,fail_detach=False,fail_after_resume=False):
        import hosted_f14_reader as reader
        import select
        import ctypes
        from test_hosted_f14 import cleanup_owned_child
        before=self.snapshot();r,w=os.pipe();d,e=os.pipe();pid=os.fork()
        if pid==0:
            os.close(w);os.close(d);os.read(r,1);os.close(r)
            def finish():
                child=threading.Thread(target=lambda:None);child.start();child.join()
                os.write(e,b'payload');os.close(e);os._exit(0)
            threading.Thread(target=finish).start()
            while True:signal.pause()
        pidfd=os.pidfd_open(pid);os.close(r);os.close(e)
        row={};diagnostic={};checks=[];returned=threading.Event();release=threading.Event()
        libc=ctypes.CDLL(None,use_errno=True)
        libc.ptrace.restype=ctypes.c_long
        libc.ptrace.argtypes=[ctypes.c_uint,ctypes.c_int,ctypes.c_void_p,ctypes.c_void_p]
        class Ptrace:
            def __call__(self,request,tid,addr,data):
                if fail_detach and request==17:
                    ctypes.set_errno(errno.EIO);return -1
                result=libc.ptrace(request,tid,addr,data)
                if request==0x420e and result>=24:
                    info=ctypes.cast(data,ctypes.POINTER(reader.SyscallInfo)).contents
                    if info.op==1 and info.data[0]==231:row['exit_tid']=tid
                if fail_after_resume and request==24 and tid==row.get('exit_tid') and result==0:
                    # Real exit_group runs; only the tracer exception is
                    # synthetic. Cleanup must drain actual ALL-thread waits.
                    time.sleep(.02)
                    raise ValueError('owned post-resume control')
                return result
        class Libc:ptrace=Ptrace()
        def validate():
            checks.append(True)
            if fail_validation and len(checks)==3:raise ValueError('owned authorization control')
        def traced():
            row['tid']=threading.get_native_id()
            try:
                if fail_detach or fail_after_resume:
                    with patch.object(reader.ctypes,'CDLL',return_value=Libc()):
                        row['result']=reader.trace_exit(pid,validate,lambda:os.write(w,b'x'),inject=inject,seconds=3,diagnostic=diagnostic)
                else:row['result']=reader.trace_exit(pid,validate,lambda:os.write(w,b'x'),inject=inject,seconds=3,diagnostic=diagnostic)
            except Exception as exc:row['error']=exc
            finally:returned.set();release.wait(2)
        thread=threading.Thread(target=traced)
        remaining=[];detached=False
        try:
            thread.start()
            self.assertTrue(returned.wait(5),'tracer did not return within operation + cleanup budgets')
            for task in Path(f'/proc/{pid}/task').glob('*'):
                try:status=(task/'status').read_text()
                except FileNotFoundError:continue
                tracer=next(line.split(':',1)[1].strip() for line in status.splitlines() if line.startswith('TracerPid:'))
                if tracer==str(row['tid']):remaining.append(int(task.name))
            detached=not remaining
        finally:
            release.set();thread.join(2)
            self.assertFalse(thread.is_alive(),'native tracer thread still active; stop')
            deadline=time.monotonic()+1
            while Path(f'/proc/self/task/{row["tid"]}').exists() and time.monotonic()<deadline:time.sleep(.001)
            self.assertFalse(Path(f'/proc/self/task/{row["tid"]}').exists(),'native tracer did not exit; stop')
            # Actual automatic detach after native tracer exit is checked, not
            # assumed. No new trial is allowed on unresolved owned state.
            for task in Path(f'/proc/{pid}/task').glob('*'):
                try:status=(task/'status').read_text()
                except FileNotFoundError:continue
                self.assertIn('TracerPid:\t0\n',status)
            cleanup_owned_child(pid,pidfd)
            payload=os.read(d,100) if select.select([d],[],[],1)[0] else None
            os.close(w);os.close(d)
            self.assertFalse(Path(f'/proc/{pid}').exists(),'owned child residue; stop')
            self.assertEqual(self.snapshot(),before,'owned FD/thread/child baseline drift; stop')
        if fail_validation or fail_after_resume:
            projected=reader.failure_record(row['error'],diagnostic)
            self.assertEqual(projected['phase'],'authorize' if fail_validation else 'resume')
            self.assertEqual(projected['detach_verified'],not fail_detach)
            self.assertEqual(projected['cleanup_failed'],fail_detach)
        if fail_detach:
            self.assertFalse(detached,'injected DETACH failure must not pretend cleanup detached')
            self.assertIsInstance(row.get('error'),ValueError,'cleanup must preserve original authorization failure')
            self.assertTrue(getattr(row['error'],'f14_cleanup_failed',False))
        else:self.assertTrue(detached,f'trace_exit returned with admitted tasks attached: {remaining}; error={row.get("error")!r}')
        self.assertEqual(payload,b'payload')
        if fail_validation or fail_after_resume:
            self.assertIsInstance(row.get('error'),ValueError)
            self.assertEqual(str(row['error']),'owned authorization control' if fail_validation else 'owned post-resume control')
        else:
            if 'error' in row:raise row['error']
            self.assertEqual(row['result'],{'natural_exit_code':0,'injected':inject,
                'terminal_exit_code':None if inject else 0,'terminal_signal':9 if inject else None})
        self.assertEqual(len(checks),3)

    def test_cleanup_verifies_detach_when_native_status_read_races_task_exit(self):
        """Hold a real status FD across DETACH, then read after task exit.

        The failing native schedule opened an exiting clone's status before
        procfs read returned ESRCH. Do not synthesize errno or ptrace success:
        deterministically separate those same two kernel operations instead.
        """
        import ctypes
        import hosted_f14_reader as reader
        from test_hosted_f14 import cleanup_owned_child
        before=self.snapshot();r,w=os.pipe();ready_r,ready_w=os.pipe();pid=os.fork()
        if pid==0:
            os.close(w);os.close(ready_r)
            def finish():
                os.write(ready_w,str(threading.get_native_id()).encode())
                os.read(r,1)
            threading.Thread(target=finish).start()
            while True:signal.pause()
        pidfd=os.pidfd_open(pid);os.close(r);os.close(ready_w)
        row={};diagnostic={};checks=[];returned=threading.Event();release=threading.Event()
        libc=ctypes.CDLL(None,use_errno=True)
        libc.ptrace.restype=ctypes.c_long
        libc.ptrace.argtypes=[ctypes.c_uint,ctypes.c_int,ctypes.c_void_p,ctypes.c_void_p]
        original_read=Path.read_text;held=[]
        primary=ValueError('owned authorization control')
        class Ptrace:
            def __call__(self,request,tid,addr,data):
                if request==17 and tid==row['worker']:
                    held.append(Path(f'/proc/{tid}/status').open())
                result=libc.ptrace(request,tid,addr,data)
                if request==17 and tid==row['worker']:row['detach_result']=result
                return result
        class Libc:ptrace=Ptrace()
        def status_read(path,*args,**kwargs):
            if path==Path(f'/proc/{row["worker"]}/status') and held:
                stream=held.pop()
                try:
                    deadline=time.monotonic()+.5
                    while Path(f'/proc/{row["worker"]}').exists() and time.monotonic()<deadline:time.sleep(.001)
                    row['worker_gone']=not Path(f'/proc/{row["worker"]}').exists()
                    try:return stream.read()
                    except ProcessLookupError as exc:
                        row['status_errno']=exc.errno
                        raise
                finally:stream.close()
            return original_read(path,*args,**kwargs)
        def validate():
            checks.append(True)
            if len(checks)==2:
                os.write(w,b'x') # Consumed only after the real worker DETACH.
                raise primary
        def traced():
            row['tid']=threading.get_native_id()
            try:
                with patch.object(reader.ctypes,'CDLL',return_value=Libc()), \
                        patch.object(Path,'read_text',status_read):
                    reader.trace_exit(pid,validate,lambda:None,inject=False,seconds=3,diagnostic=diagnostic)
            except Exception as exc:row['error']=exc
            finally:returned.set();release.wait(2)
        thread=threading.Thread(target=traced);remaining=[]
        try:
            row['worker']=int(os.read(ready_r,32));thread.start()
            self.assertTrue(returned.wait(5),'tracer did not return within operation + cleanup budgets')
            for task in Path(f'/proc/{pid}/task').glob('*'):
                try:status=(task/'status').read_text()
                except FileNotFoundError:continue
                tracer=next(line.split(':',1)[1].strip() for line in status.splitlines() if line.startswith('TracerPid:'))
                if tracer==str(row['tid']):remaining.append(int(task.name))
        finally:
            release.set();thread.join(2)
            self.assertFalse(thread.is_alive(),'native tracer thread still active; stop')
            deadline=time.monotonic()+1
            while Path(f'/proc/self/task/{row["tid"]}').exists() and time.monotonic()<deadline:time.sleep(.001)
            self.assertFalse(Path(f'/proc/self/task/{row["tid"]}').exists(),'native tracer did not exit; stop')
            for task in Path(f'/proc/{pid}/task').glob('*'):
                try:status=(task/'status').read_text()
                except FileNotFoundError:continue
                self.assertIn('TracerPid:\t0\n',status)
            for stream in held:stream.close()
            cleanup_owned_child(pid,pidfd);os.close(w);os.close(ready_r)
            self.assertFalse(Path(f'/proc/{pid}').exists(),'owned child residue; stop')
            self.assertEqual(self.snapshot(),before,'owned FD/thread/child baseline drift; stop')
        self.assertEqual(row.get('detach_result'),0,'real kernel DETACH must succeed')
        self.assertTrue(row.get('worker_gone'),'native nonleader did not exit')
        self.assertEqual(row.get('status_errno'),errno.ESRCH,'must exercise real procfs read race')
        self.assertIs(row.get('error'),primary,'cleanup must preserve original authorization failure')
        self.assertEqual(remaining,[],'must inspect exact tracer TID before it exits')
        projected=reader.failure_record(primary,diagnostic)
        self.assertEqual(projected['phase'],'authorize')
        self.assertTrue(projected['detach_verified'])
        self.assertFalse(projected['cleanup_failed'])
        self.assertEqual(len(checks),2)

    def test_real_nonleader_group_exit_control_has_no_syscall_info_ESRCH_failure(self):
        for trial in range(24):self.trial(False)

    def test_real_nonleader_group_exit_injection_preserves_payload_and_sigkill(self):
        for trial in range(6):self.trial(True)

    def test_real_nonleader_final_authorization_failure_detaches_before_return(self):
        self.trial(True,fail_validation=True)

    def test_cleanup_drains_group_terminal_after_post_resume_failure(self):
        self.trial(False,fail_after_resume=True)

    def test_cleanup_failure_preserves_primary_error_and_reports_attached_state(self):
        self.trial(True,fail_validation=True,fail_detach=True)


class F14FailureDiagnosticTests(unittest.TestCase):
    def test_failed_helper_projection_is_finite_and_contains_no_exception_text(self):
        import hosted_f14_reader as reader
        exc=OSError(errno.ESRCH,'secret exception /private/path')
        exc.f14_cleanup_failed=True
        row=reader.failure_record(exc,{'phase':'syscall_info','natural_exit_code':0,
            'injected':False,'owned_tasks':3,'stopped_tasks':1,'detach_verified':False,
            'secret':'must not project'})
        self.assertEqual(row,{'state':'failed','type':'ProcessLookupError','errno':'ESRCH',
            'phase':'syscall_info','natural_exit_code':0,'injected':False,'owned_tasks':3,
            'stopped_tasks':1,'detach_verified':False,'cleanup_failed':True})
        class PrivateError(Exception):pass
        unknown=reader.failure_record(PrivateError('secret'),{'phase':'secret'})
        self.assertEqual(unknown['type'],'OtherError');self.assertEqual(unknown['phase'],'unknown')
        self.assertNotIn('secret',str(unknown))

    def test_owner_gate_failure_survives_without_terminal_annotations(self):
        from test_hosted_f14 import F14VerifierTests
        import run_hosted_f14 as runner
        class Base:
            def observe_transport(self,*args):pass
        class Probe(runner.F14Mixin,Base):pass
        probe=Probe();probe.result={}
        attempt=F14VerifierTests().receipt()['proof']['attempts'][0]
        probe.f14_attempt={'mode':'control','owner':attempt['owner']}
        probe.owner=lambda:{'phase':'blocked','status':'quarantined','workerStartAuthorized':False,
                            'private':'secret'}
        record={'boundary':'worker-remove','container_id':attempt['owner']['workerContainerID'],
                'method':'DELETE','remove_query':'','remove_query_valid':True,'remove_force':False,
                'remove_volumes':False,'forwarded':False}
        with self.assertRaises(ValueError):probe.observe_transport('request',record)
        diagnostic=probe.result['f14_diagnostics'][0]
        self.assertEqual(diagnostic['phase'],'owner_gate')
        self.assertEqual(diagnostic['owner_phase'],'blocked')
        self.assertEqual(diagnostic['error_type'],'ValueError')
        self.assertNotIn('secret',str(diagnostic));self.assertNotIn('terminal_before_remove',record)

    def test_import_failure_retains_reader_status_without_worker_or_terminal_annotations(self):
        from test_hosted_f14 import F14VerifierTests
        from unittest.mock import Mock
        import run_hosted_f14 as runner
        class Base:
            def observe_transport(self,*args):pass
        class Probe(runner.F14Mixin,Base):pass
        probe=Probe();probe.result={};fixture=F14VerifierTests().receipt()
        attempt=fixture['proof']['attempts'][0]
        probe.f14_attempt={'mode':'control','owner':attempt['owner']}
        record=fixture['relay']['records'][2].copy();record['forwarded']=False
        for key in ('owner_before_remove','terminal_before_remove','reader_before_remove','worker_before_remove'):record.pop(key)
        probe.owner=lambda:fixture['relay']['records'][2]['owner_before_remove']
        probe.finish_reader_tracer=Mock(return_value=attempt['reader'])
        probe.terminal_proof=Mock(return_value={**attempt['terminal'],'exec_exit_code':17})
        probe.e=Mock()
        with self.assertRaises(ValueError):probe.observe_transport('request',record)
        diagnostic=probe.result['f14_diagnostics'][0]
        self.assertEqual(diagnostic['phase'],'import_terminal');self.assertEqual(diagnostic['import_exit_code'],17)
        self.assertEqual(diagnostic['reader_terminal_exit_code'],0)
        self.assertIsNone(diagnostic['worker_exit_code'])
        probe.e.inspect.assert_not_called();self.assertNotIn('terminal_before_remove',record)

    def test_helper_failure_is_retained_before_all_or_nothing_terminal_annotations(self):
        import json
        import run_hosted_f14 as runner
        from unittest.mock import Mock
        probe=runner.F14Mixin();probe.result={};probe.f14_attempt={'mode':'control'}
        child=Mock(returncode=1);child.communicate.return_value=(json.dumps({
            'state':'failed','type':'ProcessLookupError','errno':'ESRCH','phase':'syscall_info',
            'natural_exit_code':0,'injected':False,'owned_tasks':3,'stopped_tasks':1,
            'detach_verified':False,'cleanup_failed':True,'raw':'secret'}),None)
        probe.f14_tracer=child
        with self.assertRaises(ValueError):probe.finish_reader_tracer()
        diagnostic=probe.result['f14_diagnostics'][0]
        self.assertEqual(diagnostic['helper_returncode'],1)
        self.assertEqual(diagnostic['helper']['errno'],'ESRCH')
        self.assertEqual(diagnostic['phase'],'tracer_finish')
        self.assertNotIn('secret',str(diagnostic));self.assertNotIn('reader',probe.f14_attempt)


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
