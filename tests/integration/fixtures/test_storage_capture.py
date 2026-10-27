"""Offline socket/trace controls, NOT hosted PostgreSQL or ENOSPC evidence."""
import json
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest

from run_hosted_faults import FaultRelay, read_headers
from run_hosted_storage_prereqs import MissingLibraryDiagnostic


def frame(data, stream=2):
    return bytes([stream, 0, 0, 0])+len(data).to_bytes(4, 'big')+data


class CaptureTests(unittest.TestCase):
    def exchange(self, mode, observe=True):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            listener=socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(str(root/'up')); listener.listen(1); listener.settimeout(3)
            relay=FaultRelay(root/'relay', root/'up')
            relay.observe_streams=observe
            if mode=='close': relay.start()
            if mode=='export':
                from run_hosted_storage_prereqs import ExportDiagnostic
                relay.stderr_classifier_factory=lambda record: ExportDiagnostic('a'*32)
            else: relay.stderr_classifier_factory=lambda record: MissingLibraryDiagnostic()
            eid='a'*64
            relay.execs[eid]={'kind':'restore','container_id':'b'*64,'stdout_bytes':0,'stdin_bytes':0}
            client, front=socket.socketpair()
            client.settimeout(3)
            payload=MissingLibraryDiagnostic.ERROR+b'\n'+MissingLibraryDiagnostic.COMMAND+b'\n'
            if mode=='export': payload=b'PRIVATE-DUMP\0BAKABEL_EXPORT_COMPLETE_V1:'+b'a'*32+b'\0'
            if mode=='drain_bound': payload=b'PRIVATE'*20000
            if mode=='invalid_frame': payload=b'PRIVATE-NOT-MULTIPLEX'
            wire=[]; failures=[]; sent=threading.Event(); release=threading.Event()
            request=('POST /exec/'+eid+'/start HTTP/1.1\r\nHost: docker\r\nContent-Length: 2\r\n\r\n{}').encode()
            def upstream():
                try:
                    back,_=listener.accept()
                    with back:
                        head,_,_=read_headers(back)
                        wire.append(head+back.recv(2))
                        if mode in ('input_closed','drain_timeout','drain_bound'): back.shutdown(socket.SHUT_RD)
                        back.sendall(b'HTTP/1.1 101 UPGRADED\r\nConnection: Upgrade\r\n\r\n')
                        if mode in ('input_closed','output_closed','drain_timeout','drain_bound'):
                            if not sent.wait(2): raise AssertionError('client did not send')
                            time.sleep(1.2 if mode=='drain_timeout' else .05)  # Input/output closure before stderr arrives.
                        if mode=='invalid_frame': back.sendall(payload)
                        elif mode=='incomplete': back.sendall(frame(payload)[:-1])
                        else: back.sendall(frame(payload,1 if mode=='export' else 2))
                        if mode=='close': release.wait(3)
                        back.shutdown(socket.SHUT_WR)
                        if mode not in ('input_closed','drain_timeout','drain_bound'):
                            data=bytearray()
                            while True:
                                chunk=back.recv(4096)
                                if not chunk: break
                                data.extend(chunk)
                            if mode=='late_stdin': wire.append(bytes(data))
                except BrokenPipeError:
                    if mode not in ('input_closed','drain_timeout','drain_bound'): failures.append('BrokenPipeError')
                except BaseException as exc: failures.append(type(exc).__name__)
            peer=threading.Thread(target=upstream)
            def handle():
                try: relay.exchange_one(front)
                finally: front.close()
            handler=threading.Thread(target=handle)
            peer.start(); handler.start()
            try:
                client.sendall(request); read_headers(client)
                if mode in ('input_closed','drain_timeout','drain_bound'): client.sendall(b'PRIVATE-STDIN-CANARY'); sent.set()
                if mode=='output_closed': client.shutdown(socket.SHUT_RD); sent.set()
                if mode!='late_stdin': client.shutdown(socket.SHUT_WR)
                if mode=='close':
                    end=time.monotonic()+2
                    while time.monotonic()<end and relay.snapshot()['records'][0].get('capture',{}).get('stderr_bytes') != len(payload): time.sleep(.001)
                    relay.close(); release.set()
                received=bytearray()
                while True:
                    chunk=client.recv(4096)
                    if not chunk: break
                    received.extend(chunk)
                if mode=='late_stdin':
                    try: client.sendall(b'PRIVATE-LATE'); client.shutdown(socket.SHUT_WR)
                    except BrokenPipeError: self.fail('native output EOF incorrectly closed input forwarding')
            finally:
                handler.join(3); peer.join(3)
                front.close(); client.close(); listener.close(); relay.server.server_close()
            self.assertFalse(handler.is_alive()); self.assertFalse(peer.is_alive())
            self.assertEqual(failures,[]); self.assertEqual(wire,[request,b'PRIVATE-LATE'] if mode=='late_stdin' else [request])
            self.assertFalse(relay.connections)
            if observe:
                self.assertTrue(callable(getattr(relay,'wait_capture',None)), 'bounded capture barrier missing')
                relay.wait_capture(eid,time.monotonic()+.1)
            return relay.snapshot(),bytes(received),payload

    def test_repeated_close_preserves_replacement_socket_path(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); relay=FaultRelay(root/'relay',root/'up')
            relay.server.server_close(); relay.path.unlink(); relay.path.write_bytes(b'FOREIGN')
            relay.closed=True
            relay.close()
            self.assertTrue(relay.path.exists(),'repeat close removed a replacement pathname')
            self.assertEqual(relay.path.read_bytes(),b'FOREIGN')

    def test_repeated_close_cannot_bypass_an_unfinished_capture_barrier(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); relay=FaultRelay(root/'relay',root/'up')
            relay.closed=True; event=threading.Event(); relay.capture_done['a'*64]=event
            entered=threading.Event(); returned=threading.Event(); errors=[]
            def closing():
                entered.set()
                try: relay.close()
                except BaseException as exc: errors.append(type(exc).__name__)
                finally: returned.set()
            t=threading.Thread(target=closing); t.start(); entered.wait(1)
            try:
                self.assertFalse(returned.wait(.02),'closed flag bypassed live capture ownership')
            finally:
                event.set(); t.join(3); relay.server.server_close()
            self.assertFalse(t.is_alive()); self.assertEqual(errors,[])

    def test_native_output_eof_does_not_close_or_drop_still_open_stdin(self):
        result,received,payload=self.exchange('late_stdin')
        self.assertEqual(received,frame(payload))
        self.assertEqual(result['execs']['a'*64]['stdin_bytes'],len(b'PRIVATE-LATE'))
        self.assertEqual(result['records'][0]['capture']['state'],'finalized')

    def test_teardown_shutdown_is_aborted_not_a_fabricated_native_eof(self):
        result,_,_=self.exchange('close')
        record=result['records'][0]
        self.assertEqual(record['capture']['stop_reason'],'closed')
        self.assertEqual(record['capture']['state'],'aborted')
        self.assertEqual(record['import_diagnostic']['cause'],'unclassified')
        self.assertIs(record['import_diagnostic']['complete'],False)

    def test_unrelated_exec_inspect_cannot_release_live_capture_barrier(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
            listener.bind(str(root/'up')); listener.listen(1)
            relay=FaultRelay(root/'relay',root/'up'); eid='a'*64
            relay.capture_done[eid]=threading.Event()
            def peer():
                back,_=listener.accept()
                with back:
                    read_headers(back)
                    back.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}')
            t=threading.Thread(target=peer); t.start()
            client,front=socket.socketpair()
            client.sendall(('GET /exec/'+eid+'/json HTTP/1.1\r\nHost: docker\r\nConnection: close\r\n\r\n').encode())
            try:
                relay.exchange_one(front)
                with self.assertRaises(TimeoutError): relay.wait_capture(eid,time.monotonic()+.01)
            finally:
                client.close(); front.close(); t.join(3); listener.close(); relay.server.server_close()

    def test_clean_half_close_preserves_bytes_and_marks_real_eof(self):
        result,received,payload=self.exchange('clean')
        self.assertEqual(received,frame(payload))
        self.assertEqual(result['records'][0]['capture']['state'],'finalized')
        self.assertTrue(result['records'][0]['import_diagnostic']['complete'])

    def test_malformed_observation_cannot_swallow_application_bytes(self):
        result,received,payload=self.exchange('invalid_frame')
        self.assertEqual(received,payload)
        self.assertEqual(result['records'][0]['capture']['stop_reason'],'frame_invalid')
        self.assertIn('ValueError',result['errors'])
        self.assertIs(result['records'][0]['import_diagnostic']['complete'],False)

    def test_incomplete_frame_never_claims_complete_even_with_matching_error_prefix(self):
        result,_,_=self.exchange('incomplete')
        record=result['records'][0]
        self.assertEqual(record['capture']['state'],'aborted')
        self.assertEqual(record['capture']['stop_reason'],'frame_incomplete')
        self.assertIn('ValueError',result['errors'])
        self.assertEqual(record['import_diagnostic']['cause'],'unclassified')
        self.assertIs(record['import_diagnostic']['complete'],False)

    def test_output_sink_failure_still_observes_but_never_counts_failed_forward(self):
        result,received,payload=self.exchange('output_closed')
        record=result['records'][0]
        self.assertEqual(received,b'')
        self.assertEqual(record['capture']['output_stop'],'send_front_broken_pipe')
        self.assertEqual(record['capture']['stderr_bytes'],len(payload))
        self.assertEqual(record['import_diagnostic']['cause'],'hstore_binary_load_missing')
        self.assertNotIn('stdout_bytes',record)

    def test_drain_byte_limit_aborts_before_observing_more_than_64k(self):
        result,_,_=self.exchange('drain_bound')
        record=result['records'][0]
        self.assertEqual(record['capture']['state'],'aborted')
        self.assertEqual(record['capture']['stop_reason'],'drain_bound')
        self.assertLessEqual(record['capture']['stderr_bytes'],65536)
        self.assertIs(record['import_diagnostic']['complete'],False)
        self.assertNotIn('PRIVATE',json.dumps(result))

    def test_late_stderr_aborts_with_bounded_drain_not_synthetic_eof(self):
        result,_,_=self.exchange('drain_timeout')
        record=result['records'][0]
        self.assertEqual(record['capture']['stop_reason'],'drain_timeout')
        self.assertEqual(record['capture']['state'],'aborted')
        self.assertIs(record['import_diagnostic']['complete'],False)
        self.assertEqual(record['import_diagnostic']['cause'],'unclassified')

    def test_non_opted_in_exchange_keeps_original_early_disconnect_semantics(self):
        result,received,_=self.exchange('input_closed',observe=False)
        self.assertNotIn('capture',result['records'][0])
        self.assertNotIn('import_diagnostic',result['records'][0])
        self.assertEqual(received,b'')

    def test_early_input_closure_drains_real_upstream_eof_and_finalizes_cause(self):
        result,received,payload=self.exchange('input_closed')
        record=result['records'][0]
        self.assertEqual(record.get('import_diagnostic'),
                         {'cause':'hstore_binary_load_missing','complete':True,'error_count':1})
        self.assertEqual(record['capture']['state'],'finalized')
        self.assertEqual(record['capture']['stop_reason'],'upstream_eof')
        self.assertEqual(record['capture']['input_stop'],'send_back_broken_pipe')
        self.assertEqual(record['capture']['stderr_bytes'],len(payload))
        self.assertEqual(received,frame(payload))
        self.assertNotIn('PRIVATE',json.dumps(result))
        self.assertEqual(result['execs']['a'*64]['stdin_bytes'],0)


class RelayQuiescenceTests(unittest.TestCase):
    def test_close_deadline_also_bounds_a_blocked_classifier_finish(self):
        self.blocked_classifier(True,'finish')

    def test_close_deadline_bounds_nonobserved_classifier_finish(self):
        self.blocked_classifier(False,'finish')

    def test_close_deadline_bounds_nonobserved_classifier_feed(self):
        self.blocked_classifier(False,'feed')

    def blocked_classifier(self, observe, stage):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
            listener.bind(str(root/'up')); listener.listen(1); listener.settimeout(4)
            relay=FaultRelay(root/'relay',root/'up'); relay.observe_streams=observe
            eid='a'*64
            relay.execs[eid]={'kind':'restore','container_id':'b'*64,'stdout_bytes':0,'stdin_bytes':0}
            entered=threading.Event(); release=threading.Event(); closed=threading.Event(); errors=[]
            def block():
                entered.set()
                if not release.wait(8): raise AssertionError('classifier supervisor expired')
            class Diagnostic(MissingLibraryDiagnostic):
                def feed(self,data):
                    if stage=='feed': block()
                    return super().feed(data)
                def finish(self):
                    if stage=='finish': block()
                    return super().finish()
            relay.stderr_classifier_factory=lambda record:Diagnostic()
            def upstream():
                conn,_=listener.accept()
                with conn:
                    read_headers(conn); conn.recv(2)
                    conn.sendall(b'HTTP/1.1 101 UPGRADED\r\nConnection: Upgrade\r\n\r\n')
                    if stage=='feed': conn.sendall(frame(b'PRIVATE\n'))
            def closing():
                try: relay.close()
                except BaseException as exc: errors.append(type(exc).__name__)
                finally: closed.set()
            peer=threading.Thread(target=upstream)
            client,front=socket.socketpair(); client.settimeout(4)
            def handling():
                try: relay.exchange_one(front)
                finally: front.close()
            handler=threading.Thread(target=handling); closer=threading.Thread(target=closing)
            peer.start(); handler.start()
            try:
                client.sendall(('POST /exec/'+eid+'/start HTTP/1.1\r\nHost: docker\r\nContent-Length: 2\r\n\r\n{}').encode())
                read_headers(client); client.shutdown(socket.SHUT_WR)
                self.assertTrue(entered.wait(2)); closer.start()
                self.assertTrue(closed.wait(3.5),'classifier callback held the close lock past its bound')
                self.assertEqual(errors,['TimeoutError'])
            finally:
                release.set(); client.close(); handler.join(4); peer.join(4)
                if closer.ident is not None: closer.join(4)
                listener.close(); relay.close()
            self.assertFalse(handler.is_alive()); self.assertFalse(closer.is_alive())

    def test_cleanup_blocks_before_private_inputs_until_prefactory_handler_retires(self):
        from unittest.mock import Mock
        from run_hosted_faults import FaultProbe
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
            listener.bind(str(root/'up')); listener.listen(1); listener.settimeout(4)
            relay=FaultRelay(root/'relay',root/'up'); relay.observe_streams=True
            eid='a'*64
            relay.execs[eid]={'kind':'restore','container_id':'b'*64,'stdout_bytes':0,'stdin_bytes':0}
            entered=threading.Event(); release=threading.Event(); peer_release=threading.Event(); errors=[]
            def factory(record):
                entered.set()
                if not release.wait(8): raise AssertionError('factory supervisor expired')
                return MissingLibraryDiagnostic()
            relay.stderr_classifier_factory=factory
            def upstream():
                try:
                    conn,_=listener.accept()
                    with conn:
                        read_headers(conn); conn.recv(2)
                        conn.sendall(b'HTTP/1.1 101 UPGRADED\r\nConnection: Upgrade\r\n\r\n')
                        peer_release.wait(8)
                except BaseException as exc: errors.append(type(exc).__name__)
            peer=threading.Thread(target=upstream); peer.start(); relay.start()
            client=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); client.settimeout(4)
            p=FaultProbe.__new__(FaultProbe); p.root=root; p.result={}; p.case='storage-offline'
            p.daemon='unit'; p.containers={}; p.worker_owners={}; p.volumes=[]; p.roles={}; p.owner=lambda:None
            p.e=Mock(); p.e.call.return_value={'ID':'unit'}; p.relay=relay
            for name in ('private','backend','fresh-state','state'):
                (root/name).mkdir(); (root/name/'canary').write_bytes(b'PRIVATE-INPUT')
            hook=Mock(); p.before_private_cleanup=hook
            try:
                client.connect(str(root/'relay'))
                client.sendall(('POST /exec/'+eid+'/start HTTP/1.1\r\nHost: docker\r\nContent-Length: 2\r\n\r\n{}').encode())
                read_headers(client); self.assertTrue(entered.wait(2))
                self.assertEqual(len(relay.capture_done),0)
                start=time.monotonic()
                with self.assertRaises(TimeoutError): p.cleanup()
                self.assertLess(time.monotonic()-start,4)
                hook.assert_not_called()
                for name in ('private','backend','fresh-state','state'):
                    self.assertEqual((root/name/'canary').read_bytes(),b'PRIVATE-INPUT')
                rejected,front=socket.socketpair()
                try:
                    relay.exchange_one(front)
                    self.assertEqual(len(relay.snapshot()['records']),1,'closed relay admitted another exchange')
                finally: rejected.close(); front.close()
            finally:
                release.set(); peer_release.set(); client.close(); peer.join(4); listener.close()
                relay.close()
            self.assertFalse(peer.is_alive()); self.assertEqual(errors,[])
            self.assertFalse(relay.connections)
            self.assertFalse(relay.path.exists(),'successful retry-close left its owned socket pathname')
            # A failed bounded close is retryable, not a permanent transport error.
            p.cleanup(); hook.assert_called_once()
            self.assertFalse((root/'private').exists()); self.assertEqual(relay.snapshot()['errors'],[])


class RelayDeadlineTests(unittest.TestCase):
    def test_stalled_drain_send_uses_original_one_second_bound_and_counts_partial_stdout(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); relay=FaultRelay(root/'relay',root/'up')
            client,front=socket.socketpair(); back,peer=socket.socketpair()
            for conn in (client,front,back,peer): conn.settimeout(4)
            front.setsockopt(socket.SOL_SOCKET,socket.SO_SNDBUF,4096)
            peer.shutdown(socket.SHUT_RD)
            eid='a'*64; relay.execs[eid]={'kind':'restore','stdout_bytes':0,'stdin_bytes':0}
            record={}; errors=[]; stopped=threading.Event()
            def observe():
                try: relay.observe_stream(front,back,eid,record,MissingLibraryDiagnostic(),None)
                except BaseException as exc: errors.append(type(exc).__name__)
                finally: front.close(); back.close(); stopped.set()
            handler=threading.Thread(target=observe); handler.start()
            try:
                client.sendall(b'PRIVATE-INPUT')
                end=time.monotonic()+2
                while not record.get('capture',{}).get('input_stop') and time.monotonic()<end: time.sleep(.001)
                self.assertEqual(record['capture']['input_stop'],'send_back_broken_pipe')
                peer.sendall(frame(b'x'*65528,1))
                self.assertTrue(stopped.wait(1.3),'send outlived the absolute drain deadline')
                wire=bytearray()
                while True:
                    chunk=client.recv(65536)
                    if not chunk: break
                    wire.extend(chunk)
                self.assertGreater(len(wire),8); self.assertLess(len(wire),65536)
                self.assertEqual(relay.execs[eid]['stdout_bytes'],len(wire)-8)
                self.assertEqual(record['capture']['stop_reason'],'drain_timeout')
                self.assertEqual(record['capture']['state'],'aborted')
                self.assertIs(record['import_diagnostic']['complete'],False)
                self.assertEqual(relay.execs[eid]['stdin_bytes'],0)
                self.assertNotIn('PRIVATE',json.dumps(relay.snapshot()))
            finally:
                for conn in (client,peer):
                    try: conn.shutdown(socket.SHUT_RDWR)
                    except OSError: pass
                handler.join(4); client.close(); peer.close(); relay.server.server_close()
            self.assertFalse(handler.is_alive()); self.assertEqual(errors,[])

    def test_both_observed_send_directions_use_remaining_total_deadline(self):
        from types import SimpleNamespace
        from unittest.mock import patch
        import run_hosted_faults as module
        for direction in ('stdout','stdin'):
            with self.subTest(direction=direction), tempfile.TemporaryDirectory() as directory:
                root=Path(directory); relay=FaultRelay(root/'relay',root/'up')
                client,front=socket.socketpair(); back,peer=socket.socketpair()
                for conn in (client,front,back,peer): conn.settimeout(4)
                destination=front if direction=='stdout' else back
                destination.setsockopt(socket.SOL_SOCKET,socket.SO_SNDBUF,4096)
                elapsed=[0.0]
                # Real socket I/O, with only elapsed time advanced to exercise
                # the unchanged 180-second budget without a three-minute test.
                class Source:
                    def fileno(self): return front.fileno()
                    def settimeout(self,value): front.settimeout(value)
                    def recv(self,size):
                        value=front.recv(size); elapsed[0]=179.8
                        return value
                    def shutdown(self,how): front.shutdown(how)
                class Diagnostic(MissingLibraryDiagnostic):
                    def feed_stdout(self,data): elapsed[0]=179.8
                eid='a'*64; relay.execs[eid]={'kind':'restore','stdout_bytes':0,'stdin_bytes':0}
                record={}; stopped=threading.Event(); errors=[]
                def observe():
                    try: relay.observe_stream(front if direction=='stdout' else Source(),back,eid,record,Diagnostic(),None)
                    except BaseException as exc: errors.append(type(exc).__name__)
                    finally: front.close(); back.close(); stopped.set()
                clock=SimpleNamespace(monotonic=lambda:time.monotonic()+elapsed[0])
                with patch.object(module,'time',clock):
                    handler=threading.Thread(target=observe); handler.start()
                    try:
                        (peer if direction=='stdout' else client).sendall(frame(b'x'*65528,1) if direction=='stdout' else b'x'*65536)
                        self.assertTrue(stopped.wait(.8),'send reset the absolute total budget')
                        self.assertEqual(record['capture']['stop_reason'],'timeout')
                        self.assertEqual(record['capture']['state'],'aborted')
                        self.assertIs(record['import_diagnostic']['complete'],False)
                        key='stdout_bytes' if direction=='stdout' else 'stdin_bytes'
                        self.assertGreater(relay.execs[eid][key],0)
                        self.assertLess(relay.execs[eid][key],65528)
                    finally:
                        for conn in (client,peer):
                            try: conn.shutdown(socket.SHUT_RDWR)
                            except OSError: pass
                        handler.join(4)
                        client.close(); peer.close(); relay.server.server_close()
                self.assertFalse(handler.is_alive()); self.assertEqual(errors,[])


class RelayPathOwnershipTests(unittest.TestCase):
    def replacement(self, root, kind):
        path=root/'relay'; path.unlink()
        other=None
        if kind=='file': path.write_bytes(b'FOREIGN')
        elif kind=='socket':
            other=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); other.bind(str(path)); other.listen(1)
        else:
            (root/'target').write_bytes(b'FOREIGN'); (root/'target').chmod(0o640)
            path.symlink_to(root/'target')
        return other

    def test_first_close_preserves_replacement_file_socket_and_symlink(self):
        for kind in ('file','socket','symlink'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                root=Path(directory); relay=FaultRelay(root/'relay',root/'up'); relay.start()
                other=self.replacement(root,kind); before=relay.path.lstat()
                try:
                    relay.close(); relay.close()
                    self.assertTrue(relay.path.is_symlink() or relay.path.exists(),'first close removed a replacement pathname')
                    self.assertEqual(relay.path.lstat(),before)
                    if kind!='socket': self.assertEqual(relay.path.read_bytes(),b'FOREIGN')
                finally:
                    relay.server.server_close()
                    if other is not None: other.close()

    def test_start_refuses_replacements_without_chmod_or_unlink(self):
        for kind in ('file','socket','symlink'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                root=Path(directory); relay=FaultRelay(root/'relay',root/'up')
                other=self.replacement(root,kind); before=relay.path.lstat()
                target=(root/'target').stat() if kind=='symlink' else None
                try:
                    with self.assertRaises(ValueError): relay.start()
                    self.assertEqual(relay.path.lstat(),before)
                    relay.close()
                    self.assertEqual(relay.path.lstat(),before)
                    if target is not None: self.assertEqual((root/'target').stat(),target)
                finally:
                    relay.close()
                    if other is not None: other.close()

    def test_identity_is_pinned_at_bind_before_server_activation(self):
        import socketserver
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            activate=socketserver.UnixStreamServer.server_activate
            def replace(server):
                path=Path(server.server_address); path.unlink(); path.write_bytes(b'FOREIGN')
                activate(server)
            with patch.object(socketserver.UnixStreamServer,'server_activate',replace):
                relay=FaultRelay(root/'relay',root/'up')
            try:
                with self.assertRaises(ValueError): relay.start()
            finally: relay.close()
            self.assertEqual(relay.path.read_bytes(),b'FOREIGN')

    def test_unreplaced_bound_socket_is_removed_even_without_start(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); relay=FaultRelay(root/'relay',root/'up')
            relay.close(); self.assertFalse(relay.path.exists()); relay.close()


class TraceDiagnosticTests(unittest.TestCase):
    def test_native_deleted_fd_suffix_is_a_literal_enospc_write_receipt(self):
        from hosted_storage_trace import WriteStream
        # Sanitized strace 6.8 owned-file format: deletion is OUTSIDE <path>.
        # Real owned-file control returned EBADF; this ENOSPC fixture is parser
        # regression input, never temporary-filesystem pressure evidence.
        s=WriteStream(10,lambda path:'temp_pack' if path=='/tmp/restic-temp-pack-PRIVATE' else None)
        row=s.feed('[pid 11] write(6</tmp/restic-temp-pack-PRIVATE>(deleted), ""..., 4096) = -1 ENOSPC (No space left on device)')
        self.assertEqual(s.failure,{'pid':11,'syscall':'write','fd':6,'errno':28,'path_kind':'temp_pack','stage':'write'})
        self.assertEqual(row,{'pid':11,'syscall':'write','fd':6,'errno':28,'path_kind':'temp_pack'})
        self.assertNotIn('PRIVATE',json.dumps(row))
        s.finish()

    def test_deleted_fd_suffix_keeps_syscall_pairing_and_rejection_boundaries(self):
        from hosted_storage_trace import WriteStream
        classify=lambda path:'temp_pack' if path=='/tmp/restic-temp-pack-PRIVATE' else None
        for syscall,args in (('write','""..., 4096'),('pwrite64','""..., 4096, 0'),('writev','[...], 2')):
            for prefix,pid in (('',10),('[pid 11] ',11),('11 ',11)):
                with self.subTest(syscall=syscall,prefix=prefix):
                    s=WriteStream(10,classify)
                    row=s.feed(prefix+syscall+'(6</tmp/restic-temp-pack-PRIVATE>(deleted), '+args+') = -1 ENOSPC (No space left on device)')
                    self.assertEqual(row,{'pid':pid,'syscall':syscall,'fd':6,'errno':28,'path_kind':'temp_pack'})
                    s.finish()
        s=WriteStream(10,classify)
        self.assertIsNone(s.feed('[pid 11] write(6</tmp/restic-temp-pack-PRIVATE>(deleted), ""..., 4096 <unfinished ...>'))
        self.assertEqual(s.feed('[pid 11] <... write resumed>) = -1 ENOSPC (No space left on device)')['pid'],11)
        s.finish()
        base='write(6</tmp/restic-temp-pack-PRIVATE>(deleted), ""..., 4096) = -1 ENOSPC (No space left on device)'
        for line in (base.replace('(deleted)','(other)'),base.replace('(deleted)','(deleted)(deleted)'),
                     base.replace('/tmp/restic-temp-pack-PRIVATE','/private/PRIVATE'),
                     base.replace('ENOSPC (No space left on device)','EIO (I/O error)'),
                     base.replace('No space left on device','CONTROL-OTHER-REASON'),
                     'openat(AT_FDCWD, "/tmp/restic-temp-pack-PRIVATE", O_RDWR|O_CREAT, 0600) = -1 ENOSPC (No space left on device)'):
            s=WriteStream(10,classify)
            self.assertIsNone(s.feed(line))
            self.assertNotIn('PRIVATE',json.dumps(s.diagnostics))

    def test_setup_unfinished_pairs_and_trace_bounds_fail_closed_without_payload(self):
        from hosted_storage_trace import WriteStream
        s=WriteStream(10,lambda path:'temp_pack')
        s.feed('[pid 11] openat(AT_FDCWD, "/tmp/restic-temp-pack-PRIVATE", O_RDWR|O_CREAT <unfinished ...>')
        s.feed('[pid 11] <... openat resumed>) = -1 ENOSPC (No space left on device)')
        self.assertEqual(getattr(s,'failure',None),
            {'pid':11,'syscall':'openat','fd':None,'errno':28,'path_kind':'temp_pack','stage':'create_open'})
        s.finish()
        self.assertEqual(s.diagnostics['paired'],1)
        self.assertFalse(s.pending)
        s.diagnostics['lines']=10000
        with self.assertRaises(ValueError): s.feed('PRIVATE-UNKNOWN')
        self.assertEqual(s.diagnostics['lines'],10000)

    def test_trace_reader_requests_setup_only_on_opt_in_and_binds_diagnostic(self):
        import io
        import os
        from unittest.mock import Mock, patch
        import hosted_storage_trace as trace
        for enabled in (False,True):
            with self.subTest(enabled=enabled):
                t=trace.WriteTrace([os.getpid()],lambda path:'temp_pack')
                t.diagnose_setup=enabled
                t.writer_binding=lambda pid:{'root_pid':os.getpid(),'chain':[]}
                raw=b'openat(AT_FDCWD, "/tmp/restic-temp-pack-PRIVATE", O_RDWR|O_CREAT, 0600) = -1 ENOSPC (No space left on device)\n'
                proc=Mock(pid=999,stderr=io.BytesIO(raw)); proc.poll.return_value=0; proc.returncode=0
                with patch.object(trace.subprocess,'Popen',return_value=proc) as launch:
                    with self.assertRaises(ValueError): t.start()  # No actual attachment in this offline control.
                argv=launch.call_args.args[0]
                self.assertEqual('openat' in argv[argv.index('-e')+1],enabled)
                result=t.receipt()
                self.assertEqual(result['writes'],[])
                if enabled:
                    self.assertEqual(result['diagnostics']['setup_failures'],1)
                    self.assertEqual(result['failures'][0]['stage'],'create_open')
                    self.assertEqual(result['failures'][0]['writer']['root_pid'],os.getpid())
                    self.assertNotIn('PRIVATE',json.dumps(result))
                else: self.assertNotIn('failures',result)

    def test_setup_enospc_is_visible_but_never_a_write_receipt(self):
        from hosted_storage_trace import WriteStream
        s=WriteStream(10,lambda path:'temp_pack' if path.startswith('/tmp/restic-') else None)
        self.assertIsNone(s.feed('[pid 11] openat(AT_FDCWD, "/tmp/restic-temp-pack-PRIVATE", O_RDWR|O_CREAT|O_EXCL, 0600) = -1 ENOSPC (No space left on device)'))
        self.assertEqual(getattr(s,'failure',None),
            {'pid':11,'syscall':'openat','fd':None,'errno':28,'path_kind':'temp_pack','stage':'create_open'})
        self.assertNotIn('PRIVATE',json.dumps(s.diagnostics))
        self.assertEqual(s.diagnostics['setup_failures'],1)
        self.assertIsNone(s.feed('[pid 11] write(4</tmp/restic-temp-pack-PRIVATE>, ""..., 5) = -1 EIO (I/O error)'))
        self.assertEqual(s.diagnostics['write_other_errno'],1)
        self.assertIsNone(s.feed('[pid 11] write(4</private/secret>, ""..., 5) = -1 ENOSPC (No space left on device)'))
        self.assertEqual(s.diagnostics['path_unmatched'],1)
        self.assertNotIn('/private',json.dumps(s.diagnostics))


class ExportDiagnosticTests(unittest.TestCase):
    def test_real_exchange_emits_export_marker_projection_not_import_diagnostic(self):
        result,received,payload=CaptureTests().exchange('export')
        record=result['records'][0]
        self.assertEqual(record.get('export_diagnostic'),
            {'cause':'no_stderr','complete':True,'completion_marker_seen':True})
        self.assertEqual(received,frame(payload,1))
        self.assertNotIn('import_diagnostic',record)
        self.assertNotIn('PRIVATE',json.dumps(result))

    def test_export_factory_requires_exact_persisted_dump_binding(self):
        from unittest.mock import Mock
        import run_hosted_storage_prereqs as runner
        from test_hosted_storage_prereqs import synthetic
        p=runner.StorageProbe.__new__(runner.StorageProbe); p.case=runner.F19; p.tracking=True
        active=synthetic()['attempts'][0]['owner']; p.source=active['sourceContainerID']; p.owner=lambda:active
        p.relay=Mock(); p.relay.dump_bindings={active['execID']:{'run_id':active['runID'],'owner_checkpoint':active}}
        record={'boundary':'dump-start','owner_checkpoint':active,'exec_id':active['execID'],'container_id':p.source}
        diagnostic=p.import_stderr_classifier(record)
        self.assertIsInstance(diagnostic,runner.ExportDiagnostic)
        self.assertEqual(record['export_contract'],'wrapped-dump-v1')
        p.relay.dump_bindings[active['execID']]['run_id']='f'*32
        with self.assertRaises(ValueError): p.import_stderr_classifier(record)

    def test_f19_trace_setup_opt_in_does_not_change_f20_calls(self):
        import os
        from unittest.mock import Mock, patch
        import run_hosted_storage_prereqs as runner
        for case,expected in ((runner.F19,True),(runner.F20,False)):
            p=runner.StorageProbe.__new__(runner.StorageProbe); p.case=case; p.traces=[]
            obj={'Id':'b'*64,'State':{'Pid':os.getpid(),'Running':True,'StartedAt':'unit'}}
            p.owned_running=Mock(return_value=obj); p.cgroup=lambda pid,strict:Path('/scope/'+'b'*64)
            with patch.object(runner.os,'readlink',return_value='/usr/local/bin/bakabel'),patch.object(runner,'WriteTrace') as trace:
                p.start_trace({'workerStartAuthorized':True},lambda path:None)
            self.assertIs(trace.call_args.kwargs.get('diagnose_setup',False),expected)

    def test_source_completion_marker_and_stderr_are_finite_and_payload_free(self):
        import run_hosted_storage_prereqs as runner
        from run_hosted_faults import FrameCounter
        self.assertTrue(hasattr(runner,'ExportDiagnostic'),'source boundary classifier missing')
        marker=b'\0BAKABEL_EXPORT_COMPLETE_V1:'+b'a'*32+b'\0'
        diagnostic=runner.ExportDiagnostic('a'*32)
        counter=FrameCounter(stderr_observer=diagnostic.feed,stdout_observer=diagnostic.feed_stdout)
        wire=frame(b'PRIVATE-DUMP'+marker,1)+frame(b'pg_dump: error: PRIVATE-SECRET\n')
        for byte in wire: counter.feed(bytes([byte]))
        value=diagnostic.finish()
        self.assertTrue(value['completion_marker_seen'])
        self.assertEqual(value['cause'],'source_dump_error')
        self.assertNotIn('PRIVATE',json.dumps(value))
        self.assertFalse(diagnostic.buffer)
        self.assertFalse(diagnostic.tail)
        other=runner.ExportDiagnostic('a'*32)
        other.feed_stdout(b'PRIVATE'+marker[:-1])
        other.feed(b'PRIVATE-UNKNOWN\n')
        self.assertEqual(other.finish(),{'cause':'unclassified','complete':True,'completion_marker_seen':False})


class FailureReadbackTests(unittest.TestCase):
    def test_cleanup_snapshots_only_after_observation_is_quiescent(self):
        import copy
        from unittest.mock import Mock
        from run_hosted_faults import FaultProbe
        with tempfile.TemporaryDirectory() as directory:
            p=FaultProbe.__new__(FaultProbe); p.root=Path(directory); p.result={}; p.case='storage-offline'
            p.daemon='unit'; p.containers={}; p.worker_owners={}; p.volumes=[]; p.roles={}; p.owner=lambda:None
            p.e=Mock(); p.e.call.return_value={'ID':'unit'}
            for name in ('private','backend','fresh-state','state'): (p.root/name).mkdir()
            state={'errors':[],'records':[{'capture':{'state':'armed'}}]}
            p.relay=Mock(); p.relay.snapshot.side_effect=lambda:copy.deepcopy(state)
            def closed(): state['records'][0]['capture']['state']='aborted'
            p.relay.close.side_effect=closed
            p.cleanup()
            self.assertEqual(p.result['relay']['records'][0]['capture']['state'],'aborted')

    def test_storage_observation_is_opted_in_only_for_f19_f22(self):
        from unittest.mock import Mock, patch
        import run_hosted_storage_prereqs as runner
        from run_hosted_faults import FaultProbe
        def initialize(p,args,case):
            p.result={}; p.relay=Mock(observe_streams=False)
        with patch.object(FaultProbe,'__init__',initialize):
            for case,expected in ((runner.F19,True),(runner.F20,False),(runner.F22,True)):
                p=runner.StorageProbe(None,case)
                self.assertIs(p.relay.observe_streams,expected)

    def test_terminal_attempt_is_retained_when_capture_barrier_times_out(self):
        from unittest.mock import Mock
        import run_hosted_storage_prereqs as runner
        from test_hosted_storage_prereqs import synthetic
        value=synthetic()['attempts'][0]; active=value['owner']; run=active['runID']
        p=runner.StorageProbe.__new__(runner.StorageProbe)
        p.case=runner.F22; p.result={'attempts':[]}; p.operations={run:active}
        p.removals={run:{'terminal_before_remove':value['terminal']}}
        p.owner=lambda:None; p.last=lambda:{'runID':run}; p.e=Mock(); p.e.inspect.return_value=None
        p.finish=lambda *args,**kw:[value['result']]
        p.relay=Mock(); p.relay.wait_capture.side_effect=TimeoutError('PRIVATE-TIMEOUT')
        with self.assertRaises(TimeoutError): p.finish_attempt('controller')
        self.assertEqual(len(p.result['attempts']),1)
        self.assertEqual(p.result['attempts'][0]['terminal'],value['terminal'])
        self.assertNotIn('PRIVATE',json.dumps(p.result))

    def test_finish_attempt_waits_for_exact_capture_inside_original_deadline(self):
        from unittest.mock import Mock
        import run_hosted_storage_prereqs as runner
        from test_hosted_storage_prereqs import synthetic
        row=synthetic(); value=row['attempts'][0]; active=value['owner']; run=active['runID']
        p=runner.StorageProbe.__new__(runner.StorageProbe)
        p.case=runner.F22; p.result={'attempts':[]}; p.operations={run:active}
        p.removals={run:{'terminal_before_remove':value['terminal']}}
        p.owner=lambda:None; p.last=lambda:{'runID':run}; p.e=Mock(); p.e.inspect.return_value=None
        events=[]
        p.finish=lambda *args,**kw: events.append('controller_finished') or [value['result']]
        p.relay=Mock(observe_streams=True)
        def barrier(eid,deadline):
            self.assertEqual(eid,active['execID'])
            self.assertGreater(deadline,time.monotonic()); self.assertLessEqual(deadline,time.monotonic()+85)
            events.append('capture_quiescent')
        p.relay.wait_capture.side_effect=barrier
        p.finish_attempt('controller')
        self.assertEqual(events,['controller_finished','capture_quiescent'])

    def test_unclassified_cause_still_reads_full_baseline_and_never_prepares_retry(self):
        import copy
        from unittest.mock import Mock
        import run_hosted_storage_prereqs as runner
        from test_hosted_storage_cycle1 import extension_receipt
        from verify_hosted_storage_prereqs import restore_contract
        baseline,_=restore_contract(); db={'cluster_id':'123','database_oid':'16384','database':'fixture'}
        p=runner.StorageProbe.__new__(runner.StorageProbe); p.source='c'*64; p.result={}; events=[]
        p.success_snapshot=lambda:'f'*64; p.snapshot_mapping=lambda value:None; p.startpg=lambda *args:'e'*64
        p.target_identity=lambda target:{'container_id':target,'started_at':'target','restart_count':0}
        p.library_hash=lambda target:'6'*64; p.e=Mock(); p.e.exec.return_value={'exit':0}
        def sql(target,query):
            if 'server_version_num' in query:return '18'
            if 'SELECT rolname,oid' in query:return 'source' if target==p.source else 'target'
            if 'SELECT count(*) FROM pg_extension' in query:return '0'
            if 'SELECT extversion' in query:return '1.8'
            return 'fixed-fixture-data'
        p.sql=sql
        def action(target,operation,identity):
            events.append(operation)
            if operation=='prepare': raise AssertionError('must not retry unknown cause')
            return 1
        p.extension_action=action; p.controller=lambda *args:'controller'
        row=extension_receipt(); row['relay']['records'][0].pop('import_diagnostic')
        p.finish_attempt=lambda *args,**kwargs:row['attempts'][0]
        p.relay=Mock(); p.relay.snapshot.return_value=row['relay']
        p.database_identity=Mock(side_effect=[db,db]); p.catalog=Mock(side_effect=[copy.deepcopy(baseline),copy.deepcopy(baseline)])
        with self.assertRaisesRegex(ValueError,'exact missing library'): p.exercise_extension()
        ext=p.result['extension']
        self.assertEqual(ext.get('database_after_failure'),db)
        self.assertEqual(ext.get('catalog_after_failure'),baseline)
        self.assertEqual(events,['hide'])
        self.assertIsNone(ext['failure_cause'])


if __name__=='__main__': unittest.main()
