"""Offline F22 diagnostic controls; never hosted acceptance evidence.

Native block captured from the pinned PG image by the owned rootless probe.
The historical hosted 429 bytes were not retained and are NOT reconstructed.
"""
import unittest
from run_hosted_storage_prereqs import MissingLibraryDiagnostic

NATIVE=(b'pg_restore: error: could not execute query: ERROR:  could not access file "hstore": No such file or directory\n'
        b'CONTEXT:  SQL statement "CREATE FUNCTION hstore_in(cstring)\n'
        b'RETURNS hstore\n'
        b"AS '$libdir/hstore'\n"
        b'LANGUAGE C STRICT IMMUTABLE PARALLEL SAFE"\n'
        b'extension script file "hstore--1.4.sql", near line 8\n'
        b'Command was: CREATE EXTENSION IF NOT EXISTS hstore WITH SCHEMA public;\n\n\n')
EXPECTED={'cause':'hstore_binary_load_missing','complete':True,'error_count':1}

class NativeMessageTests(unittest.TestCase):
    def test_exact_observed_pinned_native_context_is_recognized(self):
        self.assertEqual(len(NATIVE),374)
        d=MissingLibraryDiagnostic()
        for byte in NATIVE: d.feed(bytes([byte]))
        self.assertEqual(d.finish(),EXPECTED)

    def test_exact_production_pg_environment_warning_plus_native_error_is_recognized(self):
        # Production pgEnv fixes PGPASSFILE=/dev/null. libpq emits this warning
        # even on successful trust-auth connections; it is not a second error.
        payload=b'WARNING: password file "/dev/null" is not a plain file\n'+NATIVE
        self.assertEqual(len(payload),429)
        d=MissingLibraryDiagnostic()
        for byte in payload:d.feed(bytes([byte]))
        self.assertEqual(d.finish(),EXPECTED)

    def test_native_context_contract_rejects_every_truncation_and_unrelated_error(self):
        # An observed known block is not a substring or an arbitrary CONTEXT skip.
        prefixed=b'WARNING: password file "/dev/null" is not a plain file\n'+NATIVE
        mutations=[payload[:n] for payload in (NATIVE,prefixed) for n in range(len(payload))]
        mutations += [prefixed.replace(b'/dev/null',b'/elsewhere'),
                      prefixed+b'pg_restore: error: PRIVATE_SECOND_ERROR\n',
                      NATIVE.replace(b'"hstore"',b'"other"'),
                      NATIVE.replace(b'CREATE EXTENSION',b'DROP EXTENSION'),
                      NATIVE.replace(b'LANGUAGE C',b'LANGUAGE X'),
                      NATIVE+b'pg_restore: error: PRIVATE_SECOND_ERROR\n',
                      b'PRIVATE_PREFIX\n'+NATIVE, NATIVE+b'PRIVATE_SUFFIX\n', b'x'*16385]
        for payload in mutations:
            with self.subTest(length=len(payload)):
                d=MissingLibraryDiagnostic();d.feed(payload);value=d.finish()
                self.assertEqual(value['cause'],'unclassified')
                self.assertNotIn('PRIVATE',str(value))
                self.assertEqual(d.buffer,bytearray())

    def test_real_unread_unix_input_reset_does_not_complete_observed_native_message(self):
        # Linux AF_UNIX kernel lifecycle control, NOT a real Docker execution.
        # The separate rootless probe establishes this block's native origin.
        import socket,select,threading,tempfile
        from pathlib import Path
        from run_hosted_faults import FaultRelay
        payload=b'WARNING: password file "/dev/null" is not a plain file\n'+NATIVE
        frame=b'\x02\0\0\0'+len(payload).to_bytes(4,'big')+payload
        with tempfile.TemporaryDirectory() as directory:
            relay=FaultRelay(Path(directory)/'relay.sock',Path(directory)/'unused')
            front,client=socket.socketpair();back,peer=socket.socketpair()
            eid='a'*64;record={};errors=[]
            relay.execs[eid]={'kind':'restore','container_id':'b'*64,'stdout_bytes':0,'stdin_bytes':0}
            def run():
                try:relay.observe_stream(front,back,eid,record,MissingLibraryDiagnostic(),None)
                except BaseException as exc:errors.append(type(exc).__name__)
                finally:
                    front.close();back.close()
                    # Direct control owns retirement; real HTTP handler sets it.
                    if eid in relay.capture_done:relay.capture_done[eid].set()
            thread=threading.Thread(target=run);thread.start()
            try:
                client.settimeout(3);peer.settimeout(3)
                client.sendall(b'owned-protocol-control-input'*128)
                self.assertEqual(select.select([peer],[],[],3)[0],[peer])
                peer.sendall(frame)
                # Close with received-but-unread stdin: real kernel reset, no
                # injected Python errno and no rule converting reset into EOF.
                peer.close()
                received=bytearray()
                while True:
                    data=client.recv(4096)
                    if not data:break
                    received.extend(data)
                thread.join(3);self.assertFalse(thread.is_alive())
                self.assertEqual(errors,[])
                import hashlib
                self.assertEqual(hashlib.sha256(received).hexdigest(),hashlib.sha256(frame).hexdigest())
                self.assertEqual(record['capture']['stop_reason'],'recv_back_reset')
                self.assertEqual(record['capture']['state'],'aborted')
                self.assertEqual(record['capture']['stderr_bytes'],len(payload))
                self.assertEqual(record.get('import_observation'),{
                    'cause':'hstore_binary_load_missing','message_complete':True,
                    'observed_error_count':1,'transport_complete':False})
                self.assertEqual(record['import_diagnostic'],{'cause':'unclassified','complete':False,'error_count':1})
            finally:
                client.close();peer.close()
                if thread.is_alive():
                    front.shutdown(socket.SHUT_RDWR);back.shutdown(socket.SHUT_RDWR);thread.join(3)
                relay.close()

    def test_finite_native_observation_cannot_replace_strict_stream_or_terminal_proof(self):
        import copy
        from test_hosted_storage_cycle1 import extension_receipt
        from verify_hosted_storage_prereqs import verify_case
        original=extension_receipt();verify_case(original)
        row=copy.deepcopy(original)
        start=next(r for r in row['relay']['records'] if r.get('boundary')=='restore-start')
        incomplete={'cause':'unclassified','complete':False,'error_count':1}
        start.update(import_diagnostic=incomplete,import_observation={
            'cause':'hstore_binary_load_missing','message_complete':True,
            'observed_error_count':1,'transport_complete':False})
        row['extension']['failure_cause']=incomplete
        with self.assertRaises(ValueError):verify_case(row)
        row=copy.deepcopy(original);row['attempts'][0]['terminal']['exec_exit_code']=0
        with self.assertRaises(ValueError):verify_case(row)
        row=copy.deepcopy(original);row['attempts'][0]['terminal']['sessions']=1
        with self.assertRaises(ValueError):verify_case(row)



class NativeFramingTests(unittest.TestCase):
    def capture_reset(self, wire):
        """Owned real AF_UNIX reset, never an Engine or hosted reply."""
        import socket, select, threading, tempfile
        from pathlib import Path
        from run_hosted_faults import FaultRelay
        with tempfile.TemporaryDirectory() as directory:
            relay=FaultRelay(Path(directory)/'r.sock',Path(directory)/'unused')
            front,client=socket.socketpair(); back,peer=socket.socketpair()
            eid='a'*64; record={}; errors=[]
            relay.execs[eid]={'kind':'restore','container_id':'b'*64,'stdout_bytes':0,'stdin_bytes':0}
            def observe():
                try: relay.observe_stream(front,back,eid,record,MissingLibraryDiagnostic(),None)
                except BaseException as exc: errors.append(type(exc).__name__)
                finally:
                    front.close(); back.close()
                    if eid in relay.capture_done: relay.capture_done[eid].set()
            thread=threading.Thread(target=observe); thread.start()
            try:
                client.settimeout(3); peer.settimeout(3)
                client.sendall(b'owned-unread-input'*32)
                self.assertEqual(select.select([peer],[],[],3)[0],[peer])
                peer.sendall(wire); peer.close()
                received=bytearray()
                while True:
                    data=client.recv(65536)
                    if not data: break
                    received.extend(data)
                thread.join(3); self.assertFalse(thread.is_alive()); self.assertEqual(errors,[])
                import hashlib
                self.assertEqual(hashlib.sha256(received).hexdigest(),hashlib.sha256(wire).hexdigest())
                self.assertEqual(record['import_diagnostic']['complete'],False)
                self.assertEqual(record['capture']['state'],'aborted')
                return record
            finally:
                client.close(); peer.close()
                if thread.is_alive():
                    for sock in (front,back):
                        try: sock.shutdown(socket.SHUT_RDWR)
                        except OSError: pass
                    thread.join(3)
                relay.close()

    @staticmethod
    def frame(payload, stream=2, length=None):
        return bytes([stream,0,0,0])+(len(payload) if length is None else length).to_bytes(4,'big')+payload

    def test_native_reset_requires_fully_consumed_valid_observed_framing(self):
        payload=b'WARNING: password file "/dev/null" is not a plain file\n'+NATIVE
        good=self.capture_reset(self.frame(payload))
        evidence=good.get('native_fatal_observation')
        self.assertIsInstance(evidence,dict,'separate native template/framing receipt missing')
        self.assertEqual(evidence,{'schema':1,'template':'pg18-hstore-devnull-429-v1',
            'observed_bytes':429,'observed_error_count':1,'framing_valid':True,
            'framing_consumed':True,'reset_candidate':True})
        # Both review counterexamples retain complete text but incomplete framing.
        bad=[self.frame(payload,length=len(payload)+1),
             self.frame(payload)+b'\x02\0',
             self.frame(payload)+self.frame(b'',length=1),
             self.frame(payload)+self.frame(b'x',stream=1,length=2),
             self.frame(payload)+self.frame(b''),
             self.frame(payload)+self.frame(b'',stream=0),
             self.frame(payload)+self.frame(b'',length=65537),
             self.frame(payload)+self.frame(b'',stream=3)]
        for wire in bad:
            with self.subTest(length=len(wire),tail=wire[-8:].hex()):
                record=self.capture_reset(wire)
                self.assertTrue(record['import_observation']['message_complete'])
                self.assertFalse(record['native_fatal_observation']['reset_candidate'])

    def test_legacy_or_other_observed_bytes_never_get_native_template_identity(self):
        legacy=MissingLibraryDiagnostic.ERROR+b'\n'+MissingLibraryDiagnostic.COMMAND+b'\n'
        for payload in (legacy,NATIVE+b'PRIVATE_SUFFIX\n',b'PRIVATE_PREFIX\n'+NATIVE,
                        NATIVE+b'pg_restore: error: PRIVATE_EXTRA\n'):
            with self.subTest(length=len(payload)):
                record=self.capture_reset(self.frame(payload))
                self.assertIsNone(record.get('native_fatal_observation',{}).get('template'))
                self.assertFalse(record.get('native_fatal_observation',{}).get('reset_candidate',True))
                self.assertNotIn('PRIVATE',str(record))


    def test_templates_are_fragment_independent_but_not_environment_proof(self):
        from run_hosted_faults import FrameCounter
        profiles=((NATIVE,'pg18-hstore-374-v1'),
                  (b'WARNING: password file "/dev/null" is not a plain file\n'+NATIVE,'pg18-hstore-devnull-429-v1'))
        for payload,template in profiles:
            wire=self.frame(payload)
            for split in range(len(wire)+1):
                with self.subTest(template=template,split=split):
                    diagnostic=MissingLibraryDiagnostic()
                    frames=FrameCounter(stderr_observer=diagnostic.feed)
                    frames.feed(wire[:split]); frames.feed(wire[split:])
                    value=diagnostic.finish()
                    self.assertEqual(value,EXPECTED)
                    self.assertEqual(diagnostic.native_template,template)
                    self.assertTrue(frames.native_framing_valid)
                    self.assertFalse(frames.header or frames.left)
            record=self.capture_reset(wire)
            self.assertTrue(record['native_fatal_observation']['reset_candidate'])
            self.assertEqual(record['native_fatal_observation']['template'],template)
            # No real create/environment/owner binding was performed by this
            # socket control, so it must never manufacture an acceptance witness.
            self.assertNotIn('native_fatal_witness',record)

    def test_valid_native_reset_still_cannot_authorize_prerequisites_or_retry(self):
        import copy
        from test_hosted_storage_cycle1 import extension_receipt
        from verify_hosted_storage_prereqs import verify_case
        row=copy.deepcopy(extension_receipt())
        record=self.capture_reset(self.frame(b'WARNING: password file "/dev/null" is not a plain file\n'+NATIVE))
        self.assertTrue(record['native_fatal_observation']['reset_candidate'])
        start=next(r for r in row['relay']['records'] if r.get('boundary')=='restore-start')
        start.update(record)
        row['extension']['failure_cause']=record['import_diagnostic']
        with self.assertRaises(ValueError): verify_case(row)
        self.assertNotIn('native_fatal_witness',row['extension'])


if __name__=='__main__': unittest.main()
