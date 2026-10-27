"""Deterministic F04 observer/selector controls; never Docker or hosted evidence."""
import copy
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import run_hosted_faults as faults

CID = 'a'*64
ACTIVE = dict(runID='b'*32, daemonID='unit', workerContainerID='c'*64,
              sourceContainerID='d'*64, execID='e'*64)
CANARY = 'PRIVATE-CANARY-password-argv-env-sql'


class RecoveryTests(unittest.TestCase):
    def probe(self, state, owners=None):
        p = faults.FaultProbe.__new__(faults.FaultProbe)
        p.worker_records = {}; p.result = {}; p.calls = []; p.clock = 0
        p.controller = lambda command: CID
        p.e = SimpleNamespace(inspect=lambda cid, *, deadline=None: copy.deepcopy(state))
        p.capture_owned_worker = lambda: None
        p.stop = lambda cid: p.calls.append(('stop',cid))
        sequence = list(owners or [ACTIVE])
        def owner():
            value = sequence.pop(0) if len(sequence) > 1 else sequence[0]
            return copy.deepcopy(value)
        p.owner = owner
        def sleep(seconds): p.clock += seconds
        p.time = (patch.object(faults.time,'monotonic',lambda:p.clock),
                  patch.object(faults.time,'sleep',sleep))
        return p

    def run_recovery(self, p):
        with p.time[0], p.time[1]: p.fresh_recovery(ACTIVE,blocked=False)

    def test_stalled_inspect_shares_fixed_observer_end_with_one_second_read_cap(self):
        p = self.probe(None)
        reads = []
        def stalled(cid, *, deadline=None):
            reads.append((p.clock, deadline))
            p.clock = p.clock+46 if deadline is None else min(p.clock+46,deadline)
            raise TimeoutError(CANARY)
        p.e.inspect = stalled
        with self.assertRaises(TimeoutError): self.run_recovery(p)
        self.assertLessEqual(p.clock,45.1,'optional inspect extended the existing wait budget')
        self.assertGreater(len(reads),1,'one optional read consumed all useful owner polling')
        for started,deadline in reads:
            self.assertIsNotNone(deadline)
            self.assertGreater(deadline,started)
            self.assertLessEqual(deadline,min(45,started+1))
        self.assertEqual(p.calls,[])
        self.assertNotIn(CANARY,json.dumps(p.result))

    def test_final_log_read_is_capped_without_masking_terminal_failure(self):
        p = self.probe({'Id':CID,'State':{'Running':False,'ExitCode':41}})
        reads = []
        def stalled(cid, *, deadline=None):
            reads.append(deadline)
            p.clock = p.clock+46 if deadline is None else min(p.clock+46,deadline)
            raise RuntimeError(CANARY)
        p.logs = stalled
        with self.assertRaisesRegex(ValueError,'fresh recovery controller terminal with retained owner'):
            self.run_recovery(p)
        self.assertEqual(reads,[1])
        self.assertLessEqual(p.clock,1)
        self.assertEqual(p.calls,[])
        self.assertEqual(p.result['recovery_observations'][0]['run_finished'],
                         {'count':None,'failed':None,'status':None})
        self.assertNotIn(CANARY,json.dumps(p.result))

    def test_deadline_log_path_projects_actual_nested_mux_with_tail_query(self):
        p = self.probe({'Id':CID,'State':{'Running':False,'ExitCode':41}})
        p.values = []
        payload = json.dumps({'event':'run_finished','failed':True,
            'result':{'runID':ACTIVE['runID'],'status':'failed','error':CANARY}}).encode()
        frame = b'\x01\0\0\0'+len(payload).to_bytes(4,'big')+payload
        reads = []
        def call(method,path,*,raw=False,deadline=None):
            reads.append((method,path,raw,deadline))
            return frame
        p.e.call = call
        with self.assertRaises(ValueError): self.run_recovery(p)
        self.assertEqual(reads,[('GET','/containers/'+CID+'/logs?stdout=true&stderr=true&tail=16',True,1)])
        self.assertEqual(p.result['recovery_observations'][0]['run_finished'],
                         {'count':1,'failed':True,'status':'failed'})
        self.assertNotIn(CANARY,json.dumps(p.result))

    def test_incomplete_diagnostic_mux_frames_stay_unknown(self):
        payload = json.dumps({'event':'run_finished','failed':True,
            'result':{'runID':ACTIVE['runID'],'status':'failed'}}).encode()
        header = b'\x01\0\0\0'+len(payload).to_bytes(4,'big')
        for raw in (header[:7], header+payload+b'\x01',
                    header[:4]+(len(payload)+1).to_bytes(4,'big')+payload,
                    b'\xff'+header[1:]+payload, b'\x01\0\x01\0'+header[4:]+payload):
            with self.subTest(size=len(raw)):
                p = self.probe({'Id':CID,'State':{'Running':False,'ExitCode':41}})
                p.values = []
                p.e.call = lambda method,path,*,raw=False,deadline=None: data
                data = raw
                with self.assertRaisesRegex(ValueError,'fresh recovery controller terminal with retained owner'):
                    self.run_recovery(p)
                self.assertEqual(p.result['recovery_observations'][0]['run_finished'],
                                 {'count':None,'failed':None,'status':None})

    def test_diagnostic_log_limit_counts_bytes_before_projection(self):
        payload = json.dumps({'event':'run_finished','failed':True,
            'result':{'runID':ACTIVE['runID'],'status':'failed'}})+'\n'+'\u00e9'*33000
        self.assertLess(len(payload),65536)
        self.assertGreater(len(payload.encode()),65536)
        for raw_path in (False,True):
            with self.subTest(raw_path=raw_path):
                p = self.probe({'Id':CID,'State':{'Running':False,'ExitCode':41}})
                if raw_path:
                    p.values = []
                    encoded = payload.encode()
                    frame = b'\x01\0\0\0'+len(encoded).to_bytes(4,'big')+encoded
                    p.e.call = lambda method,path,*,raw=False,deadline=None: frame
                else:
                    p.logs = lambda cid, *, deadline=None: payload
                with self.assertRaises(ValueError): self.run_recovery(p)
                self.assertEqual(p.result['recovery_observations'][0]['run_finished'],
                                 {'count':None,'failed':None,'status':None})

    def test_absent_owner_near_end_does_not_start_optional_read(self):
        p = self.probe(None)
        reads = []
        def released():
            p.clock = 44.75
            return None
        def inspect(cid, *, deadline=None):
            reads.append(deadline)
            return {'Id':CID,'State':{'Running':False}}
        p.owner = released; p.e.inspect = inspect
        self.run_recovery(p)
        self.assertEqual(reads,[],'released owner need not wait on a new diagnostic API read')
        self.assertEqual(p.calls,[('stop',CID)])
        d = p.result['recovery_observations'][0]
        self.assertEqual((d['outcome'],d['owner'],d['controller']),('released','absent','unavailable'))
        self.assertEqual(d['run_finished'],{'count':None,'failed':None,'status':None})

    def test_exhausted_budget_skips_final_logs_after_observed_inspect(self):
        p = self.probe(None)
        reads = []
        def owner():
            p.clock = 44
            return copy.deepcopy(ACTIVE)
        def inspect(cid, *, deadline=None):
            reads.append((p.clock,deadline)); p.clock = deadline
            return {'Id':CID,'State':{'Running':True}}
        p.owner = owner; p.e.inspect = inspect
        log_reads = []
        p.logs = lambda cid, *, deadline=None: log_reads.append(deadline)
        with self.assertRaises(TimeoutError): self.run_recovery(p)
        self.assertEqual(reads,[(44,45)])
        self.assertEqual(log_reads,[])
        self.assertLessEqual(p.clock,45.1)
        d = p.result['recovery_observations'][0]
        self.assertEqual((d['outcome'],d['controller']),('timeout','observed'))
        self.assertEqual(d['run_finished'],{'count':None,'failed':None,'status':None})

    def test_final_logs_share_original_end_after_stop_without_masking_success(self):
        for elapsed in (0,44.75,45,46):
            with self.subTest(elapsed=elapsed):
                p = self.probe({'Id':CID,'State':{'Running':False}},[None])
                reads = []
                def stop(cid):
                    p.calls.append(('stop',cid)); p.clock = elapsed
                def logs(cid, *, deadline=None):
                    reads.append(deadline)
                    p.clock = deadline
                    raise RuntimeError(CANARY)
                p.stop = stop; p.logs = logs
                self.run_recovery(p)
                self.assertEqual(reads,[min(45,elapsed+1)] if elapsed < 45 else [])
                self.assertTrue(p.result['fresh_cli_recovery'])
                self.assertEqual(p.calls,[('stop',CID)])
                self.assertNotIn(CANARY,json.dumps(p.result))

    def test_causal_owner_exception_identity_survives_failing_final_log_read(self):
        p = self.probe({'Id':CID,'State':{'Running':False,'ExitCode':41}})
        error = RuntimeError(CANARY)
        owners = [ACTIVE]
        def owner():
            if owners: return owners.pop()
            raise error
        reads = []
        def logs(cid, *, deadline=None):
            reads.append(deadline)
            raise ValueError('different optional failure')
        p.owner = owner; p.logs = logs
        with self.assertRaises(RuntimeError) as caught: self.run_recovery(p)
        self.assertIs(caught.exception,error)
        self.assertEqual(reads,[1])
        self.assertEqual(p.calls,[])
        self.assertEqual(p.result['recovery_observations'][0]['outcome'],'error')
        self.assertNotIn(CANARY,json.dumps(p.result))

    def test_no_deadline_logs_preserve_ordinary_api_and_secret_gate(self):
        p = self.probe(None); p.values = [CANARY]
        reads = []
        payload = b'ordinary'
        def call(method,path,**kwargs):
            reads.append((method,path,kwargs))
            return b'\x01\0\0\0'+len(payload).to_bytes(4,'big')+payload
        p.e.call = call
        self.assertEqual(p.logs(CID),'ordinary')
        self.assertEqual(reads,[('GET','/containers/'+CID+'/logs?stdout=true&stderr=true',{'raw':True})])
        payload = CANARY.encode()
        with self.assertRaisesRegex(ValueError,'synthetic secret in container logs'): p.logs(CID)
        with self.assertRaisesRegex(ValueError,'synthetic secret in container logs'): p.logs(CID,deadline=1)

    def test_exact_worker_set_guard_remains_after_recovery(self):
        p = self.probe(None,[None])
        p.stop = lambda cid: p.worker_records.update({'f'*64:{}})
        with self.assertRaisesRegex(ValueError,'fresh recovery created replacement worker'): self.run_recovery(p)

    def test_terminal_controller_with_retained_owner_fails_promptly_without_stop(self):
        for code in (0,1,41):
            with self.subTest(code=code):
                p = self.probe({'Id':CID,'State':{'Running':False,'ExitCode':code,'Status':'exited','Pid':0}})
                try:
                    with self.assertRaisesRegex(ValueError,'fresh recovery controller terminal with retained owner'):
                        self.run_recovery(p)
                except TimeoutError:
                    self.fail('terminal exact controller was ignored until the 45-second timeout')
                self.assertLess(p.clock,1)
                self.assertEqual(p.calls,[])
                d = p.result['recovery_observations'][0]
                self.assertEqual((d['outcome'],d['owner'],d['exit_code']),('controller_terminal','matching',code))

    def test_release_race_and_ordinary_release_keep_existing_stop_path(self):
        for owners in ([None], [ACTIVE,None]):
            p = self.probe({'Id':CID,'State':{'Running':False,'ExitCode':0}},owners)
            self.run_recovery(p)
            self.assertEqual(p.calls,[('stop',CID)])
            self.assertIs(p.result['fresh_cli_recovery'],True)
            self.assertEqual(p.result['recovery_observations'][0]['outcome'],'released')

    def test_live_timeout_keeps_45_second_bound_without_stop(self):
        p = self.probe({'Id':CID,'State':{'Running':True,'Status':'running','ExitCode':None,'Pid':23}})
        with self.assertRaises(TimeoutError): self.run_recovery(p)
        self.assertGreaterEqual(p.clock,45)
        self.assertLess(p.clock,45.1)
        self.assertEqual(p.calls,[])
        self.assertEqual(p.result['recovery_observations'][0]['outcome'],'timeout')

    def test_malformed_foreign_unavailable_observations_are_null_and_redacted(self):
        variants = [None, {'Id':'f'*64,'State':{'Running':False,'ExitCode':41}},
                    {'Id':CID,'State':CANARY},
                    {'Id':CID,'State':{'Running':CANARY,'ExitCode':True,'Pid':False,'Status':CANARY,
                                      'Env':[CANARY],'Error':CANARY}},
                    {'Id':CID,'State':{'ExitCode':-1,'Pid':-1}},
                    {'Id':CID,'State':{'ExitCode':256,'Pid':2**31}}]
        for state in variants:
            with self.subTest(state=state):
                p = self.probe(state)
                with self.assertRaises(TimeoutError): self.run_recovery(p)
                d = p.result['recovery_observations'][0]
                self.assertIsNone(d['running']); self.assertIsNone(d['exit_code']); self.assertIsNone(d['pid'])
                self.assertIsNone(d['status']); self.assertNotIn(CANARY,json.dumps(p.result))
        p = self.probe(None)
        def unavailable(cid, *, deadline=None): raise RuntimeError(CANARY)
        p.e.inspect = unavailable
        with self.assertRaises(TimeoutError): self.run_recovery(p)
        self.assertNotIn(CANARY,json.dumps(p.result))
        p = self.probe({'Id':CID,'State':{'Running':False,'ExitCode':41}},[dict(ACTIVE,execID='f'*64)])
        with self.assertRaises(TimeoutError): self.run_recovery(p)
        self.assertEqual(p.result['recovery_observations'][0]['owner'],'foreign')

    def test_observation_correlates_exact_controller_id_and_caps_attempts(self):
        p = self.probe({'Id':CID,'State':{'Running':True,'ExitCode':None}},[None])
        for _ in range(6): self.run_recovery(p)
        self.assertEqual(len(p.result['recovery_observations']),4)
        self.assertEqual(p.result['recovery_observations'][0].get('controller_id'),CID,
                         'Serve diagnostic does not identify its exact new controller')

    def test_run_finished_nested_result_is_bounded_bound_and_redacted(self):
        p = self.probe({'Id':CID,'State':{'Running':False,'ExitCode':1}})
        events = [dict(event='run_finished',failed=True,result={'runID':'f'*32,'status':'complete'}),
                  dict(event='run_finished',failed=True,result={'runID':ACTIVE['runID'],'status':'failed','error':CANARY}),
                  dict(event=CANARY,result={'runID':ACTIVE['runID'],'status':'complete'})]
        p.logs = lambda cid, *, deadline=None: '\n'.join(map(json.dumps,events))
        with self.assertRaises(ValueError): self.run_recovery(p)
        self.assertEqual(p.result['recovery_observations'][0].get('run_finished'),
                         {'count':1,'failed':True,'status':'failed'},'nested Serve result was not observed')
        self.assertNotIn(CANARY,json.dumps(p.result))

    def test_released_nested_result_missing_or_invalid_fields_stay_unknown(self):
        for event,expected in [
            ({'event':'run_finished','failed':True,'result':{'runID':ACTIVE['runID'],'status':'failed','error':CANARY}},
             {'count':1,'failed':True,'status':'failed'}),
            ({'event':'run_finished','failed':1,'result':{'runID':ACTIVE['runID'],'status':CANARY}},
             {'count':1,'failed':None,'status':None})]:
            p = self.probe({'Id':CID,'State':{'Running':False,'ExitCode':1}},[None])
            p.logs = lambda cid, *, deadline=None: json.dumps(event)
            self.run_recovery(p)
            self.assertIn('recovery_observations',p.result,'released Serve has no nested-result diagnostic')
            self.assertEqual(p.result['recovery_observations'][0]['run_finished'],expected)
            self.assertNotIn(CANARY,json.dumps(p.result))
        for mode in ('oversize','logs-error'):
            p = self.probe({'Id':CID,'State':{'Running':False,'ExitCode':41}})
            def logs(cid, *, deadline=None):
                if mode == 'logs-error': raise RuntimeError(CANARY)
                return CANARY*65536
            p.logs = logs
            with self.assertRaisesRegex(ValueError,'fresh recovery controller terminal with retained owner'):
                self.run_recovery(p)
            self.assertEqual(p.result['recovery_observations'][0]['run_finished'],{'count':None,'failed':None,'status':None})
            self.assertNotIn(CANARY,json.dumps(p.result))

    def test_owner_exception_is_not_masked_or_serialized_and_blocked_branch_unchanged(self):
        p = self.probe(None)
        error = RuntimeError(CANARY)
        def failed(): raise error
        p.owner = failed
        with self.assertRaises(RuntimeError) as caught: self.run_recovery(p)
        self.assertIs(caught.exception,error)
        self.assertNotIn(CANARY,json.dumps(p.result))
        self.assertEqual(p.result['recovery_observations'][0]['outcome'],'error')
        p = self.probe(None)
        p.finish = lambda cid,**kwargs: p.calls.append(('finish',cid,kwargs))
        p.assert_quarantine = lambda active: p.calls.append(('quarantine',active))
        p.fresh_recovery(ACTIVE,blocked=True)
        self.assertEqual(p.calls,[('finish',CID,{'expect':1,'timeout':45}),('quarantine',ACTIVE)])
        self.assertNotIn('fresh_cli_recovery',p.result)


class DiagnosticUnixTests(unittest.TestCase):
    def owned_peer(self, mode, exercise):
        import socket
        import tempfile
        import threading
        import time
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)/'owned-diagnostic-peer'
            server = socket.socket(socket.AF_UNIX)
            server.bind(str(target)); server.listen(1); server.settimeout(3)
            done = threading.Event(); requests = []; errors = []
            def peer():
                try:
                    with server:
                        conn,_ = server.accept()
                        with conn:
                            conn.settimeout(3)
                            request = b''
                            while b'\r\n\r\n' not in request:
                                chunk = conn.recv(4096)
                                if not chunk: break
                                request += chunk
                            requests.append(request.split(b'\r\n',1)[0])
                            if mode == 'stall':
                                done.wait(3)
                            else:
                                conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 4096\r\nConnection: close\r\n\r\n')
                                end = time.monotonic()+3
                                while not done.wait(.025) and time.monotonic() < end:
                                    try: conn.sendall(b'x')
                                    except (BrokenPipeError,ConnectionResetError): break
                except Exception as error:
                    errors.append(type(error).__name__)
            thread = threading.Thread(target=peer); thread.start()
            try:
                exercise(faults.Engine(target),requests)
            finally:
                done.set(); thread.join(4); server.close()
            self.assertFalse(thread.is_alive())
            self.assertEqual(errors,[])

    def test_inspect_deadline_reaches_owned_stalled_and_trickling_unix_peer(self):
        import time
        for mode in ('stall','trickle'):
            with self.subTest(mode=mode):
                def exercise(engine,requests):
                    p = RecoveryTests().probe(None)
                    p.e = engine; owners = [ACTIVE]; reads = []; log_reads = []
                    error = RuntimeError(CANARY)
                    def owner():
                        if owners: return owners.pop()
                        raise error
                    inspect = engine.inspect
                    def observed(cid, *, deadline=None):
                        reads.append(deadline)
                        return inspect(cid,deadline=deadline)
                    engine.inspect = observed; p.owner = owner
                    p.logs = lambda cid, *, deadline=None: log_reads.append(deadline)
                    started = time.monotonic()
                    with self.assertRaises(RuntimeError) as caught: p.fresh_recovery(ACTIVE,blocked=False)
                    elapsed = time.monotonic()-started
                    self.assertIs(caught.exception,error)
                    self.assertGreater(elapsed,.8); self.assertLess(elapsed,1.75)
                    self.assertEqual(len(reads),1)
                    self.assertGreater(reads[0],started); self.assertLessEqual(reads[0],started+1.1)
                    self.assertEqual(requests,[('GET /v1.55/containers/'+CID+'/json HTTP/1.1').encode()])
                    self.assertEqual(log_reads,[]); self.assertEqual(p.calls,[])
                    self.assertEqual(p.result['recovery_observations'][0]['controller'],'unavailable')
                    self.assertNotIn(CANARY,json.dumps(p.result))
                self.owned_peer(mode,exercise)

    def test_log_deadline_reaches_owned_stalled_and_trickling_unix_peer(self):
        import time
        for mode in ('stall','trickle'):
            with self.subTest(mode=mode):
                def exercise(engine,requests):
                    p = RecoveryTests().probe(None); p.e = engine; p.values = []
                    engine.inspect = lambda cid, *, deadline=None: {'Id':CID,'State':{'Running':False,'ExitCode':41}}
                    started = time.monotonic()
                    with self.assertRaisesRegex(ValueError,'fresh recovery controller terminal with retained owner'):
                        p.fresh_recovery(ACTIVE,blocked=False)
                    elapsed = time.monotonic()-started
                    self.assertGreater(elapsed,.8); self.assertLess(elapsed,1.75)
                    self.assertEqual(requests,[('GET /v1.55/containers/'+CID+
                        '/logs?stdout=true&stderr=true&tail=16 HTTP/1.1').encode()])
                    d = p.result['recovery_observations'][0]
                    self.assertEqual(d['outcome'],'controller_terminal')
                    self.assertEqual(d['run_finished'],{'count':None,'failed':None,'status':None})
                    self.assertEqual(p.calls,[])
                self.owned_peer(mode,exercise)


class ControlRelayTests(unittest.TestCase):
    def exchange(self, relay, method, path, body, response):
        import socket
        import threading
        seen = []
        server = socket.socket(socket.AF_UNIX)
        target = Path(relay.target)
        server.bind(str(target)); server.listen(); server.settimeout(3)
        request = (method+' '+path+' HTTP/1.1\r\nHost: unit\r\nConnection: close\r\nContent-Length: '+str(len(body))+'\r\n\r\n').encode()+body
        def peer():
            with server:
                conn,_ = server.accept()
                with conn:
                    head,_,fields = faults.read_headers(conn)
                    raw = head+faults.read_exact(conn,int(fields.get('content-length',0)))
                    seen.append(raw); conn.sendall(response)
        thread = threading.Thread(target=peer); thread.start()
        client = socket.socket(socket.AF_UNIX); client.settimeout(3)
        try:
            client.connect(str(relay.path)); client.sendall(request); output = b''
            while True:
                chunk = client.recv(65536)
                if not chunk: break
                output += chunk
        finally:
            client.close(); thread.join(4); target.unlink()
        self.assertFalse(thread.is_alive())
        self.assertEqual(seen,[request]); self.assertEqual(output,response)

    def reply(self, value, status=200):
        body = json.dumps(value).encode()
        return ('HTTP/1.1 '+str(status)+' Unit\r\nConnection: close\r\nContent-Length: '+str(len(body))+'\r\n\r\n').encode()+body

    def script(self, name):
        # Independent literal source binding; verify classifier against unchanged Go.
        import re
        source = Path(faults.__file__).resolve().parents[3]/'internal/platform/docker/cancel.go'
        return re.search('const '+name+r' = `([^`]*)`',source.read_text()).group(1)

    def test_control_projection_nulls_redaction_bounds_and_foreign_requests_on_unix(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); relay = faults.FaultRelay(root/'relay',root/'target')
            relay.control_owner = copy.deepcopy(ACTIVE); relay.start()
            try:
                cmd = ['sh','-c',self.script('cancelScript'),'bakabel-cancel','123','456',ACTIVE['runID'],'TERM']
                eid = '1'*64; source = ACTIVE['sourceContainerID']
                self.exchange(relay,'POST','/containers/'+source+'/exec',json.dumps({'Cmd':cmd}).encode(),self.reply({'Id':eid},201))
                variants = [({'ID':eid,'ContainerID':source,'Running':False,'ExitCode':0,'Pid':0},'observed',False,0,0),
                            ({'ID':eid,'ContainerID':source,'Running':True,'ExitCode':None,'Pid':123},'observed',True,None,123),
                            ({'ID':eid,'ContainerID':source,'Running':1,'ExitCode':False,'Pid':True},'observed',None,None,None),
                            ({'ID':eid,'ContainerID':source},'observed',None,None,None),
                            ({'ID':'f'*64,'ContainerID':source,'Running':False,'ExitCode':43},'foreign',None,None,None),
                            ({'ID':eid,'ContainerID':'f'*64,'Running':False,'ExitCode':41},'foreign',None,None,None),
                            ({'ID':eid,'ContainerID':source,'Running':CANARY,'ExitCode':256,'Pid':-1},'observed',None,None,None),
                            (None,'unavailable',None,None,None)]
                for value,observed,running,code,pid in variants:
                    self.exchange(relay,'GET','/exec/'+eid+'/json',b'',self.reply(value))
                    self.assertEqual(relay.snapshot()['records'][-1]['control_state'],
                                     dict(observation=observed,running=running,exit_code=code,pid=pid))
                raw = b'{"ID":"'+eid.encode()+b'","ContainerID":"'+source.encode()+b'","ExitCode":41,"secret":"'+b'x'*65536+b'"}'
                response = ('HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: '+str(len(raw))+'\r\n\r\n').encode()+raw
                self.exchange(relay,'GET','/exec/'+eid+'/json',b'',response)
                self.assertIsNone(relay.snapshot()['records'][-1]['control_state']['exit_code'])
                # Chunk framing/trailers also forward byte-for-byte without capture.
                raw = json.dumps({'ID':eid,'ContainerID':source,'Running':False,'ExitCode':43,'Pid':0,'secret':CANARY}).encode()
                response = b'HTTP/1.1 200 OK\r\nConnection: close\r\nTransfer-Encoding: chunked\r\n\r\n'+format(len(raw),'x').encode()+b'\r\n'+raw+b'\r\n0\r\n\r\n'
                self.exchange(relay,'GET','/exec/'+eid+'/json',b'',response)
                self.assertEqual(relay.snapshot()['records'][-1]['control_state']['exit_code'],43)
                for bad in (b'not-json',b'['*1100+b'0'+b']'*1100):
                    response = ('HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: '+str(len(bad))+'\r\n\r\n').encode()+bad
                    self.exchange(relay,'GET','/exec/'+eid+'/json',b'',response)
                    self.assertIsNone(relay.snapshot()['records'][-1]['control_state']['exit_code'])
                for cid,changed in ((source,cmd[:2]+[cmd[2]+'\n']+cmd[3:]),
                                    ('f'*64,cmd),(source,cmd[:6]+['f'*32,'TERM']),
                                    (source,cmd[:-1]+['TERM;'+CANARY])):
                    self.exchange(relay,'POST','/containers/'+cid+'/exec',json.dumps({'Cmd':changed,'Env':[CANARY]}).encode(),self.reply({'Id':'2'*64},201))
                    self.assertNotIn('control_role',relay.snapshot()['records'][-1])
                self.assertNotIn(CANARY,json.dumps(relay.snapshot()))
                self.assertEqual(relay.snapshot()['errors'],[])
                self.assertEqual(relay.execs,{})
                relay.control_execs = {format(i,'064x'):{'control_role':'scan_dump','container_id':source,'control_run_id':ACTIVE['runID']} for i in range(64)}
                self.exchange(relay,'POST','/containers/'+source+'/exec',json.dumps({'Cmd':cmd}).encode(),self.reply({'Id':'9'*64},201))
                self.assertEqual(len(relay.control_execs),64)
            finally: relay.close()

    def test_native_cancel_helpers_are_passively_bound_without_dump_authority(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            relay = faults.FaultRelay(root/'relay',root/'target')
            relay.control_owner = copy.deepcopy(ACTIVE)
            relay.start()
            try:
                for index,(role,cmd) in enumerate((
                    ('scan_dump',['sh','-c',self.script('scanScript'),'bakabel-scan',ACTIVE['runID']]),
                    ('signal_term',['sh','-c',self.script('cancelScript'),'bakabel-cancel','123','456',ACTIVE['runID'],'TERM']),
                    ('signal_kill',['sh','-c',self.script('cancelScript'),'bakabel-cancel','123','456',ACTIVE['runID'],'KILL']))):
                    eid = str(index+1)*64
                    body = json.dumps({'Cmd':cmd,'Env':[CANARY],'User':'0','AttachStdout':True,'AttachStderr':True}).encode()
                    self.exchange(relay,'POST','/containers/'+ACTIVE['sourceContainerID']+'/exec',body,self.reply({'Id':eid},201))
                    self.exchange(relay,'POST','/exec/'+eid+'/start',b'{"Detach":false,"Tty":false}',
                                  b'HTTP/1.1 101 UPGRADED\r\nConnection: close\r\n\r\n')
                    self.exchange(relay,'GET','/exec/'+eid+'/json',b'',self.reply({'ID':eid,'ContainerID':ACTIVE['sourceContainerID'],
                                  'Running':False,'ExitCode':41+index,'Pid':0,'ProcessConfig':{'arguments':[CANARY]}}))
                    rows = relay.snapshot()['records'][-3:]
                    self.assertEqual([r.get('control_role') for r in rows],[role]*3,
                                     'existing forwarded native helper responses have no role/exit diagnostics')
                    self.assertEqual([r['control_phase'] for r in rows],['create','start','inspect'])
                    for row in rows[:2]:
                        self.assertEqual(row.get('control_state'),{'observation':'unavailable','running':None,'exit_code':None,'pid':None},
                                         'unobserved control exit/state must be explicit nulls')
                    self.assertEqual(rows[-1]['control_state'],{'observation':'observed','running':False,'exit_code':41+index,'pid':0})
                snap = relay.snapshot()
                self.assertEqual(snap['execs'],{}); self.assertEqual(snap['workers'],[])
                self.assertEqual(relay.dump_bindings,{})
                self.assertEqual(relay.restore_bindings,{})
                self.assertNotIn(CANARY,json.dumps(snap))
                self.assertEqual(snap['errors'],[])
            finally: relay.close()


class SelectorTests(unittest.TestCase):
    def workflow_step(self, name):
        import textwrap
        source = Path(faults.__file__).resolve().parents[3]
        text = (source/'.github/workflows/acceptance.yaml').read_text()
        step = text.split('      - name: '+name+'\n',1)[1].split('\n      - ',1)[0]
        lines = []
        for line in step.split('        run: |\n',1)[1].splitlines():
            if line and not line.startswith('          '): break
            lines.append(line)
        return textwrap.dedent('\n'.join(lines))

    def test_actual_planning_shell_rejects_input_injection_before_provisioning(self):
        import os
        import subprocess
        import tempfile
        source = Path(faults.__file__).resolve().parents[3]
        script = self.workflow_step('Validate manual scope and case')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); output = root/'output'
            for scope,case,valid in [('single-fault',F04,True),('all','all',True),
                                      ('remaining-faults','all',True),('all',F04,False),
                                      ('single-fault',F04+'\n',False),('single-fault','$(touch INJECTED)',False),
                                      ('single-fault','../../private',False),('single-fault','all',False)]:
                output.unlink(missing_ok=True)
                cp = subprocess.run(['bash','-c',script],cwd=source,
                    env={**os.environ,'GITHUB_OUTPUT':str(output),'REQUESTED_SCOPE':scope,'REQUESTED_CASE':case},capture_output=True,text=True)
                with self.subTest(scope=scope,case=case):
                    if valid:
                        self.assertEqual(cp.returncode,0,cp.stderr)
                        matrix = json.loads(output.read_text().split('=',1)[1])
                        self.assertEqual(len(matrix),1 if scope=='single-fault' else 3 if scope=='all' else 7)
                    else:
                        self.assertNotEqual(cp.returncode,0)
                        self.assertFalse(output.exists())
                    self.assertFalse((root/'INJECTED').exists()); self.assertFalse((source/'INJECTED').exists())

    def test_actual_scoped_shell_routes_only_allowlisted_recovery_runner(self):
        import os
        import subprocess
        import tempfile
        source = Path(faults.__file__).resolve().parents[3]
        script = self.workflow_step('Independent remaining fault gate on fresh VM')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'bakabel-candidate.json').write_text(json.dumps({'source_sha256':'a'*64,'image_id':'sha256:'+'b'*64}))
            capture = root/'calls'
            # Shell observer only: no sudo/taskset/runner command is executed.
            observer = 'sudo() { printf "%s\\0" "$@" >> "$CAPTURE"; }; export -f sudo\n'
            env = {**os.environ,'RUNNER_TEMP':str(root),'CAPTURE':str(capture),'ACCEPTANCE_SUITE':'recovery','ACCEPTANCE_CASE':F04,
                   'ENGINE_SOCKET':str(root/'not-an-engine')}
            cp = subprocess.run(['bash','-c',observer+script],cwd=source,env=env,capture_output=True,text=True)
            self.assertEqual(cp.returncode,0,cp.stderr)
            args = capture.read_bytes().decode().split('\0')
            self.assertIn('tests/integration/fixtures/run_hosted_faults.py',args)
            self.assertIn('tests/integration/fixtures/verify_hosted_selection.py',args)
            self.assertIn('--case',args); self.assertIn(F04,args)
            self.assertIn(str(root/'bakabel-faults'),args)
            self.assertNotIn('run_hosted_storage_prereqs.py',args)
            for suite in ('faults','../recovery','recovery; touch INJECTED','$(touch INJECTED)',''):
                capture.unlink(missing_ok=True)
                cp = subprocess.run(['bash','-c',observer+script],cwd=root,env={**env,'ACCEPTANCE_SUITE':suite},capture_output=True)
                self.assertEqual(cp.returncode,2)
                self.assertFalse(capture.exists()); self.assertFalse((root/'INJECTED').exists())

    def test_workflow_has_exact_f04_choice_and_fault_bulk_conditions_unchanged(self):
        source = Path(faults.__file__).resolve().parents[3]
        text = (source/'.github/workflows/acceptance.yaml').read_text()
        choices = text.split('      case:\n',1)[1].split('\npermissions:',1)[0]
        self.assertIn('          - '+F04+'\n',choices)
        self.assertEqual(text.count("if: matrix.suite == 'faults'"),2)

    def test_actual_evidence_export_includes_only_selected_recovery_verdict(self):
        import os
        import subprocess
        import sys
        import tempfile
        script = self.workflow_step('Export only allowlisted evidence even on failure')
        export = script.split("python3 - <<'PY'\n",1)[1].split('\nPY',1)[0]
        source = Path(faults.__file__).resolve().parents[3]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); target = root/'bakabel-public'; target.mkdir()
            faults_dir = root/'bakabel-faults'; faults_dir.mkdir()
            (faults_dir/F04).mkdir(); (faults_dir/F04/'receipt.json').write_text('{"unit":true}')
            (faults_dir/'selected-verified.json').write_text('{"selected_case_pass":true,"full_plan_acceptance_pass":false}')
            (faults_dir/'private-canary').write_text(CANARY)
            for suite in ('recovery','reader','$(touch INJECTED)','../recovery'):
                for path in target.iterdir(): path.unlink()
                cp = subprocess.run([sys.executable,'-B','-c',export],cwd=source,
                                    env={**os.environ,'RUNNER_TEMP':str(root),'ACCEPTANCE_SUITE':suite},capture_output=True,text=True)
                self.assertEqual(cp.returncode,0,cp.stderr)
                expected = {'faults-'+F04+'.json'}
                if suite in ('recovery','reader'): expected.add(suite+'-selected-verified.json')
                self.assertEqual({p.name for p in target.iterdir()},expected)
                self.assertNotIn(CANARY,''.join(p.read_text() for p in target.iterdir()))
                self.assertFalse((root/'INJECTED').exists())

    def test_f04_generic_verifier_cli_never_promotes_subset_acceptance(self):
        import os
        import subprocess
        import sys
        import tempfile
        import verify_hosted_selection as selection
        from test_hosted_faults import VerifierTests
        source = Path(faults.__file__).resolve().parents[3]
        # Synthetic public verifier input ONLY, never a hosted execution receipt.
        row = VerifierTests().worker_loss_receipt(F04)
        row.update(quarantine_retained_before_recovery=True,fresh_cli_recovery=True,
                   source_sha256=selection.fingerprint(source))
        row['workers']['b'*64].update({'cpu.max':'200000 100000','memory.max':'536870912'})
        row['proof'].update(actual_response_status=101,stdout_bytes=65536,
            terminal={'daemon':row['daemon'],'container_id':'c'*64,'started_at':'start',
                      'exec_id':'d'*64,'exec_exit_code':137,'sessions':0,'processes':0})
        report = {'schema':1,'fault_acceptance_pass':False,'full_plan_acceptance_pass':False,
                  'cases':[{'case':F04,'status':'pass'}],**{k:row[k] for k in ('source_sha256','image_id','daemon')}}
        binding = dict(suite='recovery',case=F04,scope='single-fault',commit='a'*40,
                       **{k:row[k] for k in ('source_sha256','image_id','daemon')})
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root/F04).mkdir()
            (root/'candidate.json').write_text(json.dumps(binding))
            output = root/'selected-verified.json'
            cmd = [sys.executable,'-B',selection.__file__,'--suite','recovery','--case',F04,
                   '--source',str(source),'--runtime',str(root),'--candidate',str(root/'candidate.json'),'--output',str(output)]
            for mutation in ('valid','aggregate','full','semantic','duplicate'):
                r,receipt = copy.deepcopy((report,row))
                if mutation == 'aggregate': r['fault_acceptance_pass'] = True
                if mutation == 'full': r['full_plan_acceptance_pass'] = True
                if mutation == 'semantic': receipt['proof']['owner_released'] = False
                (root/'hosted-faults.json').write_text(json.dumps(r))
                (root/F04/'receipt.json').write_text(json.dumps(receipt))
                cp = subprocess.run(cmd+(['--case',F04] if mutation == 'duplicate' else []),capture_output=True,text=True,env=os.environ)
                if mutation == 'valid':
                    self.assertEqual(cp.returncode,0,cp.stderr)
                    self.assertEqual(json.loads(output.read_text()),{'scope':'single-fault','suite':'recovery','case':F04,
                                     'selected_case_pass':True,'full_plan_acceptance_pass':False})
                    output.unlink()
                else:
                    self.assertNotEqual(cp.returncode,0)
                    self.assertFalse(output.exists())

    def test_f04_planner_is_scoped_and_bulk_matrices_are_unchanged(self):
        import verify_hosted_selection as selection
        self.assertIn('recovery',selection.SCOPED_CASES,'F04 single-case suite is missing')
        self.assertEqual(selection.plan('single-fault',F04),[{'suite':'recovery','case':F04}])
        self.assertEqual(selection.plan('all','all'),[{'suite':s,'case':'all'} for s in ('core-resources','capacity','faults')])
        expected = ('unknown-commit-before-finalize-worker-SIGKILL','finalized-before-report-worker-SIGKILL',
                    'temp-pack-ENOSPC','restore-output-ENOSPC','file-truncate-during-native-read',
                    'restore-missing-extension-binary-prerequisites')
        remaining = selection.plan('remaining-faults','all')
        self.assertEqual(len(remaining),7)
        self.assertNotIn(F04,[row['case'] for row in remaining])
        self.assertEqual(remaining,[{'suite':s,'case':c} for s,c in (
            ('native','restic-native-exit3'),('native',expected[0]),('native',expected[1]),
            ('storage',expected[2]),('storage',expected[3]),('native',expected[4]),('storage',expected[5]))])
        for scope,case in [('all',F04),('remaining-faults',F04),('single-fault','all'),
                           ('single-fault',F04+'\n'),('single-fault','$(touch INJECTED)')]:
            with self.subTest(scope=scope,case=case), self.assertRaises(ValueError): selection.plan(scope,case)


F04 = 'docker-stream-drop-status-unavailable-recovery'


if __name__ == '__main__': unittest.main()
