"""F14 OFFLINE regressions. No Docker, public CLI or hosted acceptance claim."""
import importlib
import os
import signal
import unittest


def cleanup_owned_child(pid,pidfd):
    """Signal only the incarnation opened before tracing/waiting; no fallback."""
    import time
    try:
        try:signal.pidfd_send_signal(pidfd,signal.SIGKILL)
        except ProcessLookupError:pass
        end=time.monotonic()+2
        while time.monotonic()<end:
            try:found,status=os.waitpid(pid,os.WNOHANG|0x40000000)
            except ChildProcessError:return # Already reaped by trace_exit.
            if found and (os.WIFEXITED(status) or os.WIFSIGNALED(status)):return
            time.sleep(.001)
        raise TimeoutError('owned test child was not reaped')
    finally:os.close(pidfd)


class ReaderTracerTests(unittest.TestCase):
    def test_real_owned_child_exit_boundary_preserves_bytes_and_observes_sigkill(self):
        self.assertIsNotNone(importlib.util.find_spec('hosted_f14_reader'), 'missing external exit-boundary tracer')
        m = importlib.import_module('hosted_f14_reader')
        gate_r, gate_w = os.pipe(); data_r, data_w = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(gate_w); os.close(data_r)
            os.read(gate_r, 1); os.write(data_w, b'otherwise-valid-import-input')
            os._exit(0)
        pidfd=os.pidfd_open(pid)
        os.close(gate_r); os.close(data_w)
        checks = []
        try:
            result = m.trace_exit(pid, lambda: checks.append('checked'), lambda: os.write(gate_w,b'x'), inject=True)
            self.assertEqual(os.read(data_r, 100), b'otherwise-valid-import-input')
            self.assertEqual(result['natural_exit_code'], 0)
            self.assertEqual(result['terminal_signal'], signal.SIGKILL)
            self.assertIsNone(result['terminal_exit_code'])
            self.assertTrue(result['injected'])
            self.assertGreaterEqual(len(checks), 2)
        finally:
            os.close(gate_w); os.close(data_r)
            cleanup_owned_child(pid,pidfd)

    def test_real_owned_child_control_observes_zero_without_injection(self):
        self.assertIsNotNone(importlib.util.find_spec('hosted_f14_reader'), 'missing external exit-boundary tracer')
        m = importlib.import_module('hosted_f14_reader')
        r,w = os.pipe(); pid = os.fork()
        if pid == 0:
            os.close(w); os.read(r,1); os._exit(0)
        pidfd=os.pidfd_open(pid)
        os.close(r)
        try:
            result = m.trace_exit(pid,lambda: None,lambda: os.write(w,b'x'),inject=False)
            self.assertFalse(result['injected']); self.assertEqual(result['terminal_exit_code'],0)
            self.assertIsNone(result['terminal_signal'])
        finally:
            os.close(w)
            cleanup_owned_child(pid,pidfd)


    def test_real_owned_multithread_child_exit_from_nonleader_is_traced(self):
        m=importlib.import_module('hosted_f14_reader')
        r,w=os.pipe(); pid=os.fork()
        if pid == 0:
            import threading
            os.close(w); os.read(r,1)
            def finish():
                for _ in range(8):
                    t=threading.Thread(target=lambda: None); t.start(); t.join()
                os._exit(0)
            threading.Thread(target=finish).start()
            while True: signal.pause()
        pidfd=os.pidfd_open(pid)
        os.close(r)
        try:
            result=m.trace_exit(pid,lambda: None,lambda: os.write(w,b'x'),inject=True)
            self.assertTrue(result['injected']); self.assertEqual(result['terminal_signal'],9)
        except Exception as exc:
            print('F14_THREAD_DIAGNOSTIC',type(exc).__name__,str(exc),flush=True)
            raise
        finally:
            os.close(w)
            cleanup_owned_child(pid,pidfd)

    def test_final_authorization_failure_detaches_without_reader_kill(self):
        m=importlib.import_module('hosted_f14_reader')
        r,w=os.pipe(); pid=os.fork()
        if pid == 0:
            os.close(w); os.read(r,1); os._exit(0)
        pidfd=os.pidfd_open(pid)
        os.close(r); checks=[]
        def validate():
            checks.append(True)
            if len(checks) == 3: raise ValueError('synthetic owner drift')
        try:
            with self.assertRaisesRegex(ValueError,'owner drift'):
                m.trace_exit(pid,validate,lambda: os.write(w,b'x'),inject=True)
            _,status=os.waitpid(pid,0)
            self.assertTrue(os.WIFEXITED(status)); self.assertEqual(os.WEXITSTATUS(status),0)
        finally:
            os.close(w)
            cleanup_owned_child(pid,pidfd)


class BindingTests(unittest.TestCase):
    def test_exact_reader_binding_rejects_owner_auth_pid_command_and_incarnation_drift(self):
        m = importlib.import_module('hosted_f14_reader')
        self.assertTrue(hasattr(m,'check_binding'), 'missing exact host process authorization gate')
        a = {'runID':'a'*32,'daemonID':'unit','workerContainerID':'b'*64,'workerStartAuthorized':True,
             'phase':'exec_started','status':'active','execKind':'restore','importRunID':'restore_'+'c'*48}
        dump_path=F14VerifierTests().receipt()['proof']['target_mapping']['snapshot']['metadata']['paths'][0]
        p = {'pid':123,'ppid':100,'start_ticks':99,'exe':'/usr/bin/restic','argv':['/usr/bin/restic','--no-cache','dump','d'*64,dump_path],'cgroup':'0::/docker/'+'b'*64}
        b = {'owner':a,'worker_pid':100,'reader':p,'snapshot_id':'d'*64,'dump_path':dump_path}
        m.check_binding(b,a,p)
        import copy
        for section,key,value in [('owner','workerStartAuthorized',1),('owner','workerStartAuthorized',False),
                                  ('owner','phase','quarantine'),('reader','pid',124),('reader','ppid',101),
                                  ('reader','start_ticks',100),('reader','exe','/bin/sh'),
                                  ('reader','argv',['/usr/bin/restic','dump','d'*64,dump_path]),
                                  ('reader','cgroup','0::/docker/'+'e'*64)]:
            x = copy.deepcopy(a); y = copy.deepcopy(p)
            (x if section == 'owner' else y)[key] = value
            with self.subTest(section=section,key=key), self.assertRaises(ValueError): m.check_binding(b,x,y)


    def test_owner_drift_during_engine_readback_is_rechecked_at_final_signal_gate(self):
        m=importlib.import_module('hosted_f14_reader')
        self.assertTrue(hasattr(m,'authorize'),'missing final post-Engine owner gate')
        from unittest.mock import Mock,patch
        import copy,json,tempfile
        from pathlib import Path
        a=F14VerifierTests().receipt()['proof']['attempts'][1]['owner']
        dump_path=F14VerifierTests().receipt()['proof']['target_mapping']['snapshot']['metadata']['paths'][0]
        p={'pid':123,'ppid':100,'start_ticks':99,'exe':'/usr/bin/restic','argv':['/usr/bin/restic','--no-cache','dump','7'*64,dump_path],'cgroup':'0::/docker/'+a['workerContainerID']}
        b={'owner':a,'reader':p,'worker_pid':100,'snapshot_id':'7'*64,'dump_path':dump_path,'image_id':'sha256:'+'2'*64}
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'owner.json'; path.write_text(json.dumps(a)); engine=Mock()
            def inspect(cid):
                if cid==a['workerContainerID']: return {'State':{'Running':True,'Pid':100}}
                drift=copy.deepcopy(a); drift['workerStartAuthorized']=1; path.write_text(json.dumps(drift))
                return {'Id':a['sourceContainerID'],'State':{'Running':True,'StartedAt':a['sourceStartedAt']}}
            engine.inspect.side_effect=inspect; engine.call.return_value={'ID':a['daemonID']}
            with patch.object(m,'read_process',return_value=p),patch('run_resource_probe.worker_owned',return_value=True):
                with self.assertRaises(ValueError): m.authorize(b,path,engine)


class F14VerifierTests(unittest.TestCase):
    def receipt(self, logical='fixture/compose/project/postgres/fixture'):
        import hashlib
        source = {'container_id':'9'*64,'started_at':'source-start','restart_count':0}
        dump_path = '/bakabel/postgres/'+hashlib.sha256(logical.encode()).hexdigest()+'/database.dump'
        row = {'schema':1,'case':'restore-reader-failure-importer-zero','status':'pass','exercised':True,
               'ordinary_image':True,'request_mutations':[],'backend':'local','platform':'compose','source_unchanged':True,
               'daemon':'unit','source_sha256':'1'*64,'image_id':'sha256:'+'2'*64,'source':source,
               'workers':{},'relay':{'records':[],'execs':{},'errors':[],'workers':[]},
               'cleanup':{'containers_absent':{'9'*64:True},'volumes_absent':{'owned':True},'private_paths_absent':True},
               'proof':{'target_mapping':{'plan':{'ID':logical,'Kind':'postgres','Source':{'DaemonID':'unit','ContainerID':'9'*64,'StartedAt':'source-start'}},
                   'snapshot':{'snapshotID':'7'*64,'status':'complete','type':'postgres','source':logical,
                               'metadata':{'version':1,'kind':'postgres','source':logical,'paths':[dump_path]}}},
                        'source_data':{'rows':300000,'min':1,'max':300000,'sum':45000150000,'digest':'0'*32},'attempts':[]}}
        for mode,cid,eid,target,run in [('control','b'*64,'e'*64,'d'*64,'a'*32),('fault','c'*64,'f'*64,'6'*64,'4'*32)]:
            a = {'runID':run,'daemonID':'unit','workerContainerID':cid,'workerName':'bakabel-worker-'+run,'workerStartAuthorized':True,
                 'targetID':hashlib.sha256(logical.encode()).hexdigest(),'sourceContainerID':target,'sourceStartedAt':'target-start',
                 'execID':eid,'execKind':'restore','importRunID':'restore_'+('5' if mode=='control' else '6')*48,'phase':'exec_started','status':'active'}
            terminal = {'daemon':'unit','container_id':target,'started_at':'target-start','exec_id':eid,
                        'exec_exit_code':0,'sessions':0,'processes':0,'import_run_id':a['importRunID']}
            intent = {k:v for k,v in a.items() if k in ('runID','daemonID','workerContainerID','workerName','workerStartAuthorized','status')}; intent['phase']='intent'
            creation = {k:v for k,v in a.items() if k not in ('execID','importRunID')}; creation['phase']='creating_exec'
            command = ['/usr/bin/restic','--no-cache','dump','7'*64,dump_path]
            reader = {'pid':125 if mode=='control' else 126,'ppid':100,'start_ticks':99,'argv_sha256':hashlib.sha256(__import__('json').dumps(command,separators=(',',':')).encode()).hexdigest(),
                      'natural_exit_code':0,'injected':mode=='fault','terminal_exit_code':0 if mode=='control' else None,
                      'terminal_signal':None if mode=='control' else 9,'fresh_authorization_checks':3}
            attempt = {'mode':mode,'owner':a,'controller_id':('8' if mode=='control' else '3')*64,'worker_pid':100,'reader':reader,
                       'target':{'container_id':target,'started_at':'target-start','restart_count':0},'terminal':terminal,
                       'data':row['proof']['source_data'].copy(),'owner_released':True,'worker_absent':True,'last_success_unchanged':True,
                       'cli_exit':0 if mode=='control' else 1,'result':{'runID':run,'status':'restored' if mode=='control' else 'failed',
                           'targets':[{'targetID':logical,'snapshotID':'7'*64,'status':'restored' if mode=='control' else 'unknown',**({} if mode=='control' else {'error':'restore failed'})}]}}
            row['proof']['attempts'].append(attempt)
            row['workers'][cid] = {'container_id':cid,'run_id':run,'image_id':row['image_id'],'memory_bytes':536870912,'nanocpus':2000000000,
                'cpu.max':'200000 100000','memory.max':'536870912','socket':{'source':'/unit/relay.sock','destination':'/run/bakabel/docker.sock','read_only':True}}
            row['relay']['workers'].append(cid)
            row['relay']['execs'][eid] = {'kind':'restore','container_id':target,'stdin_bytes':20000000,'stdout_bytes':0}
            row['relay']['records'] += [
                {'method':'POST','boundary':'restore-create','container_id':target,'exec_id':eid,'forwarded':True,'status':201,'owner_checkpoint':creation},
                {'method':'POST','boundary':'restore-start','container_id':target,'exec_id':eid,'forwarded':True,'status':101,'owner_checkpoint':a},
                {'method':'DELETE','boundary':'worker-remove','container_id':cid,'forwarded':True,'status':204,'remove_query':'','remove_query_valid':True,'remove_force':False,'remove_volumes':False,
                 'owner_before_remove':intent,'terminal_before_remove':terminal,'reader_before_remove':reader,
                 'worker_before_remove':{'container_id':cid,'running':False,'pid':0,'exit_code':attempt['cli_exit']}}]
            row['cleanup']['containers_absent'].update({cid:True,target:True,attempt['controller_id']:True})
        return __import__('json').loads(__import__('json').dumps(row))

    def test_accepts_only_bound_control_and_fault_with_independent_importer_zero(self):
        m = importlib.import_module('verify_hosted_faults')
        self.assertIn('restore-reader-failure-importer-zero',m.CASES,'F14 ordinary CLI fault not registered')
        legacy = ('producer-failure-after-output','streaming-worker-SIGKILL','docker-stream-drop',
                  'docker-stream-drop-status-unavailable-recovery','worker-create-response-loss','worker-start-response-loss',
                  'dump-create-response-loss','dump-start-response-loss','restore-create-response-loss','restore-start-response-loss',
                  'backup-vs-restore-and-retention','scheduler-restart-original-deadline',
                  'dump-persisted-before-start-worker-SIGKILL','restore-active-import-worker-SIGKILL')
        prefix=legacy+('restore-reader-failure-importer-zero',)
        self.assertEqual(m.CASES[:len(prefix)],prefix,'the original fourteen case identities/order must remain intact')
        m.verify_case(self.receipt())

    def test_verifier_gate_mutation_is_killed_by_negative_controls(self):
        import copy, sys, types
        from unittest.mock import patch
        from pathlib import Path
        from run_compose_pg_acceptance import fingerprint
        root=Path(__file__).resolve().parents[3]
        original=(Path(__file__).with_name('verify_hosted_f14.py')).read_text()
        needle="all(integer(terminal.get(k),0) for k in ('exec_exit_code','sessions','processes'))"
        self.assertEqual(original.count(needle),1)
        mutant=types.ModuleType('verify_hosted_f14')
        exec(compile(original.replace(needle,"all(integer(terminal.get(k),0) for k in ('sessions','processes'))"),'<offline-verifier-mutant>','exec'),mutant.__dict__)
        row=self.receipt(); row['proof']['attempts'][1]['terminal']['exec_exit_code']=1
        row['relay']['records'][5]['terminal_before_remove']['exec_exit_code']=1
        from verify_hosted_faults import verify_case
        with self.assertRaises(ValueError): verify_case(row)
        with patch.dict(sys.modules,{'verify_hosted_f14':mutant}):
            verify_case(row) # proves this exact gate, rather than a setup failure, rejected it.

    def test_rejects_all_semantically_correlated_removal_and_exec_mutants(self):
        import copy
        from verify_hosted_faults import verify_case
        for label in ('worker-remove','restore-start','other'):
            row=self.receipt(); contradictory=copy.deepcopy(row['relay']['records'][5]); contradictory.update(boundary=label,method='GET',container_id='0'*64)
            row['relay']['records'].insert(5,contradictory)
            with self.subTest(label=label), self.assertRaises(ValueError): verify_case(row)
        for field,value in [('exec_id','0'*64),('container_id','0'*64),('method','GET'),('boundary','dump-start')]:
            row=self.receipt(); contradictory=copy.deepcopy(row['relay']['records'][4]); contradictory[field]=value
            row['relay']['records'].insert(5,contradictory)
            with self.subTest(field=field), self.assertRaises(ValueError): verify_case(row)

    def test_rejects_missing_wrong_reader_importer_public_identity_and_remove_proofs(self):
        m = importlib.import_module('verify_hosted_faults')
        self.assertIn('restore-reader-failure-importer-zero',m.CASES,'F14 ordinary CLI fault not registered')
        edits = [(('proof','attempts',1,'reader','terminal_signal'),None),
                 (('proof','attempts',1,'reader','natural_exit_code'),3),
                 (('proof','attempts',1,'reader','injected'),False),
                 (('proof','attempts',1,'reader','fresh_authorization_checks'),0),
                 (('proof','attempts',1,'terminal','exec_exit_code'),1),
                 (('proof','attempts',1,'terminal','sessions'),False),
                 (('proof','attempts',1,'owner','workerStartAuthorized'),1),
                 (('proof','attempts',1,'result','status'),'complete'),
                 (('proof','attempts',1,'result','targets',0,'status'),'restored'),
                 (('proof','attempts',1,'result','targets',0,'targetID'),'0'*64),
                 (('proof','attempts',1,'data','rows'),299999),
                 (('proof','attempts',1,'owner_released'),False),
                 (('relay','records',5,'owner_before_remove'),{}),
                 (('relay','records',5,'terminal_before_remove','exec_exit_code'),1),
                 (('relay','records',5,'remove_query'),'force=true'),
                 (('relay','records',4,'forwarded'),False),
                 (('proof','target_mapping','plan','ID'),'foreign')]
        for path,value in edits:
            row = self.receipt(); part=row
            for k in path[:-1]: part=part[k]
            part[path[-1]]=value
            with self.subTest(path=path), self.assertRaises(ValueError): m.verify_case(row)
        for key in ('target_mapping','source_data','attempts'):
            row=self.receipt(); del row['proof'][key]
            with self.subTest(missing=key), self.assertRaises(ValueError): m.verify_case(row)


class F14RunnerTests(unittest.TestCase):
    def test_actual_case_dispatch_selects_additive_mixin_without_changing_other_cases(self):
        m=importlib.import_module('run_hosted_faults')
        self.assertTrue(hasattr(m,'probe_class_for_case'),'missing actual runner F14 dispatch')
        from run_hosted_f14 import F14Mixin
        self.assertTrue(issubclass(m.probe_class_for_case('restore-reader-failure-importer-zero'),F14Mixin))
        self.assertIs(m.probe_class_for_case('restore-active-import-worker-SIGKILL'),m.FaultProbe)

    def test_actual_unix_relay_calls_reader_gate_before_forwarding_unchanged_start(self):
        self.assertIsNotNone(importlib.util.find_spec('run_hosted_f14'),'missing hosted F14 fixture')
        from run_hosted_f14 import F14Mixin
        from run_hosted_faults import FaultRelay
        import json, socket, tempfile, threading
        from pathlib import Path
        events=[]; eid='e'*64; target='d'*64; worker='b'*64
        active={'execID':eid,'sourceContainerID':target,'workerContainerID':worker,'workerStartAuthorized':True}
        class Base:
            def observe_transport(self,phase,record):
                if phase=='request': record['owner_checkpoint']=active
        class Probe(F14Mixin,Base):
            def start_reader_tracer(self,owner):
                self.assert_owner=owner; events.append('reader-armed')
        probe=Probe(); probe.f14_attempt={'mode':'fault','target':{'container_id':target}}
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); server=socket.socket(socket.AF_UNIX); server.bind(str(root/'back')); server.listen()
            body=b'{"Detach":false,"Tty":false}'
            request=b'POST /v1.55/exec/'+eid.encode()+b'/start HTTP/1.1\r\nHost: local\r\nConnection: Upgrade\r\nUpgrade: tcp\r\nContent-Length: '+str(len(body)).encode()+b'\r\n\r\n'+body
            seen=[]
            def peer():
                conn,_=server.accept()
                with conn:
                    data=b''
                    while len(data)<len(request): data+=conn.recv(4096)
                    seen.append(data); events.append('real-peer-start')
                    conn.sendall(b'HTTP/1.1 101 UPGRADED\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n'); conn.shutdown(socket.SHUT_WR)
                    while conn.recv(4096): pass
            thread=threading.Thread(target=peer); thread.start()
            relay=FaultRelay(root/'front',root/'back'); relay.execs[eid]={'kind':'restore','container_id':target,'stdin_bytes':0,'stdout_bytes':0}
            relay.observer=probe.observe_transport; relay.start()
            try:
                with socket.socket(socket.AF_UNIX) as client:
                    client.settimeout(3); client.connect(str(root/'front')); client.sendall(request); client.shutdown(socket.SHUT_WR)
                    response=b''
                    while True:
                        data=client.recv(4096)
                        if not data: break
                        response+=data
                thread.join(3)
                self.assertFalse(thread.is_alive()); self.assertEqual(seen,[request])
                self.assertEqual(events,['reader-armed','real-peer-start']); self.assertIn(b'101 UPGRADED',response)
                self.assertEqual(relay.snapshot()['errors'],[])
            finally: relay.close(); server.close()


class F14OrchestrationTests(unittest.TestCase):
    def probe(self, *, false_success=False, fixture=None):
        self.assertIsNotNone(importlib.util.find_spec('run_hosted_f14'))
        from run_hosted_f14 import F14Mixin
        from unittest.mock import Mock
        import copy, json
        fixture=fixture or F14VerifierTests().receipt(); proof=fixture['proof']; mapping=proof['target_mapping']; bymode={x['mode']:x for x in proof['attempts']}
        from run_hosted_faults import FaultProbe
        class Probe(F14Mixin,FaultProbe): pass
        p=Probe.__new__(Probe); p.source='9'*64; p.target=mapping['plan']['ID']; p.result={}; p.baseline_success='baseline'
        p.calls=[]
        def call_cli(command):
            p.calls.append((command,))
            if command=='plan': return {'targets':[copy.deepcopy(mapping['plan'])]}
            if command=='snapshots': return [copy.deepcopy(mapping['snapshot'])]
            raise AssertionError('not an ordinary public query')
        p.call_cli=call_cli; p.success_snapshot=lambda: mapping['snapshot']['snapshotID']
        def startpg(name,marked): return bymode[name.removeprefix('restore-')]['target']['container_id']
        p.startpg=startpg
        def inspect(cid,missing=False):
            for a in bymode.values():
                if cid==a['target']['container_id']:
                    return {'Id':cid,'State':{'Running':True,'StartedAt':a['target']['started_at']},'RestartCount':0}
            if missing: return None
            raise AssertionError('unowned inspect')
        p.e=Mock(); p.e.inspect.side_effect=inspect
        p.sql=lambda cid,q: json.dumps(proof['source_data'])
        def controller(*argv):
            p.calls.append(argv); mode=p.f14_attempt['mode']; a=bymode[mode]
            # Explicitly synthetic observer seam; no runtime acceptance receipt.
            for k in ('owner','terminal','reader','worker_pid'): p.f14_attempt[k]=copy.deepcopy(a[k])
            return a['controller_id']
        p.controller=controller
        def finish(cid,**kwargs):
            a=bymode[p.f14_attempt['mode']]; result=copy.deepcopy(a['result'])
            if false_success and p.f14_attempt['mode']=='fault':
                result['status']='complete'; result['targets'][0].update(status='restored',error='')
            return [result]
        p.finish=finish
        p.owner=lambda: None
        p.last=lambda: {'runID':p.f14_attempt['owner']['runID'],'operation':'restore',
                       'status':'failed' if p.f14_attempt['mode']=='fault' else 'success','lastBackupSuccessAt':'baseline'}
        return p

    def test_exercises_two_ordinary_public_cli_restores_and_retains_all_data(self):
        p=self.probe(); p.exercise_reader_failure()
        restores=[x for x in p.calls if x[0]=='restore']
        self.assertEqual(len(restores),2)
        for argv in restores:
            self.assertEqual(argv[1:3],('--snapshot','7'*64)); self.assertEqual(argv[-4:],('--database','fixture','--user','postgres'))
        self.assertEqual([a['cli_exit'] for a in p.result['proof']['attempts']],[0,1])
        self.assertEqual([a['data']['rows'] for a in p.result['proof']['attempts']],[300000,300000])

    def test_actual_orchestration_rejects_false_restored_public_result(self):
        p=self.probe(false_success=True)
        with self.assertRaises(ValueError): p.exercise_reader_failure()

    def test_production_public_dump_paths_reach_both_restores_and_verifier(self):
        from verify_hosted_f14 import verify_f14
        from pathlib import Path
        root=Path(__file__).resolve().parents[3]
        production=(root/'internal/app/workflow_worker.go').read_text()
        self.assertIn('return "/bakabel/postgres/" + targetHash(source) + "/database.dump"',production)
        self.assertIn('m.Paths = []string{postgresPath(id)}',production)
        self.assertIn('repo.Backup(ctx, workflowMetadata(p, t.ID)',production)
        self.assertIn('repo.Dump(streamCtx, snapshot.ID, m.Paths[0], writer)',(root/'internal/restore/postgres.go').read_text())
        paths=[]
        for logical in ('fixture/compose/project/postgres/fixture','fixture/compose/another/postgres/fixture'):
            row=F14VerifierTests().receipt(logical); p=self.probe(fixture=row)
            p.exercise_reader_failure(); verify_f14(row)
            path=row['proof']['target_mapping']['snapshot']['metadata']['paths'][0]
            self.assertEqual(p.f14_dump_path,path); paths.append(path)
            self.assertEqual(len(p.result['proof']['attempts']),2)
        self.assertNotEqual(*paths)

    def test_production_restored_control_result_reaches_fault_and_verifies(self):
        from pathlib import Path
        from verify_hosted_f14 import verify_f14
        root=Path(__file__).resolve().parents[3]
        self.assertIn('result.Status = "restored"',(root/'internal/app/workflow_worker.go').read_text())
        self.assertIn('j.Restore != nil && res.Status == "complete"',(root/'internal/app/workflow_controller.go').read_text())
        row=F14VerifierTests().receipt(); p=self.probe(fixture=row)
        p.exercise_reader_failure(); verify_f14(row)
        self.assertEqual([a['result']['status'] for a in p.result['proof']['attempts']],['restored','failed'])
        self.assertEqual(len([x for x in p.calls if x[0]=='restore']),2)

    def test_invented_complete_control_is_rejected_by_runner_and_verifier(self):
        from verify_hosted_f14 import verify_f14
        row=F14VerifierTests().receipt(); row['proof']['attempts'][0]['result']['status']='complete'
        p=self.probe(fixture=row)
        with self.assertRaisesRegex(ValueError,'public CLI reader failure masked'): p.exercise_reader_failure()
        self.assertEqual(len([x for x in p.calls if x[0]=='restore']),1)
        with self.assertRaisesRegex(ValueError,'public logical identity lost'): verify_f14(row)

    def test_wrong_public_snapshot_layout_refuses_before_restore(self):
        import copy,hashlib,json
        from verify_hosted_f14 import verify_f14
        path='/bakabel/postgres/'+hashlib.sha256(b'foreign').hexdigest()+'/database.dump'
        for field,value in [('paths',['/postgres.dump']),('paths',[path]),('paths',[path,path]),
                            ('source','foreign'),('kind','volume'),('version',True)]:
            row=F14VerifierTests().receipt(); row['proof']['target_mapping']['snapshot']['metadata'][field]=value
            p=self.probe(fixture=row)
            with self.subTest(field=field,value=value):
                with self.assertRaises(ValueError): p.exercise_reader_failure()
                self.assertEqual([x for x in p.calls if x[0]=='restore'],[])
                with self.assertRaises(ValueError): verify_f14(json.loads(json.dumps(row)))
        # A coherently changed path/reader digest cannot overrule the frozen plan.
        row=F14VerifierTests().receipt(); row['proof']['target_mapping']['snapshot']['metadata']['paths']=[path]
        digest=hashlib.sha256(json.dumps(['/usr/bin/restic','--no-cache','dump','7'*64,path],separators=(',',':')).encode()).hexdigest()
        for i,a in enumerate(row['proof']['attempts']):
            a['reader']['argv_sha256']=digest
            row['relay']['records'][i*3+2]['reader_before_remove']=copy.deepcopy(a['reader'])
        with self.assertRaises(ValueError): verify_f14(json.loads(json.dumps(row)))

    def test_tracer_discovers_and_binds_exact_frozen_metadata_path(self):
        import copy,io,json,tempfile
        from pathlib import Path
        from unittest.mock import Mock,patch
        import run_hosted_f14 as runner
        row=F14VerifierTests().receipt(); a=row['proof']['attempts'][0]; active=a['owner']
        path=row['proof']['target_mapping']['snapshot']['metadata']['paths'][0]
        p=self.probe(); p.f14_snapshot='7'*64; p.f14_dump_path=path; p.f14_attempt=copy.deepcopy(a)
        p.f14_attempt.pop('owner'); p.owner=lambda:copy.deepcopy(active)
        p.capture_owned_worker=Mock(); p.worker_identity_proof=Mock(); p.image=row['image_id']; p.args=Mock(socket='/owned/socket')
        p.e.inspect.side_effect=None; p.e.inspect.return_value={'State':{'Running':True,'Pid':100}}
        process={'pid':123,'ppid':100,'start_ticks':99,'exe':'/usr/bin/restic',
                 'argv':['/usr/bin/restic','--no-cache','dump','7'*64,path],'cgroup':'0::/docker/'+active['workerContainerID']}
        with tempfile.TemporaryDirectory() as directory:
            p.root=Path(directory); (p.root/'private').mkdir()
            child=Mock(stdout=io.StringIO('{"state":"armed"}\n'))
            with patch.object(runner,'find_reader',return_value=process) as discover, \
                 patch.object(runner.subprocess,'Popen',return_value=child),patch.object(runner.select,'select',return_value=([child.stdout],[],[])):
                p.start_reader_tracer(active)
            discover.assert_called_once_with(100,'7'*64,path)
            binding=json.loads((p.root/'private/f14-control.json').read_text())
            self.assertEqual(binding['dump_path'],path); self.assertEqual(binding['reader']['argv'][-1],path)

    def test_selected_annotations_cannot_replace_exact_snapshot_path_or_reader_argv(self):
        import copy,hashlib,json
        from verify_hosted_f14 import verify_f14
        row=F14VerifierTests().receipt(); p=self.probe(fixture=row)
        p.f14_dump_path='/postgres.dump'; p.f14_snapshot='8'*64
        p.exercise_reader_failure()
        self.assertEqual(p.f14_snapshot,'7'*64)
        self.assertEqual(p.f14_dump_path,row['proof']['target_mapping']['snapshot']['metadata']['paths'][0])
        for snapshot,path in [('8'*64,p.f14_dump_path),('7'*64,'/postgres.dump')]:
            changed=copy.deepcopy(row); a=changed['proof']['attempts'][0]
            a['reader']['argv_sha256']=hashlib.sha256(json.dumps(['/usr/bin/restic','--no-cache','dump',snapshot,path],separators=(',',':')).encode()).hexdigest()
            changed['relay']['records'][2]['reader_before_remove']=copy.deepcopy(a['reader'])
            with self.subTest(snapshot=snapshot,path=path),self.assertRaises(ValueError): verify_f14(json.loads(json.dumps(changed)))
        row['proof']['attempts'][0]['result']['targets'][0]['snapshotID']='8'*64
        with self.assertRaises(ValueError): verify_f14(row)
        p=self.probe(); query=p.call_cli
        p.call_cli=lambda command: [dict(query(command)[0],snapshotID='8'*64)] if command=='snapshots' else query(command)
        with self.assertRaisesRegex(ValueError,'exact trusted snapshot missing'): p.exercise_reader_failure()
        self.assertEqual([x for x in p.calls if x[0]=='restore'],[])


if __name__ == '__main__': unittest.main()
