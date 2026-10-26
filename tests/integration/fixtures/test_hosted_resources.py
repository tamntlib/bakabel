"""Offline contracts for hosted resource replay, never fabricated runtime evidence."""
import importlib
import unittest


class HostedResources(unittest.TestCase):
    def captured_failure_raw(self):
        """Synthetic raw states, NOT recovered raw evidence from hosted 133.

        Reproduces that failed attempt's public exit=0/OOM=false/32MiB shape;
        the running state and owner are explicit offline counterexamples only.
        """
        run='b'*32;cid='a'*64;name='bakabel-worker-'+run;daemon='unit-daemon'
        worker={'Id':cid,'Name':'/'+name,'Image':'candidate',
                'State':{'Status':'running','Running':True,'Pid':123,'ExitCode':0,'OOMKilled':False},
                'HostConfig':{'Memory':33554432,'NanoCpus':2000000000}}
        owner={'runID':run,'daemonID':daemon,'workerName':name,'workerContainerID':cid,
               'phase':'intent','status':'active','workerStartAuthorized':True}
        return {'mode':'oom','daemon':daemon,'image_id':'candidate','gates':[],
                'worker_last_inspect':worker,
                'workers':{cid:{**worker,'runID':run,'state':'state','Config':{'Labels':{
                    'bakabel.worker':'1','bakabel.run':run,'bakabel.daemon':daemon}}}},
                'owner_history':[{'owner':owner}],
                'failure_cgroup_samples':[{'cpu.max':'200000 100000','memory.max':'33554432','memory.events':'oom_kill 0'}]}

    def test_133_timeout_exit_zero_is_not_terminal_and_failure_is_preserved(self):
        import ast,contextlib,io,json,tempfile
        from pathlib import Path
        from types import SimpleNamespace
        from unittest.mock import Mock,patch
        import run_resource_probe as probe
        module=self.module();raw=self.captured_failure_raw()
        # Exercise the actual 133 controller wait/exception boundary with virtual
        # time, not a fresh Engine/PG/process query or a hosted runtime assertion.
        tree=ast.parse(Path(module.__file__).with_name('run_resource_failures.py').read_text())
        run=next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=='FailureProbe')
        run=next(n for n in run.body if isinstance(n,ast.FunctionDef) and n.name=='run')
        early=next(n for n in ast.walk(run) if isinstance(n,ast.If) and ast.unparse(n.test)=="self.args.mode == 'oom'" and
                   any(isinstance(x,ast.Expr) and isinstance(x.value,ast.Call) and ast.unparse(x.value.func)=='self.finish' for x in n.body))
        keywords={k.arg:ast.literal_eval(k.value) for k in early.body[0].value.keywords}
        self.assertEqual(keywords,{'expect':1,'timeout':20})
        clock=[0.0]
        def sleep(seconds):clock[0]+=seconds
        class OfflineProbe(probe.Probe):
            def __init__(self,args):
                self.root=args.runtime;self.root.mkdir();self.result=raw
                self.e=SimpleNamespace(inspect=Mock(return_value={'State':{'Running':True}}))
            def run(self):self.finish('offline-controller',**keywords)
            def logs(self,cid):raise AssertionError('running controller is not terminal')
            def cleanup(self):(self.root/'receipt.json').write_text(json.dumps(self.result))
        with tempfile.TemporaryDirectory() as directory:
            args=SimpleNamespace(runtime=Path(directory),expected_image_id='candidate',expected_source_sha256='offline-not-build-evidence')
            with patch.object(module,'HostedFailureProbe',OfflineProbe),patch.object(probe,'time',SimpleNamespace(monotonic=lambda:clock[0],sleep=sleep)),patch.object(module,'verify_early_oom') as verifier,contextlib.redirect_stdout(io.StringIO()):
                public=module.run_case(args,'oom',None)
            self.assertTrue(public['failed']);self.assertFalse(public['verified']);self.assertEqual(public['gates'],[])
            self.assertEqual(public['failure']['kind'],'RuntimeError')
            self.assertEqual([f['function'] for f in public['failure']['frames']][-2:],['finish','wait'])
            verifier.assert_not_called();self.assertNotIn('failure_safety',public)
            self.assertEqual(json.loads((Path(directory)/'oom/receipt.json').read_text())['worker_last_inspect'],raw['worker_last_inspect'])
            self.assertEqual(json.loads((Path(directory)/'oom/public.json').read_text()),public)
            observed=public['failure_observations']
            self.assertEqual(observed['worker_exit_code'],0);self.assertIs(observed['worker_oom_killed'],False)
            self.assertEqual(observed['sampled_oom_kill_max'],0)
            self.assertIn('last_captured_state',observed,'exit=0 alone cannot establish terminality')
            self.assertEqual(observed['last_captured_state'],{
                'basis':'historical_not_current','worker_running':True,'worker_pid':123,'worker_status':'running',
                'owner_phase':'intent','worker_start_authorized':True,'source_present':False,'exec_present':False})

    def test_captured_owner_projection_rejects_malformed_and_foreign_rows(self):
        import copy,json,tempfile
        from pathlib import Path
        from types import SimpleNamespace
        from unittest.mock import patch
        module=self.module();base=self.captured_failure_raw();canary='PRIVATE-CANARY'
        owner=base['owner_history'][0]['owner']
        unknown={'owner_phase':None,'worker_start_authorized':None,'source_present':None,'exec_present':None}
        bad_rows=[None,True,[],canary,{'owner':None}]
        for key in ('runID','daemonID','workerName','workerContainerID'):
            bad_rows.append({'owner':{**owner,key:'foreign'}})
        for key,values in (('phase',(True,[],{},canary)),('status',(True,[],{},'unknown')),
                           ('workerStartAuthorized',(1,0,[],{},canary)),
                           ('sourceContainerID',(True,[],{},'bad/value')),('execID',(True,[],{},'bad/value')),
                           ('sourceStartedAt',(True,[],{},canary)),('targetID',(True,[],{},'bad/value')),
                           ('execKind',(True,[],{},canary)),('importRunID',(True,[],{},'bad/value'))):
            bad_rows.extend({'owner':{**owner,key:value}} for value in values)
        bad_rows.extend({'owner':{**owner,key:canary}} for key in ('Env','command','error'))
        bad_rows.extend({'owner':{**owner,**change}} for change in (
            {'phase':'exec_started'}, {'phase':'creating_exec'}, {'status':'blocked'},
            {'sourceContainerID':'c'*64}, {'sourceStartedAt':'2026-10-26T16:50:30Z'},
            {'execID':'d'*64}, {'phase':'quarantine'}, {'importRunID':'e'*32}))
        for bad in bad_rows:
            with self.subTest(row=bad),tempfile.TemporaryDirectory() as directory:
                raw=copy.deepcopy(base);raw['owner_history']=[bad]*40
                raw['worker_last_inspect'].update(Env=[canary],command=canary,error=canary)
                raw['worker_last_inspect']['State'].update(Error=canary,StartedAt=canary,FinishedAt=canary)
                target=Path(directory)/'oom';target.mkdir();receipt=target/'receipt.json'
                receipt.write_text(json.dumps(raw));before=receipt.read_bytes()
                with patch.object(module,'run_platform',return_value={'failed':True}),patch.object(module,'verify_early_oom') as verifier:
                    public=module.run_case(SimpleNamespace(runtime=Path(directory),expected_image_id='candidate'),'oom',None)
                state=public['failure_observations']['last_captured_state']
                self.assertEqual({k:state[k] for k in unknown},unknown)
                self.assertIs(state['worker_running'],True)
                self.assertEqual(len(state),8);self.assertNotIn(canary,(target/'public.json').read_text())
                self.assertEqual(receipt.read_bytes(),before);verifier.assert_not_called()
                self.assertTrue(public['failed']);self.assertFalse(public['verified'])

    def test_captured_state_uses_last_matched_owner_not_trailing_foreign_history(self):
        import copy,json
        module=self.module();base=self.captured_failure_raw();owner=base['owner_history'][0]['owner']
        source={'sourceContainerID':'c'*64,'sourceStartedAt':'2026-10-26T16:50:30.123456789Z','targetID':'payload','execKind':'dump'}
        for phase in ('intent','creating_exec','exec_created','exec_started','quarantine'):
            with self.subTest(phase=phase):
                raw=copy.deepcopy(base)
                last={**owner,'phase':phase,'status':'blocked' if phase=='quarantine' else 'active','workerStartAuthorized':False}
                if phase in ('creating_exec','exec_created','exec_started'):last.update(source)
                if phase in ('exec_created','exec_started'):last['execID']='d'*64
                # observe_fast saves owners before the CID check. Prebinding and
                # later foreign rows are not evidence for this exact worker/run.
                prebinding={k:v for k,v in owner.items() if k not in ('workerContainerID','workerStartAuthorized')}
                raw['owner_history']=[{'owner':prebinding},{'owner':owner},{'owner':last}]+[
                    {'at':'PRIVATE-CANARY','owner':{**last,'runID':'foreign','Env':['PRIVATE-CANARY']}}]*40
                before=copy.deepcopy(raw);state=module.public_captured_failure_state(raw,'candidate')
                self.assertEqual(state['owner_phase'],phase);self.assertIs(state['worker_start_authorized'],False)
                self.assertEqual(state['source_present'],phase in ('creating_exec','exec_created','exec_started'))
                self.assertEqual(state['exec_present'],phase in ('exec_created','exec_started'))
                self.assertEqual(state['basis'],'historical_not_current');self.assertEqual(raw,before)
                for private in ('PRIVATE-CANARY',owner['runID'],owner['workerContainerID'],source['sourceContainerID'],'d'*64):
                    self.assertNotIn(private,json.dumps(state))
        raw=copy.deepcopy(base);del raw['owner_history'][0]['owner']['workerStartAuthorized']
        self.assertIsNone(module.public_captured_failure_state(raw,'candidate')['worker_start_authorized'])
        # The prebinding row cannot provide a phase for an exact matched worker.
        raw['owner_history']=[{'owner':prebinding}]
        self.assertIsNone(module.public_captured_failure_state(raw,'candidate')['owner_phase'])

    def test_captured_worker_types_binding_and_absence_remain_unknown_not_zero(self):
        import copy
        module=self.module();base=self.captured_failure_raw();cid=base['worker_last_inspect']['Id']
        unknown=module.public_captured_failure_state({},'candidate')
        self.assertEqual(unknown,{'basis':'historical_not_current',**{key:None for key in (
            'worker_running','worker_pid','worker_status','owner_phase','worker_start_authorized','source_present','exec_present')}})
        # Historical public 133 receipt dropped all these raw states. Its exit0,
        # OOM=false and numeric memory observations cannot fill in the unknowns.
        self.assertEqual(module.public_captured_failure_state({'failure_observations':{
            'worker_exit_code':0,'worker_oom_killed':False,'worker_memory_bytes':33554432}},'candidate'),unknown)
        for bad in (None,True,1,0,-1,1.5,float('nan'),float('inf'),'PRIVATE-CANARY',[],{}):
            raw=copy.deepcopy(base);raw['worker_last_inspect']['State'].update(Running=bad,Pid=bad,Status=bad)
            with self.subTest(bad=bad):
                state=module.public_captured_failure_state(raw,'candidate')
                self.assertIs(state['worker_running'],bad if type(bad) is bool else None)
                self.assertEqual(state['worker_pid'],bad if type(bad) is int and 0<=bad<2**31 else None)
                self.assertIsNone(state['worker_status'])
        for status in ('created','running','paused','restarting','removing','exited','dead'):
            raw=copy.deepcopy(base);raw['worker_last_inspect']['State']['Status']=status
            self.assertEqual(module.public_captured_failure_state(raw,'candidate')['worker_status'],status)
        for field in ('Running','Pid','Status'):
            raw=copy.deepcopy(base);del raw['worker_last_inspect']['State'][field]
            projected={'Running':'worker_running','Pid':'worker_pid','Status':'worker_status'}[field]
            self.assertIsNone(module.public_captured_failure_state(raw,'candidate')[projected])
        changes=[('daemon','foreign'),('daemon',True),('workers',None),('worker_last_inspect',None)]
        for key,value in changes:
            raw=copy.deepcopy(base);raw[key]=value
            self.assertEqual(module.public_captured_failure_state(raw,'candidate'),unknown)
        for field,value in (('Id','foreign'),('Name','/foreign'),('Image','foreign'),('Config',None)):
            raw=copy.deepcopy(base);raw['workers'][cid][field]=value
            self.assertEqual(module.public_captured_failure_state(raw,'candidate'),unknown)
        for field in ('bakabel.worker','bakabel.run','bakabel.daemon'):
            raw=copy.deepcopy(base);raw['workers'][cid]['Config']['Labels'][field]='foreign'
            self.assertEqual(module.public_captured_failure_state(raw,'candidate'),unknown)
        raw=copy.deepcopy(base);raw['worker_terminal_before_recovery']=copy.deepcopy(raw['worker_last_inspect'])
        raw['worker_terminal_before_recovery']['State'].update(Running=False,Pid=0,Status='exited')
        state=module.public_captured_failure_state(raw,'candidate')
        self.assertIs(state['worker_running'],False);self.assertEqual(state['worker_pid'],0);self.assertEqual(state['worker_status'],'exited')
        self.assertEqual(state['basis'],'historical_not_current')

    def test_failed_case_retains_numeric_observations_without_claiming_oom(self):
        module=self.module()
        import json,tempfile
        from pathlib import Path
        from types import SimpleNamespace
        from unittest.mock import patch
        secret='unit-private-worker-error-not-public'
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);case=root/'oom-active';case.mkdir()
            raw={'gates':[],'workers':{},'cleanup':{},'worker_terminal_before_recovery':{'State':{'Running':False,'ExitCode':137,'OOMKilled':False,'Error':secret},'HostConfig':{'Memory':16777216}},'failure_cgroup_samples':[{'memory.max':'536870912','memory.events':'oom_kill 0'}],'worker_failure_logs':secret}
            (case/'receipt.json').write_text(json.dumps(raw))
            with patch.object(module,'run_platform',return_value={'failed':True}):public=module.run_case(SimpleNamespace(runtime=root),'oom-active',None)
            self.assertTrue(public['failed']);self.assertFalse(public['verified'])
            observed=public['failure_observations']
            self.assertEqual(observed['worker_exit_code'],137)
            self.assertFalse(observed['worker_oom_killed'])
            self.assertEqual(observed['sampled_oom_kill_max'],0)
            self.assertNotIn(secret,json.dumps(public))

    def test_failure_diagnostic_projection_is_numeric_finite_and_canary_safe(self):
        module=self.module()
        import json,tempfile
        from pathlib import Path
        from types import SimpleNamespace
        from unittest.mock import patch
        diagnostic={'failure_code':'oom_proof','update_status':'rejected','update_http_status':500,'warning_count':1,
                    'requested_memory_bytes':16777216,'requested_swap_total_bytes':16777216,
                    'host_memory_bytes':16777216,'host_swap_total_bytes':16777216,
                    'effective_memory_bytes':16777216,'effective_swap_bytes':0,'source_unlocked':True,
                    'terminal_pid':0,'terminal_exit_code':1,'terminal_oom_killed':False,
                    'terminal_counter_status':'unavailable','terminal_oom_kill':None,
                    'targets':[{'failureCode':'backup','resticExitCode':1,'resticReason':'unknown','error':'PRIVATE-CANARY'}],
                    'path':'PRIVATE-CANARY','Env':['PRIVATE-CANARY'],'error':'PRIVATE-CANARY','logs':'PRIVATE-CANARY'}
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);case=root/'oom-active';case.mkdir()
            (case/'receipt.json').write_text(json.dumps({'failure_diagnostics':diagnostic}))
            with patch.object(module,'run_platform',return_value={'failed':True}):public=module.run_case(SimpleNamespace(runtime=root),'oom-active',None)
            self.assertIn('failure_diagnostics',public)
            projected=public['failure_diagnostics']
            self.assertEqual(projected['effective_swap_bytes'],0);self.assertEqual(projected['terminal_exit_code'],1)
            self.assertEqual(projected['failure_code'],'oom_proof');self.assertIsNone(projected['terminal_oom_kill'])
            self.assertEqual(projected['update_status'],'rejected');self.assertEqual(projected['update_http_status'],500)
            self.assertFalse(public['verified']);self.assertNotIn('PRIVATE-CANARY',json.dumps(public))
        for bad in (True,-1,1.5,float('nan'),float('inf'),'PRIVATE-CANARY',[],{}):
            with self.subTest(bad=bad):
                raw={'failure_diagnostics':{key:bad for key in diagnostic if key!='targets'}}
                self.assertTrue(hasattr(module,'public_failure_diagnostics'))
                value=module.public_failure_diagnostics(raw)
                for key in ('warning_count','effective_swap_bytes','terminal_oom_kill','terminal_exit_code','update_http_status'):self.assertIsNone(value[key])
                self.assertIsNone(value['failure_code']);self.assertIsNone(value['update_status'])
                self.assertNotIn('PRIVATE-CANARY',json.dumps(value))

    def test_failure_observer_public_projection_reaches_failed_case_and_rejects_canaries(self):
        module=self.module()
        import copy,json,tempfile
        from pathlib import Path
        from types import SimpleNamespace
        from unittest.mock import patch
        item={'code':'observer_failure','type':'AssertionError','reason':'cgroup_identity','errno':19,
              'frames':[{'file':'run_resource_failures.py','function':'terminal_reinspection','line':103,'source':'PRIVATE-CANARY'}],
              'message':'PRIVATE-CANARY','Env':['PRIVATE-CANARY'],'path':'PRIVATE-CANARY'}
        raw={'fast_observer_errors':[item]*40,'fast_observer_errors_count':50,
             'sampler_errors':[dict(item,code='sampler_failure',type='TimeoutError',reason=None,errno=110)],'sampler_errors_count':1}
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);case=root/'enospc';case.mkdir()
            (case/'receipt.json').write_text(json.dumps(raw))
            with patch.object(module,'run_platform',return_value={'failed':True}):public=module.run_case(SimpleNamespace(runtime=root),'enospc',None)
            section=public['failure_diagnostics'].get('observer_errors')
            self.assertIsNotNone(section,'fatal observers must survive the public receipt boundary')
            self.assertEqual(section['fast']['count'],50);self.assertEqual(len(section['fast']['items']),32)
            self.assertEqual(section['fast']['items'][0],{k:item[k] for k in ('code','type','reason','errno')}|{'frames':[{'file':'run_resource_failures.py','function':'terminal_reinspection','line':103}]})
            self.assertEqual(section['sampler']['count'],1)
            self.assertEqual(section['sampler']['items'][0]['type'],'TimeoutError')
            self.assertFalse(public['verified']);self.assertTrue(public['failed'])
            self.assertEqual(json.loads((case/'public.json').read_text()),public)
            self.assertNotIn('PRIVATE-CANARY',json.dumps(public))
        for bad in ('PRIVATE-CANARY',True,-1,1.5,float('nan'),float('inf'),[],{}):
            with self.subTest(bad=bad):
                poisoned=copy.deepcopy(item)
                poisoned.update({k:bad for k in ('code','type','reason','errno')})
                poisoned['frames']=[{'file':bad,'function':bad,'line':bad},
                    {'file':'run_resource_failures.py','function':'PRIVATE-CANARY','line':103},
                    {'file':'/private/run_resource_failures.py','function':'observe_fast','line':103},
                    {'file':'run_resource_probe.py','function':'sampler','line':bad}]*10
                value=module.public_failure_diagnostics({'fast_observer_errors':[poisoned]*40,'fast_observer_errors_count':bad})['observer_errors']['fast']
                self.assertIsNone(value['count']);self.assertEqual(len(value['items']),32)
                row=value['items'][0]
                self.assertTrue(all(row[k] is None for k in ('code','type','reason','errno')))
                self.assertEqual(len(row['frames']),8)
                self.assertTrue(all(f['line'] is None for f in row['frames']))
                self.assertNotIn('PRIVATE-CANARY',json.dumps(value))
        for malformed in (None,{},'PRIVATE-CANARY',True):
            with self.subTest(malformed=malformed):
                value=module.public_failure_diagnostics({'sampler_errors':malformed})['observer_errors']['sampler']
                self.assertEqual(value,{'count':None,'items':[]})

    def test_entire_resource_public_json_bounds_legacy_sampler_diagnostics_for_every_case(self):
        module=self.module();assert module is not None
        import copy,json,tempfile
        from pathlib import Path
        from types import SimpleNamespace
        from unittest.mock import patch
        canary='PRIVATE-CANARY'
        frames=[{'file':'run_resource_probe.py' if i%2==0 else canary,
                 'function':'sampler' if i%2==0 else canary,'line':100+i if i%2==0 else canary,
                 'source':canary,'locals':canary} for i in range(40)]
        errors=[{'code':'sampler_failure','type':'TimeoutError' if i%2==0 else canary,
                 'errno':110 if i%2==0 else canary,'http_status':canary,'frames':frames,
                 'message':canary,'Env':[canary],'path':canary} for i in range(40)]
        for case in module.CASES:
            for platform_failed in (True,False):
                with self.subTest(case=case,platform_failed=platform_failed),tempfile.TemporaryDirectory() as directory:
                    root=Path(directory);target=root/case;target.mkdir()
                    raw={'sampler_errors':copy.deepcopy(errors),'sampler_errors_count':40}
                    receipt=target/'receipt.json';receipt.write_text(json.dumps(raw));before=receipt.read_bytes()
                    args=SimpleNamespace(runtime=root,source=root,expected_source_sha256='d'*64,expected_image_id='candidate')
                    with patch.object(module,'run_platform',return_value={'failed':platform_failed}),patch.object(module,'verify_cleanup',wraps=module.verify_cleanup) as verify:
                        public=module.run_case(args,case,None)
                    saved=(target/'public.json').read_text()
                    self.assertFalse(canary in saved,'canary leaked in ENTIRE artifact, outside clean failure_diagnostics')
                    self.assertEqual(json.loads(saved),public)
                    self.assertEqual(receipt.read_bytes(),before,'raw errors are immutable inputs to all failure gates')
                    self.assertTrue(public['failed']);self.assertFalse(public['verified'])
                    if platform_failed:verify.assert_not_called()
                    else:
                        self.assertEqual(verify.call_count,1)
                        self.assertEqual(verify.call_args.args[0]['sampler_errors'],errors)
                    legacy=public['sampler_diagnostics']
                    self.assertEqual(len(legacy),32)
                    self.assertEqual(legacy[0]['type'],'TimeoutError');self.assertEqual(legacy[0]['errno'],110)
                    self.assertIsNone(legacy[1]['type']);self.assertIsNone(legacy[1]['errno'])
                    for item in legacy:
                        self.assertEqual(set(item),{'code','type','reason','errno','frames'})
                        self.assertEqual(len(item['frames']),8)
                        self.assertEqual(item['frames'][0],{'file':'run_resource_probe.py','function':'sampler','line':132})
                        self.assertEqual(item['frames'][1],{'file':None,'function':None,'line':None})
                    if case!='scheduler':
                        section=public['failure_diagnostics']['observer_errors']['sampler']
                        self.assertEqual(section,{'count':40,'items':legacy})

    def test_resource_public_projection_keeps_clean_success_and_malformed_errors_fatal(self):
        module=self.module();assert module is not None
        import json,tempfile
        from pathlib import Path
        from types import SimpleNamespace
        from unittest.mock import patch
        for case in module.CASES:
            for errors in ([],[None],'PRIVATE-CANARY',
                           [{'type':['PRIVATE-CANARY'],'errno':True,'http_status':{'bad':'PRIVATE-CANARY'},'frames':None}]):
                with self.subTest(case=case,errors=errors),tempfile.TemporaryDirectory() as directory:
                    root=Path(directory);target=root/case;target.mkdir()
                    raw={'sampler_errors':errors,'failure_terminal_proof':{},'failure_cgroup_samples':[],
                         'repository_space_samples':[]}
                    receipt=target/'receipt.json';receipt.write_text(json.dumps(raw));before=receipt.read_bytes()
                    args=SimpleNamespace(runtime=root,source=root,expected_source_sha256='d'*64,expected_image_id='candidate')
                    verifier=module.verify_cleanup if errors else lambda *args:None
                    with patch.object(module,'run_platform',return_value={'failed':False}),patch.object(module,'verify_cleanup',wraps=verifier) as verify,patch.object(module,'summarize',return_value={}),patch.object(module,'verify_early_oom',return_value={}),patch.object(module.subprocess,'run',return_value=SimpleNamespace(returncode=0,stdout='',stderr='')),patch.object(module,'sha',return_value='e'*64):
                        public=module.run_case(args,case,None)
                    saved=(target/'public.json').read_text()
                    self.assertNotIn('PRIVATE-CANARY',saved)
                    self.assertEqual(json.loads(saved),public)
                    self.assertEqual(receipt.read_bytes(),before)
                    self.assertEqual(verify.call_count,1)
                    self.assertEqual(verify.call_args.args[0],json.loads(before))
                    self.assertEqual(public['failed'],bool(errors));self.assertEqual(public['verified'],not errors)
                    if not errors:self.assertNotIn('sampler_diagnostics',public)
                    else:
                        self.assertEqual(len(public['sampler_diagnostics']),1)
                        item=public['sampler_diagnostics'][0]
                        self.assertEqual(set(item),{'code','type','reason','errno','frames'})
                        self.assertIsNone(item['type']);self.assertIsNone(item['errno']);self.assertEqual(item['frames'],[])

    def test_failed_probe_cannot_reuse_an_older_successful_receipt(self):
        module=self.module()
        from pathlib import Path
        from types import SimpleNamespace
        from unittest.mock import patch
        import json,tempfile
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);case=root/'scheduler';case.mkdir()
            (case/'receipt.json').write_text(json.dumps({'platform':'resources-scheduler','gates':[],'workers':{},'cleanup':{}}))
            args=SimpleNamespace(runtime=root)
            with patch.object(module,'run_platform',return_value={'failed':True}):public=module.run_case(args,'scheduler',None)
            self.assertTrue(public['failed'])
            self.assertFalse(public['verified'])

    def test_unverified_case_never_returns_successful_exit(self):
        module=self.module()
        from pathlib import Path
        from unittest.mock import patch
        import os,tempfile
        info={'ID':'unit-daemon','OSType':'linux','CgroupVersion':'2','SecurityOptions':['name=seccomp'],'Swarm':{'LocalNodeState':'inactive'},'Containers':0}
        def response(method,path):
            if path=='/info':return info
            if path=='/containers/json?all=true':return []
            return {'Id':'candidate'}
        with tempfile.TemporaryDirectory() as directory:
            args=['--socket','/unit-only','--source','/unit-only','--runtime',str(Path(directory)/'runtime'),'--image','candidate','--minio-binary','/unit-only','--expected-source-sha256','a'*64,'--expected-image-id','candidate','--exclusive-hosted-daemon','--case','scheduler']
            with patch.dict(os.environ,{'GITHUB_ACTIONS':'true','RUNNER_ENVIRONMENT':'github-hosted','RUNNER_TEMP':directory}),patch.object(module.os,'geteuid',return_value=0),patch.object(module.os,'sched_setaffinity'),patch.object(module,'fingerprint',return_value='a'*64),patch.object(module,'Engine') as engine,patch.object(module,'run_case',return_value={'case':'scheduler','verified':False,'failed':False}):
                engine.return_value.call.side_effect=response
                self.assertEqual(module.main(args),1)

    def test_guarded_lifecycle_can_run_an_explicit_resource_probe(self):
        from run_hosted_acceptance import run_platform
        from pathlib import Path
        from types import SimpleNamespace
        import tempfile
        events=[]
        class UnitProbe:
            def __init__(self,args):self.result={};events.append('init')
            def run(self):events.append('run')
            def cleanup(self):events.append('cleanup')
        with tempfile.TemporaryDirectory() as directory:
            args=SimpleNamespace(runtime=Path(directory)/'fresh',platform='resources',expected_source_sha256='a'*64,expected_image_id='owned-image')
            result=run_platform(args,probe_class=UnitProbe)
        self.assertFalse(result['failed'])
        self.assertEqual(events,['init','run','cleanup'])

    def scheduler_probe(self,root):
        from types import SimpleNamespace
        from unittest.mock import Mock
        module=self.module();cid='a'*64;run='b'*32
        probe=module.HostedResourceProbe.__new__(module.HostedResourceProbe)
        probe.root=root;probe.image='sha256:'+'c'*64;probe.daemon='unit-daemon';probe.result={}
        worker={'Id':cid,'Name':'/unit-worker','Image':probe.image,'runID':run,'state':'state','Config':{'Labels':{'bakabel.worker':'1','bakabel.run':run,'bakabel.daemon':probe.daemon},'Env':['PRIVATE-CANARY']},'State_at_first_sample':{'Status':'running','ExitCode':0,'OOMKilled':False}}
        probe.worker_records={cid:worker}
        probe.e=SimpleNamespace(inspect=Mock(return_value={**worker,'State':{'Status':'exited','Running':False,'ExitCode':137,'OOMKilled':False,'Error':'PRIVATE-CANARY'}}),call=Mock(return_value={'ID':probe.daemon}))
        return probe,cid,run

    def test_scheduler_cleanup_collects_current_owned_state_before_deletion(self):
        import json,tempfile
        from pathlib import Path
        from unittest.mock import patch
        module=self.module()
        with tempfile.TemporaryDirectory() as directory:
            probe,cid,run=self.scheduler_probe(Path(directory));calls=[]
            def cleanup(p):
                calls.append('cleanup')
                self.assertIn('scheduler_diagnostics',p.result)
                p.worker_records.clear()
            with patch.object(module.Probe,'cleanup',cleanup):probe.cleanup()
            self.assertEqual(calls,['cleanup'])
            self.assertEqual(probe.result['scheduler_diagnostics']['workers'],[{'container':cid,'run_id':run,'state_directory':'state','inspect_status':'observed','state':'exited','running':False,'exit_code':137,'oom_killed':False}])
            self.assertNotIn('PRIVATE-CANARY',json.dumps(probe.result))

    def test_scheduler_diagnostics_reject_unowned_identity_before_inspection(self):
        import copy,tempfile
        from pathlib import Path
        from unittest.mock import patch
        module=self.module()
        for field,value in (('Id','d'*64),('Image','other-image'),('Name',None),('runID','invalid-run'),('state','private'),('Config',{'Labels':{'bakabel.worker':'1','bakabel.run':'b'*32,'bakabel.daemon':'foreign'}})):
            with self.subTest(field=field),tempfile.TemporaryDirectory() as directory:
                probe,cid,_=self.scheduler_probe(Path(directory))
                probe.worker_records[cid]=copy.deepcopy(probe.worker_records[cid]);probe.worker_records[cid][field]=value
                with patch.object(module.Probe,'cleanup'):probe.cleanup()
                self.assertEqual(probe.result['scheduler_diagnostics']['workers'],[])
                probe.e.inspect.assert_not_called()
        with tempfile.TemporaryDirectory() as directory:
            probe,cid,_=self.scheduler_probe(Path(directory));probe.worker_records['not-an-id']=probe.worker_records.pop(cid)
            with patch.object(module.Probe,'cleanup'):probe.cleanup()
            self.assertEqual(probe.result['scheduler_diagnostics']['workers'],[])
            probe.e.inspect.assert_not_called()
        with tempfile.TemporaryDirectory() as directory:
            probe,_,_=self.scheduler_probe(Path(directory));probe.e.call.return_value={'ID':'foreign-daemon'}
            with patch.object(module.Probe,'cleanup'):probe.cleanup()
            self.assertEqual(probe.result['scheduler_diagnostics']['workers'],[])
            probe.e.inspect.assert_not_called()

    def test_scheduler_current_state_is_typed_bounded_not_first_sample_or_inferred(self):
        import json,tempfile
        from pathlib import Path
        from unittest.mock import patch
        module=self.module()
        for state in ({'Status':'PRIVATE-CANARY','Running':1,'ExitCode':True,'OOMKilled':0},
                      {'ExitCode':-1},{'ExitCode':256},{'ExitCode':1.5},{}):
            with self.subTest(state=state),tempfile.TemporaryDirectory() as directory:
                probe,cid,_=self.scheduler_probe(Path(directory));probe.e.inspect.return_value['State']=state
                with patch.object(module.Probe,'cleanup'):probe.cleanup()
                row=probe.result['scheduler_diagnostics']['workers'][0]
                self.assertEqual([row[k] for k in ('state','running','exit_code','oom_killed')],[None]*4)
                self.assertNotIn('PRIVATE-CANARY',json.dumps(probe.result))
        for outcome in ('missing','exception','wrong-name','wrong-image','wrong-run','wrong-daemon','wrong-worker-label','wrong-id'):
            with self.subTest(outcome=outcome),tempfile.TemporaryDirectory() as directory:
                probe,_,_=self.scheduler_probe(Path(directory))
                if outcome=='missing':probe.e.inspect.return_value=None
                elif outcome=='exception':probe.e.inspect.side_effect=OSError('PRIVATE-CANARY')
                elif outcome=='wrong-name':probe.e.inspect.return_value['Name']='/foreign'
                elif outcome=='wrong-image':probe.e.inspect.return_value['Image']='foreign'
                elif outcome=='wrong-id':probe.e.inspect.return_value['Id']='d'*64
                else:probe.e.inspect.return_value['Config']={'Labels':{'bakabel.worker':'0' if outcome=='wrong-worker-label' else '1','bakabel.run':'d'*32 if outcome=='wrong-run' else 'b'*32,'bakabel.daemon':'foreign' if outcome=='wrong-daemon' else 'unit-daemon'}}
                with patch.object(module.Probe,'cleanup'):probe.cleanup()
                row=probe.result['scheduler_diagnostics']['workers'][0]
                self.assertEqual(row['inspect_status'],'missing' if outcome=='missing' else 'unavailable')
                self.assertIsNone(row['exit_code']);self.assertIsNone(row['oom_killed'])

    def test_scheduler_durable_records_export_only_owned_run_status_phase(self):
        import json,tempfile
        from pathlib import Path
        from unittest.mock import patch
        module=self.module()
        with tempfile.TemporaryDirectory() as directory:
            probe,cid,run=self.scheduler_probe(Path(directory));state=probe.root/'state'
            (state/'workflow/output').mkdir(parents=True)
            owner={'runID':run,'workerContainerID':cid,'workerName':'unit-worker','daemonID':probe.daemon,'status':'active','phase':'exec_started','targetID':'PRIVATE-CANARY','execID':'PRIVATE-CANARY'}
            (state/'owner.json').write_text(json.dumps(owner))
            (state/'last-result.json').write_text(json.dumps({'runID':run,'status':'failed','error':'PRIVATE-CANARY'}))
            (state/'workflow/output/result.json').write_text(json.dumps({'runID':run,'status':'failed','targets':[{'targetID':'PRIVATE-CANARY','error':'PRIVATE-CANARY'}]}))
            probe.e.inspect.return_value=None
            with patch.object(module.Probe,'cleanup'):probe.cleanup()
            rows=probe.result['scheduler_diagnostics'].get('durable')
            self.assertEqual(rows,[{'state_directory':'state','record':'owner','run_id':run,'status':'active','phase':'exec_started'},
                                   {'state_directory':'state','record':'last_result','run_id':run,'status':'failed','phase':None},
                                   {'state_directory':'state','record':'workflow_output','run_id':run,'status':'failed','phase':None}])
            self.assertNotIn('PRIVATE-CANARY',json.dumps(probe.result))
            # An owner can be observed between the last sampler pass and cleanup.
            probe.worker_records={};probe.e.inspect.side_effect=None
            probe.e.inspect.return_value={'Id':cid,'Name':'/unit-worker','Image':probe.image,'Config':{'Labels':{'bakabel.worker':'1','bakabel.run':run,'bakabel.daemon':probe.daemon}},'State':{'Status':'running','Running':True}}
            with patch.object(module.Probe,'cleanup'):probe.cleanup()
            self.assertEqual(probe.result['scheduler_diagnostics']['workers'][0]['container'],cid)
            self.assertEqual(probe.result['scheduler_diagnostics'].get('durable'),rows)

    def test_scheduler_durable_records_reject_foreign_runs_identities_and_unsafe_paths(self):
        import json,tempfile
        from pathlib import Path
        from unittest.mock import patch
        module=self.module()
        for change in ({'runID':'d'*32},{'workerContainerID':'d'*64},{'workerName':'foreign'},{'daemonID':'foreign'}):
            with self.subTest(change=change),tempfile.TemporaryDirectory() as directory:
                probe,cid,run=self.scheduler_probe(Path(directory));state=probe.root/'state';state.mkdir()
                owner={'runID':run,'workerContainerID':cid,'workerName':'unit-worker','daemonID':probe.daemon,'status':'active','phase':'intent',**change}
                (state/'owner.json').write_text(json.dumps(owner))
                (state/'last-result.json').write_text(json.dumps({'runID':'d'*32,'status':'failed'}))
                with patch.object(module.Probe,'cleanup'):probe.cleanup()
                self.assertEqual(probe.result['scheduler_diagnostics'].get('durable'),[])
        for mode in ('unknown-status','oversize','symlink-file','symlink-directory','invalid-json','non-object'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as directory:
                probe,_,run=self.scheduler_probe(Path(directory));state=probe.root/'state';state.mkdir()
                path=state/'last-result.json';data={'runID':run,'status':'PRIVATE-CANARY','phase':'PRIVATE-CANARY'}
                if mode=='symlink-directory':state.rmdir();(probe.root/'private').mkdir();state.symlink_to(probe.root/'private',target_is_directory=True)
                if mode=='symlink-file':
                    target=probe.root/'private';target.write_text(json.dumps(data));path.symlink_to(target)
                else:path.write_text('x'*262145 if mode=='oversize' else '{' if mode=='invalid-json' else '[]' if mode=='non-object' else json.dumps(data))
                with patch.object(module.Probe,'cleanup'):probe.cleanup()
                rows=probe.result['scheduler_diagnostics'].get('durable')
                self.assertEqual(rows,[{'state_directory':'state','record':'last_result','run_id':run,'status':None,'phase':None}] if mode=='unknown-status' else [])
                self.assertNotIn('PRIVATE-CANARY',json.dumps(probe.result))

    def test_scheduler_event_window_starts_before_bound_probe_initialization(self):
        from unittest.mock import patch
        module=self.module();seen=[]
        def initialize(probe,args):seen.append(getattr(probe,'_events_since_ns',None))
        with patch.object(module.BoundEvidence,'__init__',initialize),patch('time.time_ns',return_value=123):
            module.HostedResourceProbe(object())
        self.assertEqual(seen,[123])

    def test_scheduler_events_use_bounded_window_exact_verified_removed_workers(self):
        import json,tempfile
        from pathlib import Path
        from unittest.mock import patch
        from urllib.parse import parse_qs,urlsplit
        module=self.module()
        with tempfile.TemporaryDirectory() as directory:
            probe,cid,_=self.scheduler_probe(Path(directory));probe._events_since_ns=1000000000;probe.e.inspect.return_value=None
            def event(action='die',container=cid,at=1500000000,code='137',kind='container'):
                return {'Type':kind,'Action':action,'timeNano':at,'Actor':{'ID':container,'Attributes':{'exitCode':code,'secret':'PRIVATE-CANARY'}}}
            events=[event(),event('oom',code='PRIVATE-CANARY'),event(container='d'*64),event('start'),event(at=999999999),event(at=2000000001),event(at=True),event(kind='image')]
            def call(method,path,**kwargs):
                if path=='/info':return {'ID':probe.daemon}
                query=parse_qs(urlsplit(path).query)
                self.assertEqual(query['since'],['1.000000000']);self.assertEqual(query['until'],['2.000000000'])
                self.assertEqual(json.loads(query['filters'][0]),{'type':['container'],'container':[cid],'event':['oom','die']})
                self.assertTrue(kwargs['raw']);return b'\n'.join(json.dumps(e).encode() for e in events)
            probe.e.call.side_effect=call
            with patch.object(module.Probe,'cleanup'),patch('time.time_ns',return_value=2000000000):probe.cleanup()
            observed=probe.result['scheduler_diagnostics'].get('events')
            self.assertEqual(observed,{'status':'observed','items':[{'container':cid,'event':'die','time_ns':1500000000,'exit_code':137},{'container':cid,'event':'oom','time_ns':1500000000,'exit_code':None}]})
            worker=probe.result['scheduler_diagnostics']['workers'][0]
            self.assertIsNone(worker['exit_code']);self.assertIsNone(worker['oom_killed'])
            self.assertNotIn('PRIVATE-CANARY',json.dumps(probe.result))

    def test_scheduler_event_failures_and_type_limits_stay_unavailable_not_zero(self):
        import json,tempfile
        from pathlib import Path
        from unittest.mock import patch
        module=self.module()
        for mode in ('exception','oversize','too-many','invalid-json','no-start','future-start','too-many-workers','codes'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as directory:
                probe,cid,_=self.scheduler_probe(Path(directory));probe._events_since_ns=1000000000
                if mode=='no-start':probe._events_since_ns=None
                if mode=='future-start':probe._events_since_ns=3000000000
                if mode=='too-many-workers':probe.worker_records={str(i):{} for i in range(129)}
                def call(method,path,**kwargs):
                    if path=='/info':return {'ID':probe.daemon}
                    if mode=='exception':raise OSError('PRIVATE-CANARY')
                    if mode=='oversize':return b'x'*262145
                    if mode=='too-many':return b'{}\n'*257
                    if mode=='invalid-json':return b'{'
                    return b'\n'.join(json.dumps({'Type':'container','Action':'die','timeNano':1500000000,'Actor':{'ID':cid,'Attributes':{'exitCode':code}}}).encode() for code in (True,137,'-1','256','1.5','PRIVATE-CANARY','0'))
                probe.e.call.side_effect=call
                with patch.object(module.Probe,'cleanup'),patch('time.time_ns',return_value=2000000000):probe.cleanup()
                events=probe.result['scheduler_diagnostics'].get('events')
                if mode=='codes':
                    self.assertIsNotNone(events)
                    self.assertEqual([r['exit_code'] for r in events['items']],[None]*6+[0])
                else:self.assertEqual(events,{'status':'unavailable','items':[]})
                self.assertNotIn('PRIVATE-CANARY',json.dumps(probe.result))

    def test_scheduler_failure_export_is_explicit_safe_and_failure_only(self):
        import json,tempfile
        from pathlib import Path
        from types import SimpleNamespace
        from unittest.mock import patch
        module=self.module();cid='a'*64;run='b'*32
        diagnostic={'workers':[{'container':cid,'run_id':run,'state_directory':'state','inspect_status':'observed','state':'exited','running':False,'exit_code':137,'oom_killed':False,'error':'PRIVATE-CANARY'}],
                    'durable':[{'state_directory':'state','record':'last_result','run_id':run,'status':'failed','phase':None,'error':'PRIVATE-CANARY'}],
                    'events':{'status':'observed','items':[{'container':cid,'event':'die','time_ns':123,'exit_code':137,'attributes':'PRIVATE-CANARY'}]},
                    'controller_completions':{'status':'observed','items':[{'state_directory':'state','run_id':run,'status':'failed','controller_failed':True,
                        'targets':[{'ordinal':0,'status':'unknown','failureCode':'backup','resticExitCode':1,'resticReason':'enospc','targetID':'PRIVATE-CANARY','error':'PRIVATE-CANARY'}]}]},'logs':'PRIVATE-CANARY'}
        for failure in ('run','verification',None):
            with self.subTest(failure=failure),tempfile.TemporaryDirectory() as directory:
                root=Path(directory);case=root/'scheduler';case.mkdir()
                (case/'receipt.json').write_text(json.dumps({'scheduler_diagnostics':diagnostic}))
                args=SimpleNamespace(runtime=root,source=root,expected_source_sha256='d'*64,expected_image_id='candidate')
                with patch.object(module,'run_platform',return_value={'failed':failure=='run'}),patch.object(module,'public_receipt',return_value={}),patch.object(module,'verify_cleanup',side_effect=ValueError('PRIVATE-CANARY') if failure=='verification' else None),patch.object(module,'summarize',return_value={}),patch.object(module.subprocess,'run',return_value=SimpleNamespace(returncode=0,stdout='',stderr='')),patch.object(module,'sha',return_value='e'*64):
                    public=module.run_case(args,'scheduler',None)
                self.assertNotIn('PRIVATE-CANARY',json.dumps(public))
                if failure:
                    self.assertIn('scheduler_diagnostics',public)
                    self.assertEqual(public['scheduler_diagnostics']['workers'][0]['exit_code'],137)
                    self.assertEqual(public['scheduler_diagnostics']['durable'][0]['status'],'failed')
                    self.assertEqual(public['scheduler_diagnostics']['events']['items'][0]['event'],'die')
                    completion=public['scheduler_diagnostics']['controller_completions']['items'][0]
                    self.assertTrue(completion['controller_failed'])
                    self.assertEqual(completion['targets'],[{'ordinal':0,'status':'unknown','failureCode':'backup','resticExitCode':1,'resticReason':'enospc'}])
                    self.assertFalse(public['verified']);self.assertTrue(public['failed'])
                else:self.assertNotIn('scheduler_diagnostics',public)
                self.assertEqual(json.loads((case/'public.json').read_text()),public)

    def test_scheduler_diagnostics_never_swallow_cleanup_or_sampler_failures(self):
        import json,tempfile
        from pathlib import Path
        from types import SimpleNamespace
        from unittest.mock import Mock,patch
        module=self.module();calls=[];test=self
        class Synthetic(module.HostedResourceProbe):
            def __init__(self,args):
                args.runtime.mkdir();p,_,_=test.scheduler_probe(args.runtime)
                self.__dict__.update(p.__dict__);self.values=[];self.stopped=Mock();self.thread=Mock()
                test.scheduler_stdout(self,OSError('PRIVATE-CANARY'))
                (self.root/'private').mkdir();(self.root/'private'/'credential').write_text('PRIVATE-CANARY')
            def run(self):
                self.result['sampler_errors']=[{'type':'OSError','frames':[]}]
                raise RuntimeError('PRIVATE-CANARY')
        def cleanup(probe):
            calls.append('cleanup')
            self.assertIn('scheduler_diagnostics',probe.result)
            raise OSError('PRIVATE-CANARY')
        with tempfile.TemporaryDirectory() as directory:
            args=SimpleNamespace(runtime=Path(directory)/'fresh',platform='resources-scheduler',expected_source_sha256='d'*64,expected_image_id='candidate')
            with patch.object(module.Probe,'cleanup',cleanup):row=module.run_platform(args,probe_class=Synthetic)
            raw=json.loads((args.runtime/'receipt.json').read_text())
            self.assertTrue(row['failed']);self.assertEqual(calls,['cleanup'])
            self.assertEqual(raw['error'],'RuntimeError');self.assertEqual(raw['cleanup_error'],'OSError')
            self.assertEqual(raw['sampler_errors'],[{'type':'OSError','frames':[]}])
            self.assertTrue((args.runtime/'private/credential').exists())
            self.assertNotIn('PRIVATE-CANARY',json.dumps(raw['scheduler_diagnostics']))
        with tempfile.TemporaryDirectory() as directory:
            probe,_,_=self.scheduler_probe(Path(directory))
            with patch.object(probe,'collect_scheduler_diagnostics',side_effect=OSError('PRIVATE-CANARY')),patch.object(module.Probe,'cleanup') as base:probe.cleanup()
            base.assert_called_once_with()

    def scheduler_stdout(self,probe,payload,framed=False):
        """Synthetic Engine bytes only; no live containers or daemon access."""
        import copy,struct
        from urllib.parse import parse_qs,urlsplit
        cid='e'*64;probe.prefix='unit-probe';name=probe.prefix+'-serve-123abc'
        probe.containers={cid:name};probe.roles={cid:'scheduler'}
        scheduler={'Id':cid,'Name':'/'+name,'Image':probe.image,
                   'Config':{'Entrypoint':['/usr/local/bin/bakabel'],'Cmd':['--config','/config.yaml','serve'],
                             'Labels':{'probe.bakabel.owner':probe.prefix,'bakabel.installation':probe.prefix,'bakabel.role':'scheduler'},'Env':['PRIVATE-CANARY']},
                   'Mounts':[{'Type':'bind','Source':str(probe.root/'state'),'Destination':'/state'}]}
        worker=copy.deepcopy(probe.e.inspect.return_value)
        probe.e.inspect.side_effect=lambda target,**kw:copy.deepcopy(scheduler if target==cid else worker)
        queries=[]
        def call(method,path,**kwargs):
            if path=='/info':return {'ID':probe.daemon}
            self.assertEqual(method,'GET');self.assertEqual(urlsplit(path).path,'/containers/'+cid+'/logs')
            query=parse_qs(urlsplit(path).query);queries.append(query)
            self.assertEqual(query,{'stdout':['true'],'stderr':['false'],'follow':['false'],'timestamps':['false'],'tail':['256']})
            self.assertTrue(kwargs['raw'])
            if isinstance(payload,Exception):raise payload
            return struct.pack('>BxxxI',1,len(payload))+payload if isinstance(payload,bytes) and not framed else payload
        probe.e.call.side_effect=call
        return scheduler,queries

    def test_scheduler_stdout_preserves_failed_first_run_after_replacement_deletes_output(self):
        import copy,json,tempfile
        from pathlib import Path
        from unittest.mock import patch
        module=self.module()
        with tempfile.TemporaryDirectory() as directory:
            probe,cid,run=self.scheduler_probe(Path(directory));next_cid='d'*64;next_run='f'*32
            replacement=copy.deepcopy(probe.worker_records[cid]);replacement.update(Id=next_cid,Name='/replacement',runID=next_run)
            replacement['Config']['Labels']['bakabel.run']=next_run;probe.worker_records[next_cid]=replacement
            state=probe.root/'state';(state/'workflow/output').mkdir(parents=True)
            output=state/'workflow/output/result.json';output.write_text(json.dumps({'runID':run,'status':'failed'}));output.unlink()
            (state/'last-result.json').write_text(json.dumps({'runID':next_run,'status':'success'}))
            event={'event':'run_finished','failed':True,'result':{'runID':run,'status':'failed','targets':[
                {'targetID':'PRIVATE-CANARY','status':'unknown','failureCode':'backup','resticExitCode':1,'resticReason':'enospc','error':'PRIVATE-CANARY'}]},'error':'PRIVATE-CANARY'}
            _,queries=self.scheduler_stdout(probe,(json.dumps(event)+'\n'+json.dumps({'event':'run_finished','result':{'runID':next_run,'status':'complete','targets':[]}})+'\n').encode())
            def cleanup(p):
                self.assertTrue(queries);self.assertFalse(output.exists())
                p.worker_records.clear()
            with patch.object(module.Probe,'cleanup',cleanup):probe.cleanup()
            public=module.public_scheduler_diagnostics(probe.result)
            completion=public.get('controller_completions',{})
            self.assertEqual(completion.get('status'),'observed')
            self.assertEqual(completion['items'],[
                {'state_directory':'state','run_id':run,'status':'failed','controller_failed':True,'targets':[
                    {'ordinal':0,'status':'unknown','failureCode':'backup','resticExitCode':1,'resticReason':'enospc'}]},
                {'state_directory':'state','run_id':next_run,'status':'complete','controller_failed':False,'targets':[]}])
            self.assertEqual(public['durable'],[{'state_directory':'state','record':'last_result','run_id':next_run,'status':'success','phase':None}])
            self.assertNotIn('PRIVATE-CANARY',json.dumps(probe.result));self.assertNotIn('PRIVATE-CANARY',json.dumps(public))

    def test_scheduler_stdout_mixed_lines_and_split_frames_keep_only_valid_stdout(self):
        import json,struct,tempfile
        from pathlib import Path
        from unittest.mock import patch
        module=self.module()
        with tempfile.TemporaryDirectory() as directory:
            probe,_,run=self.scheduler_probe(Path(directory))
            event={'event':'run_finished','failed':True,'result':{'runID':run,'status':'failed','targets':[]}}
            valid=json.dumps(event).encode()+b'\n'
            text=b'PRIVATE-CANARY\n{\n[]\nnull\n42\n'+json.dumps({'event':'tick'}).encode()+b'\n'+valid+valid
            frame=lambda stream,data:struct.pack('>BxxxI',stream,len(data))+data
            stderr=json.dumps({**event,'failed':False}).encode()+b'\n'
            self.scheduler_stdout(probe,frame(1,text[:31])+frame(2,stderr)+frame(1,text[31:]),framed=True)
            with patch.object(module.Probe,'cleanup'):probe.cleanup()
            observed=module.public_scheduler_diagnostics(probe.result)['controller_completions']
            self.assertEqual(observed,{'status':'observed','items':[{'state_directory':'state','run_id':run,'status':'failed','controller_failed':True,'targets':[]}]})
            self.assertNotIn('PRIVATE-CANARY',json.dumps(probe.result))

    def test_scheduler_stdout_missing_oversized_and_invalid_records_are_unavailable(self):
        import json,struct,tempfile
        from pathlib import Path
        from unittest.mock import patch
        module=self.module()
        modes=('missing','exception','empty','oversize','too-many-lines','bad-json','bad-utf8',
               'truncated-frame','trailing-header','reserved-header','unknown-stream','tty-text',
               'no-result','bad-result','no-targets','null-targets','bad-target','too-many-targets')
        for mode in modes:
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as directory:
                probe,_,run=self.scheduler_probe(Path(directory))
                value={'runID':run,'status':'complete','targets':[]};event={'event':'run_finished','result':value}
                if mode=='no-result':event.pop('result')
                if mode=='bad-result':event['result']=[]
                if mode=='no-targets':value.pop('targets')
                if mode=='null-targets':value['targets']=None
                if mode=='bad-target':value['targets']=[None]
                if mode=='too-many-targets':value['targets']=[{}]*129
                valid=json.dumps(event).encode()+b'\n';frame=struct.pack('>BxxxI',1,len(valid))+valid
                payload={'missing':None,'exception':OSError('PRIVATE-CANARY'),'empty':b'',
                         'oversize':valid+b' '*262145,'too-many-lines':valid+b'\n'*256,'bad-json':b'{',
                         'bad-utf8':valid+b'\xff','truncated-frame':frame[:-1],
                         'trailing-header':frame+b'\x01','reserved-header':b'\x01\x00\x01\x00'+frame[4:],
                         'unknown-stream':b'\x03'+frame[1:],'tty-text':valid}.get(mode,valid)
                self.scheduler_stdout(probe,payload,framed=mode in ('truncated-frame','trailing-header','reserved-header','unknown-stream','tty-text'))
                with patch.object(module.Probe,'cleanup') as cleanup:probe.cleanup()
                cleanup.assert_called_once_with()
                expected={'status':'unavailable','items':[]}
                self.assertEqual(probe.result['scheduler_diagnostics']['controller_completions'],expected)
                self.assertEqual(module.public_scheduler_diagnostics(probe.result)['controller_completions'],expected)
                self.assertNotIn('PRIVATE-CANARY',json.dumps(probe.result))

    def test_scheduler_stdout_queries_only_exact_owned_serve_identity_and_verified_run(self):
        import json,tempfile
        from pathlib import Path
        from unittest.mock import patch
        module=self.module()
        modes=('id','name','image','owner','installation','role-label','command','entrypoint','tty',
               'role-record','name-record','state-mount','foreign-state','daemon','worker-image','worker-run','foreign-run')
        for mode in modes:
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as directory:
                probe,cid,run=self.scheduler_probe(Path(directory))
                event={'event':'run_finished','failed':True,'result':{'runID':'f'*32 if mode=='foreign-run' else run,'status':'failed','targets':[]}}
                scheduler,queries=self.scheduler_stdout(probe,json.dumps(event).encode())
                if mode=='id':scheduler['Id']='d'*64
                if mode=='name':scheduler['Name']='/foreign'
                if mode=='image':scheduler['Image']='foreign'
                if mode in ('owner','installation','role-label'):
                    key={'owner':'probe.bakabel.owner','installation':'bakabel.installation','role-label':'bakabel.role'}[mode]
                    scheduler['Config']['Labels'][key]='foreign'
                if mode=='command':scheduler['Config']['Cmd']=['--config','/config.yaml','run']
                if mode=='entrypoint':scheduler['Config']['Entrypoint']=['sh','-c']
                if mode=='tty':scheduler['Config']['Tty']=True
                if mode=='role-record':probe.roles['e'*64]='controller'
                if mode=='name-record':probe.containers['e'*64]='foreign'
                if mode=='state-mount':scheduler['Mounts'][0]['Source']=str(probe.root/'private')
                if mode=='foreign-state':scheduler['Mounts'][0]['Source']=str(probe.root/'fresh-state')
                if mode=='worker-image':probe.worker_records[cid]['Image']='foreign'
                if mode=='worker-run':probe.worker_records[cid]['Config']['Labels']['bakabel.run']='f'*32
                if mode=='daemon':probe.e.call.side_effect=lambda *a,**kw:{'ID':'foreign'}
                with patch.object(module.Probe,'cleanup'):probe.cleanup()
                self.assertEqual(len(queries),1 if mode=='foreign-run' else 0)
                self.assertEqual(probe.result['scheduler_diagnostics']['controller_completions'],{'status':'unavailable','items':[]})

    def test_scheduler_stdout_and_public_reprojection_enforce_types_finite_codes_and_canaries(self):
        import copy,json,tempfile
        from pathlib import Path
        from unittest.mock import patch
        module=self.module()
        stages=('file_preflight','list_before','backup','list_after','source_verification','tag','final_readback','metadata_readback')
        reasons=('enospc','permission','backend','unknown')
        for failed in (True,False,'PRIVATE-CANARY',1,None,[],{}):
            with self.subTest(failed=failed),tempfile.TemporaryDirectory() as directory:
                probe,_,run=self.scheduler_probe(Path(directory));targets=[];expected=[]
                for index,stage in enumerate(stages):
                    target={'status':('complete','restored','partial','unknown')[index%4],'failureCode':stage,
                            'resticExitCode':0 if index%2==0 else 255,'resticReason':reasons[index%4]}
                    targets.append({**target,'targetID':'PRIVATE-CANARY','error':'PRIVATE-CANARY','Env':['PRIVATE-CANARY']})
                    expected.append({'ordinal':index,**target})
                for bad in ('PRIVATE-CANARY',True,False,1.5,-1,256,float('nan'),float('inf'),[],{},None):
                    targets.append({key:bad for key in ('status','failureCode','resticExitCode','resticReason')})
                    expected.append({'ordinal':len(expected),'status':None,'failureCode':None,'resticExitCode':None,'resticReason':None})
                event={'event':'run_finished','failed':failed,'result':{'runID':run,'status':'PRIVATE-CANARY','targets':targets},'logs':'PRIVATE-CANARY'}
                self.scheduler_stdout(probe,json.dumps(event).encode())
                with patch.object(module.Probe,'cleanup'):probe.cleanup()
                completion=probe.result['scheduler_diagnostics']['controller_completions']['items'][0]
                self.assertIsNone(completion['status']);self.assertEqual(completion['targets'],expected)
                self.assertEqual(completion['controller_failed'],failed if type(failed) is bool else None)
                self.assertNotIn('PRIVATE-CANARY',json.dumps(probe.result))
                # Re-project a poisoned private receipt too, not only our own collector output.
                poisoned=copy.deepcopy(probe.result)
                row=poisoned['scheduler_diagnostics']['controller_completions']['items'][0]
                row.update(status='PRIVATE-CANARY',controller_failed=failed,targets=targets,error='PRIVATE-CANARY')
                public=module.public_scheduler_diagnostics(poisoned)
                self.assertEqual(public['controller_completions']['items'][0],completion)
                self.assertNotIn('PRIVATE-CANARY',json.dumps(public))

    def test_scheduler_public_completions_require_bounded_typed_owned_records(self):
        import copy
        module=self.module();cid='a'*64;run='b'*32
        row={'state_directory':'state','run_id':run,'status':'failed','controller_failed':True,
             'targets':[{'status':'unknown','failureCode':'backup','resticExitCode':1,'resticReason':'enospc'}]}
        base={'scheduler_diagnostics':{'workers':[{'container':cid,'run_id':run,'state_directory':'state'}],
              'controller_completions':{'status':'observed','items':[row]}}}
        for mode in ('foreign-run','foreign-state','bad-run-type','bad-state-type','oversized','bad-items','no-targets','bad-targets'):
            with self.subTest(mode=mode):
                raw=copy.deepcopy(base);section=raw['scheduler_diagnostics']['controller_completions'];item=section['items'][0]
                if mode=='foreign-run':item['run_id']='f'*32
                if mode=='foreign-state':item['state_directory']='fresh-state'
                if mode=='bad-run-type':item['run_id']=[]
                if mode=='bad-state-type':item['state_directory']={}
                if mode=='oversized':section['items']*=257
                if mode=='bad-items':section['items']='PRIVATE-CANARY'
                if mode=='no-targets':item.pop('targets')
                if mode=='bad-targets':item['targets']=[None]
                self.assertEqual(module.public_scheduler_diagnostics(raw)['controller_completions'],{'status':'unavailable','items':[]})

    def test_scheduler_stdout_container_tracking_is_bounded_before_inspection(self):
        import json,tempfile
        from pathlib import Path
        from unittest.mock import patch
        module=self.module()
        for mode in ('bad-id','too-many-containers'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as directory:
                probe,_,run=self.scheduler_probe(Path(directory))
                _,queries=self.scheduler_stdout(probe,json.dumps({'event':'run_finished','result':{'runID':run,'status':'complete','targets':[]}}).encode())
                if mode=='bad-id':
                    probe.containers={'not-an-id':next(iter(probe.containers.values()))};probe.roles={'not-an-id':'scheduler'}
                else:probe.containers.update({str(i):'synthetic' for i in range(128)})
                with patch.object(module.Probe,'cleanup'):probe.cleanup()
                self.assertEqual(queries,[])
                self.assertEqual([c.args[0] for c in probe.e.inspect.call_args_list],['a'*64])
                self.assertEqual(probe.result['scheduler_diagnostics']['controller_completions'],{'status':'unavailable','items':[]})

    def test_scheduler_controller_failure_is_not_a_worker_failure_receipt(self):
        import json,tempfile
        from pathlib import Path
        from unittest.mock import patch
        module=self.module()
        with tempfile.TemporaryDirectory() as directory:
            probe,_,run=self.scheduler_probe(Path(directory))
            probe.e.inspect.return_value['State'].update(ExitCode=0,OOMKilled=False)
            output=probe.root/'state/workflow/output/result.json';output.parent.mkdir(parents=True)
            output.write_text(json.dumps({'runID':run,'status':'complete','targets':[{'targetID':'PRIVATE-CANARY','status':'complete'}]}))
            self.scheduler_stdout(probe,json.dumps({'event':'run_finished','failed':True,'result':{'runID':run,'status':'failed','targets':[
                {'targetID':'PRIVATE-CANARY','status':'unknown','error':'PRIVATE-CANARY'}]}}).encode())
            with patch.object(module.Probe,'cleanup'):probe.cleanup()
            public=module.public_scheduler_diagnostics(probe.result)
            self.assertEqual(public['workers'][0]['exit_code'],0)
            self.assertEqual(public['durable'],[{'state_directory':'state','record':'workflow_output','run_id':run,'status':'complete','phase':None}])
            controller=public['controller_completions']['items'][0]
            self.assertEqual(controller['status'],'failed');self.assertTrue(controller['controller_failed'])
            self.assertEqual(controller['targets'],[{'ordinal':0,'status':'unknown','failureCode':None,'resticExitCode':None,'resticReason':None}])
            # A controller can synthesize a failed result; never relabel it worker-published.
            self.assertNotIn('targets',public['durable'][0]);self.assertNotIn('PRIVATE-CANARY',json.dumps(public))

    def test_scheduler_stdout_multiple_schedulers_preserve_first_evidence_with_bounded_items(self):
        import copy,json,tempfile
        from pathlib import Path
        from unittest.mock import patch
        module=self.module()
        for first_missing in (False,True):
            with self.subTest(first_missing=first_missing),tempfile.TemporaryDirectory() as directory:
                probe,_,run=self.scheduler_probe(Path(directory))
                events=[{'event':'run_finished','failed':True,'result':{'runID':run,'status':'failed','targets':[
                    {'status':'unknown','failureCode':'backup','resticExitCode':code,'resticReason':'unknown'}]}} for code in range(256)]
                payload=b'\n'.join(json.dumps(e).encode() for e in events)
                scheduler,queries=self.scheduler_stdout(probe,payload)
                second=copy.deepcopy(scheduler);second['Id']='f'*64;second['Name']='/unit-probe-serve-456def'
                probe.containers[second['Id']]=second['Name'][1:];probe.roles[second['Id']]='scheduler'
                inspect=probe.e.inspect.side_effect;call=probe.e.call.side_effect
                probe.e.inspect.side_effect=lambda cid,**kw:second if cid==second['Id'] else inspect(cid,**kw)
                def response(method,path,**kwargs):
                    if '/'+scheduler['Id']+'/logs' in path:
                        if first_missing:raise OSError('PRIVATE-CANARY')
                        return call(method,path,**kwargs)
                    if '/'+second['Id']+'/logs' in path:
                        # Same run can be reported after scheduler adoption; keep provenance separate.
                        raw=json.dumps({**events[0],'failed':False}).encode()
                        return bytes([1,0,0,0])+len(raw).to_bytes(4,'big')+raw
                    return call(method,path,**kwargs)
                probe.e.call.side_effect=response
                with patch.object(module.Probe,'cleanup'):probe.cleanup()
                section=probe.result['scheduler_diagnostics']['controller_completions']
                self.assertEqual(section['status'],'observed');self.assertEqual(len(section['items']),1 if first_missing else 256)
                self.assertEqual(section['items'][0]['controller_failed'],not first_missing)
                self.assertEqual(module.public_scheduler_diagnostics(probe.result)['controller_completions'],section)

    def module(self):
        try:module=importlib.import_module('run_hosted_resources')
        except ModuleNotFoundError:module=None
        self.assertIsNotNone(module,'extended acceptance must replay current resource/failure gates on the hosted VM')
        return module

    def test_required_cases_include_lifecycle_and_real_fault_variants(self):
        module=self.module()
        self.assertEqual(module.CASES,('scheduler','oom-active','enospc','oom'))
        self.assertEqual(module.case_settings('oom-active'),{'mode':'oom-active','memory_mib':16})
        self.assertEqual(module.case_settings('oom'),{'mode':'oom','memory_mib':32})
        self.assertEqual(module.case_settings('enospc'),{'mode':'enospc','memory_mib':32})
        with self.assertRaises(ValueError):module.case_settings('invented')

    def test_public_measurements_are_numeric_not_arbitrary_diagnostics(self):
        module=self.module()
        secret='do-not-export-exception-or-sql-text'
        summary={'idle':{'seconds_between_samples':20,'cgroup_cpu_seconds_delta':0,'debug':secret},'containers':[{'role':'worker','container':'owned','process_RSS_sum_peak_bytes':2048,'cgroup_memory_peak_bytes':4096,'debug':secret}],'image':{'oci_compressed_layer_bytes':100,'debug':secret},'source_pg_first_dump_window':{'wal_bytes':12,'database_bytes_before':512,'sql':secret},'target_pg_restore_window':{'wal_bytes':100,'sql':secret},'error':secret,'commands':[secret]}
        public=module.public_measurements(summary)
        import json
        self.assertNotIn(secret,json.dumps(public))
        self.assertEqual(public['idle']['seconds_between_samples'],20)
        self.assertEqual(public['containers'][0]['cgroup_memory_peak_bytes'],4096)
        self.assertEqual(public['source_pg_first_dump_window']['wal_bytes'],12)
        self.assertEqual(public['target_pg_restore_window']['wal_bytes'],100)

    def early_oom_receipt(self,prebinding=False):
        """Offline input matching Record JSON and observe_fast's inspect projection.

        workflow.go saves active intent before CreateWorker, then the exact ID,
        then start authorization. Record's omitempty omits both zero values.
        These are source-derived fixtures, not recovered historical owner rows.
        """
        run='b'*32;cid='a'*64;name='bakabel-worker-'+run;daemon='unit-daemon'
        intent={'runID':run,'daemonID':daemon,'workerName':name,'phase':'intent','status':'active'}
        bound={**intent,'workerContainerID':cid}
        owners=[intent,bound,{**bound,'workerStartAuthorized':True}] if prebinding else [bound]
        return {'mode':'oom','daemon':daemon,'early_oom_phase':'intent-before-source-exec',
            'failure_terminal_proof':{'status':'failed','complete':False,'owner_released':True,'worker_terminal':True,
                'source_never_started':True,'session_count':0,'last_result':{'runID':run,'status':'failed'}},
            'worker_last_inspect':{'Id':cid,'Name':'/'+name,'Image':'candidate',
                'State':{'Status':'exited','Running':False,'Pid':0,'ExitCode':137,'OOMKilled':True},
                'HostConfig':{'Memory':33554432,'NanoCpus':2000000000}},
            'owner_history':[{'owner':owner} for owner in owners],
            'failure_cgroup_samples':[{'cpu.max':'200000 100000','memory.max':'33554432','memory.events':'oom_kill 1'}],
            'source_exec_events':[],'source_after':{'identity_unchanged':True,'read_write_ok':True},'snapshots_after_failure':[]}

    def test_early_oom_accepts_serialized_intent_before_worker_create(self):
        module=self.module()
        control=self.early_oom_receipt()
        raw=self.early_oom_receipt(prebinding=True)
        self.assertNotIn('workerContainerID',raw['owner_history'][0]['owner'])
        self.assertNotIn('workerStartAuthorized',raw['owner_history'][0]['owner'])
        # Only the observed history differs: same exact terminal OOM and limits.
        self.assertEqual({k:v for k,v in raw.items() if k!='owner_history'},
                         {k:v for k,v in control.items() if k!='owner_history'})
        self.assertTrue(module.verify_early_oom(control,'candidate')['verified'])
        self.assertTrue(module.verify_early_oom(raw,'candidate')['verified'])
        # Sampling may miss intermediate saves or retain repeated checkpoints;
        # neither a prebinding sample nor the intermediate ID save is mandatory.
        for indices in ((0,2),(1,2),(2,),(0,0,1,1,2)):
            sampled={**raw,'owner_history':[raw['owner_history'][i] for i in indices]}
            with self.subTest(indices=indices):self.assertTrue(module.verify_early_oom(sampled,'candidate')['verified'])

    def test_early_oom_owner_history_requires_an_exact_bound_record(self):
        import copy
        module=self.module();raw=self.early_oom_receipt(prebinding=True)
        for history in ([],raw['owner_history'][:1],[raw['owner_history'][0]]*2):
            with self.subTest(history=history),self.assertRaises(AssertionError):
                module.verify_early_oom({**raw,'owner_history':copy.deepcopy(history)},'candidate')

    def test_early_oom_owner_history_rejects_foreign_identities_in_every_state(self):
        module=self.module()
        for index in range(3):
            for key in ('runID','daemonID','workerName','workerContainerID'):
                raw=self.early_oom_receipt(prebinding=True)
                raw['owner_history'][index]['owner'][key]='foreign'
                with self.subTest(index=index,key=key),self.assertRaises(AssertionError):module.verify_early_oom(raw,'candidate')
        # Agreement between owner rows alone is not independent daemon/name proof.
        for key in ('daemonID','workerName'):
            raw=self.early_oom_receipt(prebinding=True)
            for row in raw['owner_history']:row['owner'][key]='foreign'
            with self.subTest(all_rows=key),self.assertRaises(AssertionError):module.verify_early_oom(raw,'candidate')

    def test_early_oom_owner_required_fields_fail_closed_without_key_errors(self):
        module=self.module()
        for index in range(3):
            for key in ('runID','daemonID','workerName','phase','status'):
                for value in ('missing',None,'',[],False):
                    raw=self.early_oom_receipt(prebinding=True);owner=raw['owner_history'][index]['owner']
                    if value=='missing':del owner[key]
                    else:owner[key]=value
                    with self.subTest(index=index,key=key,value=value),self.assertRaises(AssertionError):module.verify_early_oom(raw,'candidate')
        for key,value in (('Phase','intent'),('workercontainerid','foreign'),('unexpected','value')):
            raw=self.early_oom_receipt(prebinding=True);raw['owner_history'][0]['owner'][key]=value
            with self.subTest(unsupported=key),self.assertRaises(AssertionError):module.verify_early_oom(raw,'candidate')
        for history in (None,{},[None],[{}],[{'owner':None}],[{'owner':[]}]):
            raw=self.early_oom_receipt(prebinding=True);raw['owner_history']=history
            with self.subTest(history=history),self.assertRaises(AssertionError):module.verify_early_oom(raw,'candidate')

    def test_early_oom_owner_history_rejects_any_source_exec_or_phase_gap(self):
        module=self.module()
        for index in range(3):
            for key,value in (('execID','exec'),('sourceContainerID','source'),('sourceStartedAt','2026-01-01T00:00:00Z'),
                              ('targetID','target'),('execKind','dump'),('execKind','restore'),('importRunID','import'),
                              ('phase','creating_exec'),('phase','exec_created'),('phase','exec_started'),
                              ('phase','quarantine'),('status','blocked')):
                raw=self.early_oom_receipt(prebinding=True);raw['owner_history'][index]['owner'][key]=value
                with self.subTest(index=index,key=key,value=value),self.assertRaises(AssertionError):module.verify_early_oom(raw,'candidate')
            for key in ('execID','sourceContainerID','sourceStartedAt','targetID','execKind','importRunID'):
                for value in (None,False,0,[]):
                    raw=self.early_oom_receipt(prebinding=True);raw['owner_history'][index]['owner'][key]=value
                    with self.subTest(index=index,key=key,value=value),self.assertRaises(AssertionError):module.verify_early_oom(raw,'candidate')

    def test_early_oom_owner_history_rejects_authorization_and_identity_reversion(self):
        import copy
        module=self.module()
        for value in (True,None,1,'true',[]):
            raw=self.early_oom_receipt(prebinding=True)
            raw['owner_history'][0]['owner']['workerStartAuthorized']=value
            with self.subTest(prebinding_start=value),self.assertRaises(AssertionError):module.verify_early_oom(raw,'candidate')
        for index in (1,2):
            for key,value in (('workerContainerID',None),('workerContainerID',0),('workerContainerID',[]),
                              ('workerStartAuthorized',None),('workerStartAuthorized',1),('workerStartAuthorized','false')):
                raw=self.early_oom_receipt(prebinding=True);raw['owner_history'][index]['owner'][key]=value
                with self.subTest(index=index,key=key,value=value),self.assertRaises(AssertionError):module.verify_early_oom(raw,'candidate')
        for indices in ((1,0),(0,1,0),(0,1,2,1),(0,1,2,0,2)):
            raw=self.early_oom_receipt(prebinding=True)
            raw['owner_history']=[copy.deepcopy(raw['owner_history'][i]) for i in indices]
            with self.subTest(indices=indices),self.assertRaises(AssertionError):module.verify_early_oom(raw,'candidate')
        raw=self.early_oom_receipt(prebinding=True)
        raw['owner_history'].insert(2,{'owner':{**raw['owner_history'][1]['owner'],'workerContainerID':'different-worker'}})
        with self.assertRaises(AssertionError):module.verify_early_oom(raw,'candidate')

    def test_early_oom_missing_or_nonterminal_worker_proof_cannot_be_accepted(self):
        module=self.module()
        for key in ('worker_last_inspect','daemon'):
            raw=self.early_oom_receipt(prebinding=True);del raw[key]
            with self.subTest(missing=key),self.assertRaises(AssertionError):module.verify_early_oom(raw,'candidate')
        for key in ('Id','Name','State'):
            raw=self.early_oom_receipt(prebinding=True);del raw['worker_last_inspect'][key]
            with self.subTest(missing_worker=key),self.assertRaises(AssertionError):module.verify_early_oom(raw,'candidate')
        for key,value in (('Running',True),('Running',None),('Pid',12),('Pid',None),('OOMKilled',False),('OOMKilled',1)):
            raw=self.early_oom_receipt(prebinding=True);raw['worker_last_inspect']['State'][key]=value
            with self.subTest(key=key,value=value),self.assertRaises(AssertionError):module.verify_early_oom(raw,'candidate')
        for key in ('Running','Pid','OOMKilled'):
            raw=self.early_oom_receipt(prebinding=True);del raw['worker_last_inspect']['State'][key]
            with self.subTest(missing_state=key),self.assertRaises(AssertionError):module.verify_early_oom(raw,'candidate')
        for key in ('worker_terminal','owner_released','source_never_started'):
            raw=self.early_oom_receipt(prebinding=True);raw['failure_terminal_proof'][key]=False
            with self.subTest(proof=key),self.assertRaises(AssertionError):module.verify_early_oom(raw,'candidate')

    def test_early_oom_is_failure_safety_not_active_export_support(self):
        module=self.module()
        self.assertTrue(hasattr(module,'verify_early_oom'),'configured OOM requires its own exact before-source proof')
        import copy
        raw=self.early_oom_receipt()
        self.assertTrue(module.verify_early_oom(raw,'candidate')['before_source_only'])
        for key,value in (('early_oom_phase','exec_started'),('source_exec_events',[{'action':'exec_start: pg_dump -Fc'}]),('snapshots_after_failure',[{'id':'not-empty'}])):
            with self.subTest(key=key),self.assertRaises(AssertionError):module.verify_early_oom({**raw,key:value},'candidate')
        changed=copy.deepcopy(raw);changed['worker_last_inspect']['State']['OOMKilled']=False
        with self.assertRaises(AssertionError):module.verify_early_oom(changed,'candidate')

    def test_local_invocation_refuses_before_engine_is_opened(self):
        module=self.module()
        self.assertTrue(hasattr(module,'main'),'hosted resource entrypoint must enforce the VM boundary')
        from unittest.mock import patch
        args=['--socket','/never-opened','--source','/unused','--runtime','/unused','--image','candidate','--minio-binary','/unused','--expected-source-sha256','a'*64,'--expected-image-id','candidate','--exclusive-hosted-daemon']
        with patch.object(module,'Engine') as engine,patch.object(module.os,'geteuid',return_value=1000),self.assertRaises(SystemExit) as caught:module.main(args)
        self.assertEqual(caught.exception.code,2)
        engine.assert_not_called()


if __name__=='__main__':unittest.main()
