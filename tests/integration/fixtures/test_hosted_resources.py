"""Offline contracts for hosted resource replay, never fabricated runtime evidence."""
import importlib
import unittest


class HostedResources(unittest.TestCase):
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
                    'events':{'status':'observed','items':[{'container':cid,'event':'die','time_ns':123,'exit_code':137,'attributes':'PRIVATE-CANARY'}]},'logs':'PRIVATE-CANARY'}
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

    def test_early_oom_is_failure_safety_not_active_export_support(self):
        module=self.module()
        self.assertTrue(hasattr(module,'verify_early_oom'),'configured OOM requires its own exact before-source proof')
        import copy
        raw={'mode':'oom','early_oom_phase':'intent-before-source-exec','failure_terminal_proof':{'status':'failed','complete':False,'owner_released':True,'worker_terminal':True,'source_never_started':True,'session_count':0,'last_result':{'runID':'owned','status':'failed'}},'worker_last_inspect':{'Id':'worker','Image':'candidate','State':{'OOMKilled':True},'HostConfig':{'Memory':33554432,'NanoCpus':2000000000}},'owner_history':[{'owner':{'runID':'owned','phase':'intent','workerContainerID':'worker'}}],'failure_cgroup_samples':[{'cpu.max':'200000 100000','memory.max':'33554432','memory.events':'oom_kill 1'}],'source_exec_events':[],'source_after':{'identity_unchanged':True,'read_write_ok':True},'snapshots_after_failure':[]}
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
