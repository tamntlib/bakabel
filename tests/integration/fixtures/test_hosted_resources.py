"""Offline contracts for hosted resource replay, never fabricated runtime evidence."""
import importlib
import unittest


class HostedResources(unittest.TestCase):
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
