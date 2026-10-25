"""Offline safety contracts; no Docker/socket or hosted identity is fabricated live."""
import importlib
import copy
from pathlib import Path
import tempfile
import unittest

class HostedPreflight(unittest.TestCase):
    def module(self):
        try:
            module=importlib.import_module('run_hosted_acceptance')
        except ModuleNotFoundError:
            module=None
        self.assertIsNotNone(module,'manual hosted acceptance needs an exclusive-daemon guard')
        return module

    def test_only_explicit_fresh_rootful_hosted_daemon_is_admissible(self):
        m=self.module()
        env={'GITHUB_ACTIONS':'true','RUNNER_ENVIRONMENT':'github-hosted'}
        info={'ID':'fixture-daemon','OSType':'linux','CgroupVersion':'2','SecurityOptions':['name=seccomp,profile=builtin'],'Swarm':{'LocalNodeState':'inactive'},'Containers':0}
        m.require_hosted_daemon(env,0,True,info,[])
        for change in ({'ID':''},{'OSType':'windows'},{'CgroupVersion':'1'},{'SecurityOptions':['name=rootless']},{'Swarm':{'LocalNodeState':'active'}},{'Containers':1}):
            with self.subTest(change=change),self.assertRaises(ValueError):
                m.require_hosted_daemon(env,0,True,{**info,**change},[])
        for bad_env in ({},{**env,'RUNNER_ENVIRONMENT':'self-hosted'},{**env,'GITHUB_ACTIONS':'false'}):
            with self.subTest(env=bad_env),self.assertRaises(ValueError):m.require_hosted_daemon(bad_env,0,True,info,[])
        with self.assertRaises(ValueError):m.require_hosted_daemon(env,1000,True,info,[])
        with self.assertRaises(ValueError):m.require_hosted_daemon(env,0,False,info,[])
        with self.assertRaises(ValueError):m.require_hosted_daemon(env,0,True,info,[{'Id':'existing'}])

    def test_incomplete_runtime_matrix_never_passes(self):
        m=self.module()
        self.assertTrue(hasattr(m,'verify_matrix'),'matrix needs explicit required gates and both source kinds per backend')
        gates=m.required_gates('compose')
        result={'platform':'compose','gates':[{'name':name} for name in gates],'cells':{'local':['postgres','volume'],'s3':['postgres','volume']}}
        m.verify_matrix(result)
        with self.assertRaises(ValueError):m.verify_matrix({**result,'gates':result['gates'][:-1]})
        with self.assertRaises(ValueError):m.verify_matrix({**result,'cells':{'local':['postgres'],'s3':['postgres','volume']}})
        with self.assertRaises(ValueError):m.verify_matrix({**result,'error':'failed run'})
        with self.assertRaises(ValueError):m.verify_matrix({**result,'gates':result['gates']+[result['gates'][0]]})
        swarm={**result,'platform':'swarm'}
        with self.assertRaises(ValueError):m.verify_matrix(swarm)

    def test_swarm_opt_in_lives_on_service_not_task_container(self):
        m=self.module()
        self.assertTrue(hasattr(m,'service_spec'),'Swarm sources must use actual service labels')
        spec={'Image':'fixture-image','Entrypoint':['sh','-c'],'Cmd':['exec sleep 900'],'Labels':{'bakabel.type':'volume','bakabel.paths':'/data','com.docker.compose.project':'obsolete'},'HostConfig':{'Mounts':[{'Type':'volume','Source':'owned','Target':'/data'}]}}
        before=copy.deepcopy(spec)
        got=m.service_spec('owned','files','node',spec)
        self.assertEqual(got['Labels'],{'com.docker.stack.namespace':'owned','bakabel.type':'volume','bakabel.paths':'/data'})
        task=got['TaskTemplate']
        self.assertEqual(task['ContainerSpec']['Labels'],{'probe.bakabel.owner':'owned'})
        self.assertEqual(task['ContainerSpec']['Command'],['sh','-c'])
        self.assertEqual(task['ContainerSpec']['Args'],['exec sleep 900'])
        self.assertEqual(task['Placement']['Constraints'],['node.id==node'])
        self.assertEqual(task['Resources']['Limits']['NanoCPUs'],2000000000)
        self.assertEqual(spec,before)

    def test_platform_config_is_not_silently_left_as_compose(self):
        m=self.module()
        self.assertTrue(hasattr(m,'HostedProbe'),'hosted fixture must actually select Swarm discovery')
        with tempfile.TemporaryDirectory() as directory:
            probe=m.HostedProbe.__new__(m.HostedProbe)
            probe.root=Path(directory);probe.prefix='owned';probe.platform='swarm'
            probe.image='sha256:'+'a'*64;probe.repository='/repository'
            probe.config()
            text=(probe.root/'config.yaml').read_text()
            self.assertIn('platform: swarm\n',text)
            self.assertNotIn('platform: compose\n',text)
            self.assertIn('worker_image: '+probe.image,text)

    def test_identity_checker_removal_keeps_volumes_for_the_real_refusal(self):
        m=self.module();calls=[]
        class Engine:
            removed=False
            def inspect(self,cid,missing=False):
                return None if self.removed else {'Mounts':[{'Type':'volume','Name':'original'},{'Type':'volume','Name':'alternate'}]}
            def call(self,method,path,**kw):
                calls.append((method,path))
                if path.startswith('/containers/'):self.removed=True
        probe=m.HostedProbe.__new__(m.HostedProbe)
        probe.e=Engine();probe.services={};probe.restores={};probe.volumes=['original','alternate']
        probe.remove_source('checker',keep_volumes=True)
        self.assertFalse(any(path.startswith('/volumes/') for method,path in calls))

    def test_swarm_plan_uses_recorded_source_field_and_gate_identity(self):
        m=self.module()
        from unittest.mock import patch
        target={'Source':{'DaemonID':'daemon','ContainerID':'container','StartedAt':'started'}}
        class Engine:
            def call(self,method,path):
                if path=='/info':return {'Swarm':{'NodeID':'node'}}
                return [{'NodeID':'node','Status':{'State':'running','ContainerStatus':{'ContainerID':'container'}}}]
            def inspect(self,cid):return {'State':{'StartedAt':'started'}}
        probe=m.HostedProbe.__new__(m.HostedProbe)
        probe.platform='swarm';probe.repository='/repository';probe.daemon='daemon';probe.e=Engine()
        gates=[];probe.gate=lambda name,**kw:gates.append(name)
        with patch.object(m.ComposeProbe,'call_cli',return_value={'targets':[target]}):
            probe.call_cli('plan')
        self.assertEqual(gates,['local-service-labels-running-task-node-identity'])

    def test_swarm_postgres_does_not_listen_on_external_interfaces(self):
        m=self.module()
        from unittest.mock import patch,Mock
        with tempfile.TemporaryDirectory() as directory:
            probe=m.HostedProbe.__new__(m.HostedProbe)
            probe.root=Path(directory);(probe.root/'private').mkdir()
            probe.platform='swarm';probe.prefix='owned';probe.volumes=[]
            probe.e=Mock();probe.e.inspect.return_value={'State':{'Pid':123}}
            probe.wait=lambda *a:True;probe.sql=lambda *a:'127.0.0.1'
            specs=[]
            probe.swarm_source=lambda suffix,spec,role:(specs.append(spec) or 'container')
            with patch.object(m.os,'sched_getaffinity',return_value={0,1}):probe.startpg('pg-local',True)
            self.assertIn('postgres -c listen_addresses=127.0.0.1',specs[0]['Cmd'][0])

    def test_constructor_requires_only_runtime_images(self):
        m=self.module()
        from types import SimpleNamespace
        from unittest.mock import patch
        from urllib.parse import unquote
        import run_resource_probe as base
        calls=[]
        class Engine:
            def __init__(self,*a):pass
            def call(self,method,path):
                calls.append(path)
                if path=='/info':return {'ID':'daemon','Swarm':{'LocalNodeState':'inactive'}}
                image=unquote(path.removeprefix('/images/').removesuffix('/json'))
                if image not in ('candidate',m.PG):raise ValueError('unexpected auxiliary image '+image)
                return {'Id':'candidate','RepoDigests':[],'Size':1}
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);binary=root/'minio';binary.write_bytes(b'unit-only-not-a-runtime-binary')
            args=SimpleNamespace(platform='compose',runtime=root/'runtime',source=Path(__file__).resolve().parents[3],socket=root/'unused',image='candidate',minio_binary=binary)
            with patch.object(base,'Engine',Engine),patch.object(base.Probe,'sampler',lambda self:None):
                probe=m.HostedProbe(args)
                probe.thread.join(1)
            self.assertEqual(set(probe.result['images']),{'candidate',m.PG})

    def test_partial_constructor_failure_keeps_failed_receipt_not_private_files(self):
        m=self.module()
        from types import SimpleNamespace
        from unittest.mock import patch
        import json
        self.assertTrue(hasattr(m,'run_platform'),'construction must be inside guarded reporting/cleanup')
        with tempfile.TemporaryDirectory() as directory:
            args=SimpleNamespace(runtime=Path(directory)/'compose',platform='compose',expected_source_sha256='a'*64,expected_image_id='candidate')
            class BrokenProbe:
                def __init__(self,args):
                    private=args.runtime/'private';private.mkdir(parents=True)
                    (private/'password').write_text('unit-only-private-data')
                    raise ValueError('injected initialization failure')
            with patch.object(m,'HostedProbe',BrokenProbe):result=m.run_platform(args)
            self.assertTrue(result['failed'])
            receipt=json.loads((args.runtime/'receipt.json').read_text())
            self.assertEqual(receipt['error'],'ValueError')
            self.assertFalse((args.runtime/'private').exists())
            self.assertFalse(receipt['runtime_matrix_pass'])

if __name__=='__main__':unittest.main()
