import unittest
from run_resource_failures import assert_failure_proof, minimal_space_probe
import errno
import tempfile
from pathlib import Path
from unittest.mock import patch

class FailureProof(unittest.TestCase):
    def cgroup_probe(self, directory):
        from run_resource_failures import FailureProbe
        from types import SimpleNamespace
        from unittest.mock import Mock
        cid='a'*64;run='b'*32
        probe=FailureProbe.__new__(FailureProbe);probe.image='candidate';probe.daemon='unit-daemon'
        probe.result={'failure_cgroup_samples':[]};probe._cgroup_identities={};probe.root=Path(directory)
        owner={'workerContainerID':cid,'workerName':'unit-worker','runID':run,'daemonID':probe.daemon}
        worker={'Id':cid,'Name':'/unit-worker','Image':probe.image,'Config':{'Labels':{'bakabel.worker':'1','bakabel.run':run,'bakabel.daemon':probe.daemon}},'State':{'Pid':123,'Running':True},'HostConfig':{},'Mounts':[]}
        cg=Path(directory)/cid;cg.mkdir()
        for name,value in {'cpu.max':'200000 100000','memory.max':'16777216','memory.swap.max':'0','memory.current':'1024','memory.peak':'2048','memory.events':'oom_kill 0'}.items():(cg/name).write_text(value)
        probe.cgroup=Mock(return_value=cg)
        probe.e=SimpleNamespace(inspect=Mock(return_value=worker))
        self.addCleanup(probe.stop_failure_observers)
        return probe,owner,worker,cg

    def test_kernel_counter_survives_blocked_inspect_and_deleted_path(self):
        import json,os,shutil,threading,time
        from types import SimpleNamespace
        from unittest.mock import Mock
        with tempfile.TemporaryDirectory() as directory:
            probe,owner,worker,cg=self.cgroup_probe(directory)
            probe.args=SimpleNamespace(memory_mib=16);probe.blocked=Mock(return_value=owner);probe.unlock=Mock()
            worker['HostConfig']={'Memory':16777216,'MemorySwap':16777216}
            inspecting=threading.Event();release=threading.Event();errors=[];calls=[]
            independent=os.open(cg/'memory.events',os.O_RDONLY)
            def inspect(cid,**kwargs):
                calls.append(cid)
                if len(calls)>1:
                    inspecting.set();release.wait(2)
                return worker
            def update(*args,**kwargs):
                self.assertTrue(probe.result.get('kernel_counter_armed'),'reader must be synchronized before POST')
                return {'Warnings':[]}
            probe.e=SimpleNamespace(inspect=inspect,call=update)
            def activate():
                try:probe.activate_oom('pg',owner)
                except Exception as exc:errors.append(exc)
            thread=threading.Thread(target=activate);thread.start()
            try:
                self.assertTrue(inspecting.wait(.3),'POST/readback reached only after independent reader is armed')
                (cg/'memory.events').write_text('oom_kill 1')
                self.assertEqual(os.pread(independent,4096,0),b'oom_kill 1')
                deadline=time.monotonic()+.5
                while time.monotonic()<deadline and not any('oom_kill 1'==r.get('memory.events') for r in probe.result['failure_cgroup_samples']):time.sleep(.001)
                self.assertTrue(any('oom_kill 1'==r.get('memory.events') for r in probe.result['failure_cgroup_samples']))
                shutil.rmtree(cg)
            finally:
                release.set();thread.join(2);os.close(independent)
                if hasattr(probe,'stop_failure_observers'):probe.stop_failure_observers()
            self.assertFalse(thread.is_alive())
            self.assertTrue(errors,'deleted effective limit readback must not permit unlock')
            probe.unlock.assert_not_called()
            self.assertTrue(any(r.get('memory.events')=='oom_kill 1' for r in probe.result['failure_cgroup_samples']))

    def test_pid_zero_reads_last_validated_counter_even_without_owner_file(self):
        with tempfile.TemporaryDirectory() as directory:
            probe,owner,worker,cg=self.cgroup_probe(directory)
            self.assertTrue(hasattr(probe,'sample_failure_cgroup'),'terminal sampling must retain exact live cgroup identity')
            probe.sample_failure_cgroup(worker,owner)
            (cg/'memory.events').write_text('oom_kill 1')
            worker['State']={'Pid':0,'Running':False,'OOMKilled':True}
            row=probe.sample_failure_cgroup(worker,owner)
            self.assertEqual(row['memory.events'],'oom_kill 1')
            self.assertEqual(row['counter_status'],'observed')
            self.assertEqual(row['observer_pid'],0)
            self.assertEqual(len(probe.result['failure_cgroup_samples']),2)
            self.assertEqual(probe.cgroup.call_count,1)

    def test_fast_observer_uses_terminal_counter_and_rejects_drift(self):
        import json
        from types import SimpleNamespace
        from unittest.mock import Mock
        with tempfile.TemporaryDirectory() as directory:
            probe,owner,worker,cg=self.cgroup_probe(directory)
            probe.root=Path(directory);(probe.root/'state').mkdir();(probe.root/'state/owner.json').write_text(json.dumps(owner))
            probe.args=SimpleNamespace(mode='oom-active');probe.result.update(owner_history=[],restic_effective_env=[])
            probe.pids=Mock(return_value=[])
            terminal={**worker,'State':{'Pid':0,'Running':False,'OOMKilled':True,'Error':'PRIVATE-CANARY'}}
            probe.e=SimpleNamespace(inspect=Mock(side_effect=[worker,worker,terminal]))
            count=0
            def wait(_):
                nonlocal count
                count+=1
                if count==2:(cg/'memory.events').write_text('oom_kill 1')
                return count>2
            probe.observe_fast(SimpleNamespace(wait=wait))
            self.assertEqual(probe.result['failure_cgroup_samples'][-1]['memory.events'],'oom_kill 1')
            self.assertNotIn('PRIVATE-CANARY',json.dumps(probe.result))

    def test_cgroup_unavailable_is_not_zero_and_live_identity_drift_is_rejected(self):
        from unittest.mock import Mock
        for mode in ('missing-counter','deleted','replacement','pid','path','missing-path','foreign-worker'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as directory:
                probe,owner,worker,cg=self.cgroup_probe(directory);probe.sample_failure_cgroup(worker,owner)
                if mode=='missing-counter':(cg/'memory.events').unlink()
                if mode in ('deleted','replacement'):
                    cg.rename(cg.with_name('retired'))
                    if mode=='replacement':cg.mkdir()
                if mode=='pid':worker['State']['Pid']=124
                if mode=='path':probe.cgroup=Mock(return_value=cg/'other')
                if mode=='missing-path':probe.cgroup=Mock(return_value=None)
                if mode=='foreign-worker':worker['Image']='foreign'
                if mode in ('missing-counter','deleted'):
                    worker['State']={'Pid':0,'Running':False}
                    row=probe.sample_failure_cgroup(worker,owner)
                    self.assertEqual(row['counter_status'],'unavailable');self.assertEqual(row['memory.events'],'')
                    if mode=='deleted':
                        self.assertEqual(len(probe.result['failure_cgroup_samples']),1,'unavailable CPU limit must not be fabricated or invalidate genuine sample rows')
                        self.assertEqual(probe.result['terminal_cgroup_sample'],row)
                else:
                    with self.assertRaisesRegex(AssertionError,'identity'):probe.sample_failure_cgroup(worker,owner)

    def test_blocked_observer_rpc_stops_before_receipt_and_has_no_late_writes(self):
        import json,socket,threading,time
        from types import SimpleNamespace
        from run_resource_probe import Engine
        with tempfile.TemporaryDirectory() as directory:
            probe,owner,worker,cg=self.cgroup_probe(directory)
            (probe.root/'state').mkdir();(probe.root/'state/owner.json').write_text(json.dumps(owner))
            probe.args=SimpleNamespace(mode='oom-active');probe.result.update(owner_history=[],restic_effective_env=[])
            sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);address=str(probe.root/'engine.sock');sock.bind(address);sock.listen(1);sock.settimeout(3)
            entered=threading.Event();release=threading.Event()
            def serve():
                try:
                    conn,_=sock.accept()
                    with conn:
                        conn.settimeout(2);conn.recv(4096);entered.set();release.wait(5)
                finally:sock.close()
            server=threading.Thread(target=serve);server.start()
            probe.e=Engine(address);stop=threading.Event();observer=threading.Thread(target=probe.observe_fast,args=(stop,))
            probe._failure_observers=[(stop,observer)];observer.start()
            try:
                self.assertTrue(entered.wait(1))
                started=time.monotonic();probe.stop_failure_observers()
                self.assertLess(time.monotonic()-started,1.5)
                self.assertFalse(observer.is_alive())
                self.assertTrue(probe.result.get('fast_observer_errors'),'RPC timeout remains explicit failure')
                probe.save();serialized=(probe.root/'receipt.json').read_text()
                release.set();server.join(2);time.sleep(.01)
                self.assertEqual(json.loads(serialized),probe.result)
            finally:
                stop.set();release.set();server.join(3);observer.join(3)
            self.assertFalse(observer.is_alive());self.assertFalse(server.is_alive())

    def test_sampler_engine_calls_have_absolute_deadlines_without_changing_main_rpc(self):
        import threading,time
        from run_resource_probe import Probe,Engine
        with tempfile.TemporaryDirectory() as directory:
            probe,owner,worker,cg=self.cgroup_probe(directory)
            probe.sock='/unused';probe.e=Engine(probe.sock);probe.stopped=threading.Event();calls=[]
            def call(engine,method,path,*args,**kwargs):calls.append((threading.get_ident(),kwargs.get('deadline')))
            started=time.monotonic()
            with patch.object(Engine,'call',call),patch.object(Probe,'sampler',lambda p:p.e.call('GET','/info')):
                thread=threading.Thread(target=probe.sampler);thread.start();thread.join(2)
                probe.e.call('GET','/info')
            self.assertFalse(thread.is_alive())
            self.assertIsNotNone(calls[0][1]);self.assertLessEqual(calls[0][1],started+1.1)
            self.assertIsNone(calls[1][1],'ordinary main-thread Engine budgets are unchanged')

    def test_live_observer_shutdown_failure_is_explicit_and_blocks_save_and_cleanup(self):
        import threading
        from unittest.mock import patch
        from run_resource_probe import Probe
        with tempfile.TemporaryDirectory() as directory:
            probe,owner,worker,cg=self.cgroup_probe(directory)
            stop=threading.Event();release=threading.Event()
            observer=threading.Thread(target=lambda:release.wait(2));observer.start()
            probe._failure_observers=[(stop,observer)]
            try:
                with patch.object(observer,'join',return_value=None):
                    with self.assertRaisesRegex(ValueError,'observer_shutdown'):probe.stop_failure_observers()
                    self.assertTrue(stop.is_set());self.assertTrue(probe.result.get('fast_observer_errors'))
                    with self.assertRaisesRegex(ValueError,'observer'):probe.save()
                    self.assertFalse((probe.root/'receipt.json').exists())
                    with patch.object(Probe,'cleanup') as base:
                        with self.assertRaisesRegex(ValueError,'observer_shutdown'):probe.cleanup()
                        base.assert_not_called()
            finally:release.set();observer.join(2)
            self.assertFalse(observer.is_alive())

    def test_running_inspect_missing_proc_requires_exact_terminal_reinspection(self):
        import copy,time
        from types import SimpleNamespace
        from unittest.mock import Mock
        for outcome in ('terminal','still-running','foreign-image','foreign-run','missing'):
            with self.subTest(outcome=outcome),tempfile.TemporaryDirectory() as directory:
                probe,owner,worker,cg=self.cgroup_probe(directory)
                probe.sample_failure_cgroup(worker,owner)
                probe.cgroup=Mock(return_value=None)
                terminal=copy.deepcopy(worker);terminal['State']={'Running':False,'Pid':0,'ExitCode':0,'OOMKilled':False}
                if outcome=='still-running':terminal=worker
                if outcome=='foreign-image':terminal['Image']='foreign'
                if outcome=='foreign-run':terminal['Config']['Labels']['bakabel.run']='d'*32
                probe.e=SimpleNamespace(inspect=Mock(return_value=None if outcome=='missing' else terminal))
                started=time.monotonic()
                if outcome=='terminal':
                    row=probe.sample_failure_cgroup(worker,owner)
                    self.assertEqual(row['observer_pid'],0)
                    self.assertNotIn('fast_observer_errors',probe.result)
                else:
                    with self.assertRaisesRegex(AssertionError,'identity'):probe.sample_failure_cgroup(worker,owner)
                probe.e.inspect.assert_called_once()
                self.assertEqual(probe.e.inspect.call_args.args,(owner['workerContainerID'],))
                deadline=probe.e.inspect.call_args.kwargs.get('deadline')
                self.assertIsNotNone(deadline);self.assertGreater(deadline,started);self.assertLessEqual(deadline,started+1.1)

    def test_running_unavailable_cgroup_files_are_not_silently_accepted_as_live(self):
        import copy,shutil
        from types import SimpleNamespace
        from unittest.mock import Mock
        for missing in ('directory','memory.events'):
            for terminal in (True,False):
                with self.subTest(missing=missing,terminal=terminal),tempfile.TemporaryDirectory() as directory:
                    probe,owner,worker,cg=self.cgroup_probe(directory);probe.sample_failure_cgroup(worker,owner)
                    if missing=='directory':shutil.rmtree(cg)
                    else:(cg/missing).unlink()
                    after=copy.deepcopy(worker)
                    if terminal:after['State']={'Running':False,'Pid':0,'ExitCode':0,'OOMKilled':False}
                    probe.e=SimpleNamespace(inspect=Mock(return_value=after))
                    if terminal:
                        row=probe.sample_failure_cgroup(worker,owner)
                        self.assertEqual(row['observer_pid'],0);self.assertEqual(row['counter_status'],'unavailable')
                        self.assertEqual(row['memory.events'],'')
                    else:
                        with self.assertRaisesRegex(AssertionError,'identity'):probe.sample_failure_cgroup(worker,owner)
                    probe.e.inspect.assert_called_once()

    def test_oom_activation_reads_effective_no_swap_cap_before_unlock(self):
        from types import SimpleNamespace
        from unittest.mock import Mock
        for mismatch in (None,'Memory','MemorySwap','memory.max','memory.swap.max','update','update-terminal','warning'):
            with self.subTest(mismatch=mismatch),tempfile.TemporaryDirectory() as directory:
                probe,owner,worker,cg=self.cgroup_probe(directory);events=[]
                probe.args=SimpleNamespace(memory_mib=16);probe.blocked=Mock(side_effect=lambda pg:events.append('blocked') or owner)
                worker['HostConfig']={'Memory':16777216,'MemorySwap':16777216}
                if mismatch in ('Memory','MemorySwap'):worker['HostConfig'][mismatch]+=1
                if mismatch in ('memory.max','memory.swap.max'):(cg/mismatch).write_text('1')
                def call(method,path,body):
                    events.append('update');self.assertEqual(body,{'Memory':16777216,'MemorySwap':16777216})
                    if mismatch in ('update','update-terminal'):
                        if mismatch=='update-terminal':
                            worker['State']={'Pid':0,'Running':False,'ExitCode':137,'OOMKilled':True}
                            (cg/'memory.events').write_text('oom_kill 1')
                        error=RuntimeError('PRIVATE-CANARY');error.http_status=500
                        raise error
                    return {'Warnings':['PRIVATE-CANARY']} if mismatch=='warning' else {'Warnings':[]}
                probe.e=SimpleNamespace(inspect=Mock(side_effect=lambda cid,**kw:events.append('inspect') or worker),call=call)
                probe.unlock=Mock(side_effect=lambda pg:events.append('unlock'))
                self.assertTrue(hasattr(probe,'activate_oom'),'source must stream only after proven effective no-swap cap')
                if mismatch and mismatch!='warning':
                    with self.assertRaises((AssertionError,RuntimeError)):probe.activate_oom('pg',owner)
                    probe.unlock.assert_not_called()
                    if mismatch in ('update','update-terminal'):
                        self.assertEqual(probe.result['failure_diagnostics']['update_status'],'rejected')
                        self.assertEqual(probe.result['failure_diagnostics']['update_http_status'],500)
                    if mismatch=='update-terminal':
                        self.assertEqual(probe.result['failure_diagnostics'].get('terminal_oom_kill'),1)
                        self.assertTrue(probe.result['failure_diagnostics']['terminal_oom_killed'])
                else:
                    probe.activate_oom('pg',owner)
                    self.assertEqual(events,['blocked','inspect','update','inspect','unlock'])
                    self.assertEqual(probe.result['injected_memory_update']['request']['MemorySwap'],16777216)
                    self.assertEqual(probe.result['failure_diagnostics']['effective_swap_bytes'],0)
                import json
                self.assertNotIn('PRIVATE-CANARY',json.dumps(probe.result))

    def test_terminal_counter_and_finite_failure_receipt_precede_recovery(self):
        import json
        from unittest.mock import Mock
        with tempfile.TemporaryDirectory() as directory:
            probe,owner,worker,cg=self.cgroup_probe(directory);probe.sample_failure_cgroup(worker,owner)
            probe.root=Path(directory);output=probe.root/'state/workflow/output/result.json';output.parent.mkdir(parents=True)
            output.write_text(json.dumps({'runID':owner['runID'],'status':'failed','targets':[{'failureCode':'backup','resticExitCode':1,'resticReason':'unknown','error':'PRIVATE-CANARY','Env':['PRIVATE-CANARY']}]}))
            worker['State']={'Pid':0,'Running':False,'ExitCode':1,'OOMKilled':False,'Error':'PRIVATE-CANARY'}
            probe.wait=Mock(return_value=worker)
            self.assertTrue(hasattr(probe,'wait_failure_terminal'))
            probe.wait_failure_terminal(owner)
            diagnostic=probe.result['failure_diagnostics']
            self.assertEqual(diagnostic['terminal_pid'],0);self.assertEqual(diagnostic['terminal_exit_code'],1)
            self.assertFalse(diagnostic['terminal_oom_killed']);self.assertEqual(diagnostic['terminal_oom_kill'],0)
            self.assertEqual(diagnostic['targets'],[{'failureCode':'backup','resticExitCode':1,'resticReason':'unknown'}])
            self.assertNotIn('PRIVATE-CANARY',json.dumps(diagnostic))

    def test_oom_proof_rejects_non_oom_exit_and_missing_counter(self):
        import run_resource_failures as module
        require=getattr(module,'assert_oom_proof',None);self.assertIsNotNone(require)
        self.assertEqual(require([{'memory.events':'oom_kill 1'}],{'OOMKilled':True}),1)
        for events,state in (('oom_kill 0',{'ExitCode':1,'OOMKilled':False}),('',{'ExitCode':137,'OOMKilled':True}),('oom_kill 1',{'ExitCode':137,'OOMKilled':False})):
            with self.subTest(events=events,state=state),self.assertRaises(AssertionError):require([{'memory.events':events}],state)

    def test_cli_failure_does_not_persist_arbitrary_exception_text(self):
        import json
        from types import SimpleNamespace
        from unittest.mock import Mock
        import run_resource_failures as module
        probe=SimpleNamespace(result={},run=Mock(side_effect=RuntimeError('PRIVATE-CANARY')),cleanup=Mock())
        with patch.object(module.argparse.ArgumentParser,'parse_args',return_value=SimpleNamespace(memory_mib=16,mode='oom-active')),patch.object(module.os,'sched_setaffinity'),patch.object(module,'FailureProbe',return_value=probe):
            self.assertEqual(module.main(),1)
        probe.cleanup.assert_called_once_with()
        self.assertEqual(probe.result['error'],'RuntimeError')
        self.assertNotIn('PRIVATE-CANARY',json.dumps(probe.result))

    def test_cli_oom_active_defaults_to_exact_16_mib_without_changing_other_modes(self):
        from types import SimpleNamespace
        from unittest.mock import Mock
        import run_resource_failures as module
        for mode,expected in (('oom-active',16),('oom',32),('enospc',32)):
            with self.subTest(mode=mode):
                probe=SimpleNamespace(result={},run=Mock(),cleanup=Mock())
                argv=['fixture','--source','/unused','--runtime','/unused','--minio-binary','/unused','--image','candidate','--mode',mode]
                with patch('sys.argv',argv),patch.object(module.os,'sched_setaffinity'),patch.object(module,'FailureProbe',return_value=probe) as create:
                    self.assertEqual(module.main(),0)
                    self.assertEqual(create.call_args.args[0].memory_mib,expected)

    def test_engine_event_bounds_use_outward_unix_seconds(self):
        import run_resource_failures
        bounds=getattr(run_resource_failures,'event_bounds',None)
        self.assertIsNotNone(bounds,'Engine event queries need supported numeric timestamp bounds')
        self.assertEqual(bounds('1970-01-01T00:00:01.123456+00:00','1970-01-01T00:00:02.456789+00:00'),('1','3'))
        self.assertEqual(bounds('1970-01-01T07:00:01.123456+07:00','1970-01-01T00:00:02Z'),('1','2'))
    def test_source_dump_event_checks_action_when_exec_command_is_absent(self):
        import run_resource_failures
        seen=getattr(run_resource_failures,'source_dump_exec_seen',None)
        self.assertIsNotNone(seen,'Docker records exec command text in Action on this Engine')
        self.assertTrue(seen([{'Action':'exec_start: pg_dump -Fc','Actor':{'Attributes':{'execID':'owned'}}}]))
        self.assertTrue(seen([{'Action':'exec_start','Actor':{'Attributes':{'execCommand':'pg_dump -Fc'}}}]))
        self.assertFalse(seen([{'Action':'exec_start: pg_isready','Actor':{'Attributes':{}}}]))
    def test_recovery_bound_uses_original_job_deadline_not_fault_walltime(self):
        from verify_resource_failures import assert_bounded_recovery
        job={'createdAt':'2026-01-01T00:00:00Z','config':{'Timeout':45000000000}}
        assert_bounded_recovery(job,'2026-01-01T00:00:45.5Z','2026-01-01T00:00:46Z')
        with self.assertRaises(AssertionError):
            assert_bounded_recovery(job,'2026-01-01T00:00:45.5Z','2026-01-01T00:01:10Z')
    def test_space_probe_preserves_errno_and_removes_own_probe(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)
            self.assertEqual(minimal_space_probe(p)['errno'],0)
            self.assertEqual(list(p.iterdir()),[])
            with patch('os.write',side_effect=OSError(errno.ENOSPC,'No space left on device')):
                self.assertEqual(minimal_space_probe(p)['errno'],errno.ENOSPC)
            self.assertEqual(list(p.iterdir()),[])
    def test_release_requires_exact_source_and_session_terminal(self):
        p={'status':'failed','complete':False,'owner_released':True,'worker_terminal':True,'exec_terminal':True,'session_count':0}
        assert_failure_proof(p)
        for change in [{'status':'success'},{'complete':True},{'worker_terminal':False},{'exec_terminal':False},{'session_count':1}]:
            with self.assertRaises(AssertionError): assert_failure_proof({**p,**change})
    def test_uncertain_source_must_keep_owner_blocked(self):
        assert_failure_proof({'status':'failed','complete':False,'owner_released':False,'guard_blocked':True})
        with self.assertRaises(AssertionError):
            assert_failure_proof({'status':'failed','complete':False,'owner_released':False,'guard_blocked':False})

if __name__=='__main__':unittest.main()
