import unittest
from run_resource_failures import assert_failure_proof, minimal_space_probe
import errno
import tempfile
from pathlib import Path
from unittest.mock import patch

class FailureProof(unittest.TestCase):
    def cgroup_probe(self, directory, *, mode='oom-active'):
        from run_resource_failures import FailureProbe
        from types import SimpleNamespace
        from unittest.mock import Mock
        cid='a'*64;run='b'*32
        probe=FailureProbe.__new__(FailureProbe);probe.image='candidate';probe.daemon='unit-daemon'
        probe.result={'mode':mode,'failure_cgroup_samples':[]};probe._cgroup_identities={};probe.root=Path(directory)
        owner={'workerContainerID':cid,'workerName':'unit-worker','runID':run,'daemonID':probe.daemon}
        worker={'Id':cid,'Name':'/unit-worker','Image':probe.image,'Config':{'Labels':{'bakabel.worker':'1','bakabel.run':run,'bakabel.daemon':probe.daemon}},'State':{'Pid':123,'Running':True},'HostConfig':{},'Mounts':[]}
        cg=Path(directory)/cid;cg.mkdir()
        for name,value in {'cpu.max':'200000 100000','memory.max':'16777216','memory.swap.max':'0','memory.current':'1024','memory.peak':'2048','memory.events':'oom_kill 0'}.items():(cg/name).write_text(value)
        probe.cgroup=Mock(return_value=cg)
        probe.e=SimpleNamespace(inspect=Mock(return_value=worker))
        self.addCleanup(probe.stop_failure_observers)
        return probe,owner,worker,cg

    def early_oom_receipt(self,probe,owner,worker):
        """Synthetic offline verifier input, never a historical hosted receipt."""
        return {**probe.result,'mode':'oom','daemon':probe.daemon,'early_oom_phase':'intent-before-source-exec',
            'failure_terminal_proof':{'status':'failed','complete':False,'owner_released':True,
                'worker_terminal':True,'source_never_started':True,'session_count':0,
                'last_result':{'runID':owner['runID'],'status':'failed'}},
            'worker_last_inspect':worker,'owner_history':[{'owner':{**owner,'phase':'intent','status':'active'}}],
            'snapshots_after_failure':[],'source_exec_events':[],
            'source_after':{'identity_unchanged':True,'read_write_ok':True}}

    def test_terminal_cpu_only_is_diagnostic_not_an_early_oom_limit_sample(self):
        from run_hosted_resources import verify_early_oom
        with tempfile.TemporaryDirectory() as directory:
            probe,owner,worker,cg=self.cgroup_probe(directory,mode='oom')
            (cg/'memory.max').write_text('33554432');(cg/'memory.events').write_text('oom_kill 1')
            worker['HostConfig']={'Memory':33554432,'NanoCpus':2000000000}
            complete=probe.sample_failure_cgroup(worker,owner)
            (cg/'memory.max').unlink()
            worker['State']={'Pid':0,'Running':False,'OOMKilled':True}
            partial=probe.sample_failure_cgroup(worker,owner)
            self.assertTrue(verify_early_oom(self.early_oom_receipt(probe,owner,worker),'candidate')['verified'])
            self.assertEqual(probe.result['failure_cgroup_samples'],[complete])
            self.assertEqual(probe.result['terminal_cgroup_sample'],partial)
            self.assertNotIn('memory.max',partial)
            self.assertEqual(partial['unavailable_errno']['memory.max'],2)
            self.assertEqual(partial['memory.events'],'oom_kill 1')
            self.assertEqual(partial['counter_status'],'observed')

    def test_partial_contradictory_limit_cannot_hide_behind_complete_positive_proof(self):
        import json
        from run_hosted_resources import verify_early_oom
        from run_resource_probe import Probe
        for route in ('terminal','fd'):
            for remaining,missing,wrong in (('cpu.max','memory.max','100000 100000'),
                                            ('memory.max','cpu.max','16777216')):
                for value in (wrong,'','PRIVATE-CANARY'):
                    with self.subTest(route=route,remaining=remaining,value=value),tempfile.TemporaryDirectory() as directory:
                        probe,owner,worker,cg=self.cgroup_probe(directory,mode='oom')
                        (cg/'memory.max').write_text('33554432');(cg/'memory.events').write_text('oom_kill 1')
                        worker['HostConfig']={'Memory':33554432,'NanoCpus':2000000000}
                        complete=probe.sample_failure_cgroup(worker,owner)
                        rejected=False
                        if route=='terminal':
                            (cg/missing).unlink();(cg/remaining).write_text(value)
                            worker['State']={'Pid':0,'Running':False,'OOMKilled':True}
                            try:probe.sample_failure_cgroup(worker,owner)
                            except AssertionError as exc:
                                self.assertEqual(exc.args,('cgroup_identity',));rejected=True
                            partial=probe.result['terminal_cgroup_sample']
                        else:
                            partial=self.kernel_fd_unavailable(probe,owner,worker,cg,missing,remaining=(remaining,value))
                            errors=probe.result.get('fast_observer_errors',[])
                            rejected=bool(errors)
                            if rejected:
                                self.assertEqual(errors[0]['code'],'kernel_reader_failure')
                                self.assertEqual(errors[0]['type'],'AssertionError')
                                self.assertEqual(errors[0]['reason'],'cgroup_identity')
                                self.assertNotIn('PRIVATE-CANARY',json.dumps(errors))
                                with patch.object(Probe,'gate') as gate:
                                    with self.assertRaisesRegex(AssertionError,'observer_failure'):probe.gate('partial-limit')
                                    gate.assert_not_called()
                        self.assertIn(complete,probe.result['failure_cgroup_samples'])
                        self.assertTrue(all(r['cpu.max']=='200000 100000' and r['memory.max']=='33554432'
                                            for r in probe.result['failure_cgroup_samples']))
                        self.assertNotIn(partial,probe.result['failure_cgroup_samples'])
                        self.assertNotIn(missing,partial);self.assertEqual(partial[remaining],value)
                        self.assertEqual(partial['memory.events'],'oom_kill 1')
                        self.assertEqual(partial['counter_status'],'observed')
                        if not rejected:
                            worker['State']={'Pid':0,'Running':False,'OOMKilled':True}
                            self.assertTrue(verify_early_oom(self.early_oom_receipt(probe,owner,worker),'candidate')['verified'])
                        self.assertTrue(rejected,'contradictory partial row was discarded and prior positive proof still accepted')

    def test_partial_available_limits_use_known_mode_without_cached_or_hostconfig_substitution(self):
        from run_resource_failures import assert_oom_proof
        modes={'oom':('33554432',),'oom-active':('536870912','16777216'),'enospc':('536870912',)}
        for route in ('terminal','fd'):
            for mode,memories in modes.items():
                for remaining,missing,allowed,values in (
                    ('cpu.max','memory.max',('200000 100000',),
                     ('200000 100000','100000 100000','300000 100000','200000 0','max 100000','','invalid','-1 100000','0 100000','9223372036854775808 100000')),
                    ('memory.max','cpu.max',memories,
                     ('16777216','33554432','536870912','max','','invalid','-1','0','9223372036854775808'))):
                    for value in values:
                        with self.subTest(route=route,mode=mode,remaining=remaining,value=value),tempfile.TemporaryDirectory() as directory:
                            probe,owner,worker,cg=self.cgroup_probe(directory,mode=mode)
                            (cg/'memory.max').write_text(memories[0]);(cg/'memory.events').write_text('oom_kill 1')
                            # Neither host configuration nor an old full row may
                            # replace a missing limit or excuse a contrary read.
                            worker['HostConfig']={'Memory':999,'NanoCpus':999}
                            complete=probe.sample_failure_cgroup(worker,owner)
                            rejected=False
                            if route=='terminal':
                                (cg/missing).unlink();(cg/remaining).write_text(value)
                                worker['State']={'Pid':0,'Running':False,'OOMKilled':True}
                                try:probe.sample_failure_cgroup(worker,owner)
                                except AssertionError as exc:
                                    self.assertEqual(exc.args,('cgroup_identity',));rejected=True
                                partial=probe.result['terminal_cgroup_sample']
                            else:
                                partial=self.kernel_fd_unavailable(probe,owner,worker,cg,missing,remaining=(remaining,value))
                                rejected=bool(probe.result.get('fast_observer_errors'))
                            self.assertEqual(rejected,value not in allowed)
                            self.assertIn(complete,probe.result['failure_cgroup_samples'])
                            self.assertNotIn(partial,probe.result['failure_cgroup_samples'])
                            self.assertNotIn(missing,partial);self.assertEqual(partial[remaining],value)
                            self.assertEqual(partial['memory.events'],'oom_kill 1')
                            self.assertEqual(partial['counter_status'],'observed')
                            self.assertEqual(assert_oom_proof(probe.result['failure_cgroup_samples'],{'OOMKilled':True}),1)

    def kernel_fd_unavailable(self,probe,owner,worker,cg,missing,*,counter=None,remaining=None):
        import os,threading,time
        unavailable=threading.Event();pread=os.pread;partial=False
        def read(fd,size,offset):
            nonlocal partial
            # Real pinned FDs; switch the injected teardown at a row boundary.
            path=os.readlink(f'/proc/self/fd/{fd}')
            if path==str(cg/'cpu.max'):partial=unavailable.is_set()
            if partial:
                if missing is not None and path==str(cg/missing):raise OSError(19,'synthetic terminal FD unavailable')
                if remaining is not None and path==str(cg/remaining[0]):return remaining[1].encode()
            return pread(fd,size,offset)
        def wait_for(predicate):
            deadline=time.monotonic()+.5
            while time.monotonic()<deadline and not predicate():time.sleep(.001)
            self.assertTrue(predicate(),'kernel reader did not retain the transition')
        with patch('run_resource_failures.os.pread',side_effect=read):
            try:
                probe.arm_kernel_counter(worker,owner);unavailable.set()
                def transitioned():
                    row=probe.result['kernel_counter_sample']
                    if missing is not None:return missing in row.get('unavailable_errno',{})
                    assert remaining is not None
                    return row.get(remaining[0])==remaining[1]
                wait_for(transitioned)
                if counter is not None:
                    # Wait until limits are unavailable BEFORE publishing a positive
                    # counter: never accidentally create a complete positive row.
                    (cg/'memory.events').write_text(counter)
                    wait_for(lambda:probe.result['kernel_counter_sample']['memory.events']==counter)
            finally:probe.stop_failure_observers()
        return probe.result['kernel_counter_sample']

    def test_kernel_fd_partial_limits_stay_diagnostic_with_genuine_counter(self):
        from run_hosted_resources import verify_early_oom
        for missing in ('cpu.max','memory.max'):
            with self.subTest(missing=missing),tempfile.TemporaryDirectory() as directory:
                probe,owner,worker,cg=self.cgroup_probe(directory,mode='oom')
                (cg/'memory.max').write_text('33554432');(cg/'memory.events').write_text('oom_kill 1')
                worker['HostConfig']={'Memory':33554432,'NanoCpus':2000000000}
                probe.sample_failure_cgroup(worker,owner)
                partial=self.kernel_fd_unavailable(probe,owner,worker,cg,missing,counter='oom_kill 2')
                worker['State']={'Pid':0,'Running':False,'OOMKilled':True}
                self.assertTrue(verify_early_oom(self.early_oom_receipt(probe,owner,worker),'candidate')['verified'])
                self.assertNotIn(partial,probe.result['failure_cgroup_samples'])
                self.assertNotIn(missing,partial)
                self.assertEqual(partial['memory.events'],'oom_kill 2')
                self.assertEqual(partial['counter_status'],'observed')
                self.assertFalse(probe.result.get('fast_observer_errors'))

    def test_terminal_memory_only_retains_counter_without_inventing_cpu(self):
        from run_hosted_resources import verify_early_oom
        with tempfile.TemporaryDirectory() as directory:
            probe,owner,worker,cg=self.cgroup_probe(directory,mode='oom')
            (cg/'memory.max').write_text('33554432');(cg/'memory.events').write_text('oom_kill 1')
            worker['HostConfig']={'Memory':33554432,'NanoCpus':2000000000}
            complete=probe.sample_failure_cgroup(worker,owner)
            (cg/'cpu.max').unlink();worker['State']={'Pid':0,'Running':False,'OOMKilled':True}
            partial=probe.sample_failure_cgroup(worker,owner)
            self.assertEqual(probe.result['failure_cgroup_samples'],[complete])
            self.assertEqual(probe.result['terminal_cgroup_sample'],partial)
            self.assertNotIn('cpu.max',partial);self.assertEqual(partial['memory.max'],'33554432')
            self.assertEqual(partial['memory.events'],'oom_kill 1')
            self.assertEqual(partial['unavailable_errno']['cpu.max'],2)
            self.assertTrue(verify_early_oom(self.early_oom_receipt(probe,owner,worker),'candidate')['verified'])

    def test_only_positive_counter_with_unknown_limit_cannot_prove_oom_acceptance(self):
        from run_hosted_resources import verify_early_oom
        from run_resource_failures import assert_oom_proof
        for route in ('terminal','fd'):
            for missing in ('cpu.max','memory.max'):
                with self.subTest(route=route,missing=missing),tempfile.TemporaryDirectory() as directory:
                    probe,owner,worker,cg=self.cgroup_probe(directory,mode='oom')
                    (cg/'memory.max').write_text('33554432')
                    worker['HostConfig']={'Memory':33554432,'NanoCpus':2000000000}
                    probe.sample_failure_cgroup(worker,owner)
                    if route=='fd':
                        partial=self.kernel_fd_unavailable(probe,owner,worker,cg,missing,counter='oom_kill 1')
                    else:
                        (cg/missing).unlink();(cg/'memory.events').write_text('oom_kill 1')
                        worker['State']={'Pid':0,'Running':False,'OOMKilled':True}
                        probe.wait_failure_terminal(owner,worker)
                        partial=probe.result['terminal_cgroup_sample']
                        self.assertEqual(probe.result['failure_diagnostics']['terminal_oom_kill'],1)
                    worker['State']={'Pid':0,'Running':False,'OOMKilled':True}
                    rows=probe.result['failure_cgroup_samples']
                    self.assertNotIn(partial,rows);self.assertNotIn(missing,partial)
                    self.assertEqual(partial['counter_status'],'observed')
                    self.assertEqual(partial['memory.events'],'oom_kill 1')
                    self.assertTrue(all(r['memory.events']=='oom_kill 0' for r in rows))
                    with self.assertRaisesRegex(AssertionError,'No observed real cgroup'):assert_oom_proof(rows,worker['State'])
                    with self.assertRaises(AssertionError):verify_early_oom(self.early_oom_receipt(probe,owner,worker),'candidate')

    def test_missing_counter_is_unknown_but_complete_limits_remain_visible(self):
        from run_hosted_resources import verify_early_oom
        from run_resource_failures import assert_oom_proof
        for route in ('terminal','fd'):
            for prior_positive in (False,True):
                with self.subTest(route=route,prior_positive=prior_positive),tempfile.TemporaryDirectory() as directory:
                    probe,owner,worker,cg=self.cgroup_probe(directory,mode='oom')
                    (cg/'memory.max').write_text('33554432')
                    (cg/'memory.events').write_text('oom_kill '+str(int(prior_positive)))
                    worker['HostConfig']={'Memory':33554432,'NanoCpus':2000000000}
                    complete=probe.sample_failure_cgroup(worker,owner)
                    if route=='fd':unknown=self.kernel_fd_unavailable(probe,owner,worker,cg,'memory.events')
                    else:
                        (cg/'memory.events').unlink();worker['State']={'Pid':0,'Running':False,'OOMKilled':True}
                        unknown=probe.sample_failure_cgroup(worker,owner)
                    worker['State']={'Pid':0,'Running':False,'OOMKilled':True}
                    rows=probe.result['failure_cgroup_samples']
                    self.assertIn(complete,rows);self.assertIn(unknown,rows)
                    self.assertEqual(unknown['counter_status'],'unavailable');self.assertEqual(unknown['memory.events'],'')
                    self.assertIn('memory.events',unknown['unavailable_errno'])
                    self.assertEqual(unknown['cpu.max'],'200000 100000');self.assertEqual(unknown['memory.max'],'33554432')
                    raw=self.early_oom_receipt(probe,owner,worker)
                    if prior_positive:
                        self.assertTrue(verify_early_oom(raw,'candidate')['verified'])
                        self.assertEqual(assert_oom_proof(rows,worker['State']),1)
                    else:
                        with self.assertRaises(AssertionError):verify_early_oom(raw,'candidate')
                        with self.assertRaises(AssertionError):assert_oom_proof(rows,worker['State'])
                    worker['State']['OOMKilled']=False
                    with self.assertRaises(AssertionError):verify_early_oom(raw,'candidate')
                    with self.assertRaises(AssertionError):assert_oom_proof(rows,worker['State'])

    def assert_observer_limit_failure(self,probe,code):
        import json
        from run_resource_probe import Probe
        errors=probe.result.get('fast_observer_errors',[])
        self.assertEqual(len(errors),1,'an observed contradiction must become fatal, not be discarded')
        self.assertEqual(errors[0]['code'],code)
        self.assertEqual(errors[0]['type'],'AssertionError')
        self.assertEqual(errors[0]['reason'],'cgroup_identity')
        self.assertNotIn('PRIVATE-CANARY',json.dumps(errors))
        with patch.object(Probe,'gate') as gate:
            with self.assertRaisesRegex(AssertionError,'observer_failure'):probe.gate('contradictory-limit')
            gate.assert_not_called()
        self.assertFalse(any(thread.is_alive() for _,thread in getattr(probe,'_failure_observers',[])))

    def test_any_available_contradictory_limit_is_fatal_across_readers_and_modes(self):
        import copy,json
        from types import SimpleNamespace
        from unittest.mock import Mock
        modes={'oom':'33554432','oom-active':'536870912','enospc':'536870912'}
        for route in ('live','terminal','fd','fast-live','fast-terminal','settling','fast-settling'):
            for mode,memory in modes.items():
                for name,wrong in (('cpu.max','100000 100000'),('memory.max','999')):
                    other='memory.max' if name=='cpu.max' else 'cpu.max'
                    for missing in (None,other,'memory.events','memory.swap.max'):
                        for value in (wrong,'','PRIVATE-CANARY'):
                            with self.subTest(route=route,mode=mode,name=name,missing=missing,value=value),tempfile.TemporaryDirectory() as directory:
                                probe,owner,worker,cg=self.cgroup_probe(directory,mode=mode)
                                (cg/'memory.max').write_text(memory);(cg/'memory.events').write_text('oom_kill 1')
                                # Prior proof and even misleading HostConfig cannot
                                # excuse a later contrary actual kernel observation.
                                worker['HostConfig']={'Memory':999,'NanoCpus':999}
                                probe.sample_failure_cgroup(worker,owner)
                                if mode=='oom-active':
                                    (cg/'memory.max').write_text('16777216');probe.sample_failure_cgroup(worker,owner)
                                prior=list(probe.result['failure_cgroup_samples'])
                                terminal=copy.deepcopy(worker);terminal['State'].update(Running=False,Pid=0,OOMKilled=True)
                                if route=='fd':
                                    row=self.kernel_fd_unavailable(probe,owner,worker,cg,missing,remaining=(name,value))
                                    self.assertEqual(row[name],value)
                                    self.assert_observer_limit_failure(probe,'kernel_reader_failure')
                                else:
                                    (cg/name).write_text(value)
                                    if missing is not None:(cg/missing).unlink()
                                    def erase_before_terminal(*args,**kwargs):
                                        for file in cg.iterdir():file.unlink()
                                        return terminal
                                    probe.e.inspect=Mock(side_effect=erase_before_terminal)
                                    observed=terminal if route.endswith('terminal') else worker
                                    settling=route.endswith('settling')
                                    if settling:
                                        resolutions=iter([None,cg])
                                        probe.cgroup=Mock(side_effect=lambda *args,**kwargs:next(resolutions,cg))
                                        replies=iter([worker])
                                        def settle_inspect(*args,**kwargs):
                                            try:return next(replies)
                                            except StopIteration:return erase_before_terminal(*args,**kwargs)
                                        probe.e.inspect=Mock(side_effect=settle_inspect)
                                    if route.startswith('fast-'):
                                        (probe.root/'state').mkdir();(probe.root/'state/owner.json').write_text(json.dumps(owner))
                                        probe.args=SimpleNamespace(mode=mode);probe.result.update(owner_history=[],restic_effective_env=[])
                                        probe.pids=Mock(return_value=[])
                                        replies=iter([observed,observed]+([worker] if settling else []))
                                        def inspect(*args,**kwargs):
                                            try:return next(replies)
                                            except StopIteration:return erase_before_terminal(*args,**kwargs)
                                        probe.e.inspect=Mock(side_effect=inspect)
                                        waits=iter([False,True]);probe.observe_fast(SimpleNamespace(wait=lambda _:next(waits)))
                                        self.assert_observer_limit_failure(probe,'observer_failure')
                                        self.assertEqual(probe.e.inspect.call_count,3 if settling else 2,'contradiction must fail before any further gap reinspection')
                                    else:
                                        with self.assertRaisesRegex(AssertionError,'^cgroup_identity$'):probe.sample_failure_cgroup(observed,owner)
                                        self.assertEqual(probe.e.inspect.call_count,1 if settling else 0)
                                rows=probe.result['failure_cgroup_samples']
                                self.assertEqual(rows[:len(prior)],prior)
                                if route=='fd':
                                    # Arming makes one additional genuine complete
                                    # read before the injected FD transition.
                                    self.assertEqual(len(rows),len(prior)+1)
                                    self.assertEqual(rows[-1]['cpu.max'],'200000 100000')
                                    self.assertEqual(rows[-1]['memory.max'],'16777216' if mode=='oom-active' else memory)
                                else:self.assertEqual(rows,prior)
                                self.assertTrue(all(row[name]!=value for row in rows),'invalid rows must not be admitted even alongside fatal errors')

    def test_settling_contradiction_is_fatal_before_post_read_gap_exits(self):
        from unittest.mock import Mock
        for mode,memory in (('oom','33554432'),('oom-active','536870912'),('enospc','536870912')):
            for name,wrong in (('cpu.max','100000 100000'),('memory.max','999')):
                for value in (wrong,'','PRIVATE-CANARY'):
                    for exit in ('directory-disappears','proc-disappears'):
                        with self.subTest(mode=mode,name=name,value=value,exit=exit),tempfile.TemporaryDirectory() as directory:
                            probe,owner,worker,cg=self.cgroup_probe(directory,mode=mode)
                            (cg/'memory.max').write_text(memory);probe.sample_failure_cgroup(worker,owner)
                            prior=list(probe.result['failure_cgroup_samples']);(cg/name).write_text(value)
                            # Enter real bounded settling from an initial missing
                            # /proc path, then lose identity AFTER reading a bad row.
                            probe.e.inspect=Mock(return_value=worker)
                            resolutions=[]
                            def cgroup(*args,**kwargs):
                                resolutions.append(args)
                                if len(resolutions)==1:return None
                                if exit=='proc-disappears' and len(resolutions)==3:
                                    (cg/name).write_text('200000 100000' if name=='cpu.max' else memory)
                                    return None
                                return cg
                            probe.cgroup=Mock(side_effect=cgroup)
                            stat=Path.stat;stats=[]
                            def directory_stat(path,*args,**kwargs):
                                if path==cg:
                                    stats.append(path)
                                    if exit=='directory-disappears' and len(stats)==2:
                                        (cg/name).write_text('200000 100000' if name=='cpu.max' else memory)
                                        raise FileNotFoundError(2,'synthetic gap')
                                return stat(path,*args,**kwargs)
                            with patch.object(Path,'stat',directory_stat):
                                with self.assertRaisesRegex(AssertionError,'^cgroup_identity$'):probe.sample_failure_cgroup(worker,owner)
                            self.assertEqual(probe.e.inspect.call_count,1,'a contrary settling row must not reach another inspection')
                            self.assertEqual(probe.cgroup.call_count,2,'reject before post-read /proc gap')
                            self.assertEqual(len(stats),1,'reject before post-read directory gap')
                            self.assertEqual(probe.result['failure_cgroup_samples'],prior)

    def test_valid_available_limits_and_unknown_fields_remain_nonfatal_across_readers(self):
        import copy,json
        from types import SimpleNamespace
        from unittest.mock import Mock
        from run_resource_failures import assert_oom_proof
        for route in ('live','terminal','fd','fast-live','fast-terminal','settling','fast-settling'):
            for mode,memories in (('oom',('33554432',)),('oom-active',('536870912','16777216')),('enospc',('536870912',))):
                for memory in memories:
                    for missing in ('cpu.max','memory.max','memory.events','memory.swap.max'):
                        with self.subTest(route=route,mode=mode,memory=memory,missing=missing),tempfile.TemporaryDirectory() as directory:
                            probe,owner,worker,cg=self.cgroup_probe(directory,mode=mode)
                            (cg/'memory.max').write_text(memory);probe.sample_failure_cgroup(worker,owner)
                            terminal=copy.deepcopy(worker);terminal['State'].update(Running=False,Pid=0,OOMKilled=True)
                            if route=='fd':
                                row=self.kernel_fd_unavailable(probe,owner,worker,cg,missing,
                                    counter='oom_kill 1' if missing in ('cpu.max','memory.max') else None)
                            else:
                                (cg/missing).unlink()
                                if missing in ('cpu.max','memory.max'):(cg/'memory.events').write_text('oom_kill 1')
                                probe.e.inspect=Mock(return_value=terminal)
                                observed=terminal if route.endswith('terminal') else worker
                                settling=route.endswith('settling')
                                if settling:
                                    resolutions=iter([None,cg])
                                    probe.cgroup=Mock(side_effect=lambda *args,**kwargs:next(resolutions,cg))
                                    probe.e.inspect=Mock(side_effect=[worker,terminal])
                                if route.startswith('fast-'):
                                    (probe.root/'state').mkdir();(probe.root/'state/owner.json').write_text(json.dumps(owner))
                                    probe.args=SimpleNamespace(mode=mode);probe.result.update(owner_history=[],restic_effective_env=[])
                                    probe.pids=Mock(return_value=[])
                                    probe.e.inspect=Mock(side_effect=[observed,observed]+([worker] if settling else [])+[terminal])
                                    waits=iter([False,True]);probe.observe_fast(SimpleNamespace(wait=lambda _:next(waits)))
                                    row=probe.result['terminal_cgroup_sample']
                                else:row=probe.sample_failure_cgroup(observed,owner)
                            probe.stop_failure_observers()
                            self.assertFalse(probe.result.get('fast_observer_errors'))
                            if missing=='memory.events':
                                self.assertEqual(row['counter_status'],'unavailable');self.assertEqual(row['memory.events'],'')
                            else:self.assertNotIn(missing,row)
                            self.assertIn(missing,row['unavailable_errno'])
                            if missing in ('cpu.max','memory.max'):
                                self.assertNotIn(row,probe.result['failure_cgroup_samples'])
                                self.assertEqual(row['memory.events'],'oom_kill 1')
                            else:self.assertIn(row,probe.result['failure_cgroup_samples'])
                            # A genuinely positive partial diagnostic cannot borrow
                            # an old complete zero counter to establish acceptance.
                            with self.assertRaisesRegex(AssertionError,'No observed real cgroup'):
                                assert_oom_proof(probe.result['failure_cgroup_samples'],terminal['State'])

    def test_last_complete_terminal_positive_survives_later_unavailable_read(self):
        from run_hosted_resources import verify_early_oom
        from run_resource_failures import assert_oom_proof
        with tempfile.TemporaryDirectory() as directory:
            probe,owner,worker,cg=self.cgroup_probe(directory,mode='oom')
            (cg/'memory.max').write_text('33554432')
            worker['HostConfig']={'Memory':33554432,'NanoCpus':2000000000}
            probe.sample_failure_cgroup(worker,owner)
            worker['State']={'Pid':0,'Running':False,'OOMKilled':True}
            (cg/'memory.events').write_text('oom_kill 1')
            positive=probe.sample_failure_cgroup(worker,owner)
            for name in ('cpu.max','memory.max','memory.events'):(cg/name).unlink()
            unknown=probe.sample_failure_cgroup(worker,owner)
            self.assertEqual(probe.result['terminal_cgroup_sample'],unknown)
            self.assertEqual(unknown['counter_status'],'unavailable');self.assertEqual(unknown['memory.events'],'')
            self.assertIs(probe.result['failure_cgroup_samples'][-1],positive)
            self.assertEqual(positive['observer_pid'],0);self.assertEqual(positive['memory.events'],'oom_kill 1')
            self.assertEqual(assert_oom_proof(probe.result['failure_cgroup_samples'],worker['State']),1)
            self.assertTrue(verify_early_oom(self.early_oom_receipt(probe,owner,worker),'candidate')['verified'])

    def test_observer_diagnostics_are_bounded_typed_private_and_fatal(self):
        import json,threading
        from types import SimpleNamespace
        from unittest.mock import Mock
        from run_resource_probe import Probe
        with tempfile.TemporaryDirectory() as directory:
            probe,owner,worker,cg=self.cgroup_probe(directory)
            (probe.root/'state').mkdir();(probe.root/'state/owner.json').write_text(json.dumps(owner))
            probe.args=SimpleNamespace(mode='oom-active');probe.result.update(owner_history=[],restic_effective_env=[])
            probe.e.inspect=Mock(side_effect=TimeoutError(110,'PRIVATE-CANARY /private/path Env=secret'))
            waits=iter([False]*40+[True])
            probe.observe_fast(SimpleNamespace(wait=lambda _:next(waits)))
            errors=probe.result['fast_observer_errors']
            self.assertEqual(probe.result.get('fast_observer_errors_count'),40)
            self.assertEqual(len(errors),32)
            self.assertEqual(errors[0]['code'],'observer_failure')
            self.assertEqual(errors[0]['type'],'TimeoutError');self.assertEqual(errors[0]['errno'],110)
            self.assertTrue(any(f['file']=='run_resource_failures.py' and f['function']=='observe_fast' and type(f['line']) is int for f in errors[0]['frames']))
            self.assertNotIn('PRIVATE-CANARY',json.dumps(errors))
            probe.sock='/unused';probe.stopped=threading.Event()
            def sampler(p):
                for _ in range(40):
                    p.result.setdefault('sampler_errors',[]).append({'type':'OSError','message':'PRIVATE-CANARY','errno':5,
                        'frames':[{'file':'run_resource_probe.py','line':346,'function':'sampler','source':'PRIVATE-CANARY'}]*20})
            with patch.object(Probe,'sampler',sampler):probe.sampler()
            self.assertEqual(probe.result.get('sampler_errors_count'),40)
            self.assertEqual(len(probe.result['sampler_errors']),32)
            self.assertEqual(len(probe.result['sampler_errors'][0]['frames']),8)
            self.assertNotIn('PRIVATE-CANARY',json.dumps(probe.result))
            with patch.object(Probe,'gate') as gate:
                with self.assertRaisesRegex(AssertionError,'observer_failure'):probe.gate('must-remain-fatal')
                gate.assert_not_called()

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

    def test_delayed_terminal_inspect_after_missing_cgroup_is_not_false_observer_error(self):
        import copy,json,time
        from types import SimpleNamespace
        from unittest.mock import Mock
        with tempfile.TemporaryDirectory() as directory:
            probe,owner,worker,cg=self.cgroup_probe(directory)
            worker['State']['StartedAt']='2026-01-01T00:00:00Z'
            probe.sample_failure_cgroup(worker,owner)
            (probe.root/'state').mkdir();(probe.root/'state/owner.json').write_text(json.dumps(owner))
            probe.args=SimpleNamespace(mode='enospc');probe.result.update(owner_history=[],restic_effective_env=[])
            terminal=copy.deepcopy(worker);terminal['State'].update(Running=False,Pid=0,OOMKilled=False,ExitCode=1)
            probe.cgroup=Mock(return_value=None);probe.pids=Mock(return_value=[])
            # Ordinary inspect sees Running, kernel /proc is gone, first exact
            # reinspection still Running, next exact reinspection is terminal.
            probe.e.inspect=Mock(side_effect=[worker,worker,worker,terminal])
            waits=iter([False,True]);started=time.monotonic()
            probe.observe_fast(SimpleNamespace(wait=lambda _:next(waits)))
            self.assertFalse(probe.result.get('fast_observer_errors'),probe.result.get('fast_observer_errors'))
            self.assertEqual(probe.e.inspect.call_count,4)
            self.assertEqual(probe.result['terminal_cgroup_sample']['observer_pid'],0)
            bounds=[call.kwargs['deadline'] for call in probe.e.inspect.call_args_list]
            self.assertTrue(all(bound==bounds[0] for bound in bounds),'never renew the outer 1s I/O budget')
            self.assertLessEqual(bounds[0],started+1.1)

    def test_live_settle_permission_error_cannot_be_excused_by_fresh_or_terminal(self):
        import copy
        from unittest.mock import Mock
        from run_resource_probe import Probe
        for phase in ('initial-proc','settle-proc','directory','cpu.max','memory.events'):
            for outcome in ('fresh','terminal'):
                with self.subTest(phase=phase,outcome=outcome),tempfile.TemporaryDirectory() as directory:
                    probe,owner,worker,cg=self.cgroup_probe(directory)
                    probe.sample_failure_cgroup(worker,owner)
                    terminal=copy.deepcopy(worker);terminal['State'].update(Running=False,Pid=0)
                    probe.e.inspect=Mock(side_effect=[worker,terminal if outcome=='terminal' else worker])
                    read=Path.read_text;stat=Path.stat;resolutions=[0];denied=[False]
                    def cgroup(pid,**kwargs):
                        resolutions[0]+=1
                        if phase=='initial-proc' and resolutions[0]==1 or phase=='settle-proc' and resolutions[0]==2:
                            # Exercise the real resolver: non-strict mode swallows
                            # this exact /proc EACCES and lets later evidence win.
                            return Probe.cgroup(probe,pid,**kwargs)
                        if resolutions[0]==1:return None
                        return cg
                    probe.cgroup=Mock(side_effect=cgroup)
                    def read_text(path,*args,**kwargs):
                        if path==Path('/proc/123/cgroup'):
                            denied[0]=True;raise PermissionError(13,'PRIVATE-CANARY')
                        if phase==path.name and path.parent==cg and not denied[0]:
                            denied[0]=True;raise PermissionError(13,'PRIVATE-CANARY')
                        return read(path,*args,**kwargs)
                    def directory_stat(path,*args,**kwargs):
                        if phase=='directory' and path==cg and not denied[0]:
                            denied[0]=True;raise PermissionError(13,'PRIVATE-CANARY')
                        return stat(path,*args,**kwargs)
                    with patch.object(Path,'read_text',read_text),patch.object(Path,'stat',directory_stat):
                        with self.assertRaises(PermissionError):probe.sample_failure_cgroup(worker,owner)
                    self.assertTrue(denied[0])
                    self.assertEqual(len(probe.result['failure_cgroup_samples']),1)
                    self.assertNotIn('terminal_cgroup_sample',probe.result)

    def test_strict_proc_missing_errnos_settle_and_terminal_permission_stays_unknown(self):
        import copy
        from unittest.mock import Mock
        for code in (2,3,19):
            for phase in ('initial-proc','settle-proc','post-read-proc'):
                for outcome in ('fresh','terminal'):
                    with self.subTest(errno=code,phase=phase,outcome=outcome),tempfile.TemporaryDirectory() as directory:
                        probe,owner,worker,cg=self.cgroup_probe(directory);probe.sample_failure_cgroup(worker,owner)
                        terminal=copy.deepcopy(worker);terminal['State'].update(Running=False,Pid=0)
                        after=terminal if outcome=='terminal' else worker
                        probe.e.inspect=Mock(side_effect=[after] if phase=='initial-proc' else [worker,after])
                        calls=[0];fail_at={'initial-proc':1,'settle-proc':2,'post-read-proc':3}[phase]
                        def cgroup(pid,**kwargs):
                            self.assertTrue(kwargs.get('strict'),'every live resolution must be strict')
                            calls[0]+=1
                            if calls[0]==fail_at:raise OSError(code,'PRIVATE-CANARY')
                            return None if calls[0]==1 else cg
                        probe.cgroup=Mock(side_effect=cgroup)
                        row=probe.sample_failure_cgroup(worker,owner)
                        self.assertEqual(row['observer_pid'],0 if outcome=='terminal' else 123)
                        self.assertEqual(row['counter_status'],'observed')
                        self.assertEqual(len(probe.result['failure_cgroup_samples']),2)
        with tempfile.TemporaryDirectory() as directory:
            probe,owner,worker,cg=self.cgroup_probe(directory);probe.sample_failure_cgroup(worker,owner)
            terminal=copy.deepcopy(worker);terminal['State'].update(Running=False,Pid=0)
            read=Path.read_text
            def denied_counter(path,*args,**kwargs):
                if path==cg/'memory.events':raise PermissionError(13,'PRIVATE-CANARY')
                return read(path,*args,**kwargs)
            with patch.object(Path,'read_text',denied_counter):row=probe.sample_failure_cgroup(terminal,owner)
            self.assertEqual(row['counter_status'],'unavailable');self.assertEqual(row['memory.events'],'')
            self.assertEqual(row['unavailable_errno']['memory.events'],13)

    def test_settle_reinspections_share_absolute_budget_on_real_unix_socket(self):
        import copy,time
        from unittest.mock import Mock
        from test_engine_deadline import peer,reply,trickle
        def stalled(conn,stopped):stopped.wait(2)
        def stalled_body(conn,stopped):
            conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\n{');stopped.wait(2)
        for mode in ('headers','body','trickle','late-terminal'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as directory:
                probe,owner,worker,cg=self.cgroup_probe(directory);probe.sample_failure_cgroup(worker,owner)
                terminal=copy.deepcopy(worker);terminal['State'].update(Running=False,Pid=0)
                script={'headers':stalled,'body':stalled_body,
                        'trickle':trickle(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}'),
                        'late-terminal':reply(terminal,delay=.3)}[mode]  # pyright: ignore[reportArgumentType]
                probe.cgroup=Mock(return_value=None)
                with peer([reply(worker,delay=.12),script]) as (engine,requests):  # pyright: ignore[reportArgumentType]
                    probe.e=engine  # pyright: ignore[reportAttributeAccessIssue]
                    started=time.monotonic()
                    with self.assertRaises(TimeoutError):probe.sample_failure_cgroup(worker,owner,deadline=started+.3)
                    elapsed=time.monotonic()-started
                    self.assertGreaterEqual(elapsed,.28);self.assertLess(elapsed,.6)
                    self.assertEqual(requests,[b'GET /v1.55/containers/'+owner['workerContainerID'].encode()+b'/json HTTP/1.1']*2)
                self.assertEqual(len(probe.result['failure_cgroup_samples']),1)
                self.assertNotIn('terminal_cgroup_sample',probe.result)

    def test_gap_fresh_kernel_readback_is_complete_validated_and_not_cached(self):
        from unittest.mock import Mock
        for mode in ('fresh','cpu.max','memory.max','memory.swap.max','memory.events','inode-during-read','path-during-read'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as directory:
                probe,owner,worker,cg=self.cgroup_probe(directory)
                probe.sample_failure_cgroup(worker,owner)
                # Both 16 and 512 MiB are legitimate active-OOM stages; 32 MiB
                # belongs only to early OOM and is now a producer contradiction.
                (cg/'memory.max').write_text('536870912')
                if mode in ('cpu.max','memory.max','memory.swap.max','memory.events'):(cg/mode).write_text('PRIVATE-CANARY')
                probe.cgroup=Mock(side_effect=[None,cg]+[cg/'foreign' if mode=='path-during-read' else cg]*30)
                read=Path.read_text
                def read_text(path,*args,**kwargs):
                    value=read(path,*args,**kwargs)
                    if mode=='inode-during-read' and path==cg/'memory.events':
                        cg.rename(cg.with_name('retired'));cg.mkdir()
                    return value
                with patch.object(Path,'read_text',read_text):
                    if mode=='fresh':
                        row=probe.sample_failure_cgroup(worker,owner)
                        self.assertEqual(row['memory.max'],'536870912')
                        self.assertEqual(row['counter_status'],'observed')
                        self.assertEqual(len(probe.result['failure_cgroup_samples']),2)
                    else:
                        with self.assertRaisesRegex(AssertionError,'identity'):probe.sample_failure_cgroup(worker,owner)
                        self.assertEqual(len(probe.result['failure_cgroup_samples']),1)

    def test_fresh_read_disappearing_before_identity_check_still_requires_terminal(self):
        import copy
        from unittest.mock import Mock
        with tempfile.TemporaryDirectory() as directory:
            probe,owner,worker,cg=self.cgroup_probe(directory);probe.sample_failure_cgroup(worker,owner)
            terminal=copy.deepcopy(worker);terminal['State'].update(Running=False,Pid=0)
            probe.cgroup=Mock(side_effect=[None,cg]);probe.e.inspect=Mock(side_effect=[worker,terminal])
            read=Path.read_text
            def read_text(path,*args,**kwargs):
                value=read(path,*args,**kwargs)
                if path==cg/'memory.events':cg.rename(cg.with_name('retired'))
                return value
            with patch.object(Path,'read_text',read_text):
                try:row=probe.sample_failure_cgroup(worker,owner)
                except OSError:self.fail('missing kernel post-read must settle to exact terminal, not escape as an ignored observer file error')
            self.assertEqual(row['observer_pid'],0);self.assertEqual(row['counter_status'],'unavailable')
            self.assertEqual(probe.e.inspect.call_count,2)
            self.assertEqual(len(probe.result['failure_cgroup_samples']),1)

    def test_terminal_cgroup_deadline_rejects_late_reads_before_any_record_or_return(self):
        import copy
        from unittest.mock import Mock
        from run_resource_probe import kv_numbers
        for route in ('terminal','gap-terminal'):
            for phase in ('observed','unavailable','directory','before-record','already-expired','no-cache'):
                with self.subTest(route=route,phase=phase),tempfile.TemporaryDirectory() as directory:
                    probe,owner,worker,cg=self.cgroup_probe(directory);probe.sample_failure_cgroup(worker,owner)
                    terminal=copy.deepcopy(worker);terminal['State'].update(Running=False,Pid=0)
                    probe.cgroup=Mock(return_value=None);probe.e.inspect=Mock(return_value=terminal)
                    if phase=='no-cache':probe._cgroup_identities.clear()
                    before=copy.deepcopy(probe.result);clock=[10.21 if phase in ('already-expired','no-cache') else 10.0]
                    read=Path.read_text;stat=Path.stat;reads=[]
                    def read_text(path,*args,**kwargs):
                        reads.append(path);value=read(path,*args,**kwargs)
                        if path==cg/'memory.events' and phase in ('observed','unavailable'):
                            clock[0]=10.21
                            if phase=='unavailable':raise FileNotFoundError(2,'PRIVATE-CANARY')
                        return value
                    def directory_stat(path,*args,**kwargs):
                        if path==cg and phase=='directory':
                            clock[0]=10.21;raise FileNotFoundError(2,'PRIVATE-CANARY')
                        return stat(path,*args,**kwargs)
                    def parse(value):
                        result=kv_numbers(value)
                        if phase=='before-record':clock[0]=10.21
                        return result
                    with patch('run_resource_failures.time.monotonic',side_effect=lambda:clock[0]),patch.object(Path,'read_text',read_text),patch.object(Path,'stat',directory_stat),patch('run_resource_failures.kv_numbers',side_effect=parse):
                        with self.assertRaisesRegex(AssertionError,'cgroup_identity'):
                            probe.sample_failure_cgroup(terminal if route=='terminal' else worker,owner,deadline=10.2)
                    self.assertEqual(probe.result,before,'late terminal observations must leave no receipt mutation')
                    if phase in ('already-expired','no-cache'):self.assertEqual(reads,[])

    def test_gap_settle_keeps_identity_failures_and_absolute_deadline_fatal(self):
        import copy
        from unittest.mock import Mock
        for mode in ('pid','start','image','owner','id','name','daemon','path','inode','permission','unexpected-errno','timeout','expired','persistent'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as directory:
                probe,owner,worker,cg=self.cgroup_probe(directory)
                worker['State']['StartedAt']='2026-01-01T00:00:00Z';probe.sample_failure_cgroup(worker,owner)
                after=copy.deepcopy(worker);clock=[10.0];calls=[]
                if mode=='pid':after['State']['Pid']+=1
                if mode=='start':after['State']['StartedAt']='2026-01-01T00:00:01Z'
                if mode=='image':after['Image']='foreign'
                if mode=='owner':after['Config']['Labels']['bakabel.run']='d'*32
                if mode=='id':after['Id']='d'*64
                if mode=='name':after['Name']='/foreign'
                if mode=='daemon':after['Config']['Labels']['bakabel.daemon']='foreign'
                probe.cgroup=Mock(return_value=None)
                def inspect(cid,**kwargs):
                    calls.append((cid,kwargs))
                    if mode=='path':probe.cgroup=Mock(return_value=cg/'foreign')
                    if mode=='inode':
                        cg.rename(cg.with_name('retired'));cg.mkdir();probe.cgroup=Mock(return_value=cg)
                    if mode in ('permission','unexpected-errno'):raise OSError(13 if mode=='permission' else 5,'PRIVATE-CANARY')
                    if mode=='timeout':raise TimeoutError('PRIVATE-CANARY')
                    if mode=='expired':clock[0]=10.21;after['State'].update(Running=False,Pid=0)
                    return after
                probe.e.inspect=Mock(side_effect=inspect)
                with patch('run_resource_failures.time.monotonic',side_effect=lambda:clock[0]),patch('run_resource_failures.time.sleep',side_effect=lambda delay:clock.__setitem__(0,clock[0]+delay)):
                    with self.assertRaises((AssertionError,OSError)):probe.sample_failure_cgroup(worker,owner,deadline=10.2)
                self.assertTrue(calls);self.assertLessEqual(len(calls),20)
                self.assertTrue(all(cid==owner['workerContainerID'] and kw['deadline']==10.2 for cid,kw in calls))
                self.assertEqual(len(probe.result['failure_cgroup_samples']),1)
                self.assertNotIn('terminal_cgroup_sample',probe.result)

    def test_real_sampler_sanitizes_exception_at_append_without_raw_text(self):
        import json
        from unittest.mock import Mock
        with tempfile.TemporaryDirectory() as directory:
            probe,owner,worker,cg=self.cgroup_probe(directory)
            probe.sock='/unused';probe.worker_records={};probe.roles={'unit':'worker'};probe.samples=[]
            probe.stopped=Mock();probe.stopped.is_set.side_effect=[False,True]
            probe.measure=Mock(side_effect=OSError(5,'PRIVATE-CANARY /private/path Env=secret'))
            probe.sampler()
            self.assertEqual(probe.result['sampler_errors_count'],1)
            row=probe.result['sampler_errors'][0]
            self.assertEqual(row['type'],'OSError');self.assertEqual(row['errno'],5)
            self.assertEqual(row['code'],'sampler_failure')
            self.assertTrue(any(f['file']=='run_resource_probe.py' and f['function']=='sampler' for f in row['frames']))
            self.assertNotIn('PRIVATE-CANARY',json.dumps(probe.result))

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
                self.assertGreaterEqual(probe.e.inspect.call_count,2 if outcome=='still-running' else 1)
                self.assertLessEqual(probe.e.inspect.call_count,20)
                self.assertLess(time.monotonic()-started,1.15)
                self.assertTrue(all(call.args==(owner['workerContainerID'],) for call in probe.e.inspect.call_args_list))
                deadline=probe.e.inspect.call_args.kwargs.get('deadline')
                self.assertTrue(all(call.kwargs['deadline']==deadline for call in probe.e.inspect.call_args_list))
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
                    self.assertGreaterEqual(probe.e.inspect.call_count,1 if terminal else 2)
                    self.assertLessEqual(probe.e.inspect.call_count,20)

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
