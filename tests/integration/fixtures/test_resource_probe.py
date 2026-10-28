import importlib.util
from pathlib import Path
import unittest

class ProbeSafety(unittest.TestCase):
    def test_probe_fingerprint_does_not_require_internal_documents(self):
        import hashlib
        import tempfile
        from types import SimpleNamespace
        from unittest.mock import Mock, patch
        with tempfile.TemporaryDirectory(prefix='bakabel-probe-source-') as directory:
            root = Path(directory)
            source = root/'source'; source.mkdir()
            for name in ('go.mod', 'go.sum', 'Dockerfile', 'main.go'):
                (source/name).write_text('offline fixture source\n')
            minio = root/'minio'; minio.write_bytes(b'offline binary fixture')
            engine = Mock()
            engine.call.side_effect = [
                {'ID': 'offline-daemon', 'Swarm': {'LocalNodeState': 'inactive'}},
                {'Id': 'sha256:'+'a'*64},
            ]
            args = SimpleNamespace(runtime=root/'runtime', source=source,
                                   socket=root/'absent.sock', image='offline-image',
                                   minio_binary=minio)
            with patch.object(self.p, 'Engine', return_value=engine), patch.object(self.p.threading, 'Thread'):
                try:
                    probe = self.p.Probe(args, inventory_images=[])
                except FileNotFoundError:
                    self.fail('probe still requires an internal document outside its source inputs')
            expected = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
            self.assertEqual(probe.result['fingerprint'], {
                'source_files': {name: expected(source/name) for name in ('go.mod', 'go.sum', 'main.go')},
                'minio_sha256': expected(minio),
                'dockerfile_sha256': expected(source/'Dockerfile'),
                'probe_sha256': expected(Path(__file__).with_name('run_resource_probe.py')),
            })
            self.assertEqual(engine.call.call_count, 2)
            self.assertFalse(args.socket.exists())

    def test_removed_cgroup_requires_exact_container_exit_readback(self):
        import copy
        import errno
        from unittest.mock import Mock,patch
        cid='a'*64
        probe=self.p.Probe.__new__(self.p.Probe)
        live={'Id':cid,'Name':'/owned','Image':'sha256:fixture',
              'Config':{'Labels':{'probe.bakabel.owner':'owned-prefix'}},
              'State':{'Running':True,'Pid':12345,'StartedAt':'same-start'}}
        terminal=copy.deepcopy(live);terminal['State'].update(Running=False,Pid=0)
        probe.e=Mock();probe.e.inspect.side_effect=[live,live,terminal]
        probe.e.call.side_effect=[live,terminal]
        probe.result={};probe.prefix='owned-prefix';probe.containers={cid:'owned'};probe.worker_records={}
        probe.pin_container=Mock();probe.cgroup=Mock(return_value=Path('/unit-owned-cgroup')/cid)
        probe.pids=Mock(return_value=[])
        with patch.object(Path,'stat',return_value=Mock(st_dev=1,st_ino=1)),patch.object(Path,'read_text',side_effect=OSError(errno.ENODEV,'unit-only deleted cgroup')):
            self.assertIsNone(probe.measure(cid,'controller'))
        self.assertEqual(probe.result['sampler_gaps'][0]['errno'],errno.ENODEV)
        self.assertEqual(probe.result['sampler_gaps'][0]['resolution'],'terminal_stopped')
        self.assertEqual(probe.e.call.call_count,2)

    def test_disappearing_state_file_is_an_explicit_footprint_gap(self):
        from unittest.mock import Mock,patch
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            entry=Mock();entry.is_file.return_value=True
            entry.stat.side_effect=FileNotFoundError(2,'unit-only atomic rename race')
            with patch.object(Path,'rglob',return_value=iter([entry])):result=self.p.footprint(directory)
            self.assertEqual(result['files'],0)
            self.assertEqual(result['unlinked_during_sample'],1)
            entry.stat.side_effect=PermissionError(13,'unit-only inaccessible file')
            with patch.object(Path,'rglob',return_value=iter([entry])),self.assertRaises(PermissionError):self.p.footprint(directory)

    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location('probe', Path(__file__).with_name('run_resource_probe.py'))
        cls.p = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.p)
    def test_worker_identity_requires_all_durable_fields(self):
        owner={'workerContainerID':'a'*64,'workerName':'bakabel-worker-'+('b'*32),'runID':'b'*32,'daemonID':'daemon'}
        obj={'Id':'a'*64,'Name':'/'+owner['workerName'],'Image':'image','Config':{'Labels':{'bakabel.worker':'1','bakabel.run':'b'*32,'bakabel.daemon':'daemon'}}}
        self.assertTrue(self.p.worker_owned(obj, owner, 'image', 'daemon'))
        for key in ['bakabel.worker','bakabel.run','bakabel.daemon']:
            other={**obj,'Config':{'Labels':dict(obj['Config']['Labels'])}}
            other['Config']['Labels'][key]='wrong'
            self.assertFalse(self.p.worker_owned(other, owner, 'image','daemon'))
        self.assertFalse(self.p.worker_owned(obj, owner,'other','daemon'))
    def test_cgroup_parse_ignores_non_numeric_and_retains_values(self):
        self.assertEqual(self.p.kv_numbers('usage_usec 12\nuser_usec 8\nnonsense\n'), {'usage_usec':12,'user_usec':8})
    def test_cgroup_exit_race_is_absent_not_fatal(self):
        from unittest.mock import patch
        probe=self.p.Probe.__new__(self.p.Probe)
        with patch.object(Path, 'read_text', side_effect=ProcessLookupError(3,'No such process')):
            self.assertIsNone(probe.cgroup(123))
    def test_cgroup_deleted_mount_exit_race_is_absent_not_fatal(self):
        from unittest.mock import patch
        probe=self.p.Probe.__new__(self.p.Probe)
        with patch.object(probe, 'cgroup', return_value=Path('/synthetic-cgroup')):
            with patch.object(Path, 'read_text', side_effect=OSError(19,'No such device')):
                self.assertEqual(probe.pids(123),[])
    def test_current_caps_are_kernel_enforced_and_no_cpuset(self):
        import verify_resource_probe as v
        w={'HostConfig':{'NanoCpus':2000000000,'Memory':536870912,'CpusetCpus':''}}
        rows=[{'cpu.max':'200000 100000','memory.max':'536870912'}]
        v.assert_worker_resources(w,rows)
        for change in [{'memory.max':'max'},{'cpu.max':'max 100000'}]:
            with self.assertRaises(AssertionError): v.assert_worker_resources(w,[{**rows[0],**change}])
        with self.assertRaises(AssertionError):
            v.assert_worker_resources({'HostConfig':{**w['HostConfig'],'Memory':0}},rows)
    def test_memory_rollup_units(self):
        self.assertEqual(self.p.rollup('Rss: 12 kB\nPss: 7 kB\nPrivate_Dirty: 4 kB\n'), {'Rss':12288,'Pss':7168,'Private_Dirty':4096})


class CgroupSettlingTests(unittest.TestCase):
    """Synthetic kernel/Engine observations, never hosted acceptance evidence."""
    def setUp(self):
        import copy
        import tempfile
        import run_resource_probe as resource
        from unittest.mock import Mock
        self.p=resource;self.copy=copy.deepcopy;self.Mock=Mock
        self.directory=tempfile.TemporaryDirectory();self.addCleanup(self.directory.cleanup)
        self.cid='a'*64;self.cg=Path(self.directory.name)/self.cid;self.cg.mkdir()
        self.kernel={'cpu.max':'200000 100000','cpu.stat':'usage_usec 12\nuser_usec 8\nsystem_usec 4',
                     'memory.current':'1024','memory.peak':'2048','memory.max':'536870912',
                     'memory.events':'low 0\nhigh 0\nmax 0\noom 0\noom_kill 0',
                     'io.stat':'8:0 rbytes=10 wbytes=20 rios=1 wios=2','pids.current':'1'}
        for name,value in self.kernel.items():(self.cg/name).write_text(value)
        self.live={'Id':self.cid,'Name':'/owned','Image':'sha256:fixture',
                   'Config':{'Labels':{'probe.bakabel.owner':'owned-prefix'}},
                   'State':{'Running':True,'Pid':12345,'StartedAt':'same-start'}}
        self.read_text=Path.read_text

    def probe(self, cls=None):
        probe=(cls or self.p.Probe).__new__(cls or self.p.Probe)
        probe.root=Path(self.directory.name);probe.result={};probe.prefix='owned-prefix'
        probe.containers={self.cid:'owned'};probe.worker_records={};probe.capacity={}
        backend=self.Mock();backend.inspect.return_value=self.copy(self.live)
        backend.call.return_value=self.copy(self.live);probe.e=backend
        probe.pin_container=self.Mock();probe.cgroup=self.Mock(return_value=self.cg)
        probe.pids=self.Mock(return_value=[])
        return probe,backend

    def missing_once(self, target='cpu.max', code=19):
        failed=False
        def read(path,*args,**kwargs):
            nonlocal failed
            if path==self.cg/target and not failed:
                failed=True
                raise OSError(code,'synthetic private error sentinel')
            return self.read_text(path,*args,**kwargs)
        return read

    def test_retry_identity_drift_is_never_a_gap_resolution(self):
        from unittest.mock import patch
        for stopped in (False,True):
            fields=['Id','Image','Name','StartedAt','owner']+([] if stopped else ['Pid'])
            for field in fields:
                with self.subTest(stopped=stopped,field=field):
                    probe,backend=self.probe();after=self.copy(self.live)
                    if stopped:after['State'].update(Running=False,Pid=0)
                    if field in ('Pid','StartedAt'):after['State'][field]=23456 if field=='Pid' else 'new-start'
                    elif field=='owner':after['Config']['Labels']['probe.bakabel.owner']='foreign'
                    else:after[field]='changed'
                    backend.call.return_value=after
                    with patch.object(Path,'read_text',self.missing_once()),self.assertRaises((OSError,ValueError)):
                        probe.measure(self.cid,'controller')
                    self.assertEqual(probe.result['sampler_gaps'][0]['resolution'],'failed')

    def test_missing_sibling_errnos_require_the_same_bounded_proof(self):
        import errno
        from unittest.mock import patch
        for code in (errno.ENOENT,errno.ESRCH):
            for name in self.kernel:
                with self.subTest(errno=code,file=name):
                    probe,backend=self.probe();terminal=self.copy(self.live)
                    terminal['State'].update(Running=False,Pid=0)
                    backend.call.side_effect=[self.copy(self.live),terminal]
                    def read(path,*args,**kwargs):
                        if path==self.cg/name:raise OSError(code,'synthetic missing')
                        return self.read_text(path,*args,**kwargs)
                    with patch.object(Path,'read_text',read):
                        self.assertIsNone(probe.measure(self.cid,'controller'))
                    self.assertEqual(probe.result['sampler_gaps'][0]['inspections'],2)

    def test_recovered_kernel_must_be_valid_not_an_error_marker(self):
        from unittest.mock import patch
        invalid={'cpu.max':'FileNotFoundError','cpu.stat':'usage_usec broken',
                 'memory.current':'-1','memory.peak':'not measured','memory.max':'PermissionError',
                 'memory.events':'oom_kill unknown','io.stat':'8:0 rbytes=broken','pids.current':'unknown'}
        for name,value in invalid.items():
            with self.subTest(file=name):
                probe,_=self.probe();old=(self.cg/name).read_text();(self.cg/name).write_text(value)
                try:
                    with patch.object(Path,'read_text',self.missing_once()),self.assertRaises((OSError,ValueError)):
                        probe.measure(self.cid,'controller')
                    self.assertEqual(probe.result['sampler_gaps'][0]['resolution'],'failed')
                finally:(self.cg/name).write_text(old)

    def test_same_path_cgroup_inode_drift_is_not_fresh_recovery(self):
        from unittest.mock import patch
        probe,_=self.probe();original=self.cg.stat()
        changed=self.Mock(st_dev=original.st_dev,st_ino=original.st_ino+1)
        with patch.object(Path,'read_text',self.missing_once()),patch.object(Path,'stat',side_effect=[original,changed]),self.assertRaises((OSError,ValueError)):
            probe.measure(self.cid,'controller')

    def test_all_eight_reads_recover_fresh_in_both_sampler_callers(self):
        from run_compose_pg_acceptance import ComposeProbe
        from run_hosted_capacity import CapacityProbe
        from unittest.mock import patch
        for cls in (ComposeProbe,CapacityProbe):
            for target in self.kernel:
                with self.subTest(caller=cls.__name__,file=target):
                    probe,backend=self.probe(cls);missing=False;fresh=[]
                    def read(path,*args,**kwargs):
                        nonlocal missing
                        if path==self.cg/target and not missing:
                            missing=True;raise OSError(19,'private synthetic marker')
                        if missing:fresh.append(path.name)
                        elif path.name=='cpu.max':return '100000 100000'
                        elif path.name=='memory.max':return '268435456'
                        return self.read_text(path,*args,**kwargs)
                    with patch.object(Path,'read_text',read):row=probe.measure(self.cid,'controller')
                    self.assertEqual({key:row[key] for key in self.kernel},self.kernel)
                    self.assertEqual(fresh,list(self.kernel))
                    self.assertEqual(probe.result['sampler_gaps'][0]['resolution'],'fresh-kernel-read')
                    self.assertEqual(backend.call.call_count,1)
                    self.assertEqual(backend.call.call_args.args,('GET','/containers/'+self.cid+'/json'))
                    self.assertTrue(backend.call.call_args.kwargs['missing'])
                    self.assertIn('deadline',backend.call.call_args.kwargs)
                    probe.pin_container.assert_called_once_with(self.cid)

    def test_all_eight_missing_reads_resolve_only_after_terminal_retry(self):
        from run_compose_pg_acceptance import ComposeProbe
        from run_hosted_capacity import CapacityProbe
        from unittest.mock import patch
        for cls in (ComposeProbe,CapacityProbe):
            for target in self.kernel:
                for absent in (False,True):
                    with self.subTest(caller=cls.__name__,file=target,absent=absent):
                        probe,backend=self.probe(cls);terminal=self.copy(self.live)
                        terminal['State'].update(Running=False,Pid=0)
                        backend.call.side_effect=[self.copy(self.live),None if absent else terminal]
                        def read(path,*args,**kwargs):
                            if path==self.cg/target:raise OSError(19,'private synthetic marker')
                            return self.read_text(path,*args,**kwargs)
                        with patch.object(Path,'read_text',read):
                            self.assertIsNone(probe.measure(self.cid,'controller'))
                        gap=probe.result['sampler_gaps'][0]
                        self.assertEqual(gap['resolution'],'terminal_absent' if absent else 'terminal_stopped')
                        self.assertEqual(gap['inspections'],2)

    def test_persistent_live_enodev_fails_with_one_budget_and_twenty_inspects(self):
        import json
        from unittest.mock import patch
        probe,backend=self.probe();clock=[100.0];sleeps=[]
        def sleep(delay):sleeps.append(delay);clock[0]+=delay
        error=OSError(19,'private synthetic marker')
        with patch.object(self.p.time,'monotonic',side_effect=lambda:clock[0]),patch.object(self.p.time,'sleep',sleep),patch.object(Path,'read_text',side_effect=error):
            with self.assertRaises(OSError) as failure:probe.measure(self.cid,'controller')
        self.assertIs(failure.exception,error)
        self.assertEqual(backend.call.call_count,20)
        self.assertEqual({call.kwargs['deadline'] for call in backend.call.call_args_list},{101.0})
        self.assertTrue(all(0<delay<=.05 for delay in sleeps))
        self.assertLessEqual(clock[0]-100.0,1.0)
        gap=probe.result['sampler_gaps'][0]
        self.assertEqual(gap['resolution'],'failed');self.assertEqual(gap['inspections'],20)
        self.assertIs(type(gap['errno']),int);self.assertIs(type(gap['elapsed_ms']),int)
        self.assertNotIn('private synthetic marker',json.dumps(gap,allow_nan=False))

    def test_nonmissing_errors_propagate_without_retry_or_gap(self):
        import errno
        from unittest.mock import patch
        for code in (errno.EIO,errno.EACCES,errno.EPERM,errno.EINVAL):
            for name in self.kernel:
                with self.subTest(errno=code,file=name):
                    probe,backend=self.probe();error=OSError(code,'private error')
                    def read(path,*args,**kwargs):
                        if path==self.cg/name:raise error
                        return self.read_text(path,*args,**kwargs)
                    with patch.object(Path,'read_text',read),self.assertRaises(OSError) as failure:
                        probe.measure(self.cid,'controller')
                    self.assertIs(failure.exception,error);backend.call.assert_not_called()
                    self.assertNotIn('sampler_gaps',probe.result)

    def test_nonmissing_error_during_recovery_stays_failure(self):
        from unittest.mock import patch
        probe,_=self.probe();errors=iter([OSError(19,'missing'),OSError(5,'private EIO')])
        with patch.object(Path,'read_text',side_effect=lambda *a:(_ for _ in ()).throw(next(errors))),self.assertRaises(OSError) as failure:
            probe.measure(self.cid,'controller')
        self.assertEqual(failure.exception.errno,5)
        self.assertEqual(probe.result['sampler_gaps'][0]['resolution'],'failed')

    def test_missing_cgroup_during_settling_can_resolve_terminal(self):
        from unittest.mock import patch
        probe,backend=self.probe();terminal=self.copy(self.live);terminal['State'].update(Running=False,Pid=0)
        backend.call.side_effect=[self.copy(self.live),terminal]
        probe.cgroup.side_effect=[self.cg,None]
        with patch.object(Path,'read_text',self.missing_once()):
            self.assertIsNone(probe.measure(self.cid,'controller'))
        self.assertEqual(probe.result['sampler_gaps'][0]['resolution'],'terminal_stopped')

    def test_delayed_terminal_reply_cannot_resolve_an_expired_budget(self):
        from unittest.mock import patch
        probe,backend=self.probe();clock=[100.0]
        def delayed(*args,**kwargs):clock[0]+=1.01;return None
        backend.call.side_effect=delayed
        with patch.object(self.p.time,'monotonic',side_effect=lambda:clock[0]),patch.object(Path,'read_text',side_effect=OSError(19,'missing')),self.assertRaises(OSError):
            probe.measure(self.cid,'controller')
        self.assertEqual(probe.result['sampler_gaps'][0]['resolution'],'failed')

    def test_retry_inspects_enforce_shared_absolute_second_on_real_unix_io(self):
        import time
        from test_engine_deadline import peer,reply,trickle
        from run_hosted_capacity import CapacityProbe
        from unittest.mock import patch
        def stalled(conn,stopped):stopped.wait(2)
        def stalled_body(conn,stopped):
            conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\n{');stopped.wait(2)
        cases=[stalled,stalled_body,
               trickle(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}'),
               trickle(b'"'+b'x'*38+b'"',b'HTTP/1.1 200 OK\r\nContent-Length: 40\r\n\r\n'),
               reply(None,delay=.65,status=404)]
        for script in cases:
            with self.subTest(script=script.__name__),peer([reply(self.live),reply(self.live,delay=.55),script]) as (engine,requests):
                probe,_=self.probe(CapacityProbe);probe.e=engine
                started=time.monotonic()
                with patch.object(Path,'read_text',side_effect=OSError(19,'private synthetic marker')),self.assertRaises((OSError,ValueError)):
                    probe.measure(self.cid,'controller')
                elapsed=time.monotonic()-started
                self.assertGreaterEqual(elapsed,.9);self.assertLess(elapsed,1.2)
                self.assertEqual(requests,[b'GET /v1.55/containers/'+self.cid.encode()+b'/json HTTP/1.1']*3)
                self.assertEqual(probe.result['sampler_gaps'][0]['resolution'],'failed')

    def test_retry_proc_cgroup_permission_is_not_reclassified_missing(self):
        from unittest.mock import patch
        probe,backend=self.probe()
        def cgroup(pid,**kwargs):
            if kwargs.get('strict'):return self.p.Probe.cgroup(probe,pid,strict=True)
            # Current code calls without strict and silently hides permissions.
            if backend.call.call_count:return None
            return self.cg
        probe.cgroup=cgroup
        def read(path,*args,**kwargs):
            if path==Path('/proc/12345/cgroup'):raise PermissionError(13,'private permission marker')
            return self.missing_once_read(path,*args,**kwargs)
        self.missing_once_read=self.missing_once()
        terminal=self.copy(self.live);terminal['State'].update(Running=False,Pid=0)
        backend.call.side_effect=[self.copy(self.live),terminal]
        with patch.object(Path,'read_text',read),self.assertRaises(PermissionError):
            probe.measure(self.cid,'controller')
        self.assertEqual(backend.call.call_count,1)
        self.assertEqual(probe.result['sampler_gaps'][0]['resolution'],'failed')

    def test_owned_worker_recovers_but_foreign_or_unowned_identity_does_not(self):
        from unittest.mock import patch
        for ownership in ('owned-worker','foreign-worker','unowned'):
            with self.subTest(ownership=ownership):
                probe,backend=self.probe();probe.containers={}
                if ownership!='unowned':
                    probe.daemon='daemon';probe.image=self.live['Image']
                    probe.worker_records={self.cid:{'Name':'/owned','runID':'run'}}
                    obj=self.copy(self.live)
                    obj['Config']['Labels']={'bakabel.worker':'1','bakabel.run':'run','bakabel.daemon':'daemon'}
                    backend.inspect.return_value=obj;backend.call.return_value=self.copy(obj)
                    if ownership=='foreign-worker':backend.call.return_value['Config']['Labels']['bakabel.run']='foreign'
                with patch.object(Path,'read_text',self.missing_once()):
                    if ownership=='owned-worker':self.assertIsNotNone(probe.measure(self.cid,'controller'))
                    else:
                        with self.assertRaises(ValueError):probe.measure(self.cid,'controller')
                        self.assertEqual(probe.result['sampler_gaps'][0]['resolution'],'failed')
                if ownership=='unowned':backend.call.assert_not_called()

    def test_gap_history_is_finite_redacted_and_keeps_prior_sampler_errors(self):
        import json
        from unittest.mock import patch
        probe,backend=self.probe();backend.call.return_value=None
        prior=[{'type':'PriorFailure','errno':5}];probe.result['sampler_errors']=prior.copy()
        with patch.object(Path,'read_text',side_effect=OSError(19,'private synthetic marker')):
            for _ in range(70):self.assertIsNone(probe.measure(self.cid,'controller'))
        self.assertEqual(len(probe.result['sampler_gaps']),64)
        self.assertEqual(probe.result['sampler_errors'],prior)
        for gap in probe.result['sampler_gaps']:
            self.assertEqual(set(gap),{'container','at','reason','errno','resolution','inspections','elapsed_ms'})
            self.assertEqual(gap['resolution'],'terminal_absent')
            self.assertIs(type(gap['errno']),int);self.assertIs(type(gap['inspections']),int)
            self.assertIs(type(gap['elapsed_ms']),int)
        self.assertNotIn('private synthetic marker',json.dumps(probe.result['sampler_gaps'],allow_nan=False))

    def test_engine_error_during_settling_remains_failure(self):
        from unittest.mock import patch
        probe,backend=self.probe();error=RuntimeError('private engine marker');error.http_status=503
        backend.call.side_effect=error
        with patch.object(Path,'read_text',side_effect=OSError(19,'missing')),self.assertRaises(RuntimeError) as failure:
            probe.measure(self.cid,'controller')
        self.assertIs(failure.exception,error)
        self.assertEqual(probe.result['sampler_gaps'][0]['resolution'],'failed')

    def test_live_inode_drift_cannot_be_excused_by_later_terminal(self):
        from unittest.mock import patch
        probe,backend=self.probe();original=self.cg.stat()
        changed=self.Mock(st_dev=original.st_dev,st_ino=original.st_ino+1)
        terminal=self.copy(self.live);terminal['State'].update(Running=False,Pid=0)
        backend.call.side_effect=[self.copy(self.live),terminal]
        with patch.object(Path,'read_text',side_effect=OSError(19,'missing')),patch.object(Path,'stat',side_effect=[original,changed]),self.assertRaises(ValueError):
            probe.measure(self.cid,'controller')
        self.assertEqual(backend.call.call_count,1)
        self.assertEqual(probe.result['sampler_gaps'][0]['resolution'],'failed')

    def test_same_pid_cgroup_path_drift_is_not_fresh_recovery(self):
        from unittest.mock import patch
        probe,_=self.probe()
        probe.cgroup.side_effect=[self.cg,self.cg.parent/'foreign']
        with patch.object(Path,'read_text',self.missing_once()),self.assertRaises((OSError,ValueError)):
            probe.measure(self.cid,'controller')


if __name__ == '__main__': unittest.main()
