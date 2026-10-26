import importlib.util
from pathlib import Path
import unittest

class ProbeSafety(unittest.TestCase):
    def test_removed_cgroup_requires_exact_container_exit_readback(self):
        import errno
        from unittest.mock import Mock,patch
        probe=self.p.Probe.__new__(self.p.Probe)
        live={'State':{'Running':True,'Pid':12345}}
        probe.e=Mock();probe.e.inspect.side_effect=[live,{'State':{'Running':False,'Pid':0}}]
        probe.result={};probe.pin_container=Mock();probe.cgroup=Mock(return_value=Path('/unit-owned-cgroup'))
        probe.pids=Mock(return_value=[])
        with patch.object(Path,'read_text',side_effect=OSError(errno.ENODEV,'unit-only deleted cgroup')):
            self.assertIsNone(probe.measure('unit-owned-container','worker'))
        self.assertEqual(probe.result['sampler_gaps'][0]['errno'],errno.ENODEV)
        probe.e.inspect.side_effect=[live,live]
        with patch.object(Path,'read_text',side_effect=OSError(errno.ENODEV,'unit-only unexplained device error')),self.assertRaises(OSError):
            probe.measure('unit-owned-container','worker')

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
if __name__ == '__main__': unittest.main()
