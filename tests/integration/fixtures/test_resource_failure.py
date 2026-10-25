import unittest
from run_resource_failures import assert_failure_proof, minimal_space_probe
import errno
import tempfile
from pathlib import Path
from unittest.mock import patch

class FailureProof(unittest.TestCase):
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
        with tempfile.TemporaryDirectory(dir=Path.home()/'.hermes/cache/scratch') as d:
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
