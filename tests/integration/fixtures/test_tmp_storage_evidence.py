"""Offline tmp-filesystem diagnostics; not hosted capacity/ENOSPC evidence."""
import errno
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import run_hosted_capacity as c


class TmpStorageEvidenceTests(unittest.TestCase):
    def test_worker_measurement_projects_exact_tmp_filesystem_bytes(self):
        raw = {'at': '2026-01-01T00:00:00+00:00', 'monotonic': 1,
               'role': 'worker', 'container': 'a'*64, 'main_pid': 12345,
               'private_canary': 'PRIVATE-TMP-CANARY'}
        probe = c.CapacityProbe.__new__(c.CapacityProbe)
        probe.root = Path('/owned-fixture')
        probe.worker_records = {'a'*64: {'state': 'state'}}
        # Distinct free/available counts prove used is not capacity-available.
        vfs = SimpleNamespace(f_blocks=100, f_bfree=40, f_bavail=30, f_frsize=4096)
        with patch.object(c.Probe, 'measure', return_value=raw), \
                patch.object(c, 'footprint', return_value={'bytes': 0}), \
                patch.object(c.os, 'statvfs', return_value=vfs) as statvfs:
            measured = probe.measure('a'*64, 'worker')
        statvfs.assert_called_once_with(Path('/proc/12345/root/tmp'))
        expected = {'tmp_capacity_bytes': 409600, 'tmp_available_bytes': 122880,
                    'tmp_used_bytes': 245760}
        for key, value in expected.items():
            self.assertEqual(measured.get(key), value)
        projected = c.project_sample(measured)
        for key, value in expected.items():
            self.assertEqual(projected.get(key), value)
            self.assertIs(type(projected[key]), int)
        self.assertNotIn('PRIVATE-TMP-CANARY', json.dumps(projected))
        self.assertNotIn('12345', json.dumps(projected))

    def test_summary_extrema_ignore_unknown_without_inventing_zero_or_enospc(self):
        raw = {'at': '2026-01-01T00:00:00+00:00', 'monotonic': 1,
               'role': 'worker', 'container': 'a'*64}
        unknown = c.project_sample(raw)
        observed = c.project_sample({**raw, 'monotonic': 2,
                                    'tmp_available_bytes': 4096, 'tmp_used_bytes': 8192})
        later = c.project_sample({**raw, 'monotonic': 3,
                                 'tmp_available_bytes': 2048, 'tmp_used_bytes': 10240})
        summary = c.summarize_samples([unknown, later, observed])
        row = summary['containers'][0]
        self.assertEqual(row.get('sampled_tmp_available_bytes_min'), 2048)
        self.assertEqual(row.get('sampled_tmp_used_bytes_peak'), 10240)
        missing = c.summarize_samples([unknown])['containers'][0]
        for key in ('sampled_tmp_available_bytes_min', 'sampled_tmp_used_bytes_peak'):
            self.assertIn(key, missing)
            self.assertIsNone(missing[key])
        zero = c.project_sample({**raw, 'tmp_available_bytes': 0, 'tmp_used_bytes': 0})
        row = c.summarize_samples([unknown, zero])['containers'][0]
        self.assertEqual(row['sampled_tmp_available_bytes_min'], 0)
        self.assertEqual(row['sampled_tmp_used_bytes_peak'], 0)
        boundary = summary.get('tmp_filesystem_boundary', '')
        for phrase in ('other files', 'open-unlinked', 'sampled', 'not continuous',
                       'zero available bytes alone does not prove ENOSPC'):
            self.assertIn(phrase, boundary)
        self.assertNotIn('failure_code', row)

    def test_projection_rejects_noninteger_or_private_tmp_values(self):
        raw = {'at': '2026-01-01T00:00:00+00:00', 'monotonic': 1,
               'role': 'worker', 'container': 'a'*64}
        for invalid in (None, True, False, -1, 1.5, '12', 'PRIVATE-TMP-CANARY',
                        {'path': 'PRIVATE-TMP-CANARY'}, ['PRIVATE-TMP-CANARY']):
            with self.subTest(value_type=type(invalid).__name__):
                projected = c.project_sample({**raw, 'tmp_available_bytes': invalid,
                                              'tmp_used_bytes': invalid})
                for key in ('tmp_available_bytes', 'tmp_used_bytes'):
                    self.assertIn(key, projected)
                    self.assertIsNone(projected[key])
                self.assertNotIn('PRIVATE-TMP-CANARY', json.dumps(projected))
        # Older metric rows do not acquire invented zero occupancy.
        old = c.project_sample(raw)
        for key in ('tmp_available_bytes', 'tmp_used_bytes', 'tmp_capacity_bytes'):
            self.assertIsNone(old[key])

    def test_worker_exit_or_permission_gap_remains_unknown_not_zero(self):
        raw = {'at': '2026-01-01T00:00:00+00:00', 'monotonic': 1,
               'role': 'worker', 'container': 'a'*64, 'main_pid': 12345}
        probe = c.CapacityProbe.__new__(c.CapacityProbe)
        probe.root = Path('/owned-fixture')
        probe.worker_records = {'a'*64: {'state': 'state'}}
        for failure in (FileNotFoundError, ProcessLookupError, PermissionError):
            with self.subTest(failure=failure.__name__), \
                    patch.object(c.Probe, 'measure', return_value=dict(raw)), \
                    patch.object(c, 'footprint', return_value={'bytes': 0}), \
                    patch.object(c.os, 'statvfs', side_effect=failure('PRIVATE-TMP-CANARY')):
                projected = c.project_sample(probe.measure('a'*64, 'worker'))
                for key in ('tmp_capacity_bytes', 'tmp_available_bytes', 'tmp_used_bytes'):
                    self.assertIsNone(projected[key])
                self.assertNotIn('PRIVATE-TMP-CANARY', json.dumps(projected))
        with patch.object(c.Probe, 'measure', return_value=None), \
                patch.object(c.os, 'statvfs') as statvfs:
            self.assertIsNone(probe.measure('a'*64, 'worker'))
            statvfs.assert_not_called()
        with patch.object(c.Probe, 'measure', return_value=dict(raw)), \
                patch.object(c, 'footprint', return_value={'bytes': 0}), \
                patch.object(c.os, 'statvfs', side_effect=OSError(errno.EIO, 'injected I/O failure')):
            with self.assertRaises(OSError) as raised:
                probe.measure('a'*64, 'worker')
            self.assertEqual(raised.exception.errno, errno.EIO)
        with patch.object(c.Probe, 'measure', return_value={**raw, 'role': 'source-pg'}), \
                patch.object(c.os, 'statvfs') as statvfs:
            probe.measure('a'*64, 'source-pg')
            statvfs.assert_not_called()

    def test_real_open_unlinked_pack_has_zero_named_footprint_but_filesystem_usage(self):
        # Real owned file, not a Restic/Docker run. Scratch's filesystem may be
        # shared: assert occupancy, not an isolated before/after byte delta.
        with tempfile.TemporaryDirectory(dir=tempfile.gettempdir()) as root:
            root = Path(root)
            with tempfile.NamedTemporaryFile(dir=root, delete=False) as pack:
                pack.write(b'x'*(1024*1024))
                pack.flush()
                os.fsync(pack.fileno())
                Path(pack.name).unlink()  # Restic CreateTemp + Remove + live FD.
                metadata = os.fstat(pack.fileno())
                self.assertEqual(metadata.st_nlink, 0)
                self.assertGreater(metadata.st_blocks, 0)
                named = c.footprint(root)
                self.assertEqual(named['bytes'], 0)
                self.assertEqual(named['allocated_bytes'], 0)
                self.assertEqual(named['files'], 0)
                self.assertEqual(named['unlinked_during_sample'], 0)
                fd_vfs = os.fstatvfs(pack.fileno())
                self.assertGreaterEqual((fd_vfs.f_blocks-fd_vfs.f_bfree)*fd_vfs.f_frsize,
                                        metadata.st_blocks*512)
                actual_statvfs = os.statvfs
                sampled = []
                def owned_vfs(path):
                    self.assertEqual(path, Path('/proc')/str(os.getpid())/'root/tmp')
                    value = actual_statvfs(root)
                    sampled.append(value)
                    return value
                raw = {'at': '2026-01-01T00:00:00+00:00', 'monotonic': 1,
                       'role': 'worker', 'container': 'a'*64, 'main_pid': os.getpid(),
                       'tmp_cache_footprint': named}
                probe = c.CapacityProbe.__new__(c.CapacityProbe)
                probe.root = root
                probe.worker_records = {'a'*64: {'state': 'absent-state'}}
                # Redirect only the fixed worker tmp mount to our owned scratch
                # directory; the filesystem counters and unlinked file are real.
                with patch.object(c.Probe, 'measure', return_value=raw), \
                        patch.object(c.os, 'statvfs', side_effect=owned_vfs):
                    projected = c.project_sample(probe.measure('a'*64, 'worker'))
                self.assertEqual(projected['tmp']['bytes'], 0)
                self.assertGreaterEqual(projected['tmp_used_bytes'], metadata.st_blocks*512)
                self.assertEqual(projected['tmp_available_bytes'],
                                 sampled[0].f_bavail*sampled[0].f_frsize)
                summary = c.summarize_samples([projected])['containers'][0]
                self.assertEqual(summary['sampled_tmp_bytes_peak'], 0)
                self.assertEqual(summary['sampled_tmp_used_bytes_peak'], projected['tmp_used_bytes'])
                self.assertEqual(summary['sampled_tmp_available_bytes_min'], projected['tmp_available_bytes'])


if __name__ == '__main__':
    unittest.main()
