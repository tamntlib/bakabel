"""Plain-text repository checks must not enter the CLI JSON-result parser."""
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

from run_hosted_capacity import CapacityProbe


class PlainTextCheckTests(unittest.TestCase):
    def test_real_operator_path_accepts_check_progress_without_json_inference(self):
        for exit_code in (0, 1):
            with self.subTest(exit=exit_code), tempfile.TemporaryDirectory() as directory:
                p = CapacityProbe.__new__(CapacityProbe)
                p.root = Path(directory)
                p.values = []
                p.prefix = 'owned-check'
                p.capacity = {}
                p.capacity_phase = 'changed'
                cid = 'a'*64
                p.containers = {cid: 'owned-check-operator'}
                p.create = lambda *args, **kwargs: cid
                p.restic_spec = lambda argv: {'Cmd': list(argv)}
                p.e = SimpleNamespace(inspect=lambda _: {
                    'Id': cid, 'Name': '/owned-check-operator',
                    'Config': {'Labels': {'probe.bakabel.owner': p.prefix}},
                    'State': {'Running': False, 'ExitCode': exit_code}})
                p.wait = Mock(side_effect=lambda fn, *args, **kwargs: fn())
                progress = 'check all packs\n[0:00] 100.00% 72 / 72 packs\nno errors were found\n'
                p.logs = Mock(return_value=progress)
                if exit_code:
                    with self.assertRaisesRegex(ValueError, 'unexpected exit status'):
                        p.restic('check')
                else:
                    self.assertEqual(p.restic('check'), progress)
                self.assertEqual(p.capacity['commands'][0]['exit'], exit_code)
                self.assertEqual(p.capacity['commands'][0]['json_status'], 'unavailable')
                self.assertEqual(p.capacity['commands'][0]['outcomes'], [])
                self.assertNotIn('check all packs', json.dumps(p.capacity))

    def test_json_operator_still_rejects_malformed_json(self):
        with tempfile.TemporaryDirectory() as directory:
            p = CapacityProbe.__new__(CapacityProbe)
            p.root = Path(directory); p.values = []; p.prefix = 'owned-check'
            p.capacity = {}; p.capacity_phase = 'changed'
            cid = 'a'*64
            p.containers = {cid: 'owned-check-operator'}
            p.create = lambda *args, **kwargs: cid
            p.restic_spec = lambda argv: {'Cmd': list(argv)}
            p.e = SimpleNamespace(inspect=lambda _: {
                'Id': cid, 'Name': '/owned-check-operator',
                'Config': {'Labels': {'probe.bakabel.owner': p.prefix}},
                'State': {'Running': False, 'ExitCode': 0}})
            p.wait = Mock(side_effect=lambda fn, *args, **kwargs: fn())
            p.logs = Mock(return_value='{broken-json')
            with self.assertRaises(json.JSONDecodeError):
                p.restic('snapshots', '--json')


if __name__ == '__main__':
    unittest.main()
