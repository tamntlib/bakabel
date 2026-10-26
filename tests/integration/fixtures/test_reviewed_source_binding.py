"""Reviewed source pins must admit the actual candidate, never arbitrary argv."""
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest

import run_hosted_capacity as capacity
import run_hosted_faults as faults
from run_compose_pg_acceptance import fingerprint

ROOT = Path(__file__).resolve().parents[3]
OLD_R3 = '6a592fcf1159d301bbe9acf0ff82e3e681913de4d1fb6f17ccc2d05c9d394ef8'


class ReviewedSourceBinding(unittest.TestCase):
    def test_both_admission_pins_match_actual_core_source(self):
        actual = fingerprint(ROOT)
        self.assertEqual(capacity.STOCK_SOURCE, actual)
        self.assertEqual(faults.FROZEN_SOURCE, actual)

    def test_historical_pin_is_rejected_before_any_runtime_access(self):
        try:
            capacity.validate_paths(SimpleNamespace(expected_source_sha256=OLD_R3), {})
        except ValueError:
            pass
        except Exception as error:
            self.fail('historical pin passed source admission: '+type(error).__name__)
        else:
            self.fail('historical pin was admitted')
        self.assertNotEqual(faults.FROZEN_SOURCE, OLD_R3)

    def test_matching_unreviewed_source_and_argument_cannot_replace_pin(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root/'source'
            source.mkdir()
            for name in ('go.mod', 'go.sum', 'Dockerfile'):
                (source/name).write_text('offline-unreviewed-fixture\n')
            forged = fingerprint(source)
            self.assertNotEqual(forged, fingerprint(ROOT))
            with self.assertRaises(ValueError):
                capacity.validate_paths(SimpleNamespace(expected_source_sha256=forged), {})
            self.assertNotEqual(faults.FROZEN_SOURCE, forged)


if __name__ == '__main__':
    unittest.main()
