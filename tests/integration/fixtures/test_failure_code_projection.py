"""Diagnostics are finite enums/integers, never a raw upstream error channel."""
import json
import unittest
from run_hosted_capacity import project_outcomes


class FailureProjection(unittest.TestCase):
    def test_fixed_failure_stage_and_restic_exit_survive_projection(self):
        rows = project_outcomes([{'status': 'failed', 'targets': [
            {'status': 'unknown', 'error': 'backup failed', 'failureCode': 'backup',
             'resticExitCode': 1, 'resticReason': 'enospc'}]}])
        target = rows[0]['targets'][0]
        self.assertEqual(target.get('failure_code'), 'backup')
        self.assertEqual(target.get('restic_exit_code'), 1)
        self.assertEqual(target.get('restic_reason'), 'enospc')

    def test_unknown_text_boolean_and_out_of_range_diagnostics_do_not_escape(self):
        secret = 'unit-private-diagnostic-canary'
        for code in (-1, 256, True, secret, {'secret': secret}):
            rows = project_outcomes([{'status': 'failed', 'targets': [
                {'status': 'unknown', 'error': secret, 'failureCode': secret,
                 'resticExitCode': code, 'resticReason': secret}]}])
            self.assertNotIn(secret, json.dumps(rows))
            target = rows[0]['targets'][0]
            self.assertIsNone(target.get('failure_code'))
            self.assertIsNone(target.get('restic_exit_code'))
            self.assertIsNone(target.get('restic_reason'))


if __name__ == '__main__':
    unittest.main()
