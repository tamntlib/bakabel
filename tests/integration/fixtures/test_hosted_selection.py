"""Offline selection verification only; synthetic rows are not runtime evidence."""
import copy
import importlib
from pathlib import Path
import unittest

from run_compose_pg_acceptance import fingerprint
from test_hosted_native_faults import receipt as native_receipt, F16
from test_hosted_storage_prereqs import synthetic, F19

ROOT = Path(__file__).resolve().parents[3]


def fixture(suite):
    row = synthetic() if suite == 'storage' else native_receipt()
    if suite == 'native':
        row.update(status='pass', exercised=True, ordinary_image=True, request_mutations=[],
                   backend='local', platform='compose', source_unchanged=True,
                   source_sha256=fingerprint(ROOT), image_id='sha256:'+'2'*64,
                   cleanup={'containers_absent': {'b'*64: True}, 'volumes_absent': {'owned': True},
                            'private_paths_absent': True})
        row['workers']['b'*64].update(container_id='b'*64, image_id=row['image_id'],
            memory_bytes=536870912, nanocpus=2000000000,
            socket={'source':'/unit/relay.sock','destination':'/run/bakabel/docker.sock','read_only':True})
    row['source_sha256'] = fingerprint(ROOT)
    case = F19 if suite == 'storage' else F16
    report = {'schema':1, 'cases':[{'case':case,'status':'pass'}],
              ('storage_acceptance_pass' if suite == 'storage' else 'fault_acceptance_pass'):False,
              'full_plan_acceptance_pass':False,
              **{k:row[k] for k in ('source_sha256','image_id','daemon')}}
    candidate = {**{k:row[k] for k in ('source_sha256','image_id','daemon')},
                 'commit':'a'*40, 'scope':'remaining-faults', 'suite':suite, 'case':case}
    return report, [row], candidate, case


class SelectionTests(unittest.TestCase):
    def module(self):
        try:
            return importlib.import_module('verify_hosted_selection')
        except ModuleNotFoundError:
            self.fail('independent single-case selection verifier is missing')

    def test_actual_native_and_storage_case_verifiers_accept_scoped_selection_only(self):
        m = self.module()
        for suite in ('native','storage'):
            report, rows, candidate, case = fixture(suite)
            with self.subTest(suite=suite):
                result = m.verify_selection(report, rows, candidate, suite, case, ROOT)
                self.assertEqual(result, {'scope':'remaining-faults', 'suite':suite, 'case':case,
                    'selected_case_pass':True, 'full_plan_acceptance_pass':False})


    def test_selection_rejects_missing_duplicate_unexpected_manifest_and_binding_drift(self):
        m = self.module()
        for suite in ('native','storage'):
            original = fixture(suite)
            mutations = [
                ('missing rows', lambda r, rows, c: rows.clear()),
                ('duplicate rows', lambda r, rows, c: rows.append(copy.deepcopy(rows[0]))),
                ('unexpected case', lambda r, rows, c: rows[0].update(case='restore-reader-failure-importer-zero')),
                ('empty manifest', lambda r, rows, c: r.update(cases=[])),
                ('duplicate manifest', lambda r, rows, c: r['cases'].append(copy.deepcopy(r['cases'][0]))),
                ('false status', lambda r, rows, c: r['cases'][0].update(status='failed')),
                ('full claim', lambda r, rows, c: r.update(full_plan_acceptance_pass=True)),
                ('missing full flag', lambda r, rows, c: r.pop('full_plan_acceptance_pass')),
                ('suite claim', lambda r, rows, c: r.update(**{('fault_acceptance_pass' if suite == 'native' else 'storage_acceptance_pass'):True})),
                ('schema', lambda r, rows, c: r.update(schema=2)),
                ('candidate scope', lambda r, rows, c: c.update(scope='all')),
                ('candidate suite', lambda r, rows, c: c.update(suite='faults')),
                ('candidate case', lambda r, rows, c: c.update(case='another')),
                ('missing commit', lambda r, rows, c: c.pop('commit')),
            ]
            for key in ('source_sha256','image_id','daemon'):
                mutations.extend([
                    ('report drift '+key, lambda r, rows, c, k=key: r.update({k:'wrong'})),
                    ('candidate drift '+key, lambda r, rows, c, k=key: c.update({k:'wrong'})),
                    ('missing binding '+key, lambda r, rows, c, k=key: c.pop(k)),
                ])
            for label, mutate in mutations:
                report, rows, candidate, case = copy.deepcopy(original)
                mutate(report, rows, candidate)
                with self.subTest(suite=suite, mutation=label), self.assertRaises(ValueError):
                    m.verify_selection(report, rows, candidate, suite, case, ROOT)
            report, rows, candidate, case = copy.deepcopy(original)
            report['source_sha256'] = candidate['source_sha256'] = rows[0]['source_sha256'] = '9'*64
            with self.subTest(suite=suite, mutation='consistent wrong source'), self.assertRaises(ValueError):
                m.verify_selection(report, rows, candidate, suite, case, ROOT)

    def test_actual_case_assertions_and_cleanup_failures_are_not_bypassed(self):
        m = self.module()
        for suite in ('native','storage'):
            for path, value in [(('cleanup','private_paths_absent'),False),
                                (('cleanup','volumes_absent','owned'),False),
                                (('cleanup_failure',),{'kind':'offline-test'}),
                                (('status',),'failed'), (('exercised',),False)]:
                report, rows, candidate, case = fixture(suite)
                node = rows[0]
                for k in path[:-1]: node = node[k]
                node[path[-1]] = value
                with self.subTest(suite=suite, path=path), self.assertRaises(ValueError):
                    m.verify_selection(report, rows, candidate, suite, case, ROOT)
            report, rows, candidate, case = fixture(suite)
            if suite == 'native': rows[0]['proof']['public']['targets'][0]['resticExitCode'] = 0
            else: rows[0]['storage']['trace']['writes'] = []
            with self.subTest(suite=suite, mutation='semantic failure'), self.assertRaises(ValueError):
                m.verify_selection(report, rows, candidate, suite, case, ROOT)


    def test_failed_report_cannot_be_reinterpreted_as_scoped_success(self):
        m = self.module()
        for suite in ('native','storage'):
            for key in ('cleanup_failure','verification_failure'):
                report, rows, candidate, case = fixture(suite)
                report[key] = {'offline_failure':True}
                with self.subTest(suite=suite, key=key), self.assertRaises(ValueError):
                    m.verify_selection(report, rows, candidate, suite, case, ROOT)

    def test_old_aggregate_verifiers_still_reject_every_single_case_selection(self):
        from verify_hosted_faults import verify_report as verify_faults
        from verify_hosted_storage_prereqs import verify_report as verify_storage
        for suite, verify in (('native',verify_faults),('storage',verify_storage)):
            report, rows, candidate, case = fixture(suite)
            for claim in (False,True):
                report['fault_acceptance_pass' if suite == 'native' else 'storage_acceptance_pass'] = claim
                with self.subTest(suite=suite, claim=claim), self.assertRaises(ValueError):
                    verify(report,rows)
            for bad_suite, bad_case in ((suite,'restore-reader-failure-importer-zero'),('storage' if suite=='native' else 'native',case)):
                with self.subTest(suite=bad_suite, case=bad_case), self.assertRaises(ValueError):
                    self.module().verify_selection(report, rows, candidate, bad_suite, bad_case, ROOT)

    def test_cli_reads_exact_manifest_and_writes_only_scoped_verdict(self):
        import json
        import os
        import subprocess
        import sys
        import tempfile
        m = self.module()
        self.assertTrue(hasattr(m, 'main'), 'selection verifier CLI is missing')
        for suite in ('native','storage'):
            report, rows, candidate, case = fixture(suite)
            with self.subTest(suite=suite), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root/case).mkdir()
                (root/case/'receipt.json').write_text(json.dumps(rows[0]))
                report_path = root/('hosted-faults.json' if suite == 'native' else 'hosted-storage.json')
                report_path.write_text(json.dumps(report))
                binding = root/'candidate.json'; binding.write_text(json.dumps(candidate))
                output = root/'selected-verified.json'
                cmd = [sys.executable, str(Path(m.__file__)), '--suite',suite,'--case',case,
                       '--source',str(ROOT),'--runtime',str(root),'--candidate',str(binding),'--output',str(output)]
                cp = subprocess.run(cmd, capture_output=True, text=True, env=os.environ)
                self.assertEqual(cp.returncode, 0, cp.stderr)
                self.assertEqual(json.loads(output.read_text()), json.loads(cp.stdout))
                self.assertIs(json.loads(cp.stdout)['full_plan_acceptance_pass'], False)
                report['cases'] = []
                report_path.write_text(json.dumps(report)); output.unlink()
                cp = subprocess.run(cmd, capture_output=True, text=True, env=os.environ)
                self.assertNotEqual(cp.returncode, 0)
                self.assertFalse(output.exists())
                self.assertNotIn('Traceback', cp.stderr)


if __name__ == '__main__': unittest.main()
