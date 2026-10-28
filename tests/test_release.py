"""Offline stdlib release guards; never contact GitHub, GHCR or Docker."""
import importlib.util
import json
import os
from pathlib import Path
import unittest
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / '.github/release.py'
ENV = {'GITHUB_REPOSITORY': 'Owner/Bakabel', 'GITHUB_SHA': 'a' * 40,
       'VERSION': 'v0.1.0', 'CI_RUN_ID': '11', 'ACCEPTANCE_RUN_ID': '22'}
NAMES = ['selection', 'acceptance (core-resources, all)',
         'acceptance (capacity, all)', 'acceptance (faults, all)']


class ReleaseGuards(unittest.TestCase):
    def setUp(self):
        self.assertTrue(HELPER.is_file(), 'release helper must exist')
        spec = importlib.util.spec_from_file_location('release', HELPER)
        assert spec is not None and spec.loader is not None
        self.release = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.release)
        self.env = patch.dict(os.environ, ENV)
        self.env.start()
        self.addCleanup(self.env.stop)

    def responses(self):
        rows = []
        for workflow, names in [('ci', ['test-and-build']), ('acceptance', NAMES)]:
            rows.append({'head_sha': ENV['GITHUB_SHA'], 'path': f'.github/workflows/{workflow}.yaml',
                         'event': 'push' if workflow == 'ci' else 'workflow_dispatch',
                         'status': 'completed', 'conclusion': 'success'})
            jobs = [dict(name=name, status='completed', conclusion='success') for name in names]
            rows.append({'total_count': len(jobs), 'jobs': jobs})
        return rows

    def test_gate_accepts_exact_source_and_full_all(self):
        with patch.object(self.release.subprocess, 'check_output',
                          side_effect=[json.dumps(row) for row in self.responses()]) as gh:
            self.release.gate()
        self.assertEqual(gh.call_count, 4)
        for call in gh.call_args_list:
            self.assertEqual(call.args[0][:4], ['gh', 'api', '--hostname', 'github.com'])
            self.assertNotIn('shell', call.kwargs)
    def test_gate_rejects_wrong_or_missing_checkout_events(self):
        for index, events in ((0, ('pull_request', 'pull_request_target', 'workflow_run', 'workflow_dispatch', None)),
                              (2, ('push', 'pull_request', None))):
            for event in events:
                rows = self.responses()
                if event is None:
                    rows[index].pop('event')
                else:
                    rows[index]['event'] = event
                with self.subTest(index=index, event=event), patch.object(self.release.subprocess, 'check_output',
                        side_effect=[json.dumps(row) for row in rows]):
                    with self.assertRaises(ValueError):
                        self.release.gate()

    def test_inputs_are_strict_before_any_api_call(self):
        self.assertTrue(hasattr(self.release, 'validate'), 'input validation required')
        self.release.validate()
        for key, values in {'VERSION': ['v01.1.0', '1.2.3', 'v1.2.3\n', 'v1.2.3-rc.1', 'v1.2.3;id'],
                            'CI_RUN_ID': ['', '0', '-1', '11?x=1'],
                            'ACCEPTANCE_RUN_ID': ['', 'x'],
                            'GITHUB_SHA': ['a' * 39],
                            'GITHUB_REPOSITORY': ['owner/repo/extra']}.items():
            for value in values:
                with self.subTest(key=key, value=value), patch.dict(os.environ, {key: value}), \
                        patch.object(self.release.subprocess, 'check_output') as gh:
                    with self.assertRaises(ValueError): self.release.gate()
                    gh.assert_not_called()

    def test_gate_rejects_head_workflow_status_jobs_and_partial_scopes(self):
        changes = [(0, 'head_sha', 'b' * 40), (2, 'head_sha', 'b' * 40),
                   (0, 'path', '.github/workflows/other.yaml'),
                   (2, 'path', '.github/workflows/ci.yaml'),
                   (2, 'status', 'in_progress'), (0, 'conclusion', 'failure')]
        for index, key, value in changes:
            rows = self.responses(); rows[index][key] = value
            with self.subTest(index=index, key=key), patch.object(self.release.subprocess, 'check_output',
                    side_effect=[json.dumps(row) for row in rows]):
                with self.assertRaises(ValueError): self.release.gate()
        for report_index in (1, 3):
            for mode in ('empty', 'missing', 'duplicate', 'failed', 'skipped', 'running', 'partial', 'truncated'):
                rows = self.responses(); report = rows[report_index]; jobs = report['jobs']
                if mode == 'empty': jobs.clear()
                elif mode == 'missing': jobs.pop()
                elif mode == 'duplicate': jobs.append(jobs[0])
                elif mode in ('failed', 'skipped'): jobs[0]['conclusion'] = mode
                elif mode == 'running': jobs[0]['status'] = 'in_progress'
                elif mode == 'partial': jobs[-1]['name'] = 'acceptance (reader, restore-reader-failure-importer-zero)'
                report['total_count'] = len(jobs) + (mode == 'truncated')
                with self.subTest(report=report_index, mode=mode), patch.object(self.release.subprocess, 'check_output',
                        side_effect=[json.dumps(row) for row in rows]):
                    with self.assertRaises(ValueError): self.release.gate()

    def test_api_errors_do_not_pass(self):
        for error in (self.release.subprocess.CalledProcessError(1, ['gh']), ValueError('bad JSON')):
            with patch.object(self.release.subprocess, 'check_output', side_effect=error):
                with self.assertRaises((ValueError, self.release.subprocess.CalledProcessError)):
                    self.release.gate()
    def test_registry_exact_absence_and_digest_agreement(self):
        self.assertTrue(hasattr(self.release, 'registry'), 'authenticated registry guard required')
        from email.message import Message
        from urllib.error import HTTPError, URLError
        token = MagicMock(); token.__enter__.return_value.read.return_value = b'{"token":"synthetic-token"}'
        digest = 'sha256:' + 'd' * 64
        present = MagicMock(); present.__enter__.return_value.headers = {'Docker-Content-Digest': digest}
        def missing(code): return HTTPError('https://ghcr.io/test', code, 'synthetic', Message(), None)
        cases = [('check', [missing(404), missing(404)], None),
                 ('check', [present, missing(404)], ValueError),
                 ('verify', [present, present], None),
                 ('verify', [present, missing(404)], ValueError)]
        for code in (401, 403, 429, 500): cases.append(('check', [missing(code)], HTTPError))
        cases.append(('check', [URLError('offline')], URLError))
        different = MagicMock(); different.__enter__.return_value.headers = {'Docker-Content-Digest': 'sha256:' + 'e' * 64}
        cases.extend([('verify', [present, different], ValueError),
                      ('verify', [MagicMock(), present], ValueError)])
        for mode, replies, error in cases:
            with self.subTest(mode=mode, error=error), \
                    patch.dict(os.environ, {'GITHUB_ACTOR': 'actor', 'GH_TOKEN': 'synthetic-secret'}), \
                    patch.object(self.release, 'urlopen', side_effect=[token, *replies]) as http:
                if error:
                    with self.assertRaises(error): self.release.registry(mode)
                else:
                    result = self.release.registry(mode)
                    self.assertEqual(result, digest if mode == 'verify' else None)
                requests = [call.args[0] for call in http.call_args_list]
                self.assertIn('scope=repository%3Aowner%2Fbakabel%3Apull%2Cpush', requests[0].full_url)
                self.assertNotIn('synthetic-secret', requests[0].full_url)
                self.assertTrue(requests[0].get_header('Authorization').startswith('Basic '))
                for request in requests[1:]:
                    self.assertEqual(request.get_method(), 'HEAD')
                    self.assertTrue(request.full_url.startswith('https://ghcr.io/v2/owner/bakabel/manifests/'))
        with patch.dict(os.environ, {'GITHUB_ACTOR': 'actor', 'GH_TOKEN': 'synthetic-secret'}), \
                patch.object(self.release, 'urlopen', side_effect=missing(403)):
            with self.assertRaises(HTTPError): self.release.registry('check')
    def test_registry_transport_refuses_redirects_before_followup(self):
        from email.message import Message
        from urllib.request import Request
        opener = getattr(self.release.urlopen, '__self__', None)
        assert opener is not None, 'registry transport must bind an explicit no-redirect opener'
        for credential in ('Basic synthetic-token', 'Bearer synthetic-token'):
            for location in ('https://other.invalid/path', 'http://ghcr.io/path', 'https://ghcr.io/path'):
                for status in (301, 302, 303, 307, 308):
                    request = Request('https://ghcr.io/token', headers={'Authorization': credential})
                    headers = Message(); headers['Location'] = location
                    with self.subTest(credential=credential.split()[0], location=location, status=status), \
                            patch.object(opener, 'open') as followup:
                        with self.assertRaises(ValueError):
                            opener.error('http', request, None, status, 'redirect', headers)
                        followup.assert_not_called()

    def test_manual_workflow_publication_boundaries_and_shell_syntax(self):
        import re
        import subprocess
        import textwrap
        path = ROOT / '.github/workflows/release.yaml'
        self.assertTrue(path.is_file(), 'manual publication workflow required')
        workflow = path.read_text()
        self.assertEqual(re.findall(r'^  (\w+):$', workflow.split('permissions:')[0], re.M), ['workflow_dispatch'])
        self.assertIn('default: v0.1.0', workflow)
        self.assertIn('ci_run_id:', workflow); self.assertIn('acceptance_run_id:', workflow)
        self.assertEqual(re.findall(r'uses: (.*)', workflow),
                         ['actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4'])
        for required in ('persist-credentials: false', 'ref: ${{ github.sha }}',
                         'contents: read', 'actions: read', 'packages: write',
                         '--platform linux/amd64', '--password-stdin', 'if: always()',
                         'docker logout ghcr.io', '${GITHUB_REPOSITORY,,}',
                         'org.opencontainers.image.revision=$GITHUB_SHA',
                         'org.opencontainers.image.version=$VERSION',
                         'org.opencontainers.image.source=https://github.com/$GITHUB_REPOSITORY'):
            self.assertIn(required, workflow)
        positions = [workflow.index(marker) for marker in ('release.py gate', 'docker build',
                     'entrypoint /usr/bin/restic', '__release_smoke_invalid__', 'release.py check',
                     'docker login', 'docker push "$IMAGE:$VERSION"', 'docker push "$IMAGE:sha-$GITHUB_SHA"',
                     'release.py verify')]
        self.assertEqual(positions, sorted(positions))
        self.assertNotIn(':latest', workflow); self.assertNotIn('docker.sock', workflow)
        self.assertNotIn('secrets.', '\n'.join(line for line in workflow.splitlines() if 'run:' in line))
        blocks = re.findall(r'(?m)^        run: \|\n((?:(?:          [^\n]*|)\n)+)', workflow)
        self.assertGreaterEqual(len(blocks), 4)
        for block in blocks:
            subprocess.run(['bash', '-n'], input=textwrap.dedent(block), text=True, check=True)
        self.assertIn('test_release.py', (ROOT / '.github/workflows/ci.yaml').read_text())


if __name__ == '__main__':
    unittest.main()
