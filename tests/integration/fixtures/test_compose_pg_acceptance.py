"""Offline provenance checks; these tests never contact Docker or a provider."""
import hashlib
from pathlib import Path
import tempfile
import unittest

from run_compose_pg_acceptance import ComposeProbe, fingerprint


class CandidateFingerprintTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        for name, data in {'go.mod':'module fixture\n', 'go.sum':'', 'Dockerfile':'FROM scratch\n', 'main.go':'package main\n'}.items():
            (self.root/name).write_text(data)

    def test_names_and_raw_content_hashes_bind_in_sorted_order(self):
        expected = hashlib.sha256()
        for name in ('Dockerfile', 'go.mod', 'go.sum', 'main.go'):
            expected.update(name.encode()+b'\0'+hashlib.sha256((self.root/name).read_bytes()).digest())
        self.assertEqual(fingerprint(self.root), expected.hexdigest())

    def test_added_go_source_changes_candidate(self):
        before = fingerprint(self.root)
        (self.root/'extra.go').write_text('package main\n')
        self.assertNotEqual(fingerprint(self.root), before)

    def test_fixture_artifacts_do_not_change_core_candidate(self):
        before = fingerprint(self.root)
        (self.root/'receipt.json').write_text('{}')
        (self.root/'runner.py').write_text('pass\n')
        self.assertEqual(fingerprint(self.root), before)


class SourceCleanupTests(unittest.TestCase):
    def test_already_auto_removed_anonymous_volume_is_absent(self):
        class Engine:
            def __init__(self):
                self.removed = False
                self.calls = []

            def inspect(self, cid, missing=False):
                return None if self.removed else {'Config':{'Labels':{'probe.bakabel.owner':'fixture'}}, 'Mounts':[{'Type':'volume','Name':'anonymous'}]}

            def call(self, method, path, **kwargs):
                self.calls.append((method, path, kwargs))
                if path.startswith('/containers/'):
                    self.removed = True
                elif path.startswith('/volumes/') and not kwargs.get('missing'):
                    raise RuntimeError('Engine404: anonymous volume already removed with container')
                return None

        probe = ComposeProbe.__new__(ComposeProbe)
        probe.prefix = 'fixture'
        probe.containers = {'owned':'fixture-source'}
        probe.volumes = ['anonymous']
        probe.e = Engine()
        probe.remove_source('owned')
        self.assertIn(('GET','/volumes/anonymous',{'missing':True}), probe.e.calls)


if __name__ == '__main__':
    unittest.main()
