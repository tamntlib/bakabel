"""Exercise only README setup guards in disposable directories, never deploy."""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]

def block_containing(marker):
    blocks=re.findall(r'```bash\n(.*?)\n```',(ROOT/'README.md').read_text(),re.S)
    matches=[block for block in blocks if marker in block]
    if len(matches)!=1:
        raise AssertionError('documentation block is missing or ambiguous')
    return matches[0]

class DocumentationGuards(unittest.TestCase):
    def test_ci_runs_public_restore_launch_regression_at_production_path(self):
        workflow=(ROOT/'.github/workflows/ci.yaml').read_text()
        source=(ROOT/'internal/app/workflow_controller.go').read_text()
        production=re.search(r'Binary:\s*"([^"]+restic)"',source).group(1)
        configured=re.search(r'-e RESTIC_TEST_BINARY=(\S+)',workflow).group(1)
        mounted=re.search(r'-v "\$RUNNER_TEMP/restic:([^:"]+):ro"',workflow).group(1)
        self.assertEqual(configured,production)
        self.assertEqual(mounted,production)
    def test_ci_runs_real_restic_root_acl_regressions(self):
        workflow=(ROOT/'.github/workflows/ci.yaml').read_text()
        configured=re.findall(r'-e BAKABEL_FILES_RESTIC=(\S+)',workflow)
        mounted=re.findall(r'-v "\$RUNNER_TEMP/restic:([^:\"]+):ro"',workflow)
        self.assertEqual(len(mounted),1, 'pinned Restic mount must be present once')
        self.assertEqual(configured,mounted, 'real root ACL regressions must not be skipped in CI')
        self.assertIn('go test -race -count=1 -v ./...',workflow)

    def test_credential_install_is_fail_closed(self):
        for case in ('fresh','existing','missing-input','dangling-symlink'):
            with self.subTest(case=case),tempfile.TemporaryDirectory(prefix='bakabel-doc-test-') as directory:
                root=Path(directory)
                home=root/'home'
                target=home/'.local/share/bakabel/credentials/restic-password'
                target.parent.mkdir(parents=True,mode=0o700)
                source=root/'synthetic-input'
                if case!='missing-input':source.write_bytes(b'synthetic-new-key')
                if case=='existing':target.write_bytes(b'synthetic-existing-key')
                if case=='dangling-symlink':target.symlink_to(root/'absent-outside')
                command=block_containing('install -d -m 0700').replace('/secure/operator/restic-password',str(source))
                result=subprocess.run(['bash','-c',command],env={**os.environ,'HOME':str(home)},capture_output=True)
                if case=='fresh':
                    self.assertEqual(result.returncode,0)
                    self.assertEqual(target.read_bytes(),source.read_bytes())
                    self.assertEqual(target.stat().st_mode&0o777,0o600)
                else:
                    self.assertNotEqual(result.returncode,0)
                    if case=='existing':self.assertEqual(target.read_bytes(),b'synthetic-existing-key')
                    elif case=='dangling-symlink':
                        self.assertTrue(target.is_symlink())
                        self.assertFalse((root/'absent-outside').exists())
                    else:self.assertFalse(target.exists())

    def test_config_install_does_not_overwrite(self):
        with tempfile.TemporaryDirectory(prefix='bakabel-doc-test-') as directory:
            root=Path(directory);target=root/'bakabel.yaml';target.write_bytes(b'existing-configuration')
            result=subprocess.run(['bash','-c',block_containing('install -m 0600 deploy/bakabel.example.yaml')],cwd=ROOT,env={**os.environ,'BAKABEL_HOME':str(root)},capture_output=True)
            self.assertNotEqual(result.returncode,0)
            self.assertEqual(target.read_bytes(),b'existing-configuration')

    def test_failed_build_does_not_inspect_a_stale_tag(self):
        # This stand-in checks shell control flow only. No Engine response or
        # successful image result is fabricated, and Docker is never contacted.
        with tempfile.TemporaryDirectory(prefix='bakabel-doc-test-') as directory:
            root=Path(directory);calls=root/'calls';command=root/'docker'
            command.write_text('#!/bin/sh\nprintf "%s\\n" "$1" >> "$DOC_TEST_CALLS"\nexit 17\n')
            command.chmod(0o700)
            result=subprocess.run(['bash','-c',block_containing('docker build --platform')],env={**os.environ,'PATH':str(root)+os.pathsep+os.environ['PATH'],'DOC_TEST_CALLS':str(calls)},capture_output=True)
            self.assertEqual(result.returncode,17)
            self.assertEqual(calls.read_text().splitlines(),['build'])

if __name__=='__main__':unittest.main()
