"""Static contract for the manual workflow, not hosted execution evidence."""
from pathlib import Path
import re
import unittest
import os
import socket
import subprocess
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[3]

class WorkflowContract(unittest.TestCase):
    def test_extended_resource_replay_is_mandatory_and_public_report_only(self):
        text=(ROOT/'.github/workflows/acceptance.yaml').read_text()
        self.assertIn('run_hosted_resources.py',text)
        self.assertIn('bakabel-resources/resources-public.json',text)
        self.assertIn('sudo test -f "$RUNNER_TEMP/bakabel-resources/resources-public.json"',text)
        self.assertIn('"$RUNNER_TEMP/bakabel-public/resources.json"',text)
        self.assertNotIn('bakabel-resources/receipt.json',text)

    def test_action_socket_uri_becomes_real_unix_socket_path(self):
        text=(ROOT/'.github/workflows/acceptance.yaml').read_text()
        normalization='ENGINE_SOCKET=${ENGINE_SOCKET#unix://}'
        self.assertIn(normalization,text)
        self.assertLess(text.index(normalization),text.index('test -S "$ENGINE_SOCKET"'))
        with tempfile.TemporaryDirectory() as directory:
            path=str(Path(directory)/'docker.sock')
            with socket.socket(socket.AF_UNIX) as listener:
                listener.bind(path)
                for endpoint in (path,'unix://'+path):
                    cp=subprocess.run(['bash','-eu','-c',normalization+'; test -S "$ENGINE_SOCKET"'],env={**os.environ,'ENGINE_SOCKET':endpoint},capture_output=True)
                    self.assertEqual(cp.returncode,0)

    def test_resource_test_needs_no_hermes_home_on_clean_runner(self):
        with tempfile.TemporaryDirectory() as directory:
            home=Path(directory)/'home';home.mkdir()
            cp=subprocess.run([sys.executable,'-m','unittest','test_resource_failure.FailureProof.test_space_probe_preserves_errno_and_removes_own_probe'],cwd=ROOT/'tests/integration/fixtures',env={**os.environ,'HOME':str(home)},text=True,capture_output=True)
            self.assertEqual(cp.returncode,0,cp.stderr)

    def test_manual_vm_direct_engine_and_allowlisted_artifacts(self):
        path=ROOT/'.github/workflows/acceptance.yaml'
        self.assertTrue(path.exists(),'manual acceptance workflow is missing')
        text=path.read_text()
        trigger=text.split('permissions:',1)[0]
        self.assertIn('workflow_dispatch:',trigger)
        self.assertNotIn('pull_request:',trigger)
        self.assertNotIn('push:',trigger)
        self.assertIn('runs-on: ubuntu-24.04',text)
        self.assertIn('rootless: false',text)
        self.assertIn('run_hosted_acceptance.py',text)
        self.assertIn('verify_hosted_acceptance.py',text)
        self.assertIn('hosted_evidence.py',text)
        self.assertIn('if: always()',text)
        self.assertNotIn('ubuntu-slim',text)
        self.assertNotIn('docker:dind',text)
        self.assertNotRegex(text,r'\$\{\{\s*secrets\.')
        for action in re.findall(r'uses:\s*(\S+)',text):
            self.assertRegex(action,r'^[\w/-]+@[0-9a-f]{40}$')
        self.assertIn('path: ${{ runner.temp }}/bakabel-public/',text)
        self.assertNotIn('path: ${{ runner.temp }}/bakabel-acceptance/',text)

if __name__=='__main__':unittest.main()
