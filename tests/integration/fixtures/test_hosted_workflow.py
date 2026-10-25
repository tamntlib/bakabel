"""Static contract for the manual workflow, not hosted execution evidence."""
from pathlib import Path
import re
import unittest

ROOT=Path(__file__).resolve().parents[3]

class WorkflowContract(unittest.TestCase):
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
