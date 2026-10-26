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
    def test_real_export_shell_accepts_each_suite_and_excludes_private_trees(self):
        import json
        import textwrap
        from verify_hosted_faults import CASES
        text=(ROOT/'.github/workflows/acceptance.yaml').read_text()
        block=text.split('      - name: Export only allowlisted evidence even on failure',1)[1].split('      - uses:',1)[0]
        script=textwrap.dedent(block.split('        run: |\n',1)[1])
        secret='unit-only-private-export-marker'
        for suite in ('core-resources','capacity','faults'):
            with self.subTest(suite=suite),tempfile.TemporaryDirectory() as directory:
                root=Path(directory);tools=root/'tools';tools.mkdir()
                sudo=tools/'sudo'
                sudo.write_text('#!/bin/sh\ncase "$1" in --preserve-env=*) shift;; esac\nif [ "$1" = chown ]; then exit 0; fi\nexec "$@"\n');sudo.chmod(0o700)
                (root/'bakabel-candidate.json').write_text(json.dumps({'suite':suite}))
                if suite=='core-resources':
                    receipt=root/'bakabel-acceptance/compose/receipt.json';receipt.parent.mkdir(parents=True)
                    receipt.write_text(json.dumps({'platform':'compose','commands':[{'Env':[secret]}]}))
                elif suite=='capacity':
                    receipt=root/'bakabel-capacity/capacity-receipt.json';receipt.parent.mkdir()
                    receipt.write_text(json.dumps({'offline_unit_fixture':True}))
                else:
                    receipt=root/'bakabel-faults'/CASES[0]/'receipt.json';receipt.parent.mkdir(parents=True)
                    receipt.write_text(json.dumps({'offline_unit_fixture':True}))
                private=root/'bakabel-capacity/private/receipt.json';private.parent.mkdir(parents=True,exist_ok=True);private.write_text(secret)
                cp=subprocess.run(['bash','-eu','-c',script],cwd=ROOT,env={**os.environ,'RUNNER_TEMP':str(root),'PATH':str(tools)+os.pathsep+os.environ['PATH']},capture_output=True,text=True)
                self.assertEqual(cp.returncode,0,cp.stderr)
                self.assertNotIn(secret,''.join(p.read_text() for p in (root/'bakabel-public').iterdir()))
                self.assertEqual(json.loads((root/'bakabel-public/candidate.json').read_text())['suite'],suite)

    def test_capacity_and_faults_run_on_independent_fresh_vms(self):
        text=(ROOT/'.github/workflows/acceptance.yaml').read_text()
        self.assertIn('suite: [core-resources, capacity, faults]',text)
        self.assertIn('fail-fast: false',text)
        for suite,runner in (('capacity','run_hosted_capacity.py'),('faults','run_hosted_faults.py')):
            step=next(block for block in text.split('      - name: ') if runner in block)
            self.assertIn("if: matrix.suite == '"+suite+"'",step)
            self.assertIn('--image "$image_id"',step)
            self.assertNotIn('continue-on-error',step)
        self.assertIn('name: acceptance-${{ matrix.suite }}-${{ github.sha }}-${{ github.run_attempt }}',text)
        for name in ('capacity-receipt.json','capacity-metrics.json','capacity-summary.json','capacity-verified.json','hosted-faults.json'):
            self.assertIn(name,text)
        self.assertIn('from verify_hosted_faults import CASES',text)
        self.assertNotIn('sudo -E ',text)

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

    def test_entire_fixture_suite_needs_no_hermes_home_or_tmpdir(self):
        with tempfile.TemporaryDirectory() as directory:
            home=Path(directory)/'home';home.mkdir()
            temporary=Path(directory)/'portable-temp';temporary.mkdir()
            env={k:v for k,v in os.environ.items() if k not in ('TMPDIR','TMP','TEMP')}
            env.update(HOME=str(home),TEMP=str(temporary))
            script='''import sys,unittest
def flatten(suite):
    for item in suite:
        if isinstance(item,unittest.TestSuite):yield from flatten(item)
        else:yield item
tests=[test for test in flatten(unittest.defaultTestLoader.discover('.',pattern='test_*.py')) if test.id()!=sys.argv[1]]
assert any(test.id().startswith('test_hosted_capacity.') for test in tests)
raise SystemExit(not unittest.TextTestRunner(verbosity=0).run(unittest.TestSuite(tests)).wasSuccessful())
'''
            cp=subprocess.run([sys.executable,'-B','-c',script,self.id()],cwd=ROOT/'tests/integration/fixtures',env=env,text=True,capture_output=True)
            self.assertEqual(cp.returncode,0,cp.stderr)
            self.assertFalse((home/'.hermes').exists())

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
