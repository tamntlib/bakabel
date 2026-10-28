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


def export_sudo_shim(path):
    """Model env_reset and explicit preservation without executing real sudo."""
    path.write_text('#!'+sys.executable+'\n'+
        'import os,sys\n'
        'args=sys.argv[1:]; keep={"PATH"}\n'
        'if args and args[0].startswith("--preserve-env="):\n'
        '    keep.update(args.pop(0).split("=",1)[1].split(","))\n'
        'if args[0]=="chown": raise SystemExit(0)\n'
        'env={k:v for k,v in os.environ.items() if k in keep}\n'
        'os.execvpe(args[0],args,env)\n')
    path.chmod(0o700)


class WorkflowContract(unittest.TestCase):
    def test_real_selection_shell_validates_before_build_and_never_interpolates_inputs(self):
        import json
        import textwrap
        from verify_hosted_selection import plan
        text = (ROOT/'.github/workflows/acceptance.yaml').read_text()
        marker = '      - name: Validate manual scope and case'
        self.assertIn(marker, text, 'pre-build input validation is missing')
        block = text.split(marker,1)[1].split('\n  acceptance:',1)[0]
        self.assertIn('REQUESTED_SCOPE: ${{ inputs.scope }}', block)
        self.assertIn('REQUESTED_CASE: ${{ inputs.case }}', block)
        script = textwrap.dedent(block.split('        run: |\n',1)[1])
        self.assertNotIn('${{',script)
        self.assertNotIn('${{', text.split('      matrix:\n',1)[1].split('    env:',1)[0].replace('${{ fromJSON(needs.selection.outputs.matrix) }}',''))
        entries = plan('remaining-faults','all') + plan('single-fault','restore-reader-failure-importer-zero')
        pairs = [('all','all'),('remaining-faults','all')] + [('single-fault',e['case']) for e in entries]
        pairs += [('all',entries[0]['case']),('remaining-faults',entries[-1]['case']),
                  ('single-fault','all'),('bogus','all'),('single-fault','$(touch INJECTED)'),
                  ('single-fault','x\nextra=true'),('single-fault','../../private')]
        for scope, case in pairs:
            with self.subTest(scope=scope,case=case), tempfile.TemporaryDirectory() as directory:
                output = Path(directory)/'output'; output.touch()
                cp = subprocess.run(['bash','-eu','-c',script],cwd=ROOT,capture_output=True,text=True,
                    env={**os.environ,'REQUESTED_SCOPE':scope,'REQUESTED_CASE':case,'GITHUB_OUTPUT':str(output)})
                try: expected = plan(scope,case)
                except ValueError:
                    self.assertNotEqual(cp.returncode,0)
                    self.assertEqual(output.read_text(),'')
                else:
                    self.assertEqual(cp.returncode,0,cp.stderr)
                    key, value = output.read_text().strip().split('=',1)
                    self.assertEqual(key,'matrix'); self.assertEqual(json.loads(value),expected)
                self.assertFalse((ROOT/'INJECTED').exists())
        for label in ('Real current workflow fault boundaries','Additive bounded storage and extension prerequisite gates'):
            block = text.split('      - name: '+label,1)[1].split('      - name:',1)[0]
            self.assertIn("if: matrix.suite == 'faults'",block)

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
                export_sudo_shim(sudo)
                (root/'bakabel-candidate.json').write_text(json.dumps({'suite':suite}))
                if suite=='core-resources':
                    receipt=root/'bakabel-acceptance/compose/receipt.json';receipt.parent.mkdir(parents=True)
                    receipt.write_text(json.dumps({'platform':'compose','commands':[{'Env':[secret]}]}))
                elif suite=='capacity':
                    receipt=root/'bakabel-capacity/capacity-receipt.json';receipt.parent.mkdir()
                    receipt.write_text(json.dumps({'offline_unit_fixture':True}))
                else:
                    f13='dump-persisted-before-start-worker-SIGKILL'
                    f15='restore-active-import-worker-SIGKILL'
                    from verify_hosted_native_faults import NATIVE_CASES
                    self.assertTrue(set(NATIVE_CASES)<=set(CASES))
                    exported_cases=CASES
                    self.assertIn(f13,CASES)
                    self.assertIn(f15,CASES)
                    for name in exported_cases:
                        receipt=root/'bakabel-faults'/name/'receipt.json';receipt.parent.mkdir(parents=True)
                        receipt.write_text(json.dumps({'offline_unit_fixture':True,'case':name}))
                    for name in ('unknown-fault','private','proc','tracer','dump-start-private-canary'):
                        private=root/'bakabel-faults'/name/'receipt.json';private.parent.mkdir(parents=True)
                        private.write_text(secret)
                    (root/'bakabel-faults/raw-errors.log').write_text(secret)
                private=root/'bakabel-capacity/private/receipt.json';private.parent.mkdir(parents=True,exist_ok=True);private.write_text(secret)
                cp=subprocess.run(['bash','-eu','-c',script],cwd=ROOT,env={**os.environ,'RUNNER_TEMP':str(root),'PATH':str(tools)+os.pathsep+os.environ['PATH']},capture_output=True,text=True)
                self.assertEqual(cp.returncode,0,cp.stderr)
                self.assertNotIn(secret,''.join(p.read_text() for p in (root/'bakabel-public').iterdir()))
                self.assertEqual(json.loads((root/'bakabel-public/candidate.json').read_text())['suite'],suite)
                if suite=='faults':
                    exported={path.name for path in (root/'bakabel-public').iterdir()}
                    self.assertEqual(exported,{'candidate.json',*('faults-'+name+'.json' for name in exported_cases)})
                    self.assertEqual(json.loads((root/('bakabel-public/faults-'+f13+'.json')).read_text())['case'],f13)
                    self.assertEqual(json.loads((root/('bakabel-public/faults-'+f15+'.json')).read_text())['case'],f15)

    def test_remaining_gates_have_seven_exclusive_matrix_vms_without_legacy_jobs(self):
        import json
        text = (ROOT/'.github/workflows/acceptance.yaml').read_text()
        trigger = text.split('permissions:',1)[0]
        for item in ('scope:', 'type: choice', 'default: all', '- all', '- remaining-faults'):
            self.assertIn(item, trigger)
        from verify_hosted_selection import plan
        matrix = text.split('      matrix:\n',1)[1].split('    env:',1)[0]
        self.assertIn('fromJSON(needs.selection.outputs.matrix)', matrix)
        self.assertIn('needs: selection', text)
        selected, default = plan('remaining-faults','all'), plan('all','all')
        self.assertEqual(default, [{'suite':s,'case':'all'} for s in ('core-resources','capacity','faults')])
        self.assertEqual(selected, [
            {'suite':'native','case':'restic-native-exit3'},
            {'suite':'native','case':'unknown-commit-before-finalize-worker-SIGKILL'},
            {'suite':'native','case':'finalized-before-report-worker-SIGKILL'},
            {'suite':'storage','case':'temp-pack-ENOSPC'},
            {'suite':'storage','case':'restore-output-ENOSPC'},
            {'suite':'native','case':'file-truncate-during-native-read'},
            {'suite':'storage','case':'restore-missing-extension-binary-prerequisites'}])
        self.assertEqual(len({entry['case'] for entry in selected}),7)
        self.assertLess(text.index('name: Validate manual scope and case'), text.index('name: Install pinned rootful Engine'))
        self.assertNotIn('continue-on-error',text)
        self.assertIn('fail-fast: false',text)
        self.assertIn('ACCEPTANCE_SCOPE: ${{ inputs.scope }}',text)
        self.assertIn('ACCEPTANCE_CASE: ${{ matrix.case }}',text)
        self.assertIn("'scope':os.environ['ACCEPTANCE_SCOPE']",text)
        self.assertIn("'case':os.environ['ACCEPTANCE_CASE']",text)
        self.assertIn('name: acceptance-${{ matrix.suite }}-${{ github.sha }}-${{ github.run_attempt }}-${{ env.ACCEPTANCE_SCOPE }}-${{ matrix.case }}',text)

    def test_real_remaining_shell_selects_one_case_and_stops_after_failure(self):
        import json
        import textwrap
        text = (ROOT/'.github/workflows/acceptance.yaml').read_text()
        marker = '      - name: Independent remaining fault gate on fresh VM'
        self.assertIn(marker, text, 'independent case runner step is missing')
        block = text.split(marker,1)[1].split('      - name:',1)[0]
        self.assertIn("if: inputs.scope == 'remaining-faults' || inputs.scope == 'single-fault'", block)
        script = textwrap.dedent(block.split('        run: |\n',1)[1])
        from verify_hosted_selection import plan
        entries = plan('remaining-faults','all') + plan('single-fault','restore-reader-failure-importer-zero')
        for entry in entries:
            for runner_exit, verifier_exit in ((0,0),(7,0),(0,8)):
                with self.subTest(entry=entry, runner_exit=runner_exit, verifier_exit=verifier_exit), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory); tools = root/'tools'; tools.mkdir()
                    sudo = tools/'sudo'
                    sudo.write_text('#!/bin/sh\ncase "$1" in --preserve-env=*) shift;; esac\nexec "$@"\n'); sudo.chmod(0o700)
                    observer = tools/'strace'; observer.write_text('#!/bin/sh\nexit 99\n'); observer.chmod(0o700)
                    python = tools/'python3'
                    python.write_text('#!'+sys.executable+'\n'+textwrap.dedent('''\
                        import json,os,sys
                        from pathlib import Path
                        if sys.argv[1] == '-c':
                            exec(sys.argv[2]); raise SystemExit(0)
                        with open(os.environ['CALL_LOG'],'a') as out:
                            out.write(json.dumps({'args':sys.argv[1:],'cpus':sorted(os.sched_getaffinity(0))})+'\\n')
                        if Path(sys.argv[1]).name.startswith('run_'):
                            raise SystemExit(int(os.environ['RUNNER_EXIT']))
                        if Path(sys.argv[1]).name != 'verify_hosted_selection.py': raise SystemExit(99)
                        raise SystemExit(int(os.environ['VERIFIER_EXIT']))
                    ''')); python.chmod(0o700)
                    (root/'bakabel-candidate.json').write_text(json.dumps({'source_sha256':'1'*64,'image_id':'sha256:'+'2'*64}))
                    log = root/'calls.jsonl'
                    env = {**os.environ, 'PATH':str(tools)+os.pathsep+os.environ['PATH'],
                           'RUNNER_TEMP':str(root), 'ENGINE_SOCKET':'/unit-no-engine.sock',
                           'ACCEPTANCE_SUITE':entry['suite'], 'ACCEPTANCE_CASE':entry['case'],
                           'ACCEPTANCE_SCOPE':'single-fault' if entry['suite']=='reader' else 'remaining-faults','CALL_LOG':str(log),
                           'RUNNER_EXIT':str(runner_exit),'VERIFIER_EXIT':str(verifier_exit)}
                    cp = subprocess.run(['bash','-eu','-c',script], cwd=ROOT, env=env, capture_output=True, text=True)
                    self.assertEqual(cp.returncode, runner_exit or verifier_exit, cp.stderr)
                    calls = [json.loads(line) for line in log.read_text().splitlines()]
                    self.assertEqual(len(calls), 1 if runner_exit else 2)
                    runner = 'run_hosted_faults.py' if entry['suite'] in ('native','reader') else 'run_hosted_storage_prereqs.py'
                    self.assertEqual(Path(calls[0]['args'][0]).name, runner)
                    for call in calls:
                        self.assertEqual(call['cpus'],sorted(os.sched_getaffinity(0)))
                        args = call['args']
                        self.assertEqual(args.count('--case'),1)
                        self.assertEqual(args[args.index('--case')+1],entry['case'])
                    self.assertIn('--exclusive-hosted-daemon',calls[0]['args'])
                    for flag, expected in (('--source',str(ROOT)),('--image','sha256:'+'2'*64),
                                           ('--expected-image-id','sha256:'+'2'*64),('--expected-source-sha256','1'*64)):
                        args = calls[0]['args']; self.assertEqual(args[args.index(flag)+1],expected)
                    if not runner_exit:
                        args = calls[1]['args']
                        self.assertEqual(args[args.index('--suite')+1],entry['suite'])
                        self.assertEqual(args[args.index('--candidate')+1],str(root/'bakabel-candidate.json'))
                        self.assertEqual(args[args.index('--source')+1],str(ROOT))

    def test_real_export_shell_includes_allowlisted_scoped_verdict_not_private_data(self):
        import json
        import textwrap
        text = (ROOT/'.github/workflows/acceptance.yaml').read_text()
        block = text.split('      - name: Export only allowlisted evidence even on failure',1)[1].split('      - uses:',1)[0]
        script = textwrap.dedent(block.split('        run: |\n',1)[1])
        from verify_hosted_selection import plan
        entries = plan('remaining-faults','all') + plan('single-fault','restore-reader-failure-importer-zero')
        for entry in entries:
            suite, case = entry['suite'], entry['case']
            runtime = 'bakabel-storage' if suite == 'storage' else 'bakabel-faults'
            with self.subTest(suite=suite,case=case), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); tools = root/'tools'; tools.mkdir()
                sudo = tools/'sudo'
                export_sudo_shim(sudo)
                receipt = root/runtime/case/'receipt.json'; receipt.parent.mkdir(parents=True)
                receipt.write_text(json.dumps({'offline_unit_fixture':True,'case':case}))
                verdict = {'scope':'single-fault' if suite == 'reader' else 'remaining-faults','suite':suite,'case':case,
                           'selected_case_pass':True,'full_plan_acceptance_pass':False}
                (root/runtime/'selected-verified.json').write_text(json.dumps(verdict))
                private = root/runtime/'private/receipt.json'; private.parent.mkdir()
                private.write_text('PRIVATE-CANARY')
                (root/runtime/'selected-verified-private.log').write_text('PRIVATE-CANARY')
                cp = subprocess.run(['bash','-eu','-c',script],cwd=ROOT,capture_output=True,text=True,
                    env={**os.environ,'ACCEPTANCE_SUITE':suite,'RUNNER_TEMP':str(root),'PATH':str(tools)+os.pathsep+os.environ['PATH']})
                self.assertEqual(cp.returncode,0,cp.stderr)
                public = root/'bakabel-public'
                expected = ('storage-' if suite=='storage' else 'faults-')+case+'.json'
                self.assertEqual({p.name for p in public.iterdir()}, {expected,suite+'-selected-verified.json'})
                self.assertEqual(json.loads((public/(suite+'-selected-verified.json')).read_text()),verdict)
                self.assertNotIn('PRIVATE-CANARY',''.join(p.read_text() for p in public.iterdir()))

    def test_targeted_offline_shell_cannot_rerun_f14_kernel_suite(self):
        import json
        import textwrap
        text = (ROOT/'.github/workflows/acceptance.yaml').read_text()
        block = text.split('      - name: Offline fixture and documentation tests',1)[1].split('      - name:',1)[0]
        script = textwrap.dedent(block.split('        run: |\n',1)[1])
        for scope, pattern in (('all','test_*.py'),('remaining-faults','test_hosted_selection.py'),
                               ('single-fault','test_hosted_selection.py')):
            with self.subTest(scope=scope), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); python = root/'python3'; log = root/'calls'
                python.write_text('#!'+sys.executable+'\nimport json,os,sys\nwith open(os.environ["CALL_LOG"],"a") as out: out.write(json.dumps(sys.argv[1:])+"\\n")\n')
                python.chmod(0o700)
                cp = subprocess.run(['bash','-eu','-c',script],cwd=ROOT,capture_output=True,text=True,
                    env={**os.environ,'ACCEPTANCE_SCOPE':scope,'CALL_LOG':str(log),'PATH':str(root)+os.pathsep+os.environ['PATH']})
                self.assertEqual(cp.returncode,0,cp.stderr)
                calls = [json.loads(line) for line in log.read_text().splitlines()]
                self.assertEqual(calls, [
                    ['-m','unittest','discover','-s','tests/integration/fixtures','-p',pattern,'-v'],
                    ['-m','unittest','discover','-s','tests','-p','test_documentation.py','-v']])

    def test_capacity_and_faults_run_on_independent_fresh_vms(self):
        text=(ROOT/'.github/workflows/acceptance.yaml').read_text()
        from verify_hosted_selection import plan
        self.assertEqual([e['suite'] for e in plan('all','all')], ['core-resources','capacity','faults'])
        from verify_hosted_faults import CASES
        self.assertIn('restore-reader-failure-importer-zero', CASES)
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
