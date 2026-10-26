"""Offline boundary tests; protocol doubles are not Docker/hosted evidence."""
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
SCRATCH = Path(tempfile.gettempdir())


def validator_fixture():
    """Small explicit validator inputs, NOT Engine responses or hosted evidence."""
    import run_hosted_capacity as c
    image = 'sha256:'+'f'*64
    metrics = []
    for cid, role in [('a'*64, 'worker'), ('b'*64, 'worker'), ('c'*64, 'worker'),
                      ('d'*64, 'source-pg'), ('e'*64, 'source-files'), ('f'*64, 'restore-pg'),
                      ('0'*64, 'fixture-s3-backend'), ('8'*64, 'operator-readback')]:
        for tick in (1, 2):
            metrics.append(c.project_sample({'at': '2026-01-01T00:00:00+00:00', 'monotonic': tick,
                'role': role, 'container': cid, 'cpu.max': '200000 100000',
                'memory.max': '536870912', 'memory.peak': '200', 'memory.current': '100',
                'cpu.stat': 'usage_usec '+str(tick), 'io.stat': '', 'tmp_capacity_bytes': c.TMP_BYTES,
                'tmp_cache_footprint': {'bytes': 2}, 'state_footprint': {'bytes': 8}, 'log_bytes': 3,
                'processes': [{'pid': 1, 'starttime_ticks': 1, 'rss_bytes': 12,
                               'memory': {'Pss': 8, 'Rss': 12}, 'io': {'read_bytes': tick}}]}))
    resources = {'image_id': image, 'memory_bytes': 536870912, 'nanocpus': 2000000000,
        'readonly_rootfs': True, 'tmpfs': 'rw,nosuid,nodev,size=67108864', 'workflow_entrypoint': True,
        'workflow_command': True, 'cpuset_empty': True, 'credential_mounts_readonly': True}
    rounds = [{'phase': phase, 'worker': worker*64, 'file_snapshot': str(i+1)*64,
        'pg_snapshot': str(i+4)*64, 'worker_resources': dict(resources),
        'repository': {'index_objects': 1, 'decoded_index_bytes': c.FILES*100,
            'unique_indexed_data_blobs': c.FILES+(c.CHANGED_FILES if i == 2 else 0),
            'unique_indexed_tree_blobs': 2, 'unique_indexed_packs': 3,
            'raw_data_stats': {'total_size': c.FILES*c.FILE_BYTES+i*1000}}}
        for i, (phase, worker) in enumerate(zip(('first', 'repeat', 'changed'), 'abc'))]
    snapshots = {phase: {'id': str(i+1)*64, 'parent': str(i)*64 if i else None,
        'summary': {'files_unmodified': c.FILES+1 if i == 1 else 0, 'data_blobs': 0 if i == 1 else 3,
                    'data_added_packed': 0 if i == 1 else 90}}
        for i, phase in enumerate(('first', 'repeat', 'changed'))}
    def pg_stats(role, after=False):
        return {'at': '2026-01-01T00:00:00+00:00',
            'sql': {'database_bytes': 100+(100 if after else 0), 'wal_bytes': 20+(10 if after else 0),
                    'wal_records': 1, 'blks_read': 0, 'blks_hit': 0, 'temp_bytes': 0,
                    'tup_inserted': 0, 'tup_returned': 0},
            'pg_stat_io': [{'backend_type': 'client backend', 'object': 'relation', 'context': 'normal',
                           'counters': {'reads': 0}}],
            'metrics': next(m for m in metrics if m['role'] == role)}
    readback = {'rows': c.PG_ROWS, 'sum_g': c.PG_ROWS*(c.PG_ROWS+1)//2, 'ordered_payload_md5': 'a'*32}
    source = {'d'*64: {'started_at': '2026-01-01T00:00:00Z', 'restart_count': 0},
              'e'*64: {'started_at': '2026-01-01T00:00:00Z', 'restart_count': 0}}
    receipt = {'schema': 1, 'measurements_complete': True, 'full_plan_acceptance_pass': False,
        'gates': sorted(c.GATES), 'source_sha256': c.STOCK_SOURCE, 'image_id': image,
        'sampler_error_count': 0, 'retention_enabled': False, 'rounds': rounds,
        'source_windows': [{'phase': phase, 'before': pg_stats('source-pg'), 'after': pg_stats('source-pg', True)}
                           for phase in ('first', 'repeat', 'changed')],
        'corpus': {'files': c.FILES, 'file_bytes': c.FILE_BYTES, 'payload_bytes': c.FILES*c.FILE_BYTES,
            'changed_files': c.CHANGED_FILES, 'changed_payload_bytes': c.CHANGED_FILES*c.FILE_BYTES,
            'first_manifest_sha256': '1'*64, 'changed_manifest_sha256': '2'*64, 'incompressible_random': True},
        'file_snapshots': snapshots,
        'file_readbacks': [{'phase': phase, 'snapshot': snapshots[phase]['id'],
            'files_compared': c.FILES, 'payload_bytes_compared': c.FILES*c.FILE_BYTES,
            'all_sha256_equal': True, 'streamed_no_local_staging': True, 'manifest_sha256': digest*64,
            'docker_attach_exit': 0, 'restic_exit': 0} for phase, digest in (('first', '1'), ('changed', '2'))],
        'source_pg_readback': readback,
        'pg_restore': {'snapshot': rounds[0]['pg_snapshot'], 'target': 'f'*64, 'readback': dict(readback),
            'owner_acl_equal': True, 'before': pg_stats('restore-pg'), 'after': pg_stats('restore-pg', True)},
        'source_identity_before': source, 'source_identity_after': dict(source), 'source_read_write_ok': True,
        'image_measurement': {k: 1 for k in ('actual_save_tar_bytes', 'oci_compressed_layer_bytes',
            'actual_merged_export_tar_bytes', 'actual_export_extracted_regular_file_allocated_bytes',
            'merged_export_regular_file_payload_bytes', 'merged_export_regular_files')},
        'disk_checkpoints': {phase: {'state': {'bytes': 8}, 'fresh_state': {'bytes': 8},
            's3_fixture_persistent': {'bytes': c.FILES*c.FILE_BYTES+1000},
            'owned_pg_and_source_volumes': {'owned-fixture': {'bytes': c.FILES*c.FILE_BYTES}}}
            for phase in ('prepared', 'first', 'repeat', 'changed', 'after-restore')},
        'cleanup': {'containers_absent': {s['container']: True for s in metrics},
                    'volumes_absent': {'owned-fixture': True}, 'private_paths_absent': True}}
    receipt['runtime_binary_sha256'] = 'a'*64
    receipt['runtime_restic_sha256'] = 'b'*64
    receipt['binaries'] = {'bakabel': {'bytes': 1, 'sha256': 'a'*64}, 'restic': {'bytes': 2, 'sha256': 'b'*64}}
    receipt['cleanup']['target_containers'] = sorted(receipt['cleanup']['containers_absent'])
    receipt['cleanup']['target_volumes'] = sorted(receipt['cleanup']['volumes_absent'])
    return receipt, metrics


class HostedCapacityTests(unittest.TestCase):
    def test_local_cli_refuses_before_reading_socket_source_or_creating_runtime(self):
        with tempfile.TemporaryDirectory(dir=SCRATCH) as root:
            runtime = Path(root)/'uncreated'
            env = {**os.environ, 'GITHUB_ACTIONS': 'false', 'RUNNER_ENVIRONMENT': 'self-hosted'}
            cp = subprocess.run([sys.executable, str(HERE/'run_hosted_capacity.py'),
                '--socket', '/does-not-exist.sock', '--source', '/does-not-exist-source',
                '--runtime', str(runtime), '--minio-binary', '/does-not-exist-minio',
                '--image', 'sha256:'+'a'*64, '--expected-image-id', 'sha256:'+'a'*64,
                '--expected-source-sha256', '6a592fcf1159d301bbe9acf0ff82e3e681913de4d1fb6f17ccc2d05c9d394ef8',
                '--exclusive-hosted-daemon'], env=env, text=True, capture_output=True)
            self.assertEqual(cp.returncode, 2)
            self.assertIn('exclusive GitHub-hosted', cp.stderr)
            self.assertFalse(runtime.exists())


    def test_binding_rejects_nonstock_source_and_nonfresh_runtime(self):
        import run_hosted_capacity as c
        with tempfile.TemporaryDirectory(dir=SCRATCH) as root:
            args = c.parser().parse_args(['--socket', '/missing', '--source', str(HERE.parents[2]),
                '--runtime', str(Path(root)/'capacity'), '--minio-binary', '/missing',
                '--image', 'sha256:'+'a'*64, '--expected-image-id', 'sha256:'+'a'*64,
                '--expected-source-sha256', 'b'*64, '--exclusive-hosted-daemon'])
            self.assertTrue(hasattr(c, 'validate_paths'), 'missing fail-closed binding/path validator')
            with self.assertRaisesRegex(ValueError, 'stock'):
                c.validate_paths(args, {'RUNNER_TEMP': root})
            args.expected_source_sha256 = c.STOCK_SOURCE
            args.runtime.mkdir()
            with self.assertRaisesRegex(ValueError, 'fresh child'):
                c.validate_paths(args, {'RUNNER_TEMP': root})
            self.assertFalse((args.runtime/'private').exists())


    def test_worker_state_footprint_uses_exact_recorded_state_directory(self):
        from unittest.mock import patch
        from types import SimpleNamespace
        import run_hosted_capacity as c
        with tempfile.TemporaryDirectory(dir=SCRATCH) as root:
            p = c.CapacityProbe.__new__(c.CapacityProbe)
            p.root = Path(root)
            for name, payload in [('state', b'old'), ('fresh-state', b'fresh-restore-state')]:
                (p.root/name).mkdir();(p.root/name/'data').write_bytes(payload)
            p.worker_records = {'a'*64: {'state': 'state'}, 'b'*64: {'state': 'fresh-state'}}
            p.e = SimpleNamespace(inspect=lambda *a, **kw: {'State': {'Running': True, 'Pid': os.getpid()}})
            with patch.object(p, 'pin_container'), patch.object(p, 'cgroup', return_value=None), \
                    patch.object(p, 'pids', return_value=[]):
                for cid, record in p.worker_records.items():
                    row = p.measure(cid, 'worker')
                    self.assertEqual(row['state_footprint'], c.footprint(p.root/record['state']))
            self.assertNotEqual(c.footprint(p.root/'state')['bytes'], c.footprint(p.root/'fresh-state')['bytes'])

    def test_projection_and_summary_preserve_unlinked_sampling_gaps_without_zeroing_unknowns(self):
        import run_hosted_capacity as c
        raw = {'at': '2026-01-01T00:00:00+00:00', 'monotonic': 1, 'role': 'worker',
               'container': 'a'*64, 'tmp_cache_footprint': {'bytes': 2, 'unlinked_during_sample': 3},
               'state_footprint': {'bytes': 4, 'unlinked_during_sample': 5}}
        first = c.project_sample(raw)
        self.assertEqual(first['tmp'].get('unlinked_during_sample'), 3)
        self.assertEqual(first['state'].get('unlinked_during_sample'), 5)
        second = c.project_sample({**raw, 'monotonic': 2})
        summary = c.summarize_samples([first, second])['containers'][0]
        self.assertEqual(summary.get('tmp_unlinked_during_sample'), 6)
        self.assertEqual(summary.get('state_unlinked_during_sample'), 10)
        unknown = c.project_sample({**raw, 'tmp_cache_footprint': {'bytes': 2}})
        self.assertIsNone(unknown['tmp']['unlinked_during_sample'])
        self.assertIsNone(c.summarize_samples([first, unknown])['containers'][0]['tmp_unlinked_during_sample'])
        missing = c.project_sample({k: v for k, v in raw.items() if k != 'state_footprint'})
        self.assertIsNone(c.summarize_samples([first, missing])['containers'][0]['state_unlinked_during_sample'])

    def test_metric_projection_keeps_io_boundaries_and_missing_pss_without_raw_fields(self):
        import run_hosted_capacity as c
        self.assertTrue(hasattr(c, 'project_sample'), 'missing safe metric projection')
        raw = {'at': '2026-01-01T00:00:00+00:00', 'monotonic': 1.0,
               'container': 'a'*64, 'role': 'worker', 'cpu.max': '200000 100000',
               'memory.max': '536870912', 'memory.current': '27', 'memory.peak': '33',
               'cpu.stat': 'usage_usec 12\nthrottled_usec 3',
               'io.stat': '8:0 rbytes=17 wbytes=21 rios=1 wios=2\n',
               'processes': [{'pid': 1, 'starttime_ticks': 7, 'rss_bytes': 20,
                              'io': {'read_bytes': 9, 'rchar': 40}, 'Env': ['SECRET'] }],
               'stdout_stderr': 'SECRET', 'docker_stats': {'SECRET': 'SECRET'}}
        projected = c.project_sample(raw)
        self.assertEqual(projected['io_devices']['8:0']['rbytes'], 17)
        self.assertEqual(projected['processes'][0]['io']['read_bytes'], 9)
        self.assertIsNone(projected['processes'][0]['pss_bytes'])
        self.assertEqual(projected['memory_peak_bytes'], 33)
        self.assertNotIn('SECRET', json.dumps(projected))
        end = c.project_sample({**raw, 'monotonic': 2.0, 'cpu.stat': 'usage_usec 25',
            'io.stat': '8:0 rbytes=22 wbytes=30 rios=2 wios=3\n'})
        summary = c.summarize_samples([projected, end])['containers'][0]
        self.assertEqual(summary['cgroup_cpu_observed_seconds'], 13/1000000)
        self.assertEqual(summary['cgroup_io_observed_delta']['8:0']['rbytes'], 5)
        self.assertIsNone(summary['sampled_process_pss_sum_peak_bytes'])
        unavailable = c.project_sample({**raw, 'io.stat': 'PermissionError'})
        self.assertIsNone(unavailable['io_devices'])
        self.assertIsNone(c.summarize_samples([unavailable])['containers'][0]['cgroup_io_observed_delta'])


    def test_real_small_corpus_changed_subset_and_streamed_exact_checksum_readback(self):
        import hashlib
        import run_hosted_capacity as c
        self.assertTrue(hasattr(c, 'generate_corpus'), 'missing bounded corpus generator')
        with tempfile.TemporaryDirectory(dir=SCRATCH) as root:
            root = Path(root)
            original = c.generate_corpus(root, 4, 37)
            before = {p.name:p.read_bytes() for p in root.glob('file-*')}
            changed = c.generate_corpus(root, 4, 37, changed=2)
            after = {p.name:p.read_bytes() for p in root.glob('file-*')}
            self.assertEqual(sum(before[k] != after[k] for k in before), 2)
            self.assertNotEqual(original, changed)
            archive = io.BytesIO()
            with tarfile.open(fileobj=archive, mode='w') as tar:
                for path in sorted(root.iterdir()):
                    tar.add(path, arcname='data/'+path.name)
            archive.seek(0)
            result = c.verify_tar(archive, changed, 37)
            self.assertEqual(result['files_compared'], 4)
            self.assertEqual(result['payload_bytes_compared'], 148)
            self.assertEqual(result['manifest_sha256'], hashlib.sha256(changed.encode()).hexdigest())
            self.assertTrue(result['all_sha256_equal'])
            archive.seek(0)
            with self.assertRaisesRegex(ValueError, 'checksum'):
                c.verify_tar(archive, original, 37)
            with self.assertRaises(FileExistsError):
                c.generate_corpus(root, 4, 37)

    def test_stream_readback_refuses_duplicate_or_traversal_members(self):
        import hashlib
        import run_hosted_capacity as c
        self.assertTrue(hasattr(c, 'verify_tar'), 'missing exact stream verifier')
        manifest = hashlib.sha256(b'x').hexdigest()+'  file-000000.dat\n'
        for names in (['../file-000000.dat'], ['file-000000.dat', 'file-000000.dat']):
            archive = io.BytesIO()
            with tarfile.open(fileobj=archive, mode='w') as tar:
                for name in names:
                    member = tarfile.TarInfo(name);member.size = 1
                    tar.addfile(member, io.BytesIO(b'x'))
            archive.seek(0)
            with self.assertRaises(ValueError):
                c.verify_tar(archive, manifest, 1)


    def test_capacity_save_never_writes_inherited_raw_receipt_and_detects_credential_leak(self):
        import run_hosted_capacity as c
        self.assertTrue(hasattr(c, 'CapacityProbe'), 'missing focused Probe subclass')
        with tempfile.TemporaryDirectory(dir=SCRATCH) as root:
            p = c.CapacityProbe.__new__(c.CapacityProbe)
            p.root = Path(root);p.values = ['SYNTHETIC-SECRET']
            p.result = {'commands': [{'stdout_stderr': 'RAW-CLI'}], 'Config': {'Env': ['RAW-ENV']}}
            p.capacity = {'schema': 1, 'gates': [], 'capacity_pass': False}
            p.save()
            written = (p.root/'capacity-receipt.json').read_text()
            self.assertNotIn('RAW-', written)
            self.assertFalse((p.root/'receipt.json').exists())
            p.capacity['error'] = 'SYNTHETIC-SECRET'
            with self.assertRaisesRegex(ValueError, 'credential'):
                p.save()
            self.assertNotIn('SYNTHETIC-SECRET', (p.root/'capacity-receipt.json').read_text())

    def test_operator_spec_has_bounded_temp_file_credentials_no_published_ports(self):
        import run_hosted_capacity as c
        self.assertTrue(hasattr(c, 'CapacityProbe'), 'missing focused Probe subclass')
        p = c.CapacityProbe.__new__(c.CapacityProbe)
        p.root = Path('/owned-fixture');p.image = 'sha256:'+'a'*64
        p.repository = 's3:http://172.17.0.2:9000/fixture/repository'
        spec = p.restic_spec(['snapshots', '--json'])
        self.assertEqual(spec['Cmd'], ['--no-cache', 'snapshots', '--json'])
        self.assertEqual(spec['HostConfig']['Tmpfs']['/tmp'], 'rw,nosuid,nodev,size=67108864')
        self.assertTrue(spec['HostConfig']['ReadonlyRootfs'])
        self.assertEqual(spec['HostConfig'].get('LogConfig', {}).get('Config'), {'max-size': '8m', 'max-file': '1'})
        self.assertNotIn('RESTIC_PASSWORD=', json.dumps(spec))
        self.assertNotIn('AWS_SECRET_ACCESS_KEY=', json.dumps(spec))
        self.assertNotIn('PortBindings', spec['HostConfig'])
        self.assertTrue(all(m['ReadOnly'] for m in spec['HostConfig']['Mounts']))
        with self.assertRaisesRegex(ValueError, 'destructive'):
            p.restic_spec(['unlock', '--remove-all'])


    def test_snapshot_contract_requires_real_parent_zero_repeat_and_nonzero_change(self):
        import run_hosted_capacity as c
        self.assertTrue(hasattr(c, 'snapshot_evidence'), 'missing capacity snapshot verifier')
        snapshots = []
        for i in range(3):
            snapshots.append({'id': str(i+1)*64, 'parent': str(i)*64 if i else None,
                'tags': ['bakabel.status=complete'], 'paths': ['/bakabel/files/fixture/data'],
                'summary': {'files_unmodified': c.FILES+1 if i == 1 else c.FILES-c.CHANGED_FILES,
                            'data_blobs': 0 if i == 1 else c.CHANGED_FILES,
                            'data_added_packed': 0 if i == 1 else 1024}})
        result = c.snapshot_evidence(snapshots, [s['id'] for s in snapshots])
        self.assertEqual(result['repeat']['parent'], snapshots[0]['id'])
        for key, value in [('parent', 'f'*64), ('summary', {'files_unmodified': c.FILES+1, 'data_blobs': 2})]:
            bad = [dict(s) for s in snapshots];bad[1][key] = value
            with self.assertRaises(ValueError):
                c.snapshot_evidence(bad, [s['id'] for s in snapshots])
        bad = [dict(s) for s in snapshots];bad[2]['summary'] = {'data_blobs': 0}
        with self.assertRaises(ValueError):
            c.snapshot_evidence(bad, [s['id'] for s in snapshots])

    def test_decoded_index_count_and_numeric_pg_projection_preserve_measurement_boundary(self):
        import run_hosted_capacity as c
        self.assertTrue(hasattr(c, 'index_evidence'), 'missing actual index accounting')
        decoded = ['{"packs":[{"id":"opaque","blobs":[{"id":"data1","type":"data"},{"id":"tree1","type":"tree"}]}]}']
        evidence = c.index_evidence(decoded)
        self.assertEqual(evidence['unique_indexed_data_blobs'], 1)
        self.assertEqual(evidence['unique_indexed_tree_blobs'], 1)
        self.assertEqual(evidence['decoded_index_bytes'], len(decoded[0].encode()))
        self.assertNotIn('opaque', json.dumps(evidence))
        raw = {'at': '2026-01-01T00:00:00+00:00',
               'sql': json.dumps({'database_bytes': 8, 'wal_bytes': 4, 'wal_lsn': 'SECRET', 'password': 'SECRET'}),
               'pg_stat_io': [{'backend_type': 'client backend', 'object': 'relation',
                              'context': 'normal', 'reads': 0, 'read_bytes': None, 'secret': 'SECRET'}],
               'metrics': {'at': '2026-01-01T00:00:00+00:00', 'monotonic': 1, 'role': 'source-pg',
                           'container': 'a'*64, 'processes': []}}
        projected = c.project_pg(raw)
        self.assertEqual(projected['sql']['wal_bytes'], 4)
        self.assertNotIn('SECRET', json.dumps(projected))
        self.assertNotIn('read_bytes', projected['pg_stat_io'][0]['counters'])


    def test_focused_runner_sequences_three_rounds_readback_restore_without_fault_replay(self):
        import run_hosted_capacity as c
        calls = []
        class OfflineSequence(c.CapacityProbe):
            def __init__(self):
                self.capacity = {}
            def save(self): pass  # Orchestration-only test; evidence persistence tested separately.
            def prepare(self): calls.append('prepare')
            def change_corpus(self): calls.append('mutate')
            def backup_capacity(self, phase): calls.append(phase);return phase
            def verify_snapshots(self, rounds): calls.append(('parents', tuple(rounds)))
            def readback_capacity(self, rounds): calls.append(('readback', tuple(rounds)))
            def restore_capacity(self, first): calls.append(('restore', first))
            def verify_sources(self): calls.append('source-online')
            def image_audit(self): raise AssertionError('must be inside focused prepare')
        self.assertIn('run', c.CapacityProbe.__dict__, 'must not run the old whole B4/B5 probe')
        p = OfflineSequence();p.run()
        self.assertEqual(calls, ['prepare', 'first', 'repeat', 'mutate', 'changed',
            ('parents', ('first', 'repeat', 'changed')), ('readback', ('first', 'repeat', 'changed')),
            ('restore', 'first'), 'source-online'])
        self.assertTrue(p.capacity['measurements_complete'])
        self.assertNotIn('capacity_pass', p.capacity)  # Only independent readback may certify.

    def test_execute_always_cleans_up_and_retains_safe_primary_and_cleanup_failures(self):
        import run_hosted_capacity as c
        from types import SimpleNamespace
        self.assertTrue(hasattr(c, 'execute'), 'missing exception-safe capacity lifecycle')
        calls = []
        class OfflineFailure:
            def __init__(self, args):
                self.root = args.runtime;self.root.mkdir()
                self.capacity = {};self.values = []
            save = c.CapacityProbe.save
            def run(self): calls.append('run');raise RuntimeError('DO-NOT-EXPORT-RAW')
            def cleanup(self): calls.append('cleanup');raise OSError('DO-NOT-EXPORT-CLEANUP')
        with tempfile.TemporaryDirectory(dir=SCRATCH) as root:
            args = SimpleNamespace(runtime=Path(root)/'capacity')
            code = c.execute(args, probe_type=OfflineFailure)
            self.assertEqual(code, 1)
            self.assertEqual(calls, ['run', 'cleanup'])
            receipt = json.loads((args.runtime/'capacity-receipt.json').read_text())
            self.assertEqual(receipt['failure']['kind'], 'RuntimeError')
            self.assertEqual(receipt['cleanup_failure']['kind'], 'OSError')
            self.assertNotIn('DO-NOT-EXPORT', json.dumps(receipt))


    def test_operator_pretty_json_is_parsed_without_json_line_corruption(self):
        import run_hosted_capacity as c
        self.assertTrue(hasattr(c, 'json_rows'), 'missing real CLI JSON decoder')
        self.assertEqual(c.json_rows('{\n  "packs": []\n}\n'), [{'packs': []}])
        self.assertEqual(c.json_rows('[\n {"id":"one"}\n]\n'), [[{'id': 'one'}]])
        self.assertEqual(c.json_rows('diagnostic\n{"status":"complete"}\n'), [{'status': 'complete'}])
        self.assertEqual(c.json_rows('created repository\n'), [])

    def test_independent_validator_rejects_empty_or_self_attested_capacity_success(self):
        import importlib.util
        self.assertIsNotNone(importlib.util.find_spec('verify_hosted_capacity'), 'missing independent verifier')
        import verify_hosted_capacity as v
        with self.assertRaises(ValueError):
            v.validate_evidence({'schema': 1, 'capacity_pass': True, 'gates': []}, [])


    def test_independent_validator_accepts_complete_fixture_but_rejects_capacity_mutations(self):
        import copy
        import verify_hosted_capacity as v
        receipt, metrics = validator_fixture()
        self.assertEqual(v.validate_evidence(receipt, metrics)['sample_count'], len(metrics))
        mutations = [lambda r:r['corpus'].update(files=512),
            lambda r:r['rounds'][2]['repository'].update(unique_indexed_data_blobs=8192),
            lambda r:r['file_snapshots']['repeat']['summary'].update(data_blobs=1),
            lambda r:r['file_readbacks'][1].update(all_sha256_equal=False),
            lambda r:r['pg_restore']['readback'].update(rows=1),
            lambda r:r['rounds'][1]['worker_resources'].update(memory_bytes=0),
            lambda r:r['cleanup'].update(containers_absent={}),
            lambda r:r.update(retention_enabled=True),
            lambda r:r.update(sampler_error_count=1),
            lambda r:r['cleanup'].update(target_containers=[]),
            lambda r:r['binaries']['restic'].update(bytes=0),
            lambda r:r.update(source_windows=[])]
        for mutate in mutations:
            altered = copy.deepcopy(receipt);mutate(altered)
            with self.subTest(mutation=mutate.__code__.co_firstlineno):
                with self.assertRaises(ValueError):
                    v.validate_evidence(altered, metrics)
        with self.assertRaises(ValueError):
            v.validate_evidence(receipt, [s for s in metrics if s['role'] != 'restore-pg'])


    def test_authorized_cli_checks_fixed_source_binding_before_any_engine_access(self):
        from unittest.mock import patch
        import run_hosted_capacity as c
        with tempfile.TemporaryDirectory(dir=SCRATCH) as root:
            argv = ['--socket', '/not-an-engine', '--source', '/missing', '--runtime', root+'/capacity',
                    '--minio-binary', '/missing', '--image', 'sha256:'+'a'*64,
                    '--expected-image-id', 'sha256:'+'a'*64, '--expected-source-sha256', 'b'*64,
                    '--exclusive-hosted-daemon']
            with patch.dict(os.environ, {'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'github-hosted', 'RUNNER_TEMP': root}):
                with patch.object(c.os, 'geteuid', return_value=0), patch.object(c, 'Engine') as engine:
                    err = io.StringIO()
                    from contextlib import redirect_stderr
                    with redirect_stderr(err), self.assertRaises(SystemExit) as exit:
                        c.main(argv)
                    self.assertEqual(exit.exception.code, 2)
                    self.assertIn('stock', err.getvalue())
                    engine.assert_not_called()

    def test_verifier_cli_refuses_local_access_even_for_self_attested_receipt(self):
        with tempfile.TemporaryDirectory(dir=SCRATCH) as root:
            cp = subprocess.run([sys.executable, str(HERE/'verify_hosted_capacity.py'),
                '--socket', '/not-an-engine', '--source', '/missing', '--runtime', root,
                '--minio-binary', '/missing', '--image', 'sha256:'+'a'*64,
                '--expected-image-id', 'sha256:'+'a'*64,
                '--expected-source-sha256', '6a592fcf1159d301bbe9acf0ff82e3e681913de4d1fb6f17ccc2d05c9d394ef8',
                '--exclusive-hosted-daemon', '--output', root+'/capacity-verified.json'],
                env={**os.environ, 'GITHUB_ACTIONS': 'false'}, text=True, capture_output=True)
            self.assertEqual(cp.returncode, 2)
            self.assertIn('exclusive GitHub-hosted', cp.stderr)
            self.assertFalse((Path(root)/'capacity-verified.json').exists())


    def test_window_summary_keeps_process_identity_and_pg_wal_logical_io_deltas(self):
        import run_hosted_capacity as c
        self.assertTrue(hasattr(c, 'pg_window_delta'), 'missing source/restore boundary summary')
        receipt, metrics = validator_fixture()
        result = c.pg_window_delta(receipt['source_windows'][0])
        self.assertEqual(result['sql_observed_delta']['wal_bytes'], 10)
        self.assertEqual(result['database_bytes_before'], 100)
        self.assertEqual(result['database_bytes_after'], 200)
        row = next(r for r in c.summarize_samples(metrics)['containers'] if r['container'] == metrics[0]['container'])
        self.assertEqual(row['process_io_observed_deltas'][0]['io']['read_bytes'], 1)
        self.assertEqual(row['process_io_observed_deltas'][0]['starttime_ticks'], 1)
        changed = json.loads(json.dumps(metrics))
        changed[1]['processes'][0]['starttime_ticks'] = 2
        row = next(r for r in c.summarize_samples(changed)['containers'] if r['container'] == metrics[0]['container'])
        self.assertEqual(row['process_io_observed_deltas'], [])

    def test_lost_create_response_preserves_all_targets_and_private_paths(self):
        import run_hosted_capacity as c
        # Offline fault injection only: POST records a side effect then loses its
        # response. This is not a successful Docker/hosted evidence fixture.
        for operation in ('container', 'malformed-container', 'source-pg', 'restore-pg', 'partial-container'):
            with self.subTest(operation=operation), tempfile.TemporaryDirectory(dir=SCRATCH) as root:
                p = c.CapacityProbe.__new__(c.CapacityProbe)
                p.root = Path(root);p.prefix = 'owned-fixture';p.daemon = 'offline-daemon'
                p.capacity = {'cleanup': {}};p.values = [];p.result = {};p.samples = []
                p.volumes = [];p.roles = {};p.worker_records = {};p.image = 'offline-image'
                if operation != 'partial-container':
                    p.containers = {'b'*64: p.prefix+'-already-created'}
                for name in ('private', 'state', 'fresh-state', 'backend', 'bin'):
                    (p.root/name).mkdir();(p.root/name/'keep').write_text('keep')
                calls = []
                class CreatedButLost:
                    def call(self, method, path, body=None, **kwargs):
                        calls.append((method, path))
                        if method == 'POST':
                            (p.root/'created-side-effect').write_text(path)
                            if operation == 'malformed-container': return {'Id': 'not-an-exact-id'}
                            raise ConnectionError('offline response lost after creation')
                        if path == '/info':
                            return {'ID': p.daemon, 'Swarm': {'LocalNodeState': 'inactive'}}
                        if method == 'GET' and path.startswith('/volumes/'):
                            return None
                        raise AssertionError('unexpected offline call')
                p.e = CreatedButLost()
                with self.assertRaises(ValueError if operation == 'malformed-container' else ConnectionError):
                    if operation in ('container', 'partial-container', 'malformed-container'):
                        p.create('command', {'Image': p.image}, start=False)
                    else:
                        p.startpg(operation, operation == 'source-pg')
                self.assertTrue((p.root/'created-side-effect').exists())
                self.assertEqual(set(getattr(p, 'containers', {})),
                                 set() if operation == 'partial-container' else {'b'*64})
                with self.assertRaisesRegex(ValueError, 'unresolved.*creat'):
                    p.cleanup()
                self.assertFalse(any(method == 'DELETE' for method, path in calls))
                for name in ('private', 'state', 'fresh-state', 'backend', 'bin'):
                    self.assertEqual((p.root/name/'keep').read_text(), 'keep')
                if operation in ('source-pg', 'restore-pg'):
                    self.assertIn(p.prefix+'-'+operation+'-data', p.volumes)

    def test_named_volume_response_must_prove_exact_owned_default_local_identity(self):
        import run_hosted_capacity as c
        name = 'owned-fixture-capacity-files'
        good = {'Name': name, 'Driver': 'local', 'Labels': {'probe.bakabel.owner': 'owned-fixture'}, 'Options': {}}
        for mutation in ({'Name': 'other'}, {'Driver': 'remote'}, {'Labels': {}}, {'Options': {'device': '/other'}}):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory(dir=SCRATCH) as root:
                p = c.CapacityProbe.__new__(c.CapacityProbe)
                p.root = Path(root);(p.root/'private').mkdir();(p.root/'private/keep').touch()
                p.prefix = 'owned-fixture';p.capacity = {'cleanup': {}};p.volumes = []
                calls = []
                class InvalidResponse:
                    def call(self, method, path, body=None, **kwargs):
                        calls.append((method, path))
                        if method == 'GET': return None
                        if method == 'POST':
                            self_test.assertIn(name, p.volumes)
                            self_test.assertIn(('volume', name), p.unresolved_creates)
                            return {**good, **mutation}
                        raise AssertionError('destructive call')
                self_test = self
                p.e = InvalidResponse()
                with self.assertRaisesRegex(ValueError, 'volume.*identity'):
                    p.e.call('POST', '/volumes/create', {'Name': name, 'Labels': good['Labels']})
                with self.assertRaisesRegex(ValueError, 'unresolved.*creat'):
                    p.cleanup()
                self.assertTrue((p.root/'private/keep').exists())
                self.assertFalse(any(method == 'DELETE' for method, path in calls))

    def test_named_volume_creation_refuses_unowned_specs_or_existing_names_before_post(self):
        import run_hosted_capacity as c
        good = {'Name': 'owned-fixture-data', 'Labels': {'probe.bakabel.owner': 'owned-fixture'}}
        for mutation, existing in [({'Name': 'foreign-data'}, None), ({'Labels': {}}, None),
                ({'Driver': 'remote'}, None), ({'DriverOpts': {'device': '/other'}}, None),
                ({}, {'Name': good['Name'], 'Driver': 'remote', 'Labels': {}})]:
            with self.subTest(mutation=mutation, existing=existing):
                p = c.CapacityProbe.__new__(c.CapacityProbe)
                p.prefix = 'owned-fixture';p.volumes = []
                calls = []
                class PreflightOnly:
                    def call(self, method, path, body=None, **kwargs):
                        calls.append((method, path))
                        return existing if method == 'GET' else {}
                p.e = PreflightOnly()
                with self.assertRaises(ValueError):
                    p.e.call('POST', '/volumes/create', {**good, **mutation})
                self.assertFalse(any(method == 'POST' for method, path in calls))

    def test_inherited_pg_create_keeps_request_and_cleans_exact_volume_once(self):
        import run_hosted_capacity as c
        # Deterministic protocol double, not Docker acceptance evidence.
        with tempfile.TemporaryDirectory(dir=SCRATCH) as root:
            p = c.CapacityProbe.__new__(c.CapacityProbe)
            p.root = Path(root);(p.root/'private').mkdir()
            p.prefix = 'owned-fixture';p.daemon = 'offline-daemon';p.image = 'offline-image'
            p.capacity = {'cleanup': {}};p.result = {};p.values = [];p.samples = []
            p.containers = {};p.volumes = [];p.roles = {};p.worker_records = {}
            cid = 'a'*64;name = p.prefix+'-source-pg-data'
            calls = [];container = {};volume = {}
            class Lifecycle:
                def call(self, method, path, body=None, **kwargs):
                    calls.append((method, path, body))
                    if path == '/info': return {'ID': p.daemon, 'Swarm': {'LocalNodeState': 'inactive'}}
                    if method == 'POST' and path == '/volumes/create':
                        volume.update(Name=body['Name'], Labels=body['Labels'], Driver='local', Options={})
                        return dict(volume)
                    if method == 'POST' and path.startswith('/containers/create?name='):
                        container.update(Id=cid, Name='/'+p.prefix+'-source-pg', Config=body,
                            Mounts=[{'Type': 'volume', 'Name': name}], State={'Running': False, 'Pid': os.getpid()})
                        return {'Id': cid}
                    if method == 'POST' and path.endswith('/start'): return None
                    if method == 'GET' and path == '/volumes/'+name: return dict(volume) if volume else None
                    if method == 'DELETE':
                        if path.startswith('/containers/'): container.clear()
                        elif path == '/volumes/'+name: volume.clear()
                        else: raise AssertionError('unexpected deletion')
                        return None
                    raise AssertionError('unexpected offline request')
                def inspect(self, *args, **kwargs): return dict(container) if container else None
                def exec(self, *args, **kwargs): return {'exit': 0}
            p.e = Lifecycle()
            self.assertEqual(p.startpg('source-pg', True), cid)
            self.assertFalse(p.unresolved_creates)
            self.assertEqual(container['Config']['Image'], c.PG)
            self.assertEqual(container['Config']['Entrypoint'], ['sh', '-c'])
            self.assertEqual(container['Config']['HostConfig']['NanoCpus'], 2000000000)
            p.cleanup()
            self.assertEqual(sum(method == 'DELETE' and path == '/volumes/'+name for method, path, body in calls), 1)
            self.assertTrue(p.capacity['cleanup']['private_paths_absent'])

    def test_cleanup_projects_sampler_gaps_and_numeric_errno_into_receipt_and_summary(self):
        import run_hosted_capacity as c
        gap = {'container': 'a'*64, 'at': '2026-01-01T00:00:00+00:00',
               'reason': 'cgroup-removed-after-inspection', 'errno': 19}
        for unresolved in (False, True):
            with self.subTest(unresolved=unresolved), tempfile.TemporaryDirectory(dir=SCRATCH) as root:
                p = c.CapacityProbe.__new__(c.CapacityProbe)
                p.root = Path(root);p.prefix = 'owned-fixture';p.capacity = {'cleanup': {}}
                p.values = [];p.samples = [];p.containers = {}
                p.result = {'sampler_gaps': [{**gap, 'message': 'RAW-SECRET'}],
                            'sampler_errors': [{'type': 'OSError', 'errno': 5, 'message': 'RAW-SECRET', 'frames': []}]}
                class RefusedEngine:
                    def call(self, *args, **kwargs): raise PermissionError('offline refusal')
                p.e = RefusedEngine()
                if unresolved: p.unresolved_creates.add(('container', p.prefix+'-lost'))
                with self.assertRaises(ValueError if unresolved else PermissionError): p.cleanup()
                p.save()
                self.assertTrue((p.root/'capacity-summary.json').exists(), 'diagnostics lost when cleanup is refused')
                receipt = json.loads((p.root/'capacity-receipt.json').read_text())
                summary = json.loads((p.root/'capacity-summary.json').read_text())
                for artifact in (receipt, summary):
                    self.assertEqual(artifact.get('sampler_gaps'), [gap])
                    self.assertEqual(artifact.get('sampler_gap_count'), 1)
                    self.assertEqual(artifact.get('sampler_diagnostics'), [{'type': 'OSError', 'errno': 5, 'frames': []}])
                    self.assertNotIn('RAW-SECRET', json.dumps(artifact))
        unknown = c.capacity_summary({}, [])
        self.assertIn('sampler_gap_count', unknown)
        self.assertIsNone(unknown['sampler_gap_count'])
        self.assertIsNone(unknown['sampler_gaps'])

    def test_cleanup_engine_error_preserves_private_paths_and_measured_failure_artifacts(self):
        import run_hosted_capacity as c
        class RefusedEngine:
            def call(self, *args, **kwargs):
                raise PermissionError('offline refusal; never an Engine success reply')
        with tempfile.TemporaryDirectory(dir=SCRATCH) as root:
            p = c.CapacityProbe.__new__(c.CapacityProbe)
            p.root = Path(root);(p.root/'private').mkdir();(p.root/'private/keep').write_text('keep')
            p.prefix = 'owned-fixture';p.capacity = {'cleanup': {}};p.values = []
            p.result = {'sampler_errors': [{'type': 'RuntimeError', 'message': 'RAW-ERROR-SECRET',
                'http_status': 404, 'frames': [{'file': 'run_resource_probe.py', 'line': 1, 'function': 'sampler'}]}]}
            p.samples = [];p.containers = {};p.e = RefusedEngine()
            with self.assertRaises(PermissionError):
                p.cleanup()
            self.assertEqual(p.capacity.get('sampler_diagnostics'), [{'type': 'RuntimeError', 'http_status': 404,
                'frames': [{'file': 'run_resource_probe.py', 'line': 1, 'function': 'sampler'}]}])
            self.assertNotIn('RAW-ERROR-SECRET', json.dumps(p.capacity))
            self.assertEqual((p.root/'private/keep').read_text(), 'keep')
            self.assertTrue((p.root/'capacity-metrics.json').exists())
            self.assertNotIn('private_paths_absent', p.capacity['cleanup'])

    def test_execute_refuses_existing_runtime_without_constructing_probe_or_overwriting_failure(self):
        from types import SimpleNamespace
        import run_hosted_capacity as c
        calls = []
        class MustNotConstruct:
            def __init__(self, args): calls.append('constructed');raise RuntimeError('blocked')
            def cleanup(self): pass
        with tempfile.TemporaryDirectory(dir=SCRATCH) as root:
            existing = Path(root)/'capacity';existing.mkdir()
            (existing/'capacity-receipt.json').write_text('original failure')
            with self.assertRaisesRegex(ValueError, 'fresh'):
                c.execute(SimpleNamespace(runtime=existing), probe_type=MustNotConstruct)
            self.assertEqual(calls, [])
            self.assertEqual((existing/'capacity-receipt.json').read_text(), 'original failure')


    def test_stream_reader_watchdog_terminates_actual_stalled_python_pipe_without_staging(self):
        import run_hosted_capacity as c
        self.assertTrue(hasattr(c, 'consume_readback'), 'missing finite streamed-readback deadline')
        cp = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'],
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        try:
            with self.assertRaises(TimeoutError):
                c.consume_readback(cp, 'a'*64+'  file-000000.dat\n', file_bytes=1, timeout=.05)
            self.assertIsNotNone(cp.poll())
            self.assertTrue(cp.stdout.closed)
        finally:
            if cp.poll() is None:
                cp.kill();cp.wait()
            cp.stdout.close()

    def test_capacity_summary_exposes_source_restore_windows_and_temp_storage_boundary(self):
        import run_hosted_capacity as c
        self.assertTrue(hasattr(c, 'capacity_summary'), 'missing complete public capacity summary')
        receipt, metrics = validator_fixture()
        summary = c.capacity_summary(receipt, metrics)
        self.assertEqual(summary['source_pg_windows']['first']['sql_observed_delta']['wal_bytes'], 10)
        self.assertEqual(summary['restore_pg_window']['sql_observed_delta']['wal_bytes'], 10)
        self.assertEqual(summary['temporary_disk']['worker_tmpfs_capacity_bytes'], c.TMP_BYTES)
        self.assertEqual(summary['temporary_disk']['full_dump_or_file_readback_staging_bytes'], 0)
        self.assertEqual(summary['temporary_disk']['image_audit_regular_file_transient_upper_bytes'], 2)


    def test_capacity_lock_wait_allows_large_file_round_without_extending_native_fixture_lock(self):
        import run_hosted_capacity as c
        calls = []
        class OfflineWait(c.CapacityProbe):
            def __init__(self): pass
            def wait(self, predicate, seconds=90, label='condition'):
                calls.append((seconds, label));return 'wait-not-executed'
        p = OfflineWait()
        self.assertEqual(p.blocked('not-an-engine-container'), 'wait-not-executed')
        self.assertEqual(calls[0][0], 240)

    def test_pg_numeric_wal_scale_is_preserved_and_unbounded_memory_is_explicit(self):
        import run_hosted_capacity as c
        raw = {'at': '2026-01-01T00:00:00+00:00', 'sql': '{"wal_bytes":4.00,"database_bytes":8}',
            'pg_stat_io': [], 'metrics': {'at': '2026-01-01T00:00:00+00:00', 'monotonic': 1,
                'role': 'source-pg', 'container': 'a'*64, 'memory.max': 'max', 'processes': []}}
        projected = c.project_pg(raw)
        self.assertEqual(projected['sql'].get('wal_bytes'), 4)
        self.assertEqual(projected['metrics'].get('memory_limit_kind'), 'unbounded')


    def test_cleanup_inventory_rejects_any_ambiguous_exact_target_before_mutation(self):
        import copy
        import run_hosted_capacity as c
        self.assertTrue(hasattr(c, 'validate_cleanup_inventory'), 'missing all-target cleanup prevalidation')
        prefix = 'bakabel-b45-owned'
        containers = {'a'*64: prefix+'-controller', 'b'*64: 'worker-owned'}
        owner = {'workerContainerID': 'b'*64, 'workerName': 'worker-owned', 'runID': 'run', 'daemonID': 'daemon'}
        objects = {'a'*64: {'Id': 'a'*64, 'Name': '/'+prefix+'-controller',
            'Config': {'Labels': {'probe.bakabel.owner': prefix}}},
            'b'*64: {'Id': 'b'*64, 'Name': '/worker-owned', 'Image': 'image',
                'Config': {'Labels': {'bakabel.worker': '1', 'bakabel.run': 'run', 'bakabel.daemon': 'daemon'}}}}
        volumes = {prefix+'-data': {'Name': prefix+'-data', 'Labels': {'probe.bakabel.owner': prefix}, 'Driver': 'local'}}
        c.validate_cleanup_inventory(prefix, containers, {'b'*64: owner}, objects, volumes, 'image', 'daemon')
        bad = copy.deepcopy(objects);bad['a'*64]['Config']['Labels']['probe.bakabel.owner'] = 'other'
        with self.assertRaises(ValueError):
            c.validate_cleanup_inventory(prefix, containers, {'b'*64: owner}, bad, volumes, 'image', 'daemon')
        bad = copy.deepcopy(objects);bad['b'*64]['Image'] = 'changed'
        with self.assertRaises(ValueError):
            c.validate_cleanup_inventory(prefix, containers, {'b'*64: owner}, bad, volumes, 'image', 'daemon')
        bad = copy.deepcopy(volumes);bad[prefix+'-data']['Labels'] = {}
        with self.assertRaises(ValueError):
            c.validate_cleanup_inventory(prefix, containers, {'b'*64: owner}, objects, bad, 'image', 'daemon')


    def test_binary_archive_measurement_keeps_size_and_hash_but_no_binary_payload(self):
        import hashlib
        import run_hosted_capacity as c
        self.assertTrue(hasattr(c, 'binary_archive_evidence'), 'missing actual runtime binary-size accounting')
        archive = io.BytesIO()
        payload = b'fixture-binary-not-an-image'
        with tarfile.open(fileobj=archive, mode='w') as tar:
            member = tarfile.TarInfo('bakabel');member.size = len(payload)
            tar.addfile(member, io.BytesIO(payload))
        result = c.binary_archive_evidence(archive.getvalue(), 'bakabel')
        self.assertEqual(result, {'bytes': len(payload), 'sha256': hashlib.sha256(payload).hexdigest()})
        self.assertNotIn(payload.decode(), json.dumps(result))
        with self.assertRaises(ValueError):
            c.binary_archive_evidence(archive.getvalue(), 'restic')


if __name__ == '__main__':
    unittest.main()
