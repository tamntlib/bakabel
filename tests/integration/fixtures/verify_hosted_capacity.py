#!/usr/bin/env python3
"""Independent capacity evidence validation and exact direct-Engine readback."""
import json
import os
from pathlib import Path
import re
from urllib.parse import quote

from run_resource_probe import Engine, sha, utc
from run_compose_pg_acceptance import fingerprint
from run_hosted_acceptance import require_hosted_daemon
from run_hosted_capacity import (STOCK_SOURCE, FILES, FILE_BYTES, CHANGED_FILES, PG_ROWS,
    TMP_BYTES, GATES, LIMITS, parser, summarize_samples, capacity_summary)


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def validate_evidence(receipt, samples):
    require(receipt.get('schema') == 1 and receipt.get('measurements_complete') is True,
            'capacity measurements incomplete')
    require(not any(receipt.get(k) for k in ('failure', 'cleanup_failure', 'verification_failure')),
            'capacity failure retained')
    require(set(receipt.get('gates', [])) == GATES and len(receipt['gates']) == len(GATES),
            'capacity gates missing or duplicated')
    require(bool(samples), 'no real capacity metrics')
    require(receipt.get('source_sha256') == STOCK_SOURCE and receipt.get('retention_enabled') is False and
            receipt.get('full_plan_acceptance_pass') is False and receipt.get('sampler_error_count') == 0,
            'stock binding/retention/sampler boundary changed')
    corpus = receipt['corpus']
    require(all(corpus.get(k) == v for k, v in {'files': FILES, 'file_bytes': FILE_BYTES,
        'payload_bytes': FILES*FILE_BYTES, 'changed_files': CHANGED_FILES,
        'changed_payload_bytes': CHANGED_FILES*FILE_BYTES, 'incompressible_random': True}.items()),
        'bounded larger corpus differs')
    require(corpus['first_manifest_sha256'] != corpus['changed_manifest_sha256'], 'changed content not observed')
    rounds = receipt['rounds']
    require([r['phase'] for r in rounds] == ['first', 'repeat', 'changed'] and
            len({r['worker'] for r in rounds}) == 3, 'three independent capacity workers required')
    for row in rounds:
        worker = row['worker_resources']
        require(worker['image_id'] == receipt['image_id'] and worker['memory_bytes'] == 536870912 and
                worker['nanocpus'] == 2000000000 and worker['tmpfs'] == 'rw,nosuid,nodev,size=67108864' and
                all(worker[k] is True for k in ('readonly_rootfs', 'workflow_entrypoint', 'workflow_command',
                                               'cpuset_empty', 'credential_mounts_readonly')),
                'ordinary candidate worker/default resources changed')
        ss = [s for s in samples if s['container'] == row['worker'] and s['role'] == 'worker']
        require(ss and all(s['cpu_max'] == '200000 100000' and s['memory_max_bytes'] == 536870912 for s in ss),
                'no exact kernel-enforced ordinary worker limits')
        require(any(s['tmp_capacity_bytes'] == TMP_BYTES for s in ss), 'worker tmpfs capacity not measured')
        index = row['repository']
        require(index['index_objects'] > 0 and index['decoded_index_bytes'] >= FILES*64 and
                index['unique_indexed_data_blobs'] >= FILES+(CHANGED_FILES if row['phase'] == 'changed' else 0) and
                index['raw_data_stats']['total_size'] >= FILES*FILE_BYTES,
                'actual repository/index did not reach capacity scale')
    require(rounds[2]['repository']['raw_data_stats']['total_size'] > rounds[0]['repository']['raw_data_stats']['total_size'],
            'repository did not grow after changed data')
    snapshots = receipt['file_snapshots']
    for phase, row in zip(('first', 'repeat', 'changed'), rounds):
        require(snapshots[phase]['id'] == row['file_snapshot'], 'exact file snapshot mapping differs')
    require(snapshots['repeat']['parent'] == snapshots['first']['id'] and
            snapshots['changed']['parent'] == snapshots['repeat']['id'], 'exact file parent chain differs')
    require(snapshots['repeat']['summary']['files_unmodified'] == FILES+1 and
            snapshots['repeat']['summary']['data_blobs'] == 0 and
            snapshots['changed']['summary']['data_blobs'] > 0 and
            snapshots['changed']['summary']['data_added_packed'] > 0, 'parent/dedup/change proof differs')
    readbacks = receipt['file_readbacks']
    require([p['phase'] for p in readbacks] == ['first', 'changed'], 'both full file readbacks required')
    for proof, key in zip(readbacks, ('first_manifest_sha256', 'changed_manifest_sha256')):
        require(proof['snapshot'] == snapshots[proof['phase']]['id'] and proof['files_compared'] == FILES and
                proof['payload_bytes_compared'] == FILES*FILE_BYTES and proof['all_sha256_equal'] is True and
                proof['streamed_no_local_staging'] is True and proof['manifest_sha256'] == corpus[key] and
                proof['docker_attach_exit'] == 0 and proof['restic_exit'] == 0,
                'full byte/checksum readback incomplete')
    restore = receipt['pg_restore'];expected = receipt['source_pg_readback']
    require(expected['rows'] == PG_ROWS and expected['sum_g'] == PG_ROWS*(PG_ROWS+1)//2 and
            re.fullmatch('[0-9a-f]{32}', expected['ordered_payload_md5']) and restore['readback'] == expected and
            restore['snapshot'] == rounds[0]['pg_snapshot'] and restore['owner_acl_equal'] is True,
            'fresh PG data/owner/ACL readback differs')
    require(receipt['source_identity_before'] == receipt['source_identity_after'] and
            len(receipt['source_identity_before']) == 2 and receipt['source_read_write_ok'] is True,
            'source read-write/lifecycle proof differs')
    windows = receipt['source_windows']
    require([w['phase'] for w in windows] == ['first', 'repeat', 'changed'], 'source PG load windows missing')
    for window in [*windows, restore]:
        for boundary in ('before', 'after'):
            pg = window[boundary]
            require(all(k in pg['sql'] for k in ('database_bytes', 'wal_bytes', 'wal_records', 'blks_read', 'blks_hit', 'temp_bytes'))
                    and pg['metrics'] and 'usage_usec' in pg['metrics']['cpu'] and pg['pg_stat_io'],
                    'source/restore PG CPU/WAL/logical I/O measurement missing')
    roles = {s['role'] for s in samples}
    require({'worker', 'source-pg', 'restore-pg', 'source-files', 'fixture-s3-backend', 'operator-readback'} <= roles,
            'source/target/backend/readback resource sample missing')
    for key in ('actual_save_tar_bytes', 'oci_compressed_layer_bytes', 'actual_merged_export_tar_bytes',
                'actual_export_extracted_regular_file_allocated_bytes', 'merged_export_regular_file_payload_bytes'):
        require(receipt['image_measurement'][key] > 0, 'actual binary/image transfer/unpacked overhead missing')
    require(set(receipt['disk_checkpoints']) == {'prepared', 'first', 'repeat', 'changed', 'after-restore'},
            'state/backend/source/target disk checkpoints missing')
    for point in receipt['disk_checkpoints'].values():
        require(point['state']['bytes'] <= 16*1024**2 and point['fresh_state']['bytes'] <= 16*1024**2 and
                point['owned_pg_and_source_volumes'], 'state disk budget exceeded or persistent disk not measured')
    for name, key in (('bakabel', 'runtime_binary_sha256'), ('restic', 'runtime_restic_sha256')):
        binary = receipt['binaries'][name]
        require(0 < binary['bytes'] <= 64*1024**2 and binary['sha256'] == receipt[key] and
                re.fullmatch(r'[0-9a-f]{64}', binary['sha256']), 'actual runtime binary size/hash missing')
    cleanup = receipt['cleanup']
    require(set(cleanup['target_containers']) == set(cleanup['containers_absent']) and
            set(cleanup['target_volumes']) == set(cleanup['volumes_absent']), 'exact cleanup registry incomplete')
    require(cleanup['containers_absent'] and cleanup['volumes_absent'] and
            all(v is True for v in cleanup['containers_absent'].values()) and
            all(v is True for v in cleanup['volumes_absent'].values()) and cleanup['private_paths_absent'] is True,
            'exact cleanup targets missing/failed')
    require(all(s['container'] in cleanup['containers_absent'] for s in samples), 'sampled target missing from cleanup registry')
    summary = summarize_samples(samples)
    for row in summary['containers']:
        if row['role'] == 'worker':
            require(row['sampled_tmp_bytes_peak'] is not None and row['sampled_tmp_bytes_peak'] <= TMP_BYTES and
                    row['sampled_state_bytes_peak'] is not None and row['sampled_state_bytes_peak'] <= 16*1024**2 and
                    row['sampled_process_pss_sum_peak_bytes'] is not None and row['kernel_cgroup_memory_peak_bytes'] is not None,
                    'worker sampled cache/temp/state/PSS/kernel high-water missing or disk budget exceeded')
    return capacity_summary(receipt, samples)


PRIVATE_PATHS = ('private', 'state', 'fresh-state', 'backend', 'bin', 'image-unpacked',
                 'image-save.tar', 'image-export.tar', 'config.yaml', 'fresh.yaml')


def verify_runtime(args, *, output):
    require(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted'
            and os.geteuid() == 0 and args.exclusive_hosted_daemon, 'requires exclusive GitHub-hosted root VM')
    require(args.expected_source_sha256 == STOCK_SOURCE and fingerprint(args.source) == STOCK_SOURCE,
            'fixed stock source binding differs')
    require(re.fullmatch(r'sha256:[0-9a-f]{64}', args.expected_image_id) and args.image == args.expected_image_id,
            'exact image ID binding required')
    temporary = Path(os.environ['RUNNER_TEMP']).resolve()
    runtime = args.runtime.resolve()
    require(runtime != temporary and runtime.is_relative_to(temporary) and not args.runtime.is_symlink(),
            'runtime must remain below RUNNER_TEMP')
    require(output.resolve() == runtime/'capacity-verified.json', 'only exact capacity verification output is allowed')
    receipt = json.loads((runtime/'capacity-receipt.json').read_text())
    samples = json.loads((runtime/'capacity-metrics.json').read_text())
    summary = validate_evidence(receipt, samples)
    require(summary == json.loads((runtime/'capacity-summary.json').read_text()), 'summary does not recompute from metrics')
    require(receipt['source_sha256'] == args.expected_source_sha256 and receipt['image_id'] == args.expected_image_id,
            'receipt differs from exact build binding')
    require(sha(args.minio_binary) == receipt['minio_binary_sha256'], 'existing MinIO binary changed')
    for name, digest in receipt['runner_files'].items():
        require(name in ('run_hosted_capacity.py', 'verify_hosted_capacity.py', 'run_resource_probe.py',
                         'run_compose_pg_acceptance.py', 'run_hosted_acceptance.py') and
                sha(Path(__file__).with_name(name)) == digest, 'executed fixture source changed')
    require(len(receipt['runner_files']) == 5, 'fixture source binding incomplete')
    e = Engine(args.socket)
    info = e.call('GET', '/info')
    require(info['ID'] == receipt['daemon'], 'exact daemon identity changed')
    require_hosted_daemon(os.environ, os.geteuid(), args.exclusive_hosted_daemon, info,
                          e.call('GET', '/containers/json?all=true'))
    require(e.call('GET', '/images/'+quote(args.image, safe='')+'/json')['Id'] == args.expected_image_id,
            'exact candidate image changed')
    for image in receipt['images'].values():
        require(e.call('GET', '/images/'+quote(image['id'], safe='')+'/json')['Id'] == image['id'],
                'measured candidate/helper image no longer available')
    for cid in receipt['cleanup']['containers_absent']:
        require(re.fullmatch(r'[0-9a-f]{64}', cid) and e.inspect(cid, missing=True) is None,
                'exact recorded container still present')
    for name in receipt['cleanup']['volumes_absent']:
        require(re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]+', name) and
                e.call('GET', '/volumes/'+quote(name, safe=''), missing=True) is None,
                'exact recorded volume still present')
    require(all(not (runtime/name).exists() for name in PRIVATE_PATHS), 'private fixture residue remains')
    out = {'schema': 1, 'verified_at': utc(), 'capacity_pass': True, 'full_plan_acceptance_pass': False,
           'source_sha256': STOCK_SOURCE, 'image_id': args.expected_image_id, 'daemon': receipt['daemon'],
           'gates': sorted(GATES), 'independent_exact_cleanup_readback': True,
           'files': {name: sha(runtime/name) for name in
                     ('capacity-receipt.json', 'capacity-metrics.json', 'capacity-summary.json')}, 'limits': LIMITS}
    output.write_text(json.dumps(out, indent=2)+'\n')
    return out


def main(argv=None):
    p = parser()
    p.description = __doc__
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args(argv)
    if (os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted'
            or os.geteuid() != 0 or not args.exclusive_hosted_daemon):
        p.error('requires root on an explicitly exclusive GitHub-hosted VM; local/shared use refused')
    os.sched_setaffinity(0, {0, 1})
    try:
        verify_runtime(args, output=args.output)
    except Exception:
        # Raw Engine/CLI exception strings are not an artifact/logging interface.
        print(json.dumps({'capacity_pass': False, 'verification_failed': True}))
        return 1
    print(json.dumps({'capacity_pass': True, 'independent_exact_cleanup_readback': True}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
