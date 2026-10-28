#!/usr/bin/env python3
"""Bounded larger-repository capacity proof; exclusively disposable hosted VM.

No scheduler/fault replay: run_hosted_resources owns those independent gates.
Never a universal RAM, continuous affinity, or physical I/O hardware guarantee.
"""
import argparse
from decimal import Decimal
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import threading
import time
from urllib.parse import quote

from run_resource_probe import Engine, PG, Probe, footprint, kv_numbers, sha, utc, worker_owned
from run_compose_pg_acceptance import fingerprint
from run_hosted_acceptance import require_hosted_daemon, failure_location

# Reviewed completion-protocol candidate; never infer admission from CLI input.
STOCK_SOURCE = '853633d737405ddbb2b35138b007fdf5cdb4515f610869619df2ff2980e9cff5'


FILES = 8192
FILE_BYTES = 131072
CHANGED_FILES = 1024
PG_ROWS = 400000
TMP_BYTES = 67108864
GATES = {'larger-mixed-repository', 'repeat-parent-zero-new-file-data',
         'changed-parent-real-new-data', 'full-original-and-changed-file-readback',
         'fresh-target-pg-restore-readback', 'source-online-identity-unchanged'}
LIMITS = ('Measured fixture only, not a universal RAM bound. PSS/RSS and disk peaks '
          'are sampled; memory.peak is kernel high-water through last live sample. '
          'Create-to-pin gaps and short exec lifetimes are not continuous affinity proof. '
          'cgroup io.stat is device-accounted I/O; /proc IO is per-process lifetime I/O, '
          'PG counters are logical database/WAL I/O; none is a physical hardware guarantee. '
          'S3 backend data and PG restore target data are persistent fixture storage, not staging. '
          'Retention remains disabled; native Restic locks are never force-unlocked.')
ROLES = {'worker', 'source-pg', 'restore-pg', 'source-files', 'fixture-s3-backend',
         'controller', 'operator-restic', 'operator-readback'}
IO_KEYS = {'rbytes', 'wbytes', 'rios', 'wios', 'dbytes', 'dios'}
PROC_IO_KEYS = {'rchar', 'wchar', 'syscr', 'syscw', 'read_bytes', 'write_bytes', 'cancelled_write_bytes'}


def json_rows(text):
    stripped = text.strip()
    if stripped.startswith(('{', '[')):
        try:
            return [json.loads(stripped)]
        except json.JSONDecodeError:
            pass
    return [json.loads(line) for line in text.splitlines() if line.startswith(('{', '['))]


def project_outcomes(rows):
    """Retain enums only; even well-formed unknown error text is never evidence."""
    statuses = {'complete', 'failed', 'partial', 'unknown', 'restored'}
    codes = {'backup failed': 'backup_failed', 'restore failed': 'restore_failed'}
    def status(row):
        value = row.get('status')
        return value if isinstance(value, str) and value in statuses else 'unknown'
    def code(row):
        value = row.get('error')
        return codes.get(value, 'unknown') if isinstance(value, str) else 'unknown'
    def failure(row):
        stages = ('file_preflight', 'list_before', 'backup', 'list_after',
                  'source_verification', 'tag', 'final_readback', 'metadata_readback')
        reasons = ('enospc', 'permission', 'backend', 'unknown')
        fields = {}
        if row.get('failureCode') in stages:
            fields['failure_code'] = row['failureCode']
        if type(row.get('resticExitCode')) is int and 0 <= row['resticExitCode'] <= 255:
            fields['restic_exit_code'] = row['resticExitCode']
        if row.get('resticReason') in reasons:
            fields['restic_reason'] = row['resticReason']
        return fields
    if len(rows) > 128:
        raise ValueError('capacity diagnostic row bound exceeded')
    out = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        targets = row.get('targets', [])
        if not isinstance(targets, list) or len(targets) > 128:
            raise ValueError('capacity diagnostic target bound exceeded')
        out.append({'status': status(row), 'error_code': code(row),
                    'targets': [{'status': status(t), 'error_code': code(t), **failure(t)}
                                for t in targets if isinstance(t, dict)]})
    return out


def numeric(value):
    return int(value) if re.fullmatch(r'[0-9]+', str(value)) else None


def selected_numbers(values, keys):
    return {k: values[k] for k in keys if type(values.get(k)) is int and values[k] >= 0}


def project_sample(raw):
    """Allowlist values at the point metrics leave process memory; no Env/CLI/stats."""
    if raw['role'] not in ROLES or not re.fullmatch(r'[0-9a-f]{64}', raw['container']):
        raise ValueError('unrecognized metric identity')
    io_text = raw.get('io.stat')
    devices = None
    if isinstance(io_text, str) and (not io_text or re.match(r'^[0-9]+:[0-9]+ ', io_text)):
        devices = {}
        for line in io_text.splitlines():
            fields = line.split()
            if not fields or not re.fullmatch(r'[0-9]+:[0-9]+', fields[0]):
                raise ValueError('invalid cgroup I/O device')
            counters = dict(field.split('=', 1) for field in fields[1:])
            devices[fields[0]] = {k: int(v) for k, v in counters.items() if k in IO_KEYS and numeric(v) is not None}
    processes = []
    for process in raw.get('processes', []):
        if process.get('exited_during_sample'):
            continue
        processes.append({**{k: numeric(process.get(k)) for k in ('pid', 'starttime_ticks', 'cpu_ticks', 'rss_bytes')},
                          'pss_bytes': numeric(process.get('memory', {}).get('Pss')),
                          'rollup_rss_bytes': numeric(process.get('memory', {}).get('Rss')),
                          'io': selected_numbers(process['io'], PROC_IO_KEYS) if 'io' in process else None})
    out = {'at': raw['at'], 'monotonic': float(raw['monotonic']), 'role': raw['role'],
           'container': raw['container'], 'processes': processes, 'io_devices': devices,
           'cpu': selected_numbers(kv_numbers(raw.get('cpu.stat', '')), {'usage_usec', 'user_usec', 'system_usec', 'throttled_usec', 'nr_throttled'}),
           'cpu_max': raw.get('cpu.max') if re.fullmatch(r'[0-9]+ [0-9]+', raw.get('cpu.max', '')) else None,
           'memory_max_bytes': numeric(raw.get('memory.max')),
           'memory_limit_kind': 'unbounded' if raw.get('memory.max') == 'max' else
               'finite' if numeric(raw.get('memory.max')) is not None else 'unavailable',
           'memory_current_bytes': numeric(raw.get('memory.current')),
           'memory_peak_bytes': numeric(raw.get('memory.peak')),
           'memory_events': selected_numbers(kv_numbers(raw.get('memory.events', '')), {'oom', 'oom_kill', 'max', 'high', 'low'}),
           'log_bytes': numeric(raw.get('log_bytes')),
           'tmp_capacity_bytes': numeric(raw.get('tmp_capacity_bytes'))}
    for key in ('tmp_available_bytes', 'tmp_used_bytes'):
        value = raw.get(key)
        out[key] = value if type(value) is int and value >= 0 else None
    for source, target in (('tmp_cache_footprint', 'tmp'), ('state_footprint', 'state')):
        out[target] = {k: numeric(raw[source].get(k)) for k in
                       ('files', 'bytes', 'allocated_bytes', 'unlinked_during_sample')} if source in raw else None
    return out


def counter_delta(first, last):
    if first is None or last is None:
        return None
    return {k: last[k]-first[k] for k in first.keys() & last.keys()
            if type(first[k]) is int and type(last[k]) is int and last[k] >= first[k]}


def summarize_samples(samples):
    rows = []
    for cid in sorted({s['container'] for s in samples}):
        ss = sorted((s for s in samples if s['container'] == cid), key=lambda s:s['monotonic'])
        def peak(values):
            values = [v for v in values if v is not None]
            return max(values) if values else None
        def proc_peak(key):
            totals = [sum(p[key] for p in s['processes']) for s in ss
                      if s['processes'] and all(p[key] is not None for p in s['processes'])]
            return peak(totals)
        first, last = ss[0], ss[-1]
        available = [s['tmp_available_bytes'] for s in ss if s.get('tmp_available_bytes') is not None]
        io_delta = None
        if first['io_devices'] is not None and last['io_devices'] is not None:
            io_delta = {dev: counter_delta(first['io_devices'][dev], last['io_devices'][dev])
                        for dev in first['io_devices'].keys() & last['io_devices'].keys()}
        cpu = counter_delta(first['cpu'], last['cpu'])
        by_identity = {}
        for sample in ss:
            for process in sample['processes']:
                if process['pid'] is not None and process['starttime_ticks'] is not None:
                    key = (process['pid'], process['starttime_ticks'])
                    by_identity.setdefault(key, []).append(process)
        proc_io = [{'pid': pid, 'starttime_ticks': start, 'observations': len(observations),
                    'io': counter_delta(observations[0]['io'], observations[-1]['io'])}
                   for (pid, start), observations in by_identity.items() if len(observations) >= 2]
        rows.append({'container': cid, 'role': first['role'], 'samples': len(ss),
                     'process_io_observed_deltas': proc_io,
                     'observed_seconds': last['monotonic']-first['monotonic'],
                     'kernel_cgroup_memory_peak_bytes': peak(s['memory_peak_bytes'] for s in ss),
                     'sampled_cgroup_memory_current_peak_bytes': peak(s['memory_current_bytes'] for s in ss),
                     'sampled_process_rss_sum_peak_bytes': proc_peak('rss_bytes'),
                     'sampled_process_pss_sum_peak_bytes': proc_peak('pss_bytes'),
                     'process_pss_missing_observations': sum(p['pss_bytes'] is None for s in ss for p in s['processes']),
                     'sampled_tmp_bytes_peak': peak(s['tmp']['bytes'] for s in ss if s['tmp']),
                     'sampled_tmp_available_bytes_min': min(available) if available else None,
                     'sampled_tmp_used_bytes_peak': peak(s.get('tmp_used_bytes') for s in ss),
                     'sampled_state_bytes_peak': peak(s['state']['bytes'] for s in ss if s['state']),
                     **{kind+'_unlinked_during_sample':
                        sum(s[kind]['unlinked_during_sample'] for s in ss)
                        if all(s[kind] is not None and s[kind].get('unlinked_during_sample') is not None for s in ss)
                        else None for kind in ('tmp', 'state')},
                     'sampled_log_bytes_peak': peak(s['log_bytes'] for s in ss),
                     'cgroup_cpu_observed_seconds': cpu['usage_usec']/1e6 if cpu and 'usage_usec' in cpu else None,
                     'cgroup_io_observed_delta': io_delta})
    return {'containers': rows, 'sample_count': len(samples), 'limits': LIMITS,
            'tmp_filesystem_boundary':
                'Filesystem occupancy includes other files and open-unlinked packs, not just named cache files. '
                'Available-byte minima and used-byte peaks are sampled, not continuous or failure-instant proof; '
                'zero available bytes alone does not prove ENOSPC.'}


def generate_corpus(directory, files=FILES, file_bytes=FILE_BYTES, *, changed=None):
    """Write at most one small random file in RAM; never stage another corpus."""
    if not 0 < files <= FILES or not 0 < file_bytes <= FILE_BYTES:
        raise ValueError('corpus exceeds fixed capacity envelope')
    if changed is not None and not 0 < changed < files:
        raise ValueError('changed subset must be proper and nonempty')
    count = files if changed is None else changed
    for i in range(count):
        path = directory/('file-%06d.dat' % i)
        old = path.stat() if changed is not None else None
        flags = os.O_WRONLY | os.O_NOFOLLOW | (os.O_CREAT | os.O_EXCL if old is None else os.O_TRUNC)
        fd = os.open(path, flags, 0o640)
        with os.fdopen(fd, 'wb') as out:
            out.write(os.urandom(file_bytes))
        if old:
            os.utime(path, ns=(old.st_atime_ns, old.st_mtime_ns+2000000000))
    manifest = ''.join(sha(directory/('file-%06d.dat' % i))+'  file-%06d.dat\n' % i for i in range(files))
    (directory/'SHA256SUMS').write_text(manifest)
    return manifest


def verify_tar(stream, manifest, file_bytes=FILE_BYTES):
    """Stream the actual restic dump tar, compare every byte's SHA256 and size."""
    expected = {}
    for line in manifest.splitlines():
        digest, name = line.split()
        if not re.fullmatch(r'[0-9a-f]{64}', digest) or not re.fullmatch(r'file-[0-9]{6}\.dat', name) or name in expected:
            raise ValueError('invalid checksum manifest')
        expected[name] = digest
    checked = {};read_manifest = None
    with tarfile.open(fileobj=stream, mode='r|') as tar:
        for member in tar:
            parts = member.name.split('/')
            if member.name.startswith('/') or '..' in parts:
                raise ValueError('unsafe readback member')
            if member.isdir():
                continue
            name = parts[-1]
            if not member.isfile() or name in checked or (name == 'SHA256SUMS' and read_manifest is not None):
                raise ValueError('unexpected or duplicate readback member')
            src = tar.extractfile(member)
            if name == 'SHA256SUMS':
                if member.size != len(manifest.encode()):
                    raise ValueError('checksum manifest size differs')
                read_manifest = src.read().decode()
                continue
            if name not in expected or member.size != file_bytes:
                raise ValueError('unexpected file or payload size')
            h = hashlib.sha256()
            for chunk in iter(lambda: src.read(1024*1024), b''):
                h.update(chunk)
            checked[name] = h.hexdigest()
    if checked != expected or read_manifest != manifest:
        raise ValueError('full checksum readback mismatch')
    return {'files_compared': len(checked), 'payload_bytes_compared': len(checked)*file_bytes,
            'manifest_sha256': hashlib.sha256(manifest.encode()).hexdigest(),
            'all_sha256_equal': True, 'streamed_no_local_staging': True}


def snapshot_evidence(snapshots, ids):
    selected = []
    for sid in ids:
        matching = [s for s in snapshots if s['id'] == sid and 'bakabel.status=complete' in s.get('tags', [])]
        if len(matching) != 1:
            raise ValueError('exact complete snapshot missing or duplicated')
        selected.append(matching[0])
    first, repeat, changed = selected
    if (not first['paths'][0].startswith('/bakabel/files/') or
            not first['paths'] == repeat['paths'] == changed['paths'] or
            repeat.get('parent') != first['id'] or changed.get('parent') != repeat['id']):
        raise ValueError('stable file paths/exact parents not preserved')
    if repeat['summary'].get('files_unmodified') != FILES+1 or repeat['summary'].get('data_blobs') != 0:
        raise ValueError('repeat file snapshot did not reuse all data')
    if changed['summary'].get('data_blobs', 0) <= 0 or changed['summary'].get('data_added_packed', 0) <= 0:
        raise ValueError('changed snapshot has no new data')
    return {name: {'id': s['id'], 'parent': s.get('parent'),
                   'summary': selected_numbers(s['summary'], {'files_new', 'files_changed', 'files_unmodified',
                       'data_blobs', 'tree_blobs', 'data_added', 'data_added_packed', 'total_files_processed', 'total_bytes_processed'})}
            for name, s in zip(('first', 'repeat', 'changed'), selected)}


def index_evidence(decoded):
    packs = set();data = set();trees = set();size = 0;objects = 0
    for text in decoded:
        objects += 1;size += len(text.encode())
        if objects > 128 or size > 32*1024**2:
            raise ValueError('decoded repository index exceeds fixture envelope')
        for pack in json.loads(text)['packs']:
            packs.add(pack['id'])
            for blob in pack['blobs']:
                if blob['type'] == 'data':
                    data.add(blob['id'])
                elif blob['type'] == 'tree':
                    trees.add(blob['id'])
                else:
                    raise ValueError('unknown index blob type')
    return {'index_objects': objects, 'decoded_index_bytes': size, 'unique_indexed_packs': len(packs),
            'unique_indexed_data_blobs': len(data), 'unique_indexed_tree_blobs': len(trees)}


def project_pg(raw):
    counters = json.loads(raw['sql'], parse_float=Decimal)
    counters = {k: int(v) if isinstance(v, Decimal) and v.is_finite() and v == v.to_integral_value() else v
                for k, v in counters.items()}
    sql = selected_numbers(counters, {'database_bytes', 'wal_bytes', 'wal_records',
        'blks_read', 'blks_hit', 'temp_bytes', 'tup_inserted', 'tup_returned'})
    rows = []
    for row in raw['pg_stat_io']:
        if (row.get('backend_type') not in {'client backend', 'checkpointer', 'background writer'} or
                row.get('object') not in {'relation', 'temp relation', 'wal'} or
                row.get('context') not in {'normal', 'bulkread', 'bulkwrite', 'vacuum', 'init'}):
            raise ValueError('unknown PG logical I/O identity')
        rows.append({**{k: row[k] for k in ('backend_type', 'object', 'context')},
                     'counters': selected_numbers(row, {'reads', 'read_bytes', 'writes', 'write_bytes',
                         'extends', 'extend_bytes', 'hits', 'evictions', 'fsyncs', 'writebacks', 'reuses'})})
    return {'at': raw['at'], 'sql': sql, 'pg_stat_io': rows,
            'metrics': project_sample(raw['metrics']) if raw.get('metrics') else None}


def pg_window_delta(window):
    before, after = window['before'], window['after']
    cpu = counter_delta(before['metrics']['cpu'], after['metrics']['cpu']) if before['metrics'] and after['metrics'] else None
    def index(rows):
        return {tuple(row[k] for k in ('backend_type', 'object', 'context')): row['counters'] for row in rows}
    a, b = index(before['pg_stat_io']), index(after['pg_stat_io'])
    return {'database_bytes_before': before['sql'].get('database_bytes'),
            'database_bytes_after': after['sql'].get('database_bytes'),
            'sql_observed_delta': counter_delta(before['sql'], after['sql']),
            'cgroup_cpu_observed_seconds': cpu['usage_usec']/1e6 if cpu and 'usage_usec' in cpu else None,
            'pg_logical_io_observed_deltas': [{'backend_type': key[0], 'object': key[1], 'context': key[2],
                                               'counters': counter_delta(a[key], b[key])} for key in sorted(a.keys() & b.keys())],
            'boundary': 'Includes control/checksum/availability queries and lock wait, not isolated pg_dump/restore CPU or physical disk I/O.'}


def consume_readback(process, manifest, *, file_bytes=FILE_BYTES, timeout=600):
    """Finite pipe reader; timeout kills only our attach child, not arbitrary PIDs."""
    expired = threading.Event()
    def abort():
        expired.set()
        if process.poll() is None:
            process.kill()
    timer = threading.Timer(timeout, abort)
    timer.start()
    try:
        proof = verify_tar(process.stdout, manifest, file_bytes)
        # Drain bounded tar padding so closing stdout cannot turn a successful
        # restic/dockerd attach into a premature broken-pipe failure.
        trailing = 0
        for chunk in iter(lambda: process.stdout.read(65536), b''):
            trailing += len(chunk)
            if trailing > 1024*1024 or chunk.strip(b'\0'):
                raise ValueError('unexpected bytes beyond readback archive')
        code = process.wait(timeout=30)
        if expired.is_set():
            raise TimeoutError('bounded readback deadline exceeded')
        if code != 0:
            raise ValueError('readback attach exited nonzero')
        return {**proof, 'docker_attach_exit': code}
    except Exception:
        if expired.is_set():
            raise TimeoutError('bounded readback deadline exceeded') from None
        raise
    finally:
        timer.cancel()
        process.stdout.close()
        if process.poll() is None:
            process.kill()
        process.wait(timeout=15)
        timer.join()


def capacity_summary(receipt, samples):
    out = summarize_samples(samples)
    out.update({key: receipt.get(key) for key in
                ('sampler_gap_count', 'sampler_gaps', 'sampler_error_count', 'sampler_diagnostics',
                 'commands', 'worker_terminal', 'worker_events')})
    out['source_pg_windows'] = {w['phase']: pg_window_delta(w) for w in receipt.get('source_windows', [])}
    if receipt.get('pg_restore'):
        out['restore_pg_window'] = pg_window_delta(receipt['pg_restore'])
    image = receipt.get('image_measurement', {})
    out['temporary_disk'] = {'worker_tmpfs_capacity_bytes': TMP_BYTES,
        'operator_tmpfs_capacity_bytes': TMP_BYTES, 'state_acceptance_budget_bytes': 16*1024**2,
        'corpus_generator_max_payload_buffer_bytes': FILE_BYTES,
        'full_dump_or_file_readback_staging_bytes': 0,
        'image_audit_regular_file_transient_upper_bytes': max(
            image.get('actual_merged_export_tar_bytes', 0)+image.get('actual_export_extracted_regular_file_allocated_bytes', 0),
            image.get('actual_save_tar_bytes', 0)) if image else None,
        'boundary': 'Tmpfs capacity is inspected and sampled, not all disk/RAM. State/log peaks are sampled; image audit tar+extracted allocation is separate. Persistent corpus/S3/PG/restore data excluded.'}
    return out


def binary_archive_evidence(raw, expected_name):
    with tarfile.open(fileobj=io.BytesIO(raw)) as tar:
        files = [member for member in tar if member.isfile()]
        if len(files) != 1 or Path(files[0].name).name != expected_name or not 0 < files[0].size <= 64*1024**2:
            raise ValueError('unexpected candidate binary archive')
        digest = hashlib.sha256()
        src = tar.extractfile(files[0])
        for chunk in iter(lambda: src.read(1024*1024), b''):
            digest.update(chunk)
        return {'bytes': files[0].size, 'sha256': digest.hexdigest()}


def validate_cleanup_inventory(prefix, containers, workers, objects, volumes, image, daemon):
    """Pure all-target identity check; caller completes every read before DELETE."""
    for cid, name in containers.items():
        if not re.fullmatch(r'[0-9a-f]{64}', cid):
            raise ValueError('invalid exact container ID')
        obj = objects[cid]
        if obj is None:
            continue
        if cid in workers:
            if not worker_owned(obj, workers[cid], image, daemon):
                raise ValueError('worker identity ambiguous; cleanup refused')
        elif (obj['Id'] != cid or obj['Name'] != '/'+name or
                (obj['Config'].get('Labels') or {}).get('probe.bakabel.owner') != prefix):
            raise ValueError('container ownership changed; cleanup refused')
    for name, obj in volumes.items():
        if obj is None:
            continue
        named = name.startswith(prefix+'-')
        if (obj['Name'] != name or obj['Driver'] != 'local' or obj.get('Options') or
                (named and (obj.get('Labels') or {}).get('probe.bakabel.owner') != prefix) or
                (not named and not re.fullmatch(r'[0-9a-f]{64}', name))):
            raise ValueError('owned/default-local volume identity ambiguous; cleanup refused')


class CapacityEngine:
    """Keep fixture create uncertainty visible across inherited Probe methods."""
    def __init__(self, engine, probe):
        self.engine = engine
        self.probe = probe

    def __getattr__(self, name):
        return getattr(self.engine, name)

    def call(self, method, path, body=None, **kwargs):
        kind = ('container' if path.startswith('/containers/create?name=') else
                'volume' if path == '/volumes/create' else None) if method == 'POST' else None
        if kind is None:
            if body is None:
                return self.engine.call(method, path, **kwargs)
            return self.engine.call(method, path, body, **kwargs)
        p = self.probe
        name = path.split('?name=', 1)[1] if kind == 'container' else body['Name']
        if kind == 'volume':
            if (not name.startswith(p.prefix+'-') or body.get('Driver', 'local') != 'local' or
                    body.get('DriverOpts') or
                    (body.get('Labels') or {}).get('probe.bakabel.owner') != p.prefix):
                raise ValueError('fixture volume request identity ambiguous')
            # volumes/create can return a pre-existing volume without creating it.
            # Never adopt such a name, even if its labels happen to match.
            if self.engine.call('GET', '/volumes/'+quote(name, safe=''), missing=True) is not None:
                raise ValueError('fixture volume name already exists; creation refused')
        intent = (kind, name)
        p.unresolved_creates.add(intent)  # Before POST, including lost/error responses.
        if kind == 'volume' and name not in p.volumes:
            p.volumes.append(name)
        response = self.engine.call(method, path, body, **kwargs)
        if kind == 'container':
            cid = response['Id']
            if not isinstance(cid, str) or not re.fullmatch(r'[0-9a-f]{64}', cid):
                raise ValueError('fixture create response lacks exact container ID')
            p.containers[cid] = name
        elif (response.get('Name') != name or response.get('Driver') != 'local' or
              response.get('Options') or
              (response.get('Labels') or {}).get('probe.bakabel.owner') != p.prefix):
            raise ValueError('fixture volume create identity ambiguous')
        p.unresolved_creates.remove(intent)
        return response


class CapacityObservationEngine(CapacityEngine):
    """Observe the exact real inspect result without changing shared Engine calls."""
    def inspect(self, cid, missing=False):
        obj = self.engine.inspect(cid, missing=True) if missing else self.engine.inspect(cid)
        self.probe.observe_worker_terminal(cid, obj)
        return obj


class CapacityProbe(Probe):
    """Reuse real inventory, source lifecycle, sampler, controller and image audit."""
    @property
    def e(self):
        return self._engine

    @e.setter
    def e(self, engine):
        # Probe assigns its Engine before the rest of constructor initialization.
        if not hasattr(self, 'unresolved_creates'):
            self.unresolved_creates = set()
        self._engine = CapacityObservationEngine(engine, self)

    def observe_worker_terminal(self, cid, obj):
        record = getattr(self, 'worker_records', {}).get(cid)
        if (not record or obj is None or not re.fullmatch(r'[0-9a-f]{64}', cid) or
                not isinstance(record.get('Name'), str) or not isinstance(record.get('runID'), str)):
            return
        owner = {'workerContainerID': cid, 'workerName': record['Name'].lstrip('/'),
                 'runID': record['runID'], 'daemonID': self.daemon}
        if not worker_owned(obj, owner, self.image, self.daemon):
            return
        state = obj.get('State', {})
        if state.get('Running') is False and state.get('Status') in ('exited', 'dead'):
            terminal = self.capacity.setdefault('worker_terminal', {}).setdefault(cid, {'exit': None, 'oom_killed': None})
            # Missing later readback never erases a previously observed field.
            if type(state.get('ExitCode')) is int:
                terminal['exit'] = state['ExitCode']
            if type(state.get('OOMKilled')) is bool:
                terminal['oom_killed'] = state['OOMKilled']

    def collect_worker_diagnostics(self):
        """Best effort, before deletion. Cached Engine events are not an OOM census."""
        observation = {'status': 'unavailable', 'events': []}
        self.capacity['worker_events'] = observation
        try:
            records = getattr(self, 'worker_records', {})
            if len(records) > 128:
                return
            verified = []
            for cid, record in list(records.items()):
                owner = {'workerContainerID': cid, 'workerName': record['Name'].lstrip('/'),
                         'runID': record['runID'], 'daemonID': self.daemon}
                if not re.fullmatch(r'[0-9a-f]{64}', cid) or not worker_owned(record, owner, self.image, self.daemon):
                    continue
                verified.append(cid)
                self.capacity.setdefault('worker_terminal', {}).setdefault(cid, {'exit': None, 'oom_killed': None})
                self.observe_worker_terminal(cid, {**record, 'State': record.get('State_at_first_sample', {})})
                try:
                    self.e.inspect(cid, missing=True)
                except Exception:
                    pass  # No inspect result means unavailable, never false/zero.
            start = getattr(self, '_events_since_ns', None)
            end = time.time_ns()
            if not verified or type(start) is not int or not 0 < start < end:
                return
            if self.e.call('GET', '/info')['ID'] != self.daemon:
                return
            def seconds(ns): return '%d.%09d' % divmod(ns, 1000000000)
            filters = {'type': ['container'], 'container': sorted(verified), 'event': ['oom', 'die']}
            raw = self.e.call('GET', '/events?since='+seconds(start)+'&until='+seconds(end)+
                              '&filters='+quote(json.dumps(filters), safe=''), raw=True)
            if len(raw) > 256*1024:
                return
            lines = raw.splitlines()
            if len(lines) > 256:
                return
            projected = []
            for line in lines:
                row = json.loads(line)
                actor = row.get('Actor', {})
                cid, at, action = actor.get('ID'), row.get('timeNano'), row.get('Action')
                if (row.get('Type') != 'container' or cid not in verified or action not in ('oom', 'die') or
                        type(at) is not int or not start <= at <= end):
                    continue
                code = actor.get('Attributes', {}).get('exitCode')
                code = int(code) if action == 'die' and isinstance(code, str) and re.fullmatch(r'-?[0-9]{1,10}', code) else None
                projected.append({'type': action, 'container': cid, 'time_ns': at, 'exit': code})
            observation.update(status='observed', events=projected)
        except Exception:
            pass  # Diagnostics cannot turn the actual failed run into success.

    def __init__(self, args):
        self._events_since_ns = time.time_ns()
        self.capacity = {'schema': 1, 'started_at': utc(), 'gates': [], 'cleanup': {},
                         'measurements_complete': False, 'full_plan_acceptance_pass': False,
                         'source_sha256': args.expected_source_sha256, 'image_id': args.expected_image_id,
                         'limits': LIMITS, 'retention_enabled': False, 'rounds': [], 'source_windows': []}
        super().__init__(args, inventory_images=(args.image, PG))
        if self.image != args.expected_image_id:
            raise ValueError('candidate image binding changed')
        self.capacity.update(daemon=self.daemon, minio_binary_sha256=sha(args.minio_binary),
            runner_files={name: sha(Path(__file__).with_name(name)) for name in
                ('run_hosted_capacity.py', 'verify_hosted_capacity.py', 'run_resource_probe.py',
                 'run_compose_pg_acceptance.py', 'run_hosted_acceptance.py')},
            images={name: {'id': row['id'], 'engine_reported_size_bytes': row['engine_reported_size_bytes'],
                           'size_semantics': 'Engine store metadata, not unpacked physical/shared-layer allocation'}
                    for name, row in self.result['images'].items()})
        self.save()

    def create(self, suffix, spec, role=None, start=True):
        spec.setdefault('HostConfig', {}).setdefault('LogConfig',
            {'Type': 'json-file', 'Config': {'max-size': '1m', 'max-file': '1'}})
        return super().create(suffix, spec, role=role, start=start)

    def controller(self, command, *argv, **kwargs):
        cid = super().controller(command, *argv, **kwargs)
        if not hasattr(self, 'command_context'):
            self.command_context = {}
        self.command_context[cid] = {
            'operation': command if command in ('plan', 'run', 'restore') else 'unknown',
            'phase': getattr(self, 'capacity_phase', 'unknown')}
        return cid

    def logs(self, cid):
        text = super().logs(cid)
        if any(v in text for v in self.values):
            raise ValueError('synthetic credential in fixture command output')
        return text

    def finish(self, cid, expect=0, timeout=900, *, json_output=True):
        obj = self.wait(lambda: (lambda v: v if not v['State']['Running'] else None)(self.e.inspect(cid)),
                        timeout, 'capacity command terminal')
        if (not re.fullmatch(r'[0-9a-f]{64}', cid) or obj.get('Id') != cid or
                obj.get('Name') != '/'+self.containers.get(cid, '') or
                (obj.get('Config', {}).get('Labels') or {}).get('probe.bakabel.owner') != self.prefix):
            raise ValueError('capacity command identity unavailable')
        actual = obj['State'].get('ExitCode')
        if type(actual) is not int or type(expect) is not int:
            raise ValueError('capacity command integer exit unavailable')
        context = getattr(self, 'command_context', {}).get(cid, {})
        operation, phase = context.get('operation'), context.get('phase')
        diagnostic = {'container': cid, 'exit': actual, 'expected_exit': expect,
            'operation': operation if operation in ('plan', 'run', 'restore', 'restic') else 'unknown',
            'phase': phase if phase in ('prepare', 'first', 'repeat', 'changed', 'readback', 'restore') else 'unknown',
            'json_status': 'unavailable', 'outcomes': []}
        commands = self.capacity.setdefault('commands', [])
        if len(commands) >= 128:
            del commands[0]  # Bounded diagnostic history, never an acceptance gate.
        commands.append(diagnostic)
        try:
            text = self.logs(cid)  # Read even on failure; raw text stays transient.
            rows = json_rows(text) if json_output else []
        except Exception:
            self.save()
            if actual != expect:
                raise ValueError('capacity command returned unexpected exit status') from None
            raise
        try:
            if json_output and len(text.encode()) <= 512*1024:
                diagnostic.update(outcomes=project_outcomes(rows), json_status='observed')
        except ValueError:
            pass  # Oversize diagnostics do not change successful operator parsing.
        self.save()
        if actual != expect:
            raise ValueError('capacity command returned unexpected exit status')
        return rows

    def sql(self, cid, query):
        row = self.e.exec(cid, ['psql', '-XAt', '-U', 'postgres', '-d', 'fixture',
                               '-v', 'ON_ERROR_STOP=1', '-c', query])
        if row['exit']:
            raise ValueError('capacity fixture SQL failed')
        return row['stdout'].strip()

    def restic(self, *argv):
        cid = self.create('operator-'+os.urandom(4).hex(), self.restic_spec(argv), role='operator-restic')
        if not hasattr(self, 'command_context'):
            self.command_context = {}
        self.command_context[cid] = {'operation': 'restic', 'phase': getattr(self, 'capacity_phase', 'unknown')}
        if argv[0] == 'check':
            self.finish(cid, json_output=False)
        else:
            self.finish(cid)
        return self.logs(cid)

    def measure(self, cid, role):
        row = super().measure(cid, role)
        if row and role == 'worker':
            row['state_footprint'] = footprint(self.root/self.worker_records[cid]['state'])
            try:
                s = os.statvfs(Path('/proc')/str(row['main_pid'])/'root/tmp')
                row['tmp_capacity_bytes'] = s.f_blocks*s.f_frsize
                # Filesystem occupancy includes open-unlinked Restic packs that
                # a named-file footprint cannot see; it is not pack attribution.
                row['tmp_available_bytes'] = s.f_bavail*s.f_frsize
                row['tmp_used_bytes'] = (s.f_blocks-s.f_bfree)*s.f_frsize
            except (FileNotFoundError, ProcessLookupError, PermissionError):
                pass
        return row

    def gate(self, name):
        if name not in GATES or name in self.capacity['gates']:
            raise ValueError('unexpected or duplicate capacity gate')
        self.capacity['gates'].append(name)
        self.save()

    def pg_readback(self, cid):
        text = self.sql(cid, "SELECT count(*),sum(g),md5(string_agg(g::text||':'||data,',' ORDER BY g)) FROM payload")
        if not re.fullmatch(r'[0-9]+\|[0-9]+\|[0-9a-f]{32}', text):
            raise ValueError('unexpected PG checksum shape')
        rows, total, digest = text.split('|')
        return {'rows': int(rows), 'sum_g': int(total), 'ordered_payload_md5': digest}

    def identity(self, cid):
        obj = self.e.inspect(cid)
        return {'started_at': obj['State']['StartedAt'], 'restart_count': obj['RestartCount']}

    def prepare(self):
        self.image_audit()
        self.capacity['image_measurement'] = selected_numbers(self.result['image_measurement'], {
            'actual_save_tar_bytes', 'oci_compressed_layer_bytes', 'actual_merged_export_tar_bytes',
            'actual_export_extracted_regular_file_allocated_bytes', 'merged_export_regular_file_payload_bytes',
            'merged_export_regular_files'})
        self.capacity['runtime_binary_sha256'] = self.result['fingerprint']['runtime_bakabel_sha256']
        self.capacity['runtime_restic_sha256'] = self.result['fingerprint']['runtime_restic_sha256']
        audit = next(cid for cid, name in self.containers.items() if name == self.prefix+'-image-audit')
        self.capacity['binaries'] = {name: binary_archive_evidence(self.e.call('GET', '/containers/'+audit+
            '/archive?path='+path, raw=True), name) for name, path in
            (('bakabel', '/usr/local/bin/bakabel'), ('restic', '/usr/bin/restic'))}
        if (self.capacity['binaries']['bakabel']['sha256'] != self.capacity['runtime_binary_sha256'] or
                self.capacity['binaries']['restic']['sha256'] != self.capacity['runtime_restic_sha256']):
            raise ValueError('actual binary archive identity changed')
        minio = self.create('minio', {'Image': PG, 'Entrypoint': ['/minio'],
            'Cmd': ['server', '/data', '--address', '0.0.0.0:9000'],
            'Env': ['MINIO_ROOT_USER_FILE=/credentials/user', 'MINIO_ROOT_PASSWORD_FILE=/credentials/password',
                    'MINIO_BROWSER=off', 'GOMAXPROCS=2'],
            'HostConfig': {'NetworkMode': 'bridge', 'Mounts': [self.bind(self.root/'bin/minio', '/minio', True),
                self.bind(self.root/'private/minio-user', '/credentials/user', True),
                self.bind(self.root/'private/minio-password', '/credentials/password', True),
                self.bind(self.root/'backend', '/data')]}}, role='fixture-s3-backend')
        obj = self.e.inspect(minio)
        ip = obj['NetworkSettings']['Networks']['bridge']['IPAddress']
        if not ip or obj['HostConfig']['PortBindings']:
            raise ValueError('MinIO must have only a private bridge endpoint')
        self.repository = 's3:http://'+ip+':9000/bakabel-capacity/repository'
        self.wait(lambda: '9000' in self.logs(minio), 30, 'MinIO ready')
        self.restic('init')
        self.pg = self.startpg('source-pg', True)
        self.sql(self.pg, "CREATE ROLE fixture_owner; CREATE TABLE payload AS SELECT g,"
            "md5(g::text)||md5((g*17)::text)||md5((g*31)::text)||md5((g*47)::text) AS data "
            "FROM generate_series(1,"+str(PG_ROWS)+") g; ALTER TABLE payload OWNER TO fixture_owner; "
            "ALTER DATABASE fixture OWNER TO fixture_owner; REVOKE CONNECT ON DATABASE fixture FROM PUBLIC; "
            "CREATE TABLE availability_probe(n bigint)")
        self.capacity['source_pg_readback'] = self.pg_readback(self.pg)
        volume = self.prefix+'-capacity-files'
        self.e.call('POST', '/volumes/create', {'Name': volume, 'Labels': {'probe.bakabel.owner': self.prefix}})
        self.volumes.append(volume)
        self.filec = self.create('source-files', {'Image': PG, 'Entrypoint': ['sh', '-c'],
            'Cmd': ['while :; do sleep 3600; done'], 'Labels': {'com.docker.compose.project': self.prefix,
                'com.docker.compose.service': 'files', 'bakabel.type': 'volume', 'bakabel.paths': '/data'},
            'HostConfig': {'Mounts': [{'Type': 'volume', 'Source': volume, 'Target': '/data', 'ReadOnly': False}]}}, role='source-files')
        vi = self.e.call('GET', '/volumes/'+volume)
        if vi['Labels'].get('probe.bakabel.owner') != self.prefix or vi['Driver'] != 'local' or vi.get('Options'):
            raise ValueError('source corpus volume not exact owned default-local storage')
        self.file_backing = Path(vi['Mountpoint'])
        self.original_manifest = generate_corpus(self.file_backing)
        self.capacity['corpus'] = {'files': FILES, 'file_bytes': FILE_BYTES, 'payload_bytes': FILES*FILE_BYTES,
            'changed_files': CHANGED_FILES, 'changed_payload_bytes': CHANGED_FILES*FILE_BYTES,
            'first_manifest_sha256': hashlib.sha256(self.original_manifest.encode()).hexdigest(),
            'incompressible_random': True}
        self.source_identity = {cid: self.identity(cid) for cid in (self.pg, self.filec)}
        self.config(timeout='900s');self.config('fresh.yaml', timeout='900s', fresh=True)
        plan = self.finish(self.controller('plan'))[0]
        if len(plan['targets']) != 2:
            raise ValueError('capacity plan must contain exactly two sources')
        self.pg_target = next(t['ID'] for t in plan['targets'] if t['Kind'] == 'postgres')
        self.file_target = next(t['ID'] for t in plan['targets'] if t['Kind'] == 'volume')
        self.capacity['source_identity_before'] = self.source_identity
        self.disk_checkpoint('prepared')

    def disk_checkpoint(self, name):
        volumes = {}
        for volume in self.volumes:
            obj = self.e.call('GET', '/volumes/'+volume, missing=True)
            # Only paths returned for exact volumes already created by this probe.
            if obj is not None:
                volumes[volume] = footprint(obj['Mountpoint'])
        self.capacity.setdefault('disk_checkpoints', {})[name] = {
            'state': footprint(self.root/'state'), 'fresh_state': footprint(self.root/'fresh-state'),
            's3_fixture_persistent': footprint(self.root/'backend'), 'owned_pg_and_source_volumes': volumes}
        self.save()

    def repository_measurement(self):
        ids = self.restic('list', 'index').splitlines()
        if not ids or len(ids) > 128 or any(not re.fullmatch(r'[0-9a-f]{64}', sid) for sid in ids):
            raise ValueError('invalid or oversized repository index list')
        result = index_evidence(self.restic('cat', 'index', sid) for sid in ids)
        stats = json.loads(self.restic('stats', '--mode', 'raw-data', '--json'))
        result['raw_data_stats'] = selected_numbers(stats, {'total_size', 'total_file_count', 'total_blob_count', 'snapshots_count'})
        return result

    def worker_evidence(self, cid):
        obj = self.worker_records[cid];h = obj['HostConfig']
        return {'image_id': obj['Image'], 'memory_bytes': h['Memory'], 'nanocpus': h['NanoCpus'],
                'readonly_rootfs': h['ReadonlyRootfs'], 'tmpfs': h['Tmpfs'].get('/tmp'),
                'workflow_entrypoint': obj['Config']['Entrypoint'] == ['/usr/local/bin/bakabel'],
                'workflow_command': obj['Config']['Cmd'] == ['_workflow'],
                'cpuset_empty': h['CpusetCpus'] == '',
                'credential_mounts_readonly': all(any(m['Destination'] == path and not m['RW'] for m in obj['Mounts'])
                    for path in ('/run/secrets/restic-password', '/run/secrets/aws'))}

    def blocked(self, pg):
        # The 1GiB file target may precede PostgreSQL; stay below the existing
        # synthetic lock's 300s lifespan without changing the product deadline.
        def predicate():
            owner = json.loads((self.root/'state/owner.json').read_text())
            if (owner.get('phase') == 'exec_started' and self.e.call('GET', '/exec/'+owner['execID']+'/json')['Running'] and
                    self.sql(pg, "SELECT count(*) FROM pg_stat_activity WHERE application_name='"+owner['runID']+"' AND wait_event_type='Lock'") == '1'):
                return owner
        return self.wait(predicate, 240, 'capacity exact pg_dump lock wait')

    def backup_capacity(self, phase):
        before = project_pg(self.source_stats(self.pg))
        self.lock(self.pg)
        controller = self.controller('run')
        active = self.blocked(self.pg)
        self.wait(lambda: active['workerContainerID'] in self.worker_records, 10, 'capacity exact worker sample')
        self.sql(self.pg, 'INSERT INTO availability_probe VALUES (1)')
        if int(self.sql(self.pg, 'SELECT count(*) FROM availability_probe')) < 1:
            raise ValueError('source not read-write during backup')
        self.unlock(self.pg)
        outcome = self.finish(controller)[0]
        if outcome.get('status') != 'complete' or len(outcome.get('targets', [])) != 2 or any(t['status'] != 'complete' for t in outcome['targets']):
            raise ValueError('mixed capacity backup incomplete')
        cid = active['workerContainerID']
        if self.e.inspect(cid, missing=True) is not None or (self.root/'state/owner.json').exists():
            raise ValueError('ordinary backup worker/ownership not removed')
        row = {'phase': phase, 'worker': cid, 'worker_resources': self.worker_evidence(cid),
            'file_snapshot': next(t['snapshotID'] for t in outcome['targets'] if t['targetID'] == self.file_target),
            'pg_snapshot': next(t['snapshotID'] for t in outcome['targets'] if t['targetID'] == self.pg_target),
            'repository': self.repository_measurement()}
        if row['repository']['unique_indexed_data_blobs'] < FILES:
            raise ValueError('repository index did not reach the larger fixture scale')
        self.capacity['rounds'].append(row)
        self.capacity['source_windows'].append({'phase': phase, 'before': before, 'after': project_pg(self.source_stats(self.pg))})
        self.disk_checkpoint(phase)
        return row

    def change_corpus(self):
        self.changed_manifest = generate_corpus(self.file_backing, changed=CHANGED_FILES)
        if self.changed_manifest == self.original_manifest:
            raise ValueError('changed corpus has no changed content')
        self.capacity['corpus']['changed_manifest_sha256'] = hashlib.sha256(self.changed_manifest.encode()).hexdigest()

    def verify_snapshots(self, rounds):
        snapshots = json.loads(self.restic('snapshots', '--json'))
        if len(snapshots) != 6 or any('bakabel.status=complete' not in s.get('tags', []) for s in snapshots):
            raise ValueError('expected exactly six complete mixed snapshots; retention disabled')
        self.capacity['file_snapshots'] = snapshot_evidence(snapshots, [r['file_snapshot'] for r in rounds])
        self.snapshot_paths = {s['id']: s['paths'][0] for s in snapshots}
        self.restic('check')
        self.gate('larger-mixed-repository');self.gate('repeat-parent-zero-new-file-data');self.gate('changed-parent-real-new-data')

    def readback_capacity(self, rounds):
        self.capacity['file_readbacks'] = []
        for row, manifest in ((rounds[0], self.original_manifest), (rounds[2], self.changed_manifest)):
            sid = row['file_snapshot']
            spec = self.restic_spec(['dump', sid, self.snapshot_paths[sid]])
            spec['HostConfig']['LogConfig'] = {'Type': 'none'}
            cid = self.create('readback-'+row['phase'], spec, role='operator-readback', start=False)
            cp = subprocess.Popen(['docker', '-H', 'unix://'+self.sock, 'start', '-a', cid],
                                  stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            try:
                self.wait(lambda: self.e.inspect(cid)['State']['Running'], 10, 'readback started')
                self.pin_container(cid)
                proof = consume_readback(cp, manifest)
                code = cp.returncode
                obj = self.e.inspect(cid)
                if code != 0 or obj['State']['Running'] or obj['State']['ExitCode'] != 0:
                    raise ValueError('streaming repository readback did not exit successfully')
                self.capacity['file_readbacks'].append({'snapshot': sid, 'phase': row['phase'], **proof,
                                                       'docker_attach_exit': code, 'restic_exit': obj['State']['ExitCode']})
            finally:
                cp.stdout.close()
                if cp.poll() is None:
                    cp.kill();cp.wait(timeout=15)
        self.gate('full-original-and-changed-file-readback')

    def restore_capacity(self, first):
        target = self.startpg('restore-pg', False)
        self.sql(target, 'CREATE ROLE fixture_owner; ALTER DATABASE fixture OWNER TO fixture_owner; REVOKE CONNECT ON DATABASE fixture FROM PUBLIC')
        before = project_pg(self.source_stats(target))
        rows = self.finish(self.controller('restore', '--snapshot', first['pg_snapshot'],
            '--postgres-container', target, '--database', 'fixture', '--user', 'postgres', filename='fresh.yaml', fresh=True))
        if rows[0].get('status') != 'restored':
            raise ValueError('fresh capacity target restore incomplete')
        actual = self.pg_readback(target)
        owner = self.sql(target, "SELECT tableowner FROM pg_tables WHERE tablename='payload'")
        db_owner = self.sql(target, "SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname='fixture'")
        public_connect = self.sql(target, "SELECT count(*) FROM pg_database d,LATERAL aclexplode(COALESCE(d.datacl,acldefault('d',d.datdba))) a WHERE d.datname='fixture' AND a.grantee=0 AND a.privilege_type='CONNECT'")
        if actual != self.capacity['source_pg_readback'] or owner != 'fixture_owner' or db_owner != 'fixture_owner' or public_connect != '0':
            raise ValueError('fresh PG payload/owner/ACL readback differs')
        self.capacity['pg_restore'] = {'snapshot': first['pg_snapshot'], 'target': target, 'readback': actual,
            'before': before, 'after': project_pg(self.source_stats(target)), 'owner_acl_equal': True}
        self.disk_checkpoint('after-restore')
        self.gate('fresh-target-pg-restore-readback')

    def verify_sources(self):
        after = {cid: self.identity(cid) for cid in self.source_identity}
        if after != self.source_identity:
            raise ValueError('source restarted during capacity acceptance')
        self.sql(self.pg, 'INSERT INTO availability_probe VALUES (1)')
        if self.sql(self.pg, 'SELECT count(*) FROM availability_probe') != '4':
            raise ValueError('source availability readback differs')
        self.capacity.update(source_identity_after=after, source_read_write_ok=True)
        self.gate('source-online-identity-unchanged')

    def run(self):
        self.capacity_phase = 'prepare'
        self.prepare()
        rounds = []
        for phase in ('first', 'repeat', 'changed'):
            self.capacity_phase = phase
            if phase == 'changed':
                self.change_corpus()
            rounds.append(self.backup_capacity(phase))
        self.verify_snapshots(rounds)
        self.capacity_phase = 'readback'
        self.readback_capacity(rounds)
        self.capacity_phase = 'restore'
        self.restore_capacity(rounds[0])
        self.verify_sources()
        self.capacity['measurements_complete'] = True
        self.save()

    def cleanup(self):
        if hasattr(self, 'stopped'):
            self.stopped.set()
        if hasattr(self, 'thread') and self.thread.is_alive():
            self.thread.join(60)
            if self.thread.is_alive():
                raise ValueError('sampler remains active; preserve fixture for diagnosis')
        if not hasattr(self, 'prefix') and not getattr(self, 'unresolved_creates', None):
            return  # Constructor never created an Engine resource.
        errors = getattr(self, 'result', {}).get('sampler_errors', [])
        self.capacity['sampler_error_count'] = len(errors)
        self.capacity['sampler_diagnostics'] = [{'type': error['type'],
            'frames': [{key: frame[key] for key in ('file', 'line', 'function')} for frame in error.get('frames', [])],
            **({'errno': numeric(error.get('errno'))} if numeric(error.get('errno')) is not None else {}),
            **({'http_status': error['http_status']} if error.get('http_status') is not None else {})}
            for error in errors]
        gaps = getattr(self, 'result', {}).get('sampler_gaps', [])
        self.capacity['sampler_gaps'] = []
        for gap in gaps:
            if (not re.fullmatch(r'[0-9a-f]{64}', gap['container']) or
                    gap['reason'] != 'cgroup-removed-after-inspection'):
                raise ValueError('unrecognized sampling gap identity')
            self.capacity['sampler_gaps'].append({key: gap[key] for key in ('container', 'at', 'reason')})
            self.capacity['sampler_gaps'][-1]['errno'] = numeric(gap.get('errno'))
        self.capacity['sampler_gap_count'] = len(gaps)
        self.collect_worker_diagnostics()
        samples = [project_sample(row) for row in getattr(self, 'samples', [])]
        (self.root/'capacity-metrics.json').write_text(json.dumps(samples, indent=2, allow_nan=False)+'\n')
        (self.root/'capacity-summary.json').write_text(json.dumps(capacity_summary(self.capacity, samples), indent=2, allow_nan=False)+'\n')
        if getattr(self, 'unresolved_creates', None):
            self.capacity['cleanup']['unresolved_fixture_creates'] = [
                {'kind': kind, 'name': name} for kind, name in sorted(self.unresolved_creates)]
            raise ValueError('unresolved fixture create intent; preserve all targets and private paths')
        if hasattr(self, 'containers'):
            info = self.e.call('GET', '/info')
            if info['ID'] != self.daemon or info['Swarm']['LocalNodeState'] != 'inactive':
                raise ValueError('daemon identity/state changed; cleanup refused')
            workers = {}
            for cid, record in self.worker_records.items():
                workers[cid] = {'workerContainerID': cid, 'workerName': record['Name'].lstrip('/'),
                               'runID': record['runID'], 'daemonID': self.daemon}
            for state in ('state', 'fresh-state'):
                path = self.root/state/'owner.json'
                if path.exists():
                    owner = json.loads(path.read_text())
                    if owner.get('workerName') and not owner.get('workerContainerID'):
                        raise ValueError('durable worker intent lacks exact ID; preserve private ownership')
                    if owner.get('workerContainerID'):
                        workers[owner['workerContainerID']] = owner
            for cid, owner in workers.items():
                self.containers[cid] = owner['workerName']
            objects = {cid: self.e.inspect(cid, missing=True) for cid in self.containers}
            volumes = {volume: self.e.call('GET', '/volumes/'+volume, missing=True) for volume in self.volumes}
            validate_cleanup_inventory(self.prefix, self.containers, workers, objects, volumes, self.image, self.daemon)
            self.capacity['cleanup']['target_containers'] = sorted(self.containers)
            self.capacity['cleanup']['target_volumes'] = sorted(set(self.volumes))
            self.save()
            containers_absent = {}
            for cid in reversed(list(self.containers)):
                if objects[cid] is not None:
                    self.e.call('DELETE', '/containers/'+cid+'?force=true&v=true', missing=True)
                containers_absent[cid] = self.e.inspect(cid, missing=True) is None
                self.capacity['cleanup']['containers_absent'] = containers_absent
                self.save()
                if not containers_absent[cid]:
                    raise ValueError('exact container remains; preserve private paths')
            volumes_absent = {}
            for volume in dict.fromkeys(self.volumes):
                if volumes[volume] is not None:
                    self.e.call('DELETE', '/volumes/'+volume, missing=True)
                volumes_absent[volume] = self.e.call('GET', '/volumes/'+volume, missing=True) is None
                self.capacity['cleanup']['volumes_absent'] = volumes_absent
                self.save()
                if not volumes_absent[volume]:
                    raise ValueError('exact volume remains; preserve private paths')
        # Never delete credentials/state/backend before every exact Engine target is absent.
        for directory in ('private', 'state', 'fresh-state', 'backend', 'bin', 'image-unpacked'):
            path = self.root/directory
            if path.exists():
                shutil.rmtree(path)
        for name in ('config.yaml', 'fresh.yaml', 'image-export.tar', 'image-save.tar'):
            (self.root/name).unlink(missing_ok=True)
        self.capacity['cleanup']['private_paths_absent'] = all(not (self.root/name).exists() for name in
            ('private', 'state', 'fresh-state', 'backend', 'bin', 'image-unpacked', 'config.yaml', 'fresh.yaml', 'image-export.tar', 'image-save.tar'))
        self.capacity['finished_at'] = utc()
        self.save()

    def save(self):
        encoded = json.dumps(self.capacity, indent=2, allow_nan=False)+'\n'
        if any(value in encoded for value in getattr(self, 'values', [])):
            raise ValueError('synthetic credential found in capacity evidence')
        (self.root/'capacity-receipt.json').write_text(encoded)

    def restic_spec(self, argv):
        if not argv or argv[0] not in {'init', 'snapshots', 'stats', 'list', 'cat', 'dump', 'check'}:
            raise ValueError('destructive or unsupported operator command')
        return {'Image': self.image, 'Entrypoint': ['/usr/bin/restic'],
                'Cmd': ['--no-cache', *argv],
                'Env': ['RESTIC_REPOSITORY='+self.repository, 'RESTIC_PASSWORD_FILE=/password',
                        'AWS_SHARED_CREDENTIALS_FILE=/aws', 'AWS_DEFAULT_REGION=us-east-1', 'GOMAXPROCS=2'],
                'HostConfig': {'NetworkMode': 'bridge', 'ReadonlyRootfs': True,
                               'LogConfig': {'Type': 'json-file', 'Config': {'max-size': '8m', 'max-file': '1'}},
                               'Mounts': [self.bind(self.root/'private/password', '/password', True),
                                          self.bind(self.root/'private/aws', '/aws', True)],
                               'Tmpfs': {'/tmp': 'rw,nosuid,nodev,size=67108864'}}}


def execute(args, *, probe_type=CapacityProbe):
    if args.runtime.exists() or args.runtime.is_symlink():
        raise ValueError('capacity runtime must be fresh; preserve previous failures')
    probe = probe_type.__new__(probe_type)
    failed = False
    try:
        probe.__init__(args)
        probe.run()
    except Exception as error:
        failed = True
        if not hasattr(probe, 'capacity'):
            probe.capacity = {'schema': 1, 'measurements_complete': False, 'full_plan_acceptance_pass': False}
        probe.capacity['failure'] = failure_location(error)
    finally:
        try:
            probe.cleanup()
        except Exception as error:
            failed = True
            probe.capacity['cleanup_failure'] = failure_location(error)
        if hasattr(probe, 'root') and probe.root.exists() and hasattr(probe, 'capacity'):
            probe.save()
    if failed:
        return 1
    # A separate reader rechecks exact Engine targets and immutable bindings;
    # command exit 0 and our own cleanup booleans are not certification.
    try:
        from verify_hosted_capacity import verify_runtime
        verify_runtime(args, output=args.runtime/'capacity-verified.json')
    except Exception as error:
        probe.capacity['verification_failure'] = failure_location(error)
        probe.save()
        return 1
    return 0


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    for key in ('socket', 'source', 'runtime', 'minio-binary'):
        p.add_argument('--'+key, type=Path, required=True)
    for key in ('image', 'expected-image-id', 'expected-source-sha256'):
        p.add_argument('--'+key, required=True)
    p.add_argument('--exclusive-hosted-daemon', action='store_true')
    return p


def validate_paths(args, env):
    if args.expected_source_sha256 != STOCK_SOURCE:
        raise ValueError('only the fixed stock reviewed core source is admitted')
    temporary = Path(env['RUNNER_TEMP']).resolve()
    runtime = args.runtime.resolve()
    if (runtime == temporary or not runtime.is_relative_to(temporary) or
            args.runtime.is_symlink() or runtime.exists()):
        raise ValueError('runtime must be a fresh child of RUNNER_TEMP')
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', args.expected_image_id):
        raise ValueError('exact image ID required')
    if args.image != args.expected_image_id:
        raise ValueError('image must be the exact expected image ID, not a mutable tag')
    if runtime.is_relative_to(args.source.resolve()):
        raise ValueError('runtime cannot be inside source')
    if fingerprint(args.source) != STOCK_SOURCE:
        raise ValueError('source differs from fixed stock build binding')
    if not args.minio_binary.is_file() or not os.access(args.minio_binary, os.X_OK):
        raise ValueError('existing executable MinIO binary required')
    if not {0, 1} <= os.sched_getaffinity(0):
        raise ValueError('CPU 0,1 unavailable')
    if shutil.disk_usage(temporary).free < 12*1024**3:
        raise ValueError('at least 12GiB scratch space required')
    return runtime


def main(argv=None):
    p = parser()
    args = p.parse_args(argv)
    if (os.environ.get('GITHUB_ACTIONS') != 'true' or
            os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted' or
            os.geteuid() != 0 or not args.exclusive_hosted_daemon):
        p.error('requires root on an explicitly exclusive GitHub-hosted VM; local/shared use refused')
    try:
        validate_paths(args, os.environ)
    except (ValueError, KeyError, OSError) as error:
        p.error(str(error))
    engine = Engine(args.socket)
    info = engine.call('GET', '/info')
    require_hosted_daemon(os.environ, os.geteuid(), args.exclusive_hosted_daemon, info,
                          engine.call('GET', '/containers/json?all=true'))
    actual = engine.call('GET', '/images/'+quote(args.image, safe='')+'/json')
    if actual['Id'] != args.expected_image_id or actual['Size'] > 512*1024**2:
        p.error('exact candidate image binding or bounded image-audit envelope differs')
    memory = int(next(line.split()[1] for line in Path('/proc/meminfo').read_text().splitlines()
                      if line.startswith('MemTotal:')))*1024
    if memory < 4*1024**3:
        p.error('at least 4GiB hosted VM RAM required')
    os.sched_setaffinity(0, {0, 1})
    return execute(args)


if __name__ == '__main__':
    raise SystemExit(main())
