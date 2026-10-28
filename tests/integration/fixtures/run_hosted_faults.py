#!/usr/bin/env python3
"""Current-workflow faults, ONLY on an explicitly exclusive GitHub-hosted VM.

Ordinary candidate image, local disposable repository, unchanged Engine requests.
No source agents, injected positive replies, CPU/memory stripping or S3 dependency.
"""
import argparse
import datetime
import os
import copy
import json
import re
import select
import socket
import socketserver
import stat
import threading
import hashlib
import secrets
import shutil
import time
from pathlib import Path
from urllib.parse import urlsplit, quote
from run_resource_probe import Engine, PG, utc, worker_owned
from run_compose_pg_acceptance import ComposeProbe, fingerprint
from verify_hosted_faults import CASES, CREATE_GAPS, verify_case, verify_report, verify_nonforce_remove
from run_hosted_acceptance import require_hosted_daemon, failure_location
from run_hosted_capacity import CapacityEngine

# Reviewed completion-protocol candidate; never infer admission from CLI input.
FROZEN_SOURCE = 'd4045f8bfc54dfa21f156cd590136a60d280cb39b9d6254cac4c3007cb70f605'
PG_FIXTURE_PIN = 'postgres:18.6-alpine3.24@sha256:83148c0bc09eac4d598b70a61e1404d0212b76c95c504bfd6c81a4c59ec91792'
PG_FIXTURE_VOLUMES = {'/var/lib/postgresql': {}}


def relay_path(root, case):
    # Keep receipts descriptive without overflowing sockaddr_un.sun_path.
    return root.parent/('s'+hashlib.sha256(case.encode()).hexdigest()[:6])/'relay.sock'


def deadline_epoch(job):
    created = datetime.datetime.fromisoformat(job['createdAt'].replace('Z','+00:00'))
    if created.tzinfo is None or type(job['config']['Timeout']) is not int: raise ValueError('invalid durable deadline')
    return created.timestamp()+job['config']['Timeout']/1e9


def socket_binding_proof(mounts, source):
    selected = [m for m in mounts if m.get('Destination') == '/run/bakabel/docker.sock']
    if len(selected) != 1 or selected[0].get('Type') != 'bind' or selected[0].get('Source') != str(source) or selected[0].get('RW') is not False:
        raise ValueError('ordinary process socket did not use exact read-only relay host bind')
    return {'source': str(source), 'destination': '/run/bakabel/docker.sock', 'read_only': True}


class FaultProbe(ComposeProbe):
    def create_file_source(self, volume, sleep_seconds):
        # The pinned PG image is also our sleep/file fixture. Container labels
        # do NOT label image-inherited volumes; create the declared mount first.
        intent = ('file-source-mounts', self.prefix+'-files')
        self.unresolved_creates.add(intent)
        image = self.e.call('GET', '/images/'+quote(PG, safe='')+'/json')
        pinned = self.e.call('GET', '/images/'+quote(PG_FIXTURE_PIN, safe='')+'/json')
        if (image.get('Id') != pinned.get('Id') or not isinstance(image.get('Id'), str) or
                re.fullmatch(r'sha256:[a-f0-9]{64}', image['Id']) is None or
                image.get('Config', {}).get('Volumes') != PG_FIXTURE_VOLUMES or
                pinned.get('Config', {}).get('Volumes') != PG_FIXTURE_VOLUMES):
            raise ValueError('pinned file fixture image volumes changed')
        name = self.prefix+'-files-image-data'
        created = self.e.call('POST', '/volumes/create', {'Name': name, 'Driver': 'local', 'DriverOpts': {},
            'Labels': {'probe.bakabel.owner': self.prefix}})
        if ('Options' not in created or not (created['Options'] is None or
                (type(created['Options']) is dict and not created['Options']))):
            raise ValueError('exact owned file fixture image volume unavailable')
        obj = self.e.call('GET', '/volumes/'+quote(name, safe=''))
        if (obj.get('Name') != name or obj.get('Driver') != 'local' or obj.get('Scope') != 'local' or
                'Options' not in obj or not (obj['Options'] is None or
                    (type(obj['Options']) is dict and not obj['Options'])) or
                (obj.get('Labels') or {}).get('probe.bakabel.owner') != self.prefix):
            raise ValueError('exact owned file fixture image volume unavailable')
        expected = {('/data', volume), ('/var/lib/postgresql', name)}
        self.strict_file_source_volumes = getattr(self, 'strict_file_source_volumes', set())
        self.strict_file_source_volumes.add(name)
        cid = self.create('files', {'Image': PG, 'Entrypoint': ['sh', '-c'], 'Cmd': ['exec sleep '+str(sleep_seconds)],
            'Labels': {'com.docker.compose.project': self.prefix, 'com.docker.compose.service': 'files',
                       'bakabel.type': 'volume', 'bakabel.paths': '/data'},
            'HostConfig': {'Mounts': [{'Type': 'volume', 'Source': source, 'Target': target, 'ReadOnly': False}
                                    for target, source in sorted(expected)]}},
            role='source-files', start=False, record_image_volumes=False)
        obj = self.e.inspect(cid)
        mounts = obj.get('Mounts')
        if (obj.get('Image') != image['Id'] or not isinstance(mounts, list) or len(mounts) != len(expected) or
                any(not isinstance(m, dict) or m.get('Type') != 'volume' or m.get('RW') is not True or
                    (m.get('Destination'), m.get('Name')) not in expected for m in mounts) or
                {(m['Destination'], m['Name']) for m in mounts} != expected):
            # Do not adopt unexpected volumes, nor let v=true delete them as an
            # implicit side effect. Ambiguous mounts retain the ENTIRE plan.
            raise ValueError('file fixture mount identity mismatch')
        self.unresolved_creates.remove(intent)
        self.e.call('POST', '/containers/'+cid+'/start')
        self.pin_container(cid)
        return cid

    def __init__(self, args, case):
        # No source/private volume reads and no Engine writes in construction.
        self.args = args; self.case = case; self.root = args.runtime
        self.root.mkdir(mode=0o700)
        self.prefix = 'bakabel-fault-'+secrets.token_hex(6)
        self.unresolved_creates = set()
        self.e = CapacityEngine(Engine(args.socket), self); self.daemon = self.e.call('GET', '/info')['ID']
        self.image = args.expected_image_id; self.repository = '/repository'
        self.containers = {}; self.volumes = []; self.roles = {}; self.worker_records = {}; self.worker_owners = {}
        self.samples = []; self.values = [secrets.token_hex(24)]; self.source = None
        self.result = {'schema': 1, 'case': case, 'status': 'blocked', 'started_at': utc(),
                       'daemon': self.daemon, 'source_sha256': args.expected_source_sha256,
                       'image_id': self.image, 'backend': 'local', 'platform': 'compose',
                       'ordinary_image': True, 'request_mutations': [], 'images': {}, 'commands': [], 'cleanup': {}}
        for image in (args.image, PG):
            self.result['images'][image] = self.e.call('GET', '/images/'+quote(image, safe='')+'/json')['Id']
        for name in ('private', 'state', 'fresh-state', 'backend'):
            (self.root/name).mkdir(mode=0o700)
        (self.root/'backend/local').mkdir(mode=0o700)
        (self.root/'private/password').write_text(self.values[0]); (self.root/'private/password').chmod(0o600)
        # Inherited controller/restic mount helper expects this path; NO S3
        # config, credentials, process or network endpoint is used by this suite.
        (self.root/'private/aws').write_text(''); (self.root/'private/aws').chmod(0o600)
        socket_path = relay_path(self.root,case); socket_path.parent.mkdir(mode=0o700)
        self.sock = str(socket_path)
        self.relay = FaultRelay(self.sock, args.socket)
        self.relay.observer = self.observe_transport
        self.relay.start()

    def worker_identity_proof(self, obj, owner):
        if (not worker_owned(obj, owner, self.image, self.daemon) or
                obj['Config'].get('Cmd') != ['_workflow'] or
                obj['Config'].get('Entrypoint') != ['/usr/local/bin/bakabel'] or
                obj['HostConfig'].get('NanoCpus') != 2000000000 or
                obj['HostConfig'].get('Memory') != 536870912):
            raise ValueError('ordinary worker identity or default limits changed')
        state = obj.get('State')
        if (not isinstance(state, dict) or type(state.get('Running')) is not bool or
                (state['Running'] and (type(state.get('Pid')) is not int or state['Pid'] <= 0))):
            raise ValueError('exact worker state unavailable')
        proof = {'container_id': obj['Id'], 'run_id': owner['runID'], 'image_id': obj['Image'],
                 'nanocpus': 2000000000, 'memory_bytes': 536870912,
                 'socket': socket_binding_proof(obj['Mounts'], self.sock)}
        return proof

    @staticmethod
    def worker_observation(cid, obj, started):
        # Only the known ID and typed scalar state survive; never raw inspect,
        # timestamps, cgroup paths/text, Env, or exception messages.
        state = obj.get('State') if isinstance(obj, dict) else None
        if not isinstance(state, dict): state = {}
        known = (type(state.get('Running')) is bool and
                 (state['Running'] is False or (type(state.get('Pid')) is int and state['Pid'] > 0)))
        return {'container_id': cid, 'elapsed_ms': max(0, int((time.monotonic()-started)*1000)),
                'observation_state': 'missing' if obj is None else 'observed' if known else 'unavailable',
                'running': state.get('Running') if type(state.get('Running')) is bool else None,
                'pid': state.get('Pid') if type(state.get('Pid')) is int else None,
                'exit_code': state.get('ExitCode') if type(state.get('ExitCode')) is int else None}

    def worker_proof(self, obj, owner):
        proof = self.worker_identity_proof(obj, owner)
        cid = proof['container_id']; gap = None; started = None
        while True:
            # Revalidate every exact Engine snapshot, even a terminal one.
            proof = self.worker_identity_proof(obj, owner)
            if obj['State']['Running'] is False:
                if gap is not None: gap['resolution'] = 'terminal_stopped'
                return proof
            # Keep the existing one-time affinity action outside settling;
            # gap retries are read-only exact inspections and kernel reads.
            if gap is None: self.pin_container(cid)
            try:
                cgroup = self.cgroup(obj['State']['Pid'])
                if cgroup is None:
                    raise FileNotFoundError('exact worker cgroup unavailable')
                if cid not in str(cgroup):
                    raise ValueError('exact worker cgroup identity changed')
                kernel = {'cpu.max': (cgroup/'cpu.max').read_text().strip(),
                          'memory.max': (cgroup/'memory.max').read_text().strip(),
                          'memory.peak': int((cgroup/'memory.peak').read_text().strip())}
            except (FileNotFoundError, ProcessLookupError, PermissionError) as exc:
                if gap is None:
                    started = time.monotonic()
                    gap = {'reason': 'unavailable', 'resolution': 'failed',
                           'rows': [self.worker_observation(cid, obj, started)]}
                    old = self.worker_records.get(cid, {})
                    # Retain a genuine prior kernel read only as historical.
                    self.worker_records[cid] = {**old, **proof,
                        'kernel_readback_state': 'historical' if 'cpu.max' in old else 'unavailable',
                        'observation_gaps': [*old.get('observation_gaps', [])[-63:], gap]}
                if isinstance(exc, PermissionError):
                    raise ValueError('exact worker cgroup unavailable') from None
                # This settles only missing kernel observation, not a product
                # deadline or liveness threshold. Bound both time and read count.
                remaining = 1.0-(time.monotonic()-started)
                if remaining <= 0 or len(gap['rows']) >= 20:
                    raise ValueError('exact worker cgroup unavailable') from None
                if len(gap['rows']) > 1: time.sleep(min(.05, remaining))
                if time.monotonic()-started >= 1.0:
                    raise ValueError('exact worker cgroup unavailable') from None
                try:
                    if self.e.call('GET', '/info', deadline=started+1.0)['ID'] != self.daemon:
                        raise ValueError('worker observation daemon changed')
                    obj = self.e.inspect(cid, missing=True, deadline=started+1.0)
                except Exception:
                    row = self.worker_observation(cid, {}, started)
                    gap['rows'].append(row)
                    raise
                row = self.worker_observation(cid, obj, started)
                gap['rows'].append(row)
                if time.monotonic()-started >= 1.0:
                    raise ValueError('exact worker cgroup unavailable') from None
                if row['observation_state'] == 'unavailable':
                    raise ValueError('exact worker state unavailable')
                if obj is None:
                    gap['resolution'] = 'terminal_absent'
                    return proof
                continue
            if gap is not None and time.monotonic()-started >= 1.0:
                raise ValueError('exact worker cgroup unavailable')
            if kernel['cpu.max'] != '200000 100000' or kernel['memory.max'] != '536870912':
                raise ValueError('kernel worker limits differ from ordinary defaults')
            proof.update(kernel, kernel_readback_state='observed')
            if gap is not None: gap['resolution'] = 'kernel_observed'
            return proof

    def exercise_stream_fault(self):
        controller = self.controller('run')
        active, session, count = self.await_stream(self.source, controller=controller)
        self.result['injection'] = {'stdout_bytes_before_fault': count, 'owner': active, 'session': session}
        if self.case == 'producer-failure-after-output':
            # The producer's exact server session fails after real dump output;
            # never kill/restart the PostgreSQL service or replace pg_dump.
            started = session['backend_start'].replace("'", "''")
            if self.sql(self.source, "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE pid="+str(int(session['pid']))+" AND backend_start='"+started+"'::timestamptz AND application_name='"+active['runID']+"'") != 't':
                raise ValueError('exact producer backend no longer matched')
        elif self.case == 'streaming-worker-SIGKILL':
            self.e.call('POST', '/containers/'+active['workerContainerID']+'/kill?signal=KILL')
        else:
            raise ValueError('unsupported streaming mutation')
        self.finish_failure(controller, active)

    def terminal_proof(self, active):
        cid = active['sourceContainerID']
        obj = self.e.inspect(cid)
        execution = self.e.call('GET', '/exec/'+active['execID']+'/json')
        if (self.e.call('GET', '/info')['ID'] != active['daemonID'] or active['daemonID'] != self.daemon or
                obj.get('Id') != cid or obj['State']['StartedAt'] != active['sourceStartedAt'] or not obj['State']['Running'] or
                execution.get('ID') != active['execID'] or execution.get('ContainerID') != cid or
                execution.get('Running') is not False or type(execution.get('ExitCode')) is not int):
            raise ValueError('exact source exec terminal state unavailable')
        token = active.get('importRunID') or active['runID']
        if not re.fullmatch('[a-zA-Z0-9_]{16,128}', token): raise ValueError('invalid source token')
        sessions = int(self.sql(cid, "SELECT count(*) FROM pg_stat_activity WHERE application_name='"+token+"'"))
        processes = self.process_count(cid, token, 'pg_restore' if active.get('execKind') == 'restore' else 'pg_dump')
        if sessions or processes: raise ValueError('source still has exact owned export/import activity')
        return {'daemon': self.daemon, 'container_id': cid, 'started_at': active['sourceStartedAt'],
                'exec_id': active['execID'], 'exec_exit_code': execution['ExitCode'], 'sessions': sessions, 'processes': processes}

    def launch_terminal_proof(self, active):
        # Launch replies can be lost before the product records any source/exec
        # ID. Use the fixed planned source and owned run, not an invented exec.
        cid = self.source_before['container_id']; token = active['runID']
        obj = self.e.inspect(cid)
        if (not re.fullmatch('[a-f0-9]{32}', token) or active['daemonID'] != self.daemon or
                self.e.call('GET','/info')['ID'] != self.daemon or obj.get('Id') != cid or
                not obj['State']['Running'] or obj['State']['StartedAt'] != self.source_before['started_at']):
            raise ValueError('exact launch source identity unavailable')
        execs = {}
        for record in self.relay.snapshot()['records']:
            if (record.get('owner_checkpoint',{}).get('runID') != token or
                    record.get('boundary') not in ('dump-create','dump-start') or not record.get('forwarded')):
                continue
            eid = record.get('exec_id','')
            if record.get('container_id') != cid or not re.fullmatch('[a-f0-9]{64}',eid):
                raise ValueError('recorded source exec terminal identity unavailable')
            execution = self.e.call('GET','/exec/'+eid+'/json')
            if (execution.get('ID') != eid or execution.get('ContainerID') != cid or execution.get('Running') is not False or
                    type(execution.get('ExitCode')) is not int or execution['ExitCode'] < 0):
                raise ValueError('recorded source exec terminal state unavailable')
            execs[eid] = execution['ExitCode']
        sessions = int(self.sql(cid, "SELECT count(*) FROM pg_stat_activity WHERE application_name='"+token+"'"))
        processes = self.process_count(cid,token,'pg_dump')
        if sessions or processes: raise ValueError('source still has exact owned export activity')
        return {'daemon':self.daemon,'container_id':cid,'started_at':self.source_before['started_at'],
                'run_id':token,'execs':execs,'sessions':sessions,'processes':processes}

    def save(self):
        # Inherited helpers may retain raw logs/specs transiently. Never export
        # them: allow only structured receipts plus bounded ID/metric records.
        result = {k: v for k, v in self.result.items() if k not in ('commands', 'container_specs')}
        result['commands'] = [{k: v for k, v in c.items() if k in ('container', 'operation', 'exit', 'status', 'expected_exit', 'complete_rows', 'failed_rows')} for c in self.result.get('commands', [])]
        result['workers'] = self.worker_records
        encoded = json.dumps(result, indent=2)
        if any(secret in encoded for secret in self.values): raise ValueError('synthetic secret in structured evidence')
        (self.root/'receipt.json').write_text(encoded+'\n')

    def await_stream(self, pg, controller=None):
        def streaming():
            if controller is not None:
                cli = self.e.inspect(controller)
                if not cli['State']['Running']:
                    self.result['commands'].append({'container':controller, 'exit':cli['State']['ExitCode']})
                    raise TimeoutError('CLI exited before live pg_dump after 64KiB stdout')
            active = self.owner()
            if not active or active.get('phase') != 'exec_started' or not active.get('execID'): return None
            count = self.relay.snapshot()['execs'].get(active['execID'], {}).get('stdout_bytes', 0)
            execution = self.e.call('GET', '/exec/'+active['execID']+'/json')
            if count < 65536 or execution.get('Running') is not True or execution.get('ContainerID') != pg: return None
            sessions = json.loads(self.sql(pg, "SELECT coalesce(json_agg(json_build_object('pid',pid,'backend_start',backend_start::text,'application_name',application_name)),'[]'::json) FROM pg_stat_activity WHERE application_name='"+active['runID']+"'"))
            if len(sessions) != 1 or sessions[0]['application_name'] != active['runID']: return None
            return active, sessions[0], count
        return self.wait(streaming, 40, 'live pg_dump after 64KiB stdout')

    def active_import(self, target, controller):
        # A live reader or stdin byte count alone is not import progress. This
        # trusted fixture's CHECK function sleeps inside the real COPY backend.
        if self.e.inspect(controller)['State']['Running'] is not True:
            raise TimeoutError('public restore exited before active COPY')
        active = self.owner()
        if not active or active.get('phase') != 'exec_started': return None
        token = active.get('importRunID','')
        if (not re.fullmatch('restore_[a-f0-9]{48}',token) or token == active.get('runID') or
                active.get('execKind') != 'restore' or active.get('status') != 'active' or
                active.get('workerStartAuthorized') is not True or
                active.get('sourceContainerID') != target or target == self.source or
                active.get('daemonID') != self.daemon or self.e.call('GET','/info')['ID'] != self.daemon):
            raise ValueError('independent import checkpoint mismatch')
        obj = self.e.inspect(target)
        if (obj.get('Id') != target or obj['State'].get('Running') is not True or
                obj['State'].get('StartedAt') != active.get('sourceStartedAt') or
                type(obj.get('RestartCount')) is not int):
            raise ValueError('restore target incarnation changed')
        execution = self.e.call('GET','/exec/'+active['execID']+'/json')
        if execution.get('Running') is not True: return None
        process = execution.get('ProcessConfig',{})
        if (execution.get('ID') != active['execID'] or execution.get('ContainerID') != target or
                type(execution.get('Pid')) is not int or execution['Pid'] <= 0 or
                process.get('entrypoint') != '/usr/local/bin/pg_restore' or process.get('arguments') !=
                ['--no-password','--exit-on-error','--dbname',"host='/var/run/postgresql' port='5432' user='postgres' dbname='fixture'"]):
            raise ValueError('exact restore exec command mismatch')
        sessions = json.loads(self.sql(target,
            "SELECT coalesce(json_agg(json_build_object('pid',pid,'backend_start',backend_start::text,"
            "'application_name',application_name,'datname',datname,'usename',usename,'state',state,'wait_event',wait_event,"
            "'copy_active',query LIKE 'COPY public.payload %')),'[]'::json) FROM pg_stat_activity WHERE application_name='"+token+"'"))
        if len(sessions) != 1: return None
        session = sessions[0]
        if (session.get('application_name') != token or session.get('datname') != 'fixture' or
                session.get('usename') != 'postgres' or session.get('state') != 'active' or
                session.get('wait_event') != 'PgSleep' or session.get('copy_active') is not True or
                type(session.get('pid')) is not int or session['pid'] <= 0 or not session.get('backend_start') or
                self.process_count(target,token,'pg_restore') != 1): return None
        return {'owner':active,'session':session,'exec_pid':execution['Pid'],'processes':1,
                'target':{'container_id':target,'started_at':active['sourceStartedAt'],'restart_count':obj['RestartCount']}}

    def run(self):
        if self.case not in CASES: raise ValueError('unknown fault case')
        self.prepare()
        if self.case in ('producer-failure-after-output', 'streaming-worker-SIGKILL'):
            self.exercise_stream_fault()
        elif self.case.startswith('docker-stream-drop'):
            self.exercise_stream_drop()
        elif self.case.endswith('-response-loss'):
            self.exercise_response_loss()
        elif self.case == 'backup-vs-restore-and-retention':
            self.exercise_overlap()
        elif self.case == 'scheduler-restart-original-deadline':
            self.exercise_restart()
        elif self.case == 'dump-persisted-before-start-worker-SIGKILL':
            self.exercise_persisted_start()
        elif self.case == 'restore-active-import-worker-SIGKILL':
            self.exercise_import_kill()
        self.verify_source_online()
        self.result['exercised'] = True

    def prepare(self):
        self.config(); self.restic('init')
        self.source = self.startpg('pg', True)
        self.sql(self.source, 'CREATE TABLE payload AS SELECT g,md5(g::text)||md5((g*17)::text)||md5((g*31)::text)||md5((g*47)::text) AS data FROM generate_series(1,300000) g; CREATE TABLE availability_probe(n bigint)')
        obj = self.e.inspect(self.source)
        self.source_before = {'container_id': self.source, 'started_at': obj['State']['StartedAt'], 'restart_count': obj['RestartCount']}
        plan = self.call_cli('plan')
        if not plan or len(plan['targets']) != 1: raise ValueError('fixture requires exactly one marked source')
        target = plan['targets'][0]
        if target['Kind'] != 'postgres' or target['Source']['DaemonID'] != self.daemon or target['Source']['ContainerID'] != self.source or target['Source']['StartedAt'] != self.source_before['started_at']:
            raise ValueError('public plan source binding mismatch')
        self.target = target['ID']; self.result['source'] = self.source_before
        if getattr(self,'case',None) == 'restore-active-import-worker-SIGKILL':
            self.f15_plan = {'ID':target['ID'],'Kind':target['Kind'],
                'Source':{k:target['Source'][k] for k in ('DaemonID','ContainerID','StartedAt')}}

    def finish_failure(self, controller, active):
        rows = self.finish(controller, expect=1, timeout=85)
        if not rows or rows[0].get('runID') != active['runID'] or rows[0].get('status') != 'failed':
            raise ValueError('CLI did not report exact failed workflow')
        terminal = self.terminal_proof(active)
        if self.owner() is not None or self.e.inspect(active['workerContainerID'], missing=True) is not None:
            raise ValueError('terminal failure did not release exact worker ownership')
        last = self.last()
        if last['runID'] != active['runID'] or last['status'] != 'failed' or last.get('lastBackupSuccessAt', '') != getattr(self, 'baseline_success', ''):
            raise ValueError('failed run changed last backup success')
        no_complete = self.no_complete_snapshot(active)
        if not no_complete: raise ValueError('failed export has complete snapshot')
        self.result['proof'] = {'outcome':'failed','owner_released':True,'worker_absent':True,'terminal':terminal,'no_complete_snapshot':no_complete,'last_success_unchanged':True}

    def owner(self):
        path = self.root/'state/owner.json'
        if not path.exists(): return None
        if path.stat().st_size > 65536: raise ValueError('owner size bound')
        value = json.loads(path.read_text())
        if not re.fullmatch('[a-f0-9]{32}', value.get('runID','')): raise ValueError('invalid durable run identity')
        return value

    def capture_owned_worker(self, cid=None):
        owner = self.owner()
        if not owner: return
        cid = cid or owner.get('workerContainerID')
        if not cid: return
        obj = self.e.inspect(cid, missing=True)
        if not obj: return
        owner = {**owner, 'workerContainerID':cid}
        self.worker_owners[cid] = owner  # Cleanup authority survives failed limits audit.
        proof = self.worker_proof(obj, owner)
        old = self.worker_records.get(cid, {})
        if proof.get('kernel_readback_state') != 'observed':
            proof['kernel_readback_state'] = 'historical' if 'cpu.max' in old else 'unavailable'
        self.worker_records[cid] = {**old, **proof}
        self.roles[cid] = 'worker'

    def wait(self, fn, seconds=90, label='condition'):
        end = time.monotonic()+seconds
        while time.monotonic() < end:
            self.capture_owned_worker()
            try:
                value = fn()
                if value: return value
            except (FileNotFoundError, KeyError, json.JSONDecodeError): pass
            time.sleep(.05)
        raise TimeoutError('bounded fixture condition: '+label)

    def logs(self, cid, *, deadline=None):
        if deadline is None:
            text = super().logs(cid)
        else:
            b = self.e.call('GET','/containers/'+cid+'/logs?stdout=true&stderr=true&tail=16',raw=True,deadline=deadline)
            if len(b) > 65536: raise ValueError('oversize diagnostic logs')
            out = []
            while b:
                if len(b) < 8 or b[0] not in (1,2) or b[1:4] != b'\0\0\0':
                    raise ValueError('invalid diagnostic log frame')
                n = int.from_bytes(b[4:8],'big')
                if n > len(b)-8: raise ValueError('incomplete diagnostic log frame')
                out.append(b[8:8+n].decode(errors='replace'))
                b = b[8+n:]
            text = ''.join(out)
        if any(secret in text for secret in self.values): raise ValueError('synthetic secret in container logs')
        return text

    def finish(self, cid, expect=0, timeout=120):
        obj = self.wait(lambda: (lambda obj: obj if not obj['State']['Running'] else None)(self.e.inspect(cid)), timeout, 'CLI exit')
        text = self.logs(cid)
        if any(secret in text for secret in self.values): raise ValueError('synthetic secret in CLI logs')
        rows = [json.loads(line) for line in text.splitlines() if line.startswith(('{','['))]
        # Public stdout stays transient. Numeric projections distinguish a real
        # false success from an observation failure without exporting messages.
        self.result['commands'].append({'container':cid, 'exit':obj['State']['ExitCode'], 'expected_exit':expect,
                                        'complete_rows':sum(isinstance(row,dict) and row.get('status') == 'complete' for row in rows),
                                        'failed_rows':sum(isinstance(row,dict) and row.get('status') == 'failed' for row in rows)})
        if obj['State']['ExitCode'] != expect: raise ValueError('unexpected CLI exit')
        return rows

    def process_count(self, cid, token, tool):
        if not re.fullmatch('[a-zA-Z0-9_]{16,128}', token) or tool not in ('pg_dump','pg_restore'): raise ValueError('invalid process proof selector')
        # Fixed read-only /proc inspection in the already supported source image.
        # Read environments only for the exact executable; return a count, never
        # environment bytes. Missing permission is an error, not zero activity.
        script = 'n=0; for p in /proc/[0-9]*; do x=$(readlink "$p/exe" 2>/dev/null) || continue; [ "$x" = "/usr/local/bin/'+tool+'" ] || continue; [ -r "$p/environ" ] || exit 9; if tr "\\000" "\\n" < "$p/environ" | grep -Fxq "PGAPPNAME='+token+'"; then n=$((n+1)); fi; done; printf "%s\\n" "$n"'
        result = self.e.exec(cid, ['sh','-c',script])
        if result['exit'] or not re.fullmatch('[0-9]+\\n?', result['stdout']): raise ValueError('source process terminal proof unavailable')
        return int(result['stdout'])

    def no_complete_snapshot(self, active):
        token = active['runID']+'-'+hashlib.sha256(self.target.encode()).hexdigest()
        snapshots = json.loads(self.restic('snapshots','--json'))
        return not any('bakabel.run='+token in snap.get('tags',[]) and 'bakabel.status=complete' in snap.get('tags',[]) for snap in snapshots)

    def verify_source_online(self):
        obj = self.e.inspect(self.source)
        if (self.e.call('GET','/info')['ID'] != self.daemon or not obj['State']['Running'] or
                obj['Id'] != self.source_before['container_id'] or obj['State']['StartedAt'] != self.source_before['started_at'] or
                obj['RestartCount'] != self.source_before['restart_count']):
            raise ValueError('backup source incarnation changed or stopped')
        self.sql(self.source,'INSERT INTO availability_probe VALUES (1)')
        if int(self.sql(self.source,'SELECT count(*) FROM availability_probe')) < 1: raise ValueError('source not read/write available')
        self.result['source_unchanged'] = True

    def observe_transport(self, phase, record):
        if record['boundary'] == 'worker-remove':
            # Existing cases keep their original observation path. For F15 the
            # real CLI's nonforce removal is after its cancellation proof and
            # before durable owner release (workflow_controller.go).
            if getattr(self,'case',None) != 'restore-active-import-worker-SIGKILL': return
            if phase != 'request': return
            verify_nonforce_remove(record)
            if record.get('forwarded') is not False: raise ValueError('removal observation was not pre-forward')
            if not hasattr(self,'f15_active'): return  # Baseline backup: query gate only.
            active = self.f15_active
            if record.get('container_id') != active['workerContainerID']: return
            if self.owner() != active or hasattr(self,'f15_terminal'):
                raise ValueError('import ownership lost before terminal observation')
            obj = self.e.inspect(active['workerContainerID']); self.worker_identity_proof(obj,active)
            state = obj['State']
            if (state.get('Running') is not False or type(state.get('ExitCode')) is not int or state['ExitCode'] != 137 or
                    type(state.get('Pid')) is not int or state['Pid'] != 0):
                raise ValueError('exact killed worker not terminal before removal')
            terminal = {**self.terminal_proof(active),'import_run_id':active['importRunID']}
            if type(terminal.get('exec_exit_code')) is not int or terminal['exec_exit_code'] <= 0 or self.owner() != active:
                raise ValueError('import terminal not proved while owned')
            record.update(terminal_before_remove=terminal,owner_before_remove=active,
                          worker_before_remove=self.worker_observation(active['workerContainerID'],obj,time.monotonic()))
            self.f15_terminal = terminal
            self.f15_events.append('import-terminal-before-worker-remove')
            return
        if record['boundary'] == 'other': return
        if phase == 'request':
            active = self.owner()
            if not active: raise ValueError('side effect without durable workflow intent')
            record['owner_checkpoint'] = active
            if record['boundary'] in ('dump-start','restore-start') and active.get('execID') != record.get('exec_id'):
                raise ValueError('exec start arrived before exact ID persistence')
        elif phase == 'response' and record['boundary'] == 'worker-create':
            self.capture_owned_worker(record['container_id'])

    def fault_record(self):
        records = [r for r in self.relay.snapshot()['records'] if r.get('fault') in ('response-loss','stream-drop')]
        if len(records) != 1 or records[0].get('forwarded') is not True or records[0].get('status') not in (101,200,201,204):
            raise ValueError('no unique actual forwarded response/stream fault')
        return records[0]

    def assert_quarantine(self, active):
        current = self.owner()
        if not current or current.get('phase') != 'quarantine' or current.get('status') != 'blocked':
            raise ValueError('unknown terminal status did not retain quarantine')
        for key in ('runID','workerContainerID','sourceContainerID','execID'):
            if current.get(key,'') != active.get(key,''): raise ValueError('quarantine identity changed')
        return current

    def fresh_recovery(self, active, *, blocked):
        before = set(self.worker_records)
        scheduler = self.controller('serve')
        if blocked:
            self.finish(scheduler, expect=1, timeout=45)
            self.assert_quarantine(active)
        else:
            observer_end = time.monotonic()+45
            def diagnostic_deadline():
                now = time.monotonic()
                return min(observer_end,now+1) if now < observer_end else None
            observation = {'outcome':'waiting', 'owner':'unavailable', 'controller':'unavailable',
                           'controller_id':scheduler if isinstance(scheduler,str) and re.fullmatch('[a-f0-9]{64}',scheduler) else None,
                           'running':None, 'status':None, 'exit_code':None, 'pid':None}
            # Bounded, typed projections only: no logs, argv, Env or exception text.
            observations = self.result.setdefault('recovery_observations', [])
            if len(observations) < 4: observations.append(observation)
            def owner_state(owner):
                if owner is None: return 'absent'
                keys = ('runID','daemonID','workerContainerID','sourceContainerID','execID')
                return ('matching' if isinstance(owner,dict) and
                        all(active.get(k) and owner.get(k) == active[k] for k in keys) else 'foreign')
            def recovered():
                owner = self.owner()
                observation['owner'] = owner_state(owner)
                observation.update(controller='unavailable',running=None,status=None,exit_code=None,pid=None)
                # Already released: do not spend a nearly exhausted budget on
                # optional API work. Ordinary success diagnostics stay best effort.
                if owner is None and observer_end-time.monotonic() < 1: return True
                try:
                    deadline = diagnostic_deadline()
                    obj = self.e.inspect(scheduler,deadline=deadline) if deadline is not None else None
                    if isinstance(obj,dict) and obj.get('Id') == scheduler:
                        state = obj.get('State')
                        observation['controller'] = 'observed' if isinstance(state,dict) else 'malformed'
                        if isinstance(state,dict):
                            observation.update(
                                running=state.get('Running') if type(state.get('Running')) is bool else None,
                                status=state.get('Status') if state.get('Status') in
                                    ('created','running','paused','restarting','removing','exited','dead') else None,
                                exit_code=state.get('ExitCode') if type(state.get('ExitCode')) is int and
                                    0 <= state['ExitCode'] <= 255 else None,
                                pid=state.get('Pid') if type(state.get('Pid')) is int and 0 <= state['Pid'] <= 2**31-1 else None)
                    elif obj is not None: observation['controller'] = 'foreign'
                except Exception: pass  # Diagnostic failure cannot replace the owner/wait failure.
                if owner is None: return True
                if observation['running'] is False and observation['owner'] == 'matching':
                    # The controller may have released ownership between the
                    # first owner read and terminal inspect. Causally reread it.
                    observation['owner'] = owner_state(self.owner())
                    if observation['owner'] == 'absent': return True
                    if observation['owner'] == 'matching':
                        observation['outcome'] = 'controller_terminal'
                        raise ValueError('fresh recovery controller terminal with retained owner')
                return False
            try:
                self.wait(recovered, 45, 'fresh CLI terminal recovery')
                observation['outcome'] = 'released'
                self.stop(scheduler)
                self.result['fresh_cli_recovery'] = True
            except TimeoutError:
                observation['outcome'] = 'timeout'
                raise
            except Exception:
                if observation['outcome'] != 'controller_terminal': observation['outcome'] = 'error'
                raise
            finally:
                observation['run_finished'] = {'count':None,'failed':None,'status':None}
                deadline = diagnostic_deadline()
                if observation['controller'] == 'observed' and deadline is not None:
                    try:
                        text = self.logs(scheduler,deadline=deadline)  # Transient only; never attach raw logs.
                        if len(text.encode()) <= 65536:
                            summary = {'count':0,'failed':None,'status':None}
                            for line in text.splitlines()[-16:]:
                                try: event = json.loads(line)
                                except ValueError: continue
                                if not isinstance(event,dict) or event.get('event') != 'run_finished': continue
                                result = event.get('result')
                                if not isinstance(result,dict) or result.get('runID') != active.get('runID'): continue
                                summary.update(count=summary['count']+1,
                                    failed=event.get('failed') if type(event.get('failed')) is bool else None,
                                    status=result.get('status') if result.get('status') in ('complete','failed','blocked') else None)
                            observation['run_finished'] = summary
                    except Exception: pass  # Preserve the initiating error, including timeout.
        if set(self.worker_records) != before: raise ValueError('fresh recovery created replacement worker')

    def success_snapshot(self):
        outcome = self.call_cli('run')
        if outcome.get('status') != 'complete' or self.owner() is not None: raise ValueError('trusted restore prerequisite backup failed')
        last = self.last()
        if last['runID'] != outcome['runID'] or last['status'] != 'success' or last['finishedAt'] != last['lastBackupSuccessAt']:
            raise ValueError('baseline last-success not durable')
        self.baseline_success = last['lastBackupSuccessAt']
        snapshot = outcome['targets'][0]['snapshotID']
        listed = self.call_cli('snapshots')
        if not any(row['snapshotID'] == snapshot and row['status'] == 'complete' for row in listed):
            raise ValueError('trusted restore snapshot missing exact complete readback')
        return snapshot

    def nullable_unstarted_proof(self, active, command_sha256):
        # Inspect the real raw API shape. An integer zero is NOT converted to
        # null, and relay non-forwarding is NOT production fencing authority.
        cid = active['sourceContainerID']; eid = active['execID']
        source = self.e.inspect(cid)
        execution = self.e.call('GET','/exec/'+eid+'/json')
        process = execution.get('ProcessConfig',{})
        command = [process.get('entrypoint'),*(process.get('arguments') or [])]
        actual_hash = hashlib.sha256(json.dumps(command,separators=(',',':')).encode()).hexdigest()
        if (self.e.call('GET','/info')['ID'] != self.daemon or active['daemonID'] != self.daemon or
                source.get('Id') != cid or source['State'].get('Running') is not True or
                source['State'].get('StartedAt') != active['sourceStartedAt'] or
                source.get('RestartCount') != self.source_before['restart_count'] or
                execution.get('ID') != eid or execution.get('ContainerID') != cid or actual_hash != command_sha256):
            raise ValueError('exact never-started source/exec identity unavailable')
        if (execution.get('Running') is not False or type(execution.get('Pid')) is not int or execution['Pid'] != 0 or
                execution.get('ExitCode') is not None):
            raise TimeoutError('raw nullable never-started exec API unavailable')
        token = active['runID']
        if not re.fullmatch('[a-f0-9]{32}',token): raise ValueError('invalid durable dump run')
        sessions = int(self.sql(cid,"SELECT count(*) FROM pg_stat_activity WHERE application_name='"+token+"'"))
        processes = self.process_count(cid,token,'pg_dump')
        if sessions or processes: raise ValueError('never-started source has export activity')
        return {'daemon':self.daemon,'container_id':cid,'started_at':active['sourceStartedAt'],'exec_id':eid,
                'restart_count':source['RestartCount'],
                'running':False,'pid':execution['Pid'],'exit_code':execution.get('ExitCode'),
                'exit_state':'null' if 'ExitCode' in execution else 'absent','command_sha256':actual_hash,
                'sessions':sessions,'processes':processes}

    def exercise_persisted_start(self):
        self.success_snapshot()  # Established durable last-success baseline.
        baseline = self.last()
        self.relay.arm('dump-start','hold-before-forward')
        controller = self.controller('run')
        if not self.relay.hit.wait(45): raise TimeoutError('persisted dump start hold not reached')
        records = self.relay.snapshot()['records']
        held = [r for r in records if r.get('fault') == 'hold-before-forward']
        if len(held) != 1 or held[0].get('hold_state') != 'held' or held[0].get('forwarded') is not False or 'status' in held[0]:
            raise TimeoutError('exact unforwarded hold unavailable')
        record = held[0]; active = record['owner_checkpoint']; cid = active['workerContainerID']; eid = active['execID']
        self.result['injection'] = record
        events = ['persisted-start-held']
        if (active.get('phase') != 'exec_started' or active.get('status') != 'active' or active.get('execKind') != 'dump' or
                active.get('sourceContainerID') != self.source or active.get('sourceStartedAt') != self.source_before['started_at'] or
                active.get('targetID') != hashlib.sha256(self.target.encode()).hexdigest() or self.owner() != active):
            raise ValueError('prekill durable owner/frozen target changed')
        self.capture_owned_worker(cid)
        before = self.e.inspect(cid); self.worker_identity_proof(before,active)
        if before['State'].get('Running') is not True: raise ValueError('owned worker not live before kill')
        started = time.monotonic()
        worker_observations = [self.worker_observation(cid,before,started)]
        exec_observations = [self.nullable_unstarted_proof(active,record['command_sha256'])]
        owner_before = self.owner()
        if owner_before != active: raise ValueError('owner changed before kill')
        # Reinspect immediately before the only signal; prior capture is not
        # sufficient authority. Watchdog expiry never authorizes a late kill.
        before = self.e.inspect(cid); self.worker_identity_proof(before,active)
        if before['State'].get('Running') is not True: raise ValueError('worker stopped before injection')
        end = self.relay.held_deadline(eid)
        events.extend(('prekill-checked','worker-kill-requested'))
        self.e.call('POST','/containers/'+cid+'/kill?signal=KILL',deadline=end)
        terminal = None
        while time.monotonic() < end:
            observed = self.e.inspect(cid,deadline=end); self.worker_identity_proof(observed,active)
            if observed['State']['Running'] is False:
                state = observed['State']
                if type(state.get('ExitCode')) is not int or state['ExitCode'] != 137 or type(state.get('Pid')) is not int or state['Pid'] != 0:
                    raise ValueError('exact killed worker not terminal 137')
                terminal = observed; break
            time.sleep(min(.02,max(0,end-time.monotonic())))
        if terminal is None: raise TimeoutError('worker terminal not observed during hold')
        worker_observations.append(self.worker_observation(cid,terminal,started))
        owner_after = self.owner()
        if not owner_after or any(owner_after.get(k) != active.get(k) for k in active if k not in ('phase','status')):
            raise ValueError('persisted exec identity lost across kill')
        events.append('worker-terminal-137')
        self.relay.discard_start(eid); events.append('start-discarded')
        self.finish(controller,expect=1,timeout=85)
        quarantine = self.assert_quarantine(active); events.append('quarantine-retained')
        exec_observations.append(self.nullable_unstarted_proof(active,record['command_sha256']))
        workers_before = self.relay.snapshot()['workers']
        self.fresh_recovery(active,blocked=True)
        fresh = self.assert_quarantine(active)
        if any(fresh.get(k) != active.get(k) for k in active if k not in ('phase','status')):
            raise ValueError('fresh scheduler changed persisted identity')
        workers_after = self.relay.snapshot()['workers']
        if workers_before != workers_after: raise ValueError('fresh scheduler created replacement worker')
        observed = self.e.inspect(cid); self.worker_identity_proof(observed,active)
        state = observed['State']
        if state.get('Running') is not False or type(state.get('ExitCode')) is not int or state['ExitCode'] != 137 or state.get('Pid') != 0:
            raise ValueError('fresh scheduler lost retained terminal worker')
        worker_observations.append(self.worker_observation(cid,observed,started))
        exec_observations.append(self.nullable_unstarted_proof(active,record['command_sha256']))
        events.append('fresh-scheduler-quarantine')
        if self.last() != baseline or not self.no_complete_snapshot(active):
            raise ValueError('quarantine changed last success/result or committed snapshot')
        self.verify_source_online(); events.append('source-online-before-cleanup')
        self.result['proof'] = {'outcome':'quarantined','owner_retained':True,'fresh_cli_blocked':True,'exec_never_started':True,
            'persisted_exec_id':True,'fault_forwarded':False,'cli_exit':1,'fresh_cli_exit':1,
            'last_success_unchanged':True,'last_result_unchanged':True,'no_complete_snapshot':True,
            'owner_before_kill':owner_before,'owner_after_kill':owner_after,'owner_quarantine':quarantine,'owner_fresh':fresh,
            'exec_observations':exec_observations,'worker_observations':worker_observations,
            'workers_before_fresh':workers_before,'workers_after_fresh':workers_after,'events':events}

    def exercise_import_kill(self):
        # Same trusted-dump technique as postgres_cancel_integration_test.go:
        # no target-side DDL after preflight, extra image tool, or source agent.
        self.sql(self.source,"CREATE FUNCTION public.f15_check(i integer) RETURNS boolean LANGUAGE plpgsql AS $$ BEGIN IF i=1 AND current_setting('application_name') LIKE 'restore_%' THEN PERFORM pg_sleep(90); END IF; RETURN true; END $$; ALTER TABLE public.payload ADD CHECK (public.f15_check(g))")
        snapshot = self.success_snapshot()
        # Public restore uses exact snapshot metadata.Source as its logical ID;
        # owner.targetID is independently SHA-256(logical UTF-8), never that ID.
        plan = self.f15_plan
        if (not isinstance(self.target,str) or not self.target or plan.get('ID') != self.target or
                plan.get('Kind') != 'postgres' or plan.get('Source') != {
                    'DaemonID':self.daemon,'ContainerID':self.source,
                    'StartedAt':self.source_before['started_at']}):
            raise ValueError('frozen public plan source binding changed')
        listed = self.call_cli('snapshots')
        if not isinstance(listed,list) or any(not isinstance(row,dict) for row in listed):
            raise ValueError('trusted snapshot readback must be a public list')
        exact = [row for row in listed if row.get('snapshotID') == snapshot]
        if (len(exact) != 1 or exact[0].get('status') != 'complete' or exact[0].get('type') != 'postgres' or
                exact[0].get('source') != self.target or type(exact[0].get('metadata',{}).get('version')) is not int or
                exact[0]['metadata']['version'] != 1 or
                exact[0]['metadata'].get('kind') != 'postgres' or exact[0]['metadata'].get('source') != self.target):
            raise ValueError('exact trusted snapshot logical source differs from frozen plan')
        snap = exact[0]
        mapping = {'plan':copy.deepcopy(plan),'snapshot':{k:snap[k] for k in ('snapshotID','status','type','source')}}
        mapping['snapshot']['metadata'] = {k:snap['metadata'][k] for k in ('version','kind','source')}
        logical = mapping['snapshot']['metadata']['source']
        target = self.startpg('restore',False)
        controller = self.controller('restore','--snapshot',snapshot,'--postgres-container',target,'--database','fixture','--user','postgres')
        observed = self.wait(lambda: self.active_import(target,controller),40,'active restore COPY backend sleep')
        active = observed['owner']; cid = active['workerContainerID']
        if active.get('workerStartAuthorized') is not True: raise ValueError('worker start not strictly authorized')
        if active.get('targetID') != hashlib.sha256(logical.encode('utf-8')).hexdigest():
            raise ValueError('durable import target digest differs from trusted logical source')
        self.f15_active = active; self.f15_events = ['active-copy-observed']
        self.capture_owned_worker(cid)
        # Reobserve the SAME backend/exec/import token immediately before the
        # only signal. A reader-only window or drift never authorizes a kill.
        fresh = self.active_import(target,controller)
        if fresh != observed or self.owner() != active: raise ValueError('active import changed before worker kill')
        obj = self.e.inspect(cid); self.worker_identity_proof(obj,active)
        if obj['State'].get('Running') is not True: raise ValueError('owned worker stopped before injection')
        prekill = self.worker_observation(cid,obj,time.monotonic())
        self.result['injection'] = {'active_import':fresh,'worker_before_kill':prekill,'snapshot_id':snapshot,
            'controller_id':controller,'target_mapping':mapping}
        final_owner = self.owner()
        if final_owner != active or not final_owner or final_owner.get('workerStartAuthorized') is not True:
            raise ValueError('exact strictly authorized owner lost at final kill gate')
        self.f15_events.extend(('prekill-rechecked','worker-kill-requested'))
        self.e.call('POST','/containers/'+cid+'/kill?signal=KILL')
        # The ordinary public restore controller is a separate process from the
        # killed worker. It performs exact import-token cancellation itself;
        # the fixture NEVER cancels the import or supplies a successful reply.
        rows = self.finish(controller,expect=1,timeout=85)
        if (len(rows) != 1 or rows[0].get('runID') != active['runID'] or rows[0].get('status') != 'failed' or
                len(rows[0].get('targets',[])) != 1 or any(t.get('status') in ('restored','complete') or
                t.get('targetID') != logical or t.get('snapshotID') != snapshot for t in rows[0]['targets'])):
            raise ValueError('public restore falsely succeeded or lost exact snapshot')
        if not hasattr(self,'f15_terminal') or self.owner() is not None or self.e.inspect(cid,missing=True) is not None:
            raise ValueError('public CLI did not prove import terminal before ownership release')
        last = self.last()
        if (last.get('runID') != active['runID'] or last.get('status') != 'failed' or last.get('operation') != 'restore' or
                last.get('lastBackupSuccessAt') != self.baseline_success):
            raise ValueError('failed restore changed last backup success')
        self.f15_events.append('public-restore-failed')
        obj = self.e.inspect(target)
        target_after = {'container_id':obj['Id'],'started_at':obj['State']['StartedAt'],'restart_count':obj['RestartCount']}
        if (obj['State']['Running'] is not True or target_after != observed['target'] or
                self.sql(target,"SELECT to_regclass('public.payload') IS NOT NULL") != 't' or
                self.sql(target,'SELECT count(*) FROM public.payload') != '0'):
            raise ValueError('partial restore destination removed or unexpectedly complete')
        self.f15_events.append('partial-target-retained')
        self.result['proof'] = {'outcome':'failed','owner_released':True,'worker_absent':True,'cli_exit':1,
            'last_success_unchanged':True,'terminal':self.f15_terminal,'restore_result':rows[0],
            'partial_target':{**target_after,'payload_exists':True,'payload_rows':0},'events':self.f15_events,
            'recovery_boundary':'original public restore CLI controller, independent of killed worker'}

    def exercise_response_loss(self):
        boundary = self.case.removesuffix('-response-loss')
        if boundary.startswith('restore-'):
            snapshot = self.success_snapshot(); target = self.startpg('restore', False)
            command = ('restore','--snapshot',snapshot,'--postgres-container',target,'--database','fixture','--user','postgres')
        else:
            command = ('run',)
        self.relay.arm(boundary,'response-loss')
        controller = self.controller(*command)
        if not self.relay.hit.wait(45): raise TimeoutError('response loss boundary not reached')
        record = self.fault_record(); active = record['owner_checkpoint']
        self.result['injection'] = record
        if self.case in CREATE_GAPS:
            self.finish(controller,expect=1,timeout=85)
            current = self.assert_quarantine(active)
            if current.get('execID'): raise ValueError('lost create reply unexpectedly persisted exec ID')
            execution = self.e.call('GET','/exec/'+record['exec_id']+'/json')
            if execution['Running'] or execution['ContainerID'] != current['sourceContainerID']:
                raise ValueError('unpersisted exec unexpectedly started')
            starts = [r for r in self.relay.snapshot()['records'] if r.get('exec_id') == record['exec_id'] and r['boundary'].endswith('-start') and r.get('forwarded')]
            if starts: raise ValueError('unpersisted exec was started')
            self.fresh_recovery(current,blocked=True)
            self.result['proof'] = {'outcome':'quarantined','owner_retained':True,'fresh_cli_blocked':True,'exec_never_started':True,
                                    'fault_forwarded':True,'actual_response_status':record['status'],'persisted_exec_id':False}
        elif boundary.startswith('worker-'):
            rows = self.finish(controller,expect=1,timeout=85)
            cid = record['container_id']
            if (self.owner() is not None or self.e.inspect(cid,missing=True) is not None or not rows or
                    rows[0].get('runID') != active['runID'] or rows[0].get('status') != 'failed'):
                raise ValueError('worker launch response loss was not reconciled failed')
            terminal = self.launch_terminal_proof(active)
            last = self.last()
            if (last.get('runID') != active['runID'] or last.get('status') != 'failed' or
                    last.get('lastBackupSuccessAt','') != getattr(self,'baseline_success','')):
                raise ValueError('failed worker launch changed last backup success')
            if not self.no_complete_snapshot(active): raise ValueError('failed worker launch has complete snapshot')
            self.result['proof'] = {'outcome':'failed','owner_released':True,'worker_absent':True,'terminal':terminal,
                                    'last_success_unchanged':True,'no_complete_snapshot':True,
                                    'fault_forwarded':True,'actual_response_status':record['status']}
        else:
            self.finish_failure(controller,active)
            self.result['proof'].update(fault_forwarded=True,actual_response_status=record['status'],persisted_exec_id=True)

    def exercise_stream_drop(self):
        unavailable = self.case.endswith('-status-unavailable-recovery')
        self.relay.arm('dump-start','stream-drop',after_stdout=65536,deny_status=unavailable)
        controller = self.controller('run')
        if not self.relay.hit.wait(45): raise TimeoutError('stream drop threshold not reached')
        record = self.fault_record(); active = record['owner_checkpoint']
        self.result['injection'] = record
        if record.get('stdout_bytes',0) < 65536: raise ValueError('stream drop before partial stdout')
        if unavailable:
            # Bind only this already observed F04 source/run. Never source commands.
            self.relay.control_owner = copy.deepcopy(active)
            self.finish(controller,expect=1,timeout=85)
            self.assert_quarantine(active)
            self.fresh_recovery(active,blocked=True)
            self.result['quarantine_retained_before_recovery'] = True
            self.relay.recover_transport()
            self.fresh_recovery(active,blocked=False)
        self.finish_failure(controller,active)
        self.result['proof'].update(fault_forwarded=True,actual_response_status=record['status'],stdout_bytes=record['stdout_bytes'])

    def call_cli(self, command, *argv, filename='config.yaml', fresh=False, expect=0):
        cid = self.controller(command,*argv,filename=filename,fresh=fresh)
        rows = self.finish(cid,expect=expect)
        return rows[0] if rows else None

    def exercise_overlap(self):
        snapshot = self.success_snapshot(); target = self.startpg('restore',False)
        self.config('retention.yaml')
        with (self.root/'retention.yaml').open('a') as out: out.write('retention:\n  daily: 1\n')
        self.lock(self.source)
        controller = self.controller('run'); active = self.blocked(self.source)
        workers = self.relay.snapshot()['workers']
        self.call_cli('restore','--snapshot',snapshot,'--postgres-container',target,'--database','fixture','--user','postgres',expect=1)
        self.call_cli('run',filename='retention.yaml',expect=1)
        if self.owner() != active or self.relay.snapshot()['workers'] != workers: raise ValueError('overlap replaced workflow owner/worker')
        if self.sql(target,"SELECT count(*) FROM pg_class WHERE relname='payload'") != '0': raise ValueError('overlapping restore wrote target')
        self.unlock(self.source)
        rows = self.finish(controller)
        if rows[0].get('status') != 'complete' or self.owner() is not None: raise ValueError('primary overlap workflow failed')
        terminal = self.terminal_proof(active)
        self.result['proof'] = {'outcome':'complete-after-overlap-refusal','same_owner':True,'restore_cli_exit':1,'retention_run_exit':1,
                                'target_unchanged':True,'no_new_worker':True,'owner_released':True,'terminal':terminal,
                                'maintenance_boundary':'retention-configured public run; no standalone maintenance CLI exists'}

    def exercise_restart(self):
        self.success_snapshot(); self.config(timeout='90s')
        self.lock(self.source)
        controller = self.controller('run'); active = self.blocked(self.source)
        path = self.root/'state/workflow/job.json'; original = path.read_bytes(); job = json.loads(original)
        deadline = deadline_epoch(job)
        self.e.call('POST','/containers/'+controller+'/kill?signal=KILL'); self.finish(controller,expect=137)

        def live_until(epoch):
            # Sample continuously, including between restarts: an immediate or
            # materially early failure is not evidence of the original timeout.
            while True:
                current = self.owner()
                execution = self.e.call('GET','/exec/'+active['execID']+'/json')
                if (path.read_bytes() != original or not current or current.get('runID') != active['runID'] or
                        current.get('workerContainerID') != active['workerContainerID'] or
                        not self.e.inspect(active['workerContainerID'])['State']['Running'] or
                        execution.get('Running') is not True or execution.get('ContainerID') != self.source or
                        self.sql(self.source,"SELECT count(*) FROM pg_stat_activity WHERE application_name='"+active['runID']+"' AND wait_event_type='Lock'") != '1'):
                    raise ValueError('workflow not still live until near original deadline')
                observed = time.time()
                if observed >= epoch: return observed
                time.sleep(min(.1,epoch-observed))

        # Both renewed deadlines are far beyond the original +10s cleanup cap.
        # Annual cron prevents a new scheduled job racing startup recovery.
        live_until(deadline-30)
        first = self.controller('serve'); first_epoch = time.time()
        live_until(deadline-15)
        self.e.call('POST','/containers/'+first+'/kill?signal=KILL'); self.finish(first,expect=137)
        second = self.controller('serve'); second_epoch = time.time()
        alive_until = live_until(deadline-2)
        def failed():
            value = self.last()
            return value if value.get('runID') == active['runID'] and value.get('status') == 'failed' and self.owner() is None else None
        last = self.wait(failed,max(0,deadline+10-time.time()),'original deadline scheduler failure')
        observed = time.time()
        if observed < deadline-2 or observed > deadline+10 or last.get('lastBackupSuccessAt') != self.baseline_success:
            raise ValueError('restart violated original deadline or refreshed last success')
        terminal = self.terminal_proof(active)
        if self.e.inspect(active['workerContainerID'],missing=True) is not None or not self.no_complete_snapshot(active):
            raise ValueError('restarted scheduler lost failed workflow boundary')
        self.stop(second); self.unlock(self.source)
        self.result['proof'] = {'outcome':'failed','owner_released':True,'worker_absent':True,'terminal':terminal,'no_complete_snapshot':True,
                                'last_success_unchanged':True,'same_job_bytes':True,'same_worker':True,'deadline_epoch':deadline,
                                'original_timeout_seconds':job['config']['Timeout']/1e9,'scheduler_restart_epochs':[first_epoch,second_epoch],
                                'alive_until_epoch':alive_until,'observed_terminal_epoch':observed,
                                'seconds_after_original_deadline':observed-deadline,'scheduler_restarts':2}

    def cleanup(self):
        persisted_start = getattr(self,'case',None) == 'dump-persisted-before-start-worker-SIGKILL'
        if persisted_start:
            # Close/discard, never forward a pending request during teardown.
            self.relay.close()
            proof = self.result.get('proof')
            if proof and self.assert_quarantine(proof['owner_fresh']) != proof['owner_fresh']:
                raise ValueError('quarantine identity changed before cleanup')
        # Validate the ENTIRE deletion authority before the first write. These
        # are only immutable create-returned IDs, never a daemon-wide inventory.
        if getattr(self,'unresolved_creates',set()): raise ValueError('unresolved fixture create; preserve all recovery paths')
        if self.e.call('GET','/info')['ID'] != self.daemon: raise ValueError('cleanup daemon changed')
        targets = dict(self.containers)
        for cid, owner in self.worker_owners.items(): targets[cid] = owner['workerName']
        for cid, name in targets.items():
            obj = self.e.inspect(cid,missing=True)
            if obj is None: continue
            if cid in self.worker_owners:
                if not worker_owned(obj,self.worker_owners[cid],self.image,self.daemon): raise ValueError('cleanup worker identity mismatch')
            elif obj.get('Id') != cid or obj.get('Name') != '/'+name or (obj.get('Config',{}).get('Labels') or {}).get('probe.bakabel.owner') != self.prefix:
                raise ValueError('cleanup fixture identity mismatch')
        for name in dict.fromkeys(self.volumes):
            # One bounded mismatch projection, never an inspect/error dump.
            # Unknown readbacks remain null, not a fabricated failed predicate.
            check = {'volume': name if isinstance(name, str) and
                     re.fullmatch(r'(?:bakabel-fault-[a-f0-9]{12}-[a-z0-9][a-z0-9_.-]{0,63}|[a-f0-9]{64})', name) else None,
                     'observation': 'unavailable', 'name_matches': None, 'owner_matches': None,
                     'driver_local': None, 'options_empty': None, 'before_delete': True}
            try:
                obj = self.e.call('GET','/volumes/'+quote(name,safe=''),missing=True)
            except Exception:
                self.result.setdefault('cleanup', {})['volume_identity_mismatch'] = check
                raise
            if obj is None: continue
            if isinstance(obj, dict):
                check.update(observation='observed',
                    name_matches=obj['Name'] == name if isinstance(obj.get('Name'), str) else None,
                    owner_matches=(obj['Labels'].get('probe.bakabel.owner') == self.prefix
                                   if isinstance(obj.get('Labels'), dict) else False if 'Labels' in obj and obj['Labels'] is None else None),
                    driver_local=obj['Driver'] == 'local' if isinstance(obj.get('Driver'), str) else None,
                    options_empty=(obj['Options'] is None or obj['Options'] == {}) if 'Options' in obj else None)
            else: check['observation'] = 'malformed'
            # Preserve the existing owner/Name/local/Options deletion guard;
            # malformed/unavailable identity also refuses, never grants authority.
            try:
                mismatch = (obj.get('Name') != name or
                    (obj.get('Labels') or {}).get('probe.bakabel.owner') != self.prefix or
                    obj.get('Driver') != 'local' or obj.get('Options'))
            except (AttributeError, TypeError): mismatch = True
            if name in getattr(self, 'strict_file_source_volumes', set()):
                options_known_empty = (isinstance(obj, dict) and 'Options' in obj and
                    (obj['Options'] is None or (type(obj['Options']) is dict and not obj['Options'])))
                if isinstance(obj, dict) and 'Options' in obj:
                    check['options_empty'] = options_known_empty
                mismatch = mismatch or not options_known_empty
            if mismatch:
                self.result.setdefault('cleanup', {})['volume_identity_mismatch'] = check
                raise ValueError('cleanup volume identity mismatch')
        absent = {}
        # Source removal is post-gate fixture teardown, NEVER cancellation proof
        # and never used to pass online/terminal/quarantine assertions above.
        order = sorted(targets, key=lambda cid: self.roles.get(cid) in ('source-pg','restore-pg'))
        for cid in order:
            self.e.call('DELETE','/containers/'+cid+'?force=true&v=true',missing=True)
            absent[cid] = self.e.inspect(cid,missing=True) is None
        volabsent = {}
        for name in dict.fromkeys(self.volumes):
            self.e.call('DELETE','/volumes/'+quote(name,safe=''),missing=True)
            volabsent[name] = self.e.call('GET','/volumes/'+quote(name,safe=''),missing=True) is None
        # Keep credentials, repository and recovery state intact unless every
        # exact Engine object was read back absent. A successful DELETE is not
        # absence proof; ambiguous teardown must remain operator-recoverable.
        if not all(absent.values()) or not all(volabsent.values()): raise ValueError('owned cleanup absence not observed')
        self.relay.close()
        if hasattr(self, 'before_private_cleanup'): self.before_private_cleanup()
        retained = self.owner() is not None
        self.result['relay'] = self.relay.snapshot()
        for name in ('private','backend','fresh-state'):
            shutil.rmtree(self.root/name)
        if not retained: shutil.rmtree(self.root/'state')
        self.result['cleanup'] = {'containers_absent':absent,'volumes_absent':volabsent,'private_paths_absent':not (self.root/'private').exists(),
                                  'quarantine_state_retained':retained,'source_removed_only_after_gate':True}
        if persisted_start and self.result.get('proof'):
            self.result['proof']['events'].append('owned-cleanup')
        if self.result['relay']['errors']: raise ValueError('unclassified relay transport errors')

    def config(self, filename='config.yaml', timeout='45s', fresh=False):
        (self.root/filename).write_text(
            f'version: 1\ninstallation: {self.prefix}\nplatform: compose\nscope: [{self.prefix}]\n'
            f'repository: /repository\ncredentials:\n  password_file: /password\nstate_dir: /state\n'
            f'worker_image: {self.image}\ntimeout: {timeout}\nschedule: "0 0 1 1 *"\ntimezone: UTC\n')
        return 'fresh-state' if fresh else 'state'


def read_headers(conn):
    data = bytearray()
    while not data.endswith(b'\r\n\r\n'):
        chunk = conn.recv(1)  # Never prefetch hijacked stream bytes.
        if not chunk:
            raise EOFError('transport closed before headers')
        data.extend(chunk)
        if len(data) > 65536:
            raise ValueError('HTTP header limit')
    lines = bytes(data).split(b'\r\n')
    headers = {}
    for line in lines[1:-2]:
        key, value = line.split(b':', 1)
        headers[key.decode('ascii').lower()] = value.strip().decode('latin1')
    return bytes(data), lines[0].decode('ascii'), headers


def read_exact(conn, count):
    out = bytearray()
    while len(out) < count:
        chunk = conn.recv(min(65536, count-len(out)))
        if not chunk:
            raise EOFError('truncated HTTP body')
        out.extend(chunk)
    return bytes(out)


class FrameCounter:
    """Docker multiplex stdout byte count; never retains payload or stderr."""
    def __init__(self, stderr_observer=None, stdout_observer=None):
        self.header = bytearray(); self.left = 0; self.stream = 0; self.stdout = 0
        self.stderr_observer = stderr_observer
        self.stdout_observer = stdout_observer
        self.stderr = 0
        self.native_framing_valid = True  # Additional native-only restrictions; original parser unchanged.

    def feed(self, data):
        view = memoryview(data)
        while view:
            if not self.left:
                n = min(8-len(self.header), len(view))
                self.header.extend(view[:n]); view = view[n:]
                if len(self.header) < 8: break
                if self.header[0] not in (0, 1, 2) or self.header[1:4] != b'\0\0\0':
                    self.native_framing_valid = False
                    raise ValueError('not a Docker multiplex stream')
                self.stream = self.header[0]
                self.left = int.from_bytes(self.header[4:8], 'big'); self.header.clear()
                if self.stream not in (1,2) or not 0 < self.left <= 65536:
                    self.native_framing_valid = False
                if not self.left: continue
            n = min(self.left, len(view)); self.left -= n
            if self.stream == 2:
                self.stderr += n
                if self.stderr_observer: self.stderr_observer(view[:n])
            if self.stream == 1:
                self.stdout += n
                if self.stdout_observer: self.stdout_observer(view[:n])
            view = view[n:]


# Exact internal/platform/docker/dump_command.go contract. Do not parse shell
# syntax or search for pg_dump/format substrings: unknown wrappers fail closed.
DUMP_SCRIPT = r'''run=$1
shift
BAKABEL_RUN_ID="$run" PGAPPNAME="$run" /usr/local/bin/pg_dump "$@"
code=$?
[ "$code" -eq 0 ] || exit "$code"
printf '\000BAKABEL_EXPORT_COMPLETE_V1:%s\000' "$run"'''
DUMP_ENV = ['PGAPPNAME=', 'BAKABEL_RUN_ID=', 'PGHOSTADDR=', 'PGPASSWORD=',
            'PGPASSFILE=/dev/null', 'PGSERVICEFILE=/dev/null', 'PGOPTIONS=', 'PGCONNECT_TIMEOUT=10']


def is_dump_conninfo(value):
    # Only the canonical local-socket conninfo emitted by Postgres.conninfo.
    quoted = r"'((?:[^'\\\x00]|\\['\\])*)'"
    match = re.fullmatch(r"host='/var/run/postgresql' port='5432' user="+quoted+r' dbname='+quoted, value)
    if match is None:
        return False
    try:
        return all(0 < len(re.sub(r"\\(['\\])", r'\1', name).encode('utf-8')) <= 256 for name in match.groups())
    except UnicodeEncodeError:
        return False


def is_dump_wrapper(value):
    cmd = value.get('Cmd')
    return (isinstance(cmd, list) and len(cmd) == 10 and all(isinstance(arg, str) for arg in cmd) and
            cmd[:4] == ['/bin/sh', '-c', DUMP_SCRIPT, 'bakabel-export-v1'] and
            re.fullmatch(r'[a-zA-Z0-9_-]{16,63}', cmd[4]) is not None and
            cmd[5:7] == ['--no-password', '--dbname'] and is_dump_conninfo(cmd[7]) and
            cmd[8:] == ['--format=custom', '--compress=gzip:9'] and value.get('Env') == DUMP_ENV and
            value.get('User') == '0' and value.get('AttachStdout') is True and
            value.get('AttachStderr') is True and value.get('AttachStdin') is False and value.get('Tty') is False)


# Literal public native control contracts, observation only. No argv is retained.
CONTROL_SCAN = r'''token=$1
for f in /proc/[0-9]*/environ; do
 [ -r "$f" ] || continue
 env=$(tr '\000' '\n' < "$f" 2>/dev/null) || continue
 case "
$env
" in *"
BAKABEL_RUN_ID=$token
"*)
 p=${f%/environ}; p=${p##*/}
 IFS= read -r stat < /proc/$p/stat || exit 41
 rest=${stat##*) }; set -- $rest; shift 19; start=$1
 exe=$(readlink /proc/$p/exe) || exit 43
 printf '%s|%s|%s\n' "$p" "$start" "$exe"
 ;; esac
done'''
CONTROL_CANCEL = r'''p=$1; expected=$2; token=$3; sig=$4
case "$p" in ''|*[!0-9]*) exit 40;; esac
case "$sig" in TERM|KILL) ;; *) exit 49;; esac
IFS= read -r stat < /proc/$p/stat || exit 41
rest=${stat##*) }; set -- $rest; shift 19; actual=$1
[ "$actual" = "$expected" ] || { echo STARTTIME_MISMATCH; exit 42; }
exe=$(readlink /proc/$p/exe) || exit 43
[ "$exe" = /usr/local/bin/pg_dump ] || exit 44
env=$(tr '\000' '\n' < /proc/$p/environ) || exit 45
case "
$env
" in *"
BAKABEL_RUN_ID=$token
"*) ;; *) exit 46;; esac
IFS= read -r stat < /proc/$p/stat || exit 47
rest=${stat##*) }; set -- $rest; shift 19
[ "$1" = "$expected" ] || exit 48
kill -"$sig" "$p"'''


class FaultRelay:
    """Byte-preserving, bounded Unix transport. Never generates HTTP replies.

    Request parsing is classification only unless an explicit private validator
    is opted in. Bodies/Env/argv/stream content are never recorded. Not related
    to cli_relay's nested CPU rewrite.
    """
    def __init__(self, path, target):
        self.path = Path(path)
        self.target = str(target)
        self.lock = threading.RLock()
        self.quiescent = threading.Condition(self.lock)
        self.active_handlers = 0
        self.records = []
        self.errors = []
        self.connections = set()
        self.execs = {}
        # Separate diagnostic identities can never admit dump/restore starts or cleanup.
        self.control_owner = None
        self.control_execs = {}  # At most 64 F04 helper creates.
        self.workers = set()
        self.rule = None
        self.denied_exec = None
        self.hit = threading.Event()
        self.denied_start = None
        self.dump_bindings = {}
        self.restore_validator = None  # F22-only transient request contract.
        self.restore_pending = {}
        self.restore_bindings = {}
        self.restore_tokens = set()
        self.restore_starts = set()
        self.hold = None
        self.closed = False
        self.observer = None
        self.stderr_classifier_factory = None  # Opt-in transient classifier, never raw capture.
        self.observe_streams = False  # Storage F19/F22 only; original fault semantics unchanged.
        self.capture_done = {}
        relay = self
        class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
            daemon_threads = True
            def server_bind(self):
                super().server_bind()
                bound = relay.path.lstat()
                if not stat.S_ISSOCK(bound.st_mode): raise ValueError('relay socket identity missing')
                relay.socket_identity = (bound.st_dev,bound.st_ino,stat.S_IFMT(bound.st_mode))
            def process_request(self, request, client_address):
                # Admission precedes even thread scheduling or user callbacks.
                if not relay.admit_handler(request):
                    self.shutdown_request(request)
                    return
                try: super().process_request(request, client_address)
                except BaseException:
                    relay.retire_handler(request)
                    raise
            def process_request_thread(self, request, client_address):
                try: super().process_request_thread(request, client_address)
                finally: relay.retire_handler(request)
            def handle_error(self, *args):
                with relay.lock:
                    relay.errors.append('handler error')
        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                relay.handle(self.request)
        self.server = Server(str(path), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def owns_socket_path(self):
        try: current = self.path.lstat()
        except FileNotFoundError: return False
        return (current.st_dev,current.st_ino,stat.S_IFMT(current.st_mode)) == self.socket_identity

    def start(self):
        with self.lock:
            if self.closed or not self.owns_socket_path(): raise ValueError('relay socket identity changed')
            os.chmod(self.path,0o600,follow_symlinks=False)
            self.thread.start()

    def arm(self, boundary, action, *, after_stdout=65536, deny_status=False, hold_seconds=10):
        if boundary not in ('worker-create', 'worker-start', 'dump-create', 'dump-start', 'restore-create', 'restore-start') or action not in ('response-loss', 'stream-drop', 'hold-before-forward'):
            raise ValueError('unsupported transport boundary')
        if action == 'hold-before-forward' and (boundary != 'dump-start' or type(hold_seconds) not in (int,float) or not 0 < hold_seconds <= 10):
            raise ValueError('invalid bounded pre-forward hold')
        if action == 'stream-drop' and (boundary != 'dump-start' or after_stdout < 1):
            raise ValueError('stream drop requires positive dump stdout threshold')
        with self.lock:
            if self.rule is not None: raise ValueError('fault already armed')
            self.rule = {'boundary': boundary, 'action': action, 'after_stdout': after_stdout, 'deny_status': deny_status}
            if action == 'hold-before-forward': self.rule['hold_seconds'] = hold_seconds
            self.hit.clear()

    def held_deadline(self, eid):
        with self.lock:
            if (not self.hold or self.denied_start != eid or self.hold['record']['hold_state'] != 'held' or
                    time.monotonic() >= self.hold['deadline']):
                raise TimeoutError('pre-forward hold expired or unavailable')
            return self.hold['deadline']

    def discard_start(self, eid):
        with self.lock:
            self.held_deadline(eid)
            self.hold['record']['hold_state'] = 'discarded'
            self.hold['done'].set()

    def status_allowed(self, eid):
        with self.lock:
            return eid != self.denied_exec

    def recover_transport(self):
        with self.lock:
            self.denied_exec = None
            self.rule = None

    def validate_restore_request(self,record,body):
        if self.restore_validator is None or record['boundary'] not in ('restore-create','restore-start'): return
        def unique(pairs):
            value={}
            for key,item in pairs:
                if key in value: raise ValueError('duplicate private request field')
                value[key]=item
            return value
        spec=json.loads(body,object_pairs_hook=unique)
        if record['boundary'] == 'restore-create':
            receipt=self.restore_validator('create',record,spec,None)
            token=receipt['import_run_id']
            with self.lock:
                if token in self.restore_tokens or id(record) in self.restore_pending:
                    raise ValueError('replayed restore create')
                self.restore_tokens.add(token)
                self.restore_pending[id(record)]=copy.deepcopy(receipt)
        else:
            eid=record['exec_id']
            with self.lock:
                if eid not in self.restore_bindings or eid in self.restore_starts: raise ValueError('unbound or replayed restore start')
                binding=copy.deepcopy(self.restore_bindings[eid])
                self.restore_starts.add(eid) # Failed admission cannot be retried.
            if json.dumps(spec,sort_keys=True) != json.dumps({'Detach':False,'Tty':False},sort_keys=True):
                raise ValueError('nonproduction restore start')
            record['restore_start']=self.restore_validator('start',record,spec,binding)

    def bind_restore_response(self,record,eid):
        with self.lock:
            if eid in self.restore_bindings or eid in self.execs: raise ValueError('duplicate real create identity')
            receipt=self.restore_pending.pop(id(record),None)
            if receipt is None or re.fullmatch('[a-f0-9]{64}',eid or '') is None: raise ValueError('unvalidated restore create response')
            receipt['exec_id']=eid
            self.restore_bindings[eid]=copy.deepcopy(receipt)
            record['restore_create']=receipt

    def observe_control_response(self, record, raw):
        """Finite projection of existing response bytes; never transport authority."""
        if not 200 <= record['status'] < 300: return
        try:
            value = json.loads(raw)
            if not isinstance(value,dict): return
            with self.lock:
                if record['control_phase'] == 'create':
                    eid = value.get('Id')
                    if (isinstance(eid,str) and re.fullmatch('[a-f0-9]{64}',eid) and
                            eid not in self.execs and eid not in self.control_execs and len(self.control_execs) < 64):
                        record['exec_id'] = eid
                        self.control_execs[eid] = {k:record[k] for k in ('control_role','container_id','control_run_id')}
                elif record['control_phase'] == 'inspect':
                    state = record['control_state']
                    if value.get('ID') != record['exec_id'] or value.get('ContainerID') != record['container_id']:
                        state['observation'] = 'foreign'
                        return
                    state.update(observation='observed',
                        running=value.get('Running') if type(value.get('Running')) is bool else None,
                        exit_code=value.get('ExitCode') if type(value.get('ExitCode')) is int and 0 <= value['ExitCode'] <= 255 else None,
                        pid=value.get('Pid') if type(value.get('Pid')) is int and 0 <= value['Pid'] <= 2**31-1 else None)
        except Exception: pass  # Never replace forwarding with diagnostic validation.

    def classify(self, method, path, body):
        url = urlsplit(path)
        path = re.sub(r'^/v[0-9.]+', '', url.path)
        record = {'method': method, 'boundary': 'other', 'forwarded': False}
        # Read-only external observer seam; never changes bytes or replies.
        if method == 'GET' and path == '/containers/json' and url.query == 'all=true' and not url.fragment:
            record['inventory_all'] = True
        removal = re.fullmatch(r'/containers/([a-f0-9]{64})',path)
        if method == 'DELETE' and removal and removal[1] in self.workers:
            record.update(boundary='worker-remove',container_id=removal[1])
            options = {}; valid = not bool(url.fragment)
            for item in url.query.split('&') if url.query else ():
                match = re.fullmatch(r'(force|v)=(true|false)',item)
                if match is None or match[1] in options:
                    valid = False
                else:
                    options[match[1]] = match[2] == 'true'
            # Observation only for all other cases: do not change request bytes
            # or forwarding. F15 checks this before its terminal callback.
            record.update(remove_query=url.query,remove_query_valid=valid,
                          remove_force=options.get('force',False) if valid else None,
                          remove_volumes=options.get('v',False) if valid else None)
        value = json.loads(body) if body else {}
        if not isinstance(value, dict): value = {}
        if method == 'POST' and path == '/containers/create':
            if (value.get('Labels') or {}).get('bakabel.worker') == '1':
                record['boundary'] = 'worker-create'
        match = re.fullmatch(r'/containers/([a-f0-9]{64})/(exec|start)', path)
        if method == 'POST' and match:
            cid, operation = match.groups()
            record['container_id'] = cid
            if operation == 'start' and cid in self.workers:
                record['boundary'] = 'worker-start'
            elif operation == 'exec':
                cmd = value.get('Cmd') or []
                if not isinstance(cmd, list) or not all(isinstance(arg, str) for arg in cmd): cmd = []
                owner = getattr(self,'control_owner',None)
                role = None
                if (isinstance(owner,dict) and owner.get('sourceContainerID') == cid and
                        isinstance(owner.get('runID'),str) and re.fullmatch('[a-f0-9]{32}',owner['runID'])):
                    token = owner['runID']
                    if cmd == ['sh','-c',CONTROL_SCAN,'bakabel-scan',token]: role = 'scan_dump'
                    elif (len(cmd) == 8 and cmd[:4] == ['sh','-c',CONTROL_CANCEL,'bakabel-cancel'] and
                          re.fullmatch('[0-9]{1,10}',cmd[4]) and re.fullmatch('[0-9]{1,20}',cmd[5]) and
                          cmd[6] == token and cmd[7] in ('TERM','KILL')):
                        role = 'signal_term' if cmd[7] == 'TERM' else 'signal_kill'
                if role:
                    record.update(control_role=role,control_phase='create',control_run_id=owner['runID'],
                                  control_state={'observation':'unavailable','running':None,'exit_code':None,'pid':None})
                tool = Path(cmd[0]).name if cmd else ''
                if is_dump_wrapper(value) or (tool == 'pg_dump' and '--format=custom' in cmd):
                    # Direct pg_dump recognition is retained for old fixtures;
                    # it never admits a shell/env wrapper by substring.
                    record['boundary'] = 'dump-create'
                elif tool == 'pg_restore' and '--exit-on-error' in cmd:
                    record['boundary'] = 'restore-create'
        match = re.fullmatch(r'/exec/([a-f0-9]{64})/(start|json)', path)
        if match:
            eid, operation = match.groups(); record['exec_id'] = eid
            binding = getattr(self,'control_execs',{}).get(eid)
            if binding and ((operation == 'start' and method == 'POST') or (operation == 'json' and method == 'GET')):
                record.update(binding,control_phase='start' if operation == 'start' else 'inspect')
                record['control_state'] = {'observation':'unavailable','running':None,'exit_code':None,'pid':None}
            if operation == 'start' and eid == getattr(self,'denied_start',None):
                record['fault'] = 'start-transport-refused'
            if operation == 'start' and eid in self.execs:
                record['boundary'] = self.execs[eid]['kind']+'-start'
                record['container_id'] = self.execs[eid]['container_id']
            if operation == 'json' and method == 'GET' and not self.status_allowed(eid):
                record['fault'] = 'status-transport-refused'
        return record

    def snapshot(self):
        with self.lock:
            out = {'records': self.records, 'errors': self.errors, 'execs': self.execs, 'workers':sorted(self.workers), 'denied_exec': self.denied_exec}
            if self.denied_start is not None: out['denied_start'] = self.denied_start
            return copy.deepcopy(out)

    def wait_capture(self, eid, deadline):
        with self.lock: done = self.capture_done.get(eid)
        if done is None: raise ValueError('exact stream capture missing')
        if not done.wait(max(0,deadline-time.monotonic())):
            raise TimeoutError('stream capture not quiescent')

    def admit_handler(self, front):
        with self.quiescent:
            if self.closed: return False
            self.active_handlers += 1
            self.connections.add(front)
            return True

    def retire_handler(self, front):
        with self.quiescent:
            self.connections.discard(front)
            self.active_handlers -= 1
            self.quiescent.notify_all()

    def close(self):
        deadline = time.monotonic()+3
        with self.lock:
            already_closed = self.closed
            self.closed = True
            if self.hold and self.hold['record']['hold_state'] == 'held':
                self.hold['record']['hold_state'] = 'closed'
                self.hold['done'].set()
        if not already_closed and self.thread.ident is not None:
            self.server.shutdown()
            self.thread.join(max(0,deadline-time.monotonic()))
        self.server.server_close()
        with self.quiescent:
            for conn in list(self.connections):
                try: conn.shutdown(socket.SHUT_RDWR)
                except OSError: pass
            while self.active_handlers:
                remaining = deadline-time.monotonic()
                if remaining <= 0: raise TimeoutError('relay handlers not quiescent')
                self.quiescent.wait(remaining)
            captures = list(self.capture_done)
        for eid in captures: self.wait_capture(eid,deadline)
        if self.owns_socket_path(): self.path.unlink(missing_ok=True)

    def observe_stream(self, front, back, eid, record, diagnostic, rule):
        """Opt-in storage observation; forwarding counts still mean successful sends.

        An input EPIPE does not imply output EOF. Retire input and allow at most
        one second/64KiB of upstream observation, inside the original deadline.
        No synthetic EOF, HTTP response, stream retry, or payload retention.
        """
        done = threading.Event()
        capture = {'state':'armed','stop_reason':None,'input_stop':None,
                   'output_stop':None,'stderr_bytes':0,'stdout_observed_bytes':0}
        with self.lock:
            record['capture'] = capture
            self.capture_done[eid] = done
        deadline = time.monotonic()+180
        draining = False; drained = 0; output_open = True
        observed = FrameCounter(stderr_observer=diagnostic.feed if diagnostic is not None else None,
                                stdout_observer=getattr(diagnostic,'feed_stdout',None))
        forwarded = FrameCounter()
        readers = [front, back]
        reason = 'closed'
        def remaining():
            value = deadline-time.monotonic()
            if value <= 0: raise TimeoutError('relay stream deadline')
            return value
        def send(dst, data):
            view = memoryview(data)
            while view:
                dst.settimeout(remaining())
                sent = dst.send(view)
                if not sent: raise BrokenPipeError('relay send closed')
                if dst is front:
                    # Count only bytes the kernel accepted, including a partial
                    # frame before timeout/EPIPE. Parsing never suppresses bytes.
                    try: forwarded.feed(view[:sent])
                    except ValueError: pass
                    with self.lock:
                        self.execs[eid]['stdout_bytes'] = forwarded.stdout
                        record['stdout_bytes'] = forwarded.stdout
                else:
                    with self.lock: self.execs[eid]['stdin_bytes'] += sent
                view = view[sent:]
        try:
            while readers:
                ready, _, _ = select.select(readers, [], [], remaining())
                if not ready:
                    reason = 'drain_timeout' if draining else 'timeout'; break
                for src in ready:
                    limit = min(65536,65536-drained) if src is back and draining else 65536
                    if not limit: reason = 'drain_bound'; return
                    try:
                        src.settimeout(remaining())
                        data = src.recv(limit)
                    except ConnectionResetError:
                        if src is back: reason = 'recv_back_reset'; return
                        capture['input_stop'] = 'recv_front_reset'; data = b''
                    if not data:
                        readers.remove(src)
                        if src is back:
                            reason = 'closed' if self.closed else ('frame_incomplete' if observed.header or observed.left else 'upstream_eof')
                            try: front.shutdown(socket.SHUT_WR)
                            except OSError: pass
                            if reason != 'upstream_eof': return
                            continue
                        capture['input_stop'] = capture['input_stop'] or 'client_eof'
                        try: back.shutdown(socket.SHUT_WR)
                        except OSError: pass
                        continue
                    if src is back:
                        parse_failed = False
                        try: observed.feed(data)  # Observe before a failing output send.
                        except ValueError: parse_failed = True  # Still forward this original chunk.
                        capture['stdout_observed_bytes'] = observed.stdout
                        capture['stderr_bytes'] = observed.stderr
                        if draining: drained += len(data)
                        if output_open:
                            try: send(front,data)
                            except (BrokenPipeError, ConnectionResetError) as exc:
                                capture['output_stop'] = 'send_front_broken_pipe' if isinstance(exc,BrokenPipeError) else 'send_front_reset'
                                output_open = False
                                if front in readers: readers.remove(front)
                                try: back.shutdown(socket.SHUT_WR)
                                except OSError: pass
                                draining = True; deadline = min(deadline,time.monotonic()+1)
                        if rule and rule['action'] == 'stream-drop' and forwarded.stdout >= rule['after_stdout']:
                            with self.lock:
                                record['fault'] = 'stream-drop'
                                if rule['deny_status']: self.denied_exec = eid
                            self.hit.set(); reason = 'fault_stream_drop'; return
                        if parse_failed: reason = 'frame_invalid'; return
                    else:
                        try: send(back,data)
                        except (BrokenPipeError, ConnectionResetError) as exc:
                            capture['input_stop'] = 'send_back_broken_pipe' if isinstance(exc,BrokenPipeError) else 'send_back_reset'
                            readers.remove(front)
                            try: back.shutdown(socket.SHUT_WR)
                            except OSError: pass
                            draining = True; deadline = min(deadline,time.monotonic()+1)
        except TimeoutError:
            reason = 'drain_timeout' if draining else 'timeout'
        except ValueError:
            reason = 'frame_invalid'
        finally:
            with self.lock:
                capture['stop_reason'] = reason
                capture['state'] = 'finalized' if reason == 'upstream_eof' else 'aborted'
                if reason in ('frame_invalid','frame_incomplete'): self.errors.append('ValueError')
                elif reason == 'timeout': self.errors.append('TimeoutError')
            if diagnostic is not None:
                # Classifier callbacks may block; never lend them the close lock.
                value = diagnostic.finish()
                if getattr(diagnostic,'observe_import_message',False):
                    # Finite observed native message != complete diagnostic
                    # stream. Preserve this evidence before the fail-closed
                    # transport projection below. F22 consumes it only together
                    # with private create/start provenance and terminal proof.
                    observation = {'cause':value['cause'],
                        'message_complete':value['complete'] is True and value['cause'] == 'hstore_binary_load_missing',
                        'observed_error_count':value['error_count'],
                        'transport_complete':reason == 'upstream_eof'}
                    with self.lock: record['import_observation'] = observation
                    template = getattr(diagnostic,'native_template',None)
                    framing_consumed = not observed.header and not observed.left
                    native = {'schema':1,'template':template,'observed_bytes':observed.stderr,
                        'observed_error_count':value['error_count'],
                        'framing_valid':observed.native_framing_valid,'framing_consumed':framing_consumed,
                        'reset_candidate':bool(template and observed.native_framing_valid and framing_consumed and
                            reason == 'recv_back_reset' and capture['output_stop'] is None and
                            capture['input_stop'] in (None,'client_eof','send_back_broken_pipe') and
                            observed.stdout == 0 and not rule and not self.closed)}
                    with self.lock: record['native_fatal_observation'] = native
                if reason != 'upstream_eof':
                    value.update(cause='unclassified',complete=False)
                if reason != 'upstream_eof' and 'completion_marker_seen' in value:
                    value['completion_marker_seen'] = None
                key = getattr(diagnostic,'receipt_key','import_diagnostic')
                if key not in ('import_diagnostic','export_diagnostic'): raise ValueError('invalid diagnostic projection')
                with self.lock: record[key] = value

    def handle(self, front):
        while self.exchange_one(front):
            pass

    def exchange_one(self, front):
        # Direct offline callers share the same barrier as server admissions.
        if not self.admit_handler(front): return
        back = None
        try:
            back = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            front.settimeout(180); back.settimeout(180)
            with self.lock: self.connections.add(back)
            head, line, headers = read_headers(front)
            method, path, _ = line.split(' ')
            if headers.get('transfer-encoding'):
                raise ValueError('chunked requests not admitted')
            n = int(headers.get('content-length', 0))
            if n < 0 or n > 2*1024*1024:
                raise ValueError('request body limit')
            with self.lock:
                holding = self.denied_start is not None or (self.rule and self.rule['action'] == 'hold-before-forward')
            if holding and re.fullmatch(r'/v[0-9.]+/exec/[a-f0-9]{64}/start|/exec/[a-f0-9]{64}/start',urlsplit(path).path) and n > 4096:
                raise ValueError('held start body limit')
            body = read_exact(front, n)
            with self.lock:
                record = self.classify(method, path, body)
                if len(self.records) >= 12000: raise ValueError('bounded relay record limit')
                self.records.append(record)
                if record.get('fault') in ('status-transport-refused','start-transport-refused'): return
                rule = None
                if self.rule and self.rule['boundary'] == record['boundary']:
                    rule = self.rule; self.rule = None
                    if rule['action'] == 'hold-before-forward': self.denied_start = record['exec_id']
            if self.observer: self.observer('request',record)
            self.validate_restore_request(record,body)
            if rule and rule['action'] == 'hold-before-forward':
                # Never connect, send, or synthesize a reply on this path. A
                # retry is denied from the instant the exact hold is installed.
                if method != 'POST' or body != b'{"Detach":false,"Tty":false}':
                    raise ValueError('unexpected held start command')
                with self.lock:
                    eid = record['exec_id']
                    if self.closed or self.hold is not None: raise ValueError('hold unavailable')
                    if eid not in self.dump_bindings: raise ValueError('exact wrapped create missing')
                    binding = self.dump_bindings[eid]; active = record.get('owner_checkpoint',{})
                    created = binding.get('owner_checkpoint',{})
                    keys = ('runID','daemonID','workerContainerID','workerName','workerStartAuthorized','sourceContainerID','sourceStartedAt','targetID','execKind')
                    if (any(not active.get(k) or active.get(k) != created.get(k) for k in keys) or
                            any(re.fullmatch('[a-f0-9]{64}',active.get(k,'')) is None for k in ('workerContainerID','sourceContainerID','targetID')) or
                            re.fullmatch('[a-f0-9]{32}',active.get('runID','')) is None or
                            active['runID'] != binding['run_id'] or active.get('execID') != eid or
                            active.get('sourceContainerID') != record.get('container_id') or
                            active.get('execKind') != 'dump' or active.get('workerStartAuthorized') is not True or
                            active.get('phase') != 'exec_started' or active.get('status') != 'active' or
                            created.get('phase') != 'creating_exec' or created.get('execID')):
                        raise ValueError('durable pre-forward binding mismatch')
                    self.denied_start = eid
                    record.update(fault='hold-before-forward',hold_state='held',held_bytes=len(head)+len(body),
                                  producer_contract='wrapped-dump-v1',command_sha256=binding['command_sha256'])
                    done = threading.Event(); deadline = time.monotonic()+rule['hold_seconds']
                    self.hold = {'record':record,'done':done,'deadline':deadline}
                    self.hit.set()
                done.wait(max(0,deadline-time.monotonic()))  # No relay lock held.
                with self.lock:
                    if record['hold_state'] == 'held': record['hold_state'] = 'expired'
                return
            back.connect(self.target)
            back.sendall(head+body)
            with self.lock: record['forwarded'] = True
            response, status, fields = read_headers(back)
            with self.lock: record['status'] = int(status.split(' ')[1])
            response_body = None
            if record['boundary'].endswith('-create') and 200 <= record['status'] < 300:
                size = int(fields.get('content-length', -1))
                if size < 0 or size > 65536: raise ValueError('unbounded create response')
                response_body = read_exact(back, size)
                identity = json.loads(response_body).get('Id')
                if not re.fullmatch('[a-f0-9]{64}', identity or ''): raise ValueError('invalid real Engine identity')
                with self.lock:
                    if record['boundary'] == 'worker-create':
                        record['container_id'] = identity; self.workers.add(identity)
                    else:
                        if self.restore_validator and record['boundary'] == 'restore-create':
                            self.bind_restore_response(record,identity)
                        record['exec_id'] = identity
                        self.execs[identity] = {'kind': record['boundary'].removesuffix('-create'), 'container_id': record['container_id'], 'stdout_bytes': 0, 'stdin_bytes': 0}
                        spec = json.loads(body)
                        if record['boundary'] == 'dump-create' and is_dump_wrapper(spec):
                            self.dump_bindings[identity] = {'run_id':spec['Cmd'][4],'owner_checkpoint':copy.deepcopy(record.get('owner_checkpoint',{})),
                                'command_sha256':hashlib.sha256(json.dumps(spec['Cmd'],separators=(',',':')).encode()).hexdigest()}
                            if self.rule and self.rule['action'] == 'hold-before-forward':
                                record.update(producer_contract='wrapped-dump-v1',producer_run_id=spec['Cmd'][4],
                                              command_sha256=self.dump_bindings[identity]['command_sha256'])
            if self.observer: self.observer('response',record)
            if rule and rule['action'] == 'response-loss':
                with self.lock: record['fault'] = 'response-loss'
                self.hit.set()
                return  # Actual request and real daemon response already observed.
            keepalive = headers.get('connection','').lower() != 'close' and fields.get('connection','').lower() != 'close'
            front.sendall(response)
            if method == 'HEAD' or record['status'] in (204,304): return keepalive
            if response_body is not None:
                front.sendall(response_body)
                return keepalive
            eid = record.get('exec_id') if record['boundary'].endswith('-start') else None
            diagnostic = self.stderr_classifier_factory(record) if eid and record['status'] == 101 and self.stderr_classifier_factory else None
            if record['status'] == 101 and eid and self.observe_streams:
                return self.observe_stream(front, back, eid, record, diagnostic, rule)
            counter = FrameCounter(stderr_observer=diagnostic.feed if diagnostic is not None else None)
            # Capture only bounded create/inspect JSON while forwarding the same
            # bytes immediately. Oversize/truncated/unparsed data stays unknown.
            control_body = bytearray() if record.get('control_phase') in ('create','inspect') else None
            control_projected = False
            def control_complete():
                nonlocal control_projected
                if control_body is not None and not control_projected:
                    self.observe_control_response(record,control_body)
                    control_projected = True
            def forward(src, dst, data):
                nonlocal control_body
                if src is back and control_body is not None:
                    if len(control_body)+len(data) <= 65536: control_body.extend(data)
                    else: control_body = None
                    # Install a create binding before the client can receive its
                    # final body byte and immediately submit the matching start.
                    if 'content-length' in fields and control_body is not None and len(control_body) == int(fields['content-length']):
                        control_complete()
                dst.sendall(data)
                if eid:
                    if src is back: counter.feed(data)
                    with self.lock:
                        if src is back:
                            self.execs[eid]['stdout_bytes'] = counter.stdout
                            record['stdout_bytes'] = counter.stdout
                        else:
                            self.execs[eid]['stdin_bytes'] += len(data)
                        if rule and rule['action'] == 'stream-drop' and counter.stdout >= rule['after_stdout']:
                            record['fault'] = 'stream-drop'
                            if rule['deny_status']: self.denied_exec = eid
                            self.hit.set()
                            return False
                return True
            if record['status'] == 101:
                readers = [front, back]
                while readers:
                    ready, _, _ = select.select(readers, [], [], 180)
                    if not ready: raise TimeoutError('relay stream deadline')
                    for src in ready:
                        dst = back if src is front else front
                        data = src.recv(65536)
                        if data:
                            if not forward(src, dst, data): return
                        else:
                            if src is back and diagnostic is not None:
                                if counter.header or counter.left: raise ValueError('incomplete diagnostic frame')
                                value = diagnostic.finish()
                                with self.lock: record['import_diagnostic'] = value
                            readers.remove(src)
                            try: dst.shutdown(socket.SHUT_WR)
                            except OSError: pass
            elif 'content-length' in fields:
                left = int(fields['content-length'])
                while left:
                    chunk = back.recv(min(65536, left))
                    if not chunk: raise EOFError('truncated response')
                    if not forward(back, front, chunk): return
                    left -= len(chunk)
                control_complete()
                return keepalive
            elif fields.get('transfer-encoding','').lower() == 'chunked':
                def line():
                    out = bytearray()
                    while not out.endswith(b'\r\n'):
                        out.extend(read_exact(back, 1))
                        if len(out) > 8192: raise ValueError('chunk line limit')
                    return bytes(out)
                while True:
                    chunkline = line(); front.sendall(chunkline)
                    left = int(chunkline.split(b';')[0], 16)
                    if not left:
                        trailer_bytes = 0
                        while True:
                            trailer = line()
                            if trailer == b'\r\n': control_complete()
                            front.sendall(trailer); trailer_bytes += len(trailer)
                            if trailer_bytes > 65536: raise ValueError('trailer limit')
                            if trailer == b'\r\n': return keepalive
                    while left:
                        data = back.recv(min(left, 65536))
                        if not data: raise EOFError('truncated chunk')
                        if not forward(back, front, data): return
                        left -= len(data)
                    ending = read_exact(back, 2)
                    if ending != b'\r\n': raise ValueError('invalid chunk ending')
                    front.sendall(ending)
            else:
                while True:
                    chunk = back.recv(65536)
                    if not chunk: break
                    if not forward(back, front, chunk): return
                control_complete()
        except (BrokenPipeError, ConnectionResetError, EOFError):
            pass
        except Exception as exc:
            with self.lock:
                self.errors.append(type(exc).__name__)
        finally:
            if back is not None:
                back.close()
                with self.lock: self.connections.discard(back)
            if 'record' in locals() and 'capture' in record:
                self.capture_done[record['exec_id']].set()
            self.retire_handler(front)


def probe_class_for_case(case):
    if case == 'restore-reader-failure-importer-zero':
        from run_hosted_f14 import F14Mixin
        class F14Probe(F14Mixin, FaultProbe):
            pass
        return F14Probe
    from verify_hosted_native_faults import NATIVE_CASES
    if case in NATIVE_CASES:
        from run_hosted_native_faults import NativeFaultProbe
        return NativeFaultProbe
    return FaultProbe


def run_case(args, case, probe_class=None, case_verifier=None, failure_projector=None):
    locate = failure_projector or failure_location
    if args.runtime.exists(): raise ValueError('case runtime must be fresh')
    cls = probe_class or probe_class_for_case(case)
    probe = cls.__new__(cls); initialized = False
    result = {'schema':1,'case':case,'status':'blocked','source_sha256':args.expected_source_sha256,'image_id':args.expected_image_id,'full_plan_acceptance_pass':False}
    try:
        probe.__init__(args,case); initialized = True; result = probe.result
        probe.run(); result['status'] = 'pass'
    except Exception as exc:
        result['status'] = 'blocked' if not initialized or isinstance(exc,(TimeoutError,ConnectionError,FileNotFoundError)) else 'failed'
        result['failure'] = locate(exc)
    finally:
        try:
            if initialized:
                probe.cleanup()
            else:
                if hasattr(probe,'relay'): probe.relay.close()
                # Constructor performs no Engine writes. Remove only its exact
                # new owned scratch tree; do not inventory a daemon on failure.
                if args.runtime.exists(): shutil.rmtree(args.runtime)
                args.runtime.mkdir(mode=0o700)
                result['cleanup'] = {'initialization_only':True,'private_paths_absent':True}
        except Exception as exc:
            result['status'] = 'failed'; result['cleanup_failure'] = locate(exc)
            if hasattr(probe,'relay'):
                try: probe.relay.close()
                except Exception: pass
        result['finished_at'] = utc()
        if initialized:
            if result['status'] == 'pass':
                try:
                    # Validate the public projection exactly as the independent
                    # verifier will, before returning success to a workflow.
                    probe.save(); (case_verifier or verify_case)(json.loads((args.runtime/'receipt.json').read_text()))
                except Exception as exc:
                    result['status'] = 'failed'; result['verification_failure'] = locate(exc)
            try:
                probe.save()
            except Exception as exc:
                result['status'] = 'failed'
                safe = {'schema':1,'case':case,'status':'failed','source_sha256':args.expected_source_sha256,
                        'image_id':args.expected_image_id,'evidence_failure':locate(exc),'full_plan_acceptance_pass':False}
                (args.runtime/'receipt.json').write_text(json.dumps(safe,indent=2)+'\n')
        else:
            (args.runtime/'receipt.json').write_text(json.dumps(result,indent=2)+'\n')
    return {'case':case,'status':result['status']}


def select_cases(selected):
    values = list(selected) if selected else list(CASES)
    if len(values) != len(set(values)) or not set(values).issubset(CASES): raise ValueError('invalid/duplicate fault case selection')
    return values


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--socket', type=Path, required=True)
    parser.add_argument('--runtime', type=Path, required=True)
    parser.add_argument('--source', type=Path)
    parser.add_argument('--image')
    parser.add_argument('--expected-image-id')
    parser.add_argument('--expected-source-sha256')
    parser.add_argument('--exclusive-hosted-daemon', action='store_true')
    parser.add_argument('--preflight-only', action='store_true')
    parser.add_argument('--case', action='append', choices=CASES, help='diagnostic subset; omitted means every named fault gate')
    args = parser.parse_args(argv)
    if (os.environ.get('GITHUB_ACTIONS') != 'true' or
            os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted' or
            os.geteuid() != 0 or not args.exclusive_hosted_daemon):
        parser.error('requires root on an explicitly exclusive GitHub-hosted VM; local/shared use refused')
    selected = select_cases(args.case)
    engine = Engine(args.socket); info = engine.call('GET','/info')
    require_hosted_daemon(os.environ,os.geteuid(),args.exclusive_hosted_daemon,info,engine.call('GET','/containers/json?all=true'))
    if args.preflight_only:
        print(json.dumps({'daemon':info['ID'],'rootful':True,'cgroup_version':'2','existing_containers':0}))
        return 0
    if not all((args.source,args.image,args.expected_image_id,args.expected_source_sha256)):
        parser.error('explicit source/image and exact source/image binding required')
    if args.expected_source_sha256 != FROZEN_SOURCE or fingerprint(args.source) != args.expected_source_sha256:
        parser.error('frozen reviewed source binding differs')
    if not re.fullmatch('sha256:[a-f0-9]{64}',args.expected_image_id): parser.error('literal full candidate image ID required')
    if engine.call('GET','/images/'+quote(args.image,safe='')+'/json')['Id'] != args.expected_image_id:
        parser.error('ordinary candidate image differs from exact binding')
    temporary = Path(os.environ['RUNNER_TEMP']).resolve(); runtime = args.runtime.resolve()
    if runtime == temporary or not runtime.is_relative_to(temporary) or runtime.exists(): parser.error('runtime must be a fresh child of RUNNER_TEMP')
    if max(len(str(relay_path(runtime/name,name)).encode()) for name in selected) >= 104:
        parser.error('runtime is too deep for an inherited Unix socket; use a short RUNNER_TEMP child')
    os.sched_setaffinity(0,{0,1}); runtime.mkdir(mode=0o700)
    rows = []
    for name in selected:
        scoped = copy.copy(args); scoped.runtime = runtime/name
        row = run_case(scoped,name); rows.append(row)
        print(json.dumps(row),flush=True)
        # A cleanup failure stops subsequent fixtures, never leaves them racing
        # a quarantine/unknown Engine teardown. Other gates retain blocked rows.
        receipt = json.loads((scoped.runtime/'receipt.json').read_text())
        if receipt.get('cleanup_failure'): break
    complete = len(rows) == len(CASES) and {r['case'] for r in rows} == set(CASES) and all(r['status'] == 'pass' for r in rows)
    report = {'schema':1,'source_sha256':args.expected_source_sha256,'image_id':args.expected_image_id,'daemon':info['ID'],
              'cases':rows,'fault_acceptance_pass':complete,'full_plan_acceptance_pass':False,'finished_at':utc(),
              'scope':'current workflow Compose/local fault boundaries; not Swarm/S3/capacity or the full PLAN'}
    if complete:
        try:
            verify_report(report,[json.loads((runtime/r['case']/'receipt.json').read_text()) for r in rows])
        except Exception as exc:
            report['fault_acceptance_pass'] = False; report['verification_failure'] = failure_location(exc)
    (runtime/'hosted-faults.json').write_text(json.dumps(report,indent=2)+'\n')
    if any(r['status'] == 'failed' for r in rows) or report.get('verification_failure'): return 1
    if any(r['status'] == 'blocked' for r in rows) or len(rows) != len(selected): return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
