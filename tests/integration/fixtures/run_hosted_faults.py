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
import threading
import hashlib
import secrets
import shutil
import time
from pathlib import Path
from urllib.parse import urlsplit, quote
from run_resource_probe import Engine, PG, utc, worker_owned
from run_compose_pg_acceptance import ComposeProbe, fingerprint
from verify_hosted_faults import CASES, CREATE_GAPS, verify_case, verify_report
from run_hosted_acceptance import require_hosted_daemon, failure_location
from run_hosted_capacity import CapacityEngine

FROZEN_SOURCE = '6a592fcf1159d301bbe9acf0ff82e3e681913de4d1fb6f17ccc2d05c9d394ef8'


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

    def worker_proof(self, obj, owner):
        if (not worker_owned(obj, owner, self.image, self.daemon) or
                obj['Config'].get('Cmd') != ['_workflow'] or
                obj['Config'].get('Entrypoint') != ['/usr/local/bin/bakabel'] or
                obj['HostConfig'].get('NanoCpus') != 2000000000 or
                obj['HostConfig'].get('Memory') != 536870912):
            raise ValueError('ordinary worker identity or default limits changed')
        proof = {'container_id': obj['Id'], 'run_id': owner['runID'], 'image_id': obj['Image'],
                 'nanocpus': 2000000000, 'memory_bytes': 536870912,
                 'socket': socket_binding_proof(obj['Mounts'], self.sock)}
        if obj['State']['Running']:
            self.pin_container(obj['Id'])
            try:
                cgroup = self.cgroup(obj['State']['Pid'])
                if cgroup is None or obj['Id'] not in str(cgroup):
                    raise FileNotFoundError('exact worker cgroup unavailable')
                kernel = {'cpu.max': (cgroup/'cpu.max').read_text().strip(),
                          'memory.max': (cgroup/'memory.max').read_text().strip(),
                          'memory.peak': int((cgroup/'memory.peak').read_text().strip())}
            except (FileNotFoundError, ProcessLookupError):
                # Engine Running/Pid is a snapshot: the exact worker may have
                # exited before /proc or cgroup readback. Only a second exact
                # absent/stopped readback resolves that race. Never suppress a
                # still-live failure, even if an earlier limits proof exists.
                terminal = self.e.inspect(obj['Id'], missing=True)
                if terminal is None: return proof
                if terminal['State']['Running'] is not False:
                    raise ValueError('exact worker cgroup unavailable') from None
                return self.worker_proof(terminal, owner)
            if kernel['cpu.max'] != '200000 100000' or kernel['memory.max'] != '536870912':
                raise ValueError('kernel worker limits differ from ordinary defaults')
            proof.update(kernel)
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

    def logs(self, cid):
        text = super().logs(cid)
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
            self.wait(lambda: self.owner() is None, 45, 'fresh CLI terminal recovery')
            self.stop(scheduler)
            self.result['fresh_cli_recovery'] = True
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
            obj = self.e.call('GET','/volumes/'+quote(name,safe=''),missing=True)
            if obj is not None and (obj.get('Name') != name or
                    (obj.get('Labels') or {}).get('probe.bakabel.owner') != self.prefix or
                    obj.get('Driver') != 'local' or obj.get('Options')):
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
        retained = self.owner() is not None
        self.result['relay'] = self.relay.snapshot()
        self.relay.close()
        for name in ('private','backend','fresh-state'):
            shutil.rmtree(self.root/name)
        if not retained: shutil.rmtree(self.root/'state')
        self.result['cleanup'] = {'containers_absent':absent,'volumes_absent':volabsent,'private_paths_absent':not (self.root/'private').exists(),
                                  'quarantine_state_retained':retained,'source_removed_only_after_gate':True}
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
    def __init__(self):
        self.header = bytearray(); self.left = 0; self.stream = 0; self.stdout = 0

    def feed(self, data):
        view = memoryview(data)
        while view:
            if not self.left:
                n = min(8-len(self.header), len(view))
                self.header.extend(view[:n]); view = view[n:]
                if len(self.header) < 8: break
                if self.header[0] not in (0, 1, 2) or self.header[1:4] != b'\0\0\0':
                    raise ValueError('not a Docker multiplex stream')
                self.stream = self.header[0]
                self.left = int.from_bytes(self.header[4:8], 'big'); self.header.clear()
                if not self.left: continue
            n = min(self.left, len(view)); self.left -= n; view = view[n:]
            if self.stream == 1: self.stdout += n


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


class FaultRelay:
    """Byte-preserving, bounded Unix transport. Never generates HTTP replies.

    Ephemeral request parsing is classification only; bodies/Env/argv/stream
    content are never recorded. Not related to cli_relay's nested CPU rewrite.
    """
    def __init__(self, path, target):
        self.path = Path(path)
        self.target = str(target)
        self.lock = threading.RLock()
        self.records = []
        self.errors = []
        self.connections = set()
        self.execs = {}
        self.workers = set()
        self.rule = None
        self.denied_exec = None
        self.hit = threading.Event()
        self.observer = None
        relay = self
        class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
            daemon_threads = True
            def handle_error(self, *args):
                with relay.lock:
                    relay.errors.append('handler error')
        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                relay.handle(self.request)
        self.server = Server(str(path), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def start(self):
        self.path.chmod(0o600)
        self.thread.start()

    def arm(self, boundary, action, *, after_stdout=65536, deny_status=False):
        if boundary not in ('worker-create', 'worker-start', 'dump-create', 'dump-start', 'restore-create', 'restore-start') or action not in ('response-loss', 'stream-drop'):
            raise ValueError('unsupported transport boundary')
        if action == 'stream-drop' and (boundary != 'dump-start' or after_stdout < 1):
            raise ValueError('stream drop requires positive dump stdout threshold')
        with self.lock:
            if self.rule is not None: raise ValueError('fault already armed')
            self.rule = {'boundary': boundary, 'action': action, 'after_stdout': after_stdout, 'deny_status': deny_status}
            self.hit.clear()

    def status_allowed(self, eid):
        with self.lock:
            return eid != self.denied_exec

    def recover_transport(self):
        with self.lock:
            self.denied_exec = None
            self.rule = None

    def classify(self, method, path, body):
        path = re.sub(r'^/v[0-9.]+', '', urlsplit(path).path)
        record = {'method': method, 'boundary': 'other', 'forwarded': False}
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
            if operation == 'start' and eid in self.execs:
                record['boundary'] = self.execs[eid]['kind']+'-start'
                record['container_id'] = self.execs[eid]['container_id']
            if operation == 'json' and method == 'GET' and not self.status_allowed(eid):
                record['fault'] = 'status-transport-refused'
        return record

    def snapshot(self):
        with self.lock:
            return copy.deepcopy({'records': self.records, 'errors': self.errors, 'execs': self.execs, 'workers':sorted(self.workers), 'denied_exec': self.denied_exec})

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        with self.lock:
            for conn in list(self.connections):
                try: conn.shutdown(socket.SHUT_RDWR)
                except OSError: pass
        self.thread.join(3)
        self.path.unlink(missing_ok=True)

    def handle(self, front):
        while self.exchange_one(front):
            pass

    def exchange_one(self, front):
        back = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        front.settimeout(180); back.settimeout(180)
        with self.lock:
            self.connections.update((front, back))
        try:
            head, line, headers = read_headers(front)
            method, path, _ = line.split(' ')
            if headers.get('transfer-encoding'):
                raise ValueError('chunked requests not admitted')
            n = int(headers.get('content-length', 0))
            if n < 0 or n > 2*1024*1024:
                raise ValueError('request body limit')
            body = read_exact(front, n)
            with self.lock:
                record = self.classify(method, path, body)
                if len(self.records) >= 12000: raise ValueError('bounded relay record limit')
                self.records.append(record)
                if record.get('fault') == 'status-transport-refused': return
                rule = None
                if self.rule and self.rule['boundary'] == record['boundary']:
                    rule = self.rule; self.rule = None
            if self.observer: self.observer('request',record)
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
                        record['exec_id'] = identity
                        self.execs[identity] = {'kind': record['boundary'].removesuffix('-create'), 'container_id': record['container_id'], 'stdout_bytes': 0, 'stdin_bytes': 0}
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
            counter = FrameCounter()
            def forward(src, dst, data):
                dst.sendall(data)
                if eid:
                    with self.lock:
                        if src is back:
                            counter.feed(data)
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
                            trailer = line(); front.sendall(trailer); trailer_bytes += len(trailer)
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
        except (BrokenPipeError, ConnectionResetError, EOFError):
            pass
        except Exception as exc:
            with self.lock:
                self.errors.append(type(exc).__name__)
        finally:
            with self.lock:
                self.connections.discard(front); self.connections.discard(back)
            back.close()


def run_case(args, case, probe_class=None):
    if args.runtime.exists(): raise ValueError('case runtime must be fresh')
    cls = probe_class or FaultProbe
    probe = cls.__new__(cls); initialized = False
    result = {'schema':1,'case':case,'status':'blocked','source_sha256':args.expected_source_sha256,'image_id':args.expected_image_id,'full_plan_acceptance_pass':False}
    try:
        probe.__init__(args,case); initialized = True; result = probe.result
        probe.run(); result['status'] = 'pass'
    except Exception as exc:
        result['status'] = 'blocked' if not initialized or isinstance(exc,(TimeoutError,ConnectionError,FileNotFoundError)) else 'failed'
        result['failure'] = failure_location(exc)
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
            result['status'] = 'failed'; result['cleanup_failure'] = failure_location(exc)
            if hasattr(probe,'relay'):
                try: probe.relay.close()
                except Exception: pass
        result['finished_at'] = utc()
        if initialized:
            if result['status'] == 'pass':
                try:
                    # Validate the public projection exactly as the independent
                    # verifier will, before returning success to a workflow.
                    probe.save(); verify_case(json.loads((args.runtime/'receipt.json').read_text()))
                except Exception as exc:
                    result['status'] = 'failed'; result['verification_failure'] = failure_location(exc)
            try:
                probe.save()
            except Exception as exc:
                result['status'] = 'failed'
                safe = {'schema':1,'case':case,'status':'failed','source_sha256':args.expected_source_sha256,
                        'image_id':args.expected_image_id,'evidence_failure':failure_location(exc),'full_plan_acceptance_pass':False}
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
        parser.error('frozen R3 source binding differs')
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
