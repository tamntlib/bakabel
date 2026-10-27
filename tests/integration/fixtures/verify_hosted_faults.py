#!/usr/bin/env python3
"""Fail-closed, offline verifier for current-workflow hosted fault receipts.

PASS is only this named Compose/local fault suite, never the entire PLAN.
Expected permanent create-gap quarantine is a safety PASS, NOT recovered work.
"""
import argparse
import hashlib
import json
import math
from pathlib import Path
import re

CASES = (
    'producer-failure-after-output',
    'streaming-worker-SIGKILL',
    'docker-stream-drop',
    'docker-stream-drop-status-unavailable-recovery',
    'worker-create-response-loss',
    'worker-start-response-loss',
    'dump-create-response-loss',
    'dump-start-response-loss',
    'restore-create-response-loss',
    'restore-start-response-loss',
    'backup-vs-restore-and-retention',
    'scheduler-restart-original-deadline',
    'dump-persisted-before-start-worker-SIGKILL',
    'restore-active-import-worker-SIGKILL',
)
CREATE_GAPS = ('dump-create-response-loss', 'restore-create-response-loss')
STREAMING = ('producer-failure-after-output', 'streaming-worker-SIGKILL', 'docker-stream-drop', 'docker-stream-drop-status-unavailable-recovery')


def demand(condition, reason):
    if not condition:
        raise ValueError(reason)


def verify_case(row):
    name = row.get('case')
    demand(name in CASES and row.get('status') == 'pass' and row.get('exercised') is True, 'fault case not exercised/passed')
    demand(row.get('ordinary_image') is True and row.get('request_mutations') == [], 'ordinary image/request preservation missing')
    demand(row.get('backend') == 'local' and row.get('platform') == 'compose' and row.get('source_unchanged') is True, 'scope or source online identity missing')
    demand(bool(row.get('daemon')) and re.fullmatch('[a-f0-9]{64}', row.get('source_sha256','')) and re.fullmatch('sha256:[a-f0-9]{64}', row.get('image_id','')), 'exact build/daemon binding missing')
    workers = row.get('workers', {})
    demand(isinstance(workers, dict) and bool(workers), 'no exact ordinary worker readback')
    for cid, worker in workers.items():
        demand(re.fullmatch('[a-f0-9]{64}', cid) and worker.get('container_id') == cid and worker.get('image_id') == row['image_id'], 'worker identity mismatch')
        demand(worker.get('memory_bytes') == 536870912 and worker.get('nanocpus') == 2000000000, 'ordinary worker limits changed')
        binding = worker.get('socket', {})
        demand(binding.get('read_only') is True and binding.get('destination') == '/run/bakabel/docker.sock' and str(binding.get('source','')).endswith('/relay.sock'), 'worker bypasses relay')
    cleanup = row.get('cleanup', {})
    for key in ('containers_absent', 'volumes_absent'):
        mapping = cleanup.get(key, {})
        demand(isinstance(mapping, dict) and bool(mapping) and all(value is True for value in mapping.values()), 'exact owned cleanup missing')
    demand(cleanup.get('private_paths_absent') is True, 'credential cleanup missing')
    proof = row.get('proof', {})
    if name == 'dump-persisted-before-start-worker-SIGKILL':
        verify_persisted_start(row)
    elif name == 'restore-active-import-worker-SIGKILL':
        verify_import_kill(row)
    elif name in CREATE_GAPS:
        demand(proof.get('outcome') == 'quarantined', 'create gap incorrectly claimed recovered')
        for key in ('owner_retained','fresh_cli_blocked','exec_never_started','fault_forwarded'):
            demand(proof.get(key) is True, 'unknown create ownership not retained')
        demand(proof.get('actual_response_status') == 201 and proof.get('persisted_exec_id') is False, 'create response loss not proved')
    else:
        demand(proof.get('owner_released') is True, 'terminal ownership not released')
        if name == 'backup-vs-restore-and-retention':
            demand(proof.get('outcome') == 'complete-after-overlap-refusal' and proof.get('restore_cli_exit') == 1 and proof.get('retention_run_exit') == 1, 'public overlap refusals missing')
            for key in ('same_owner','target_unchanged','no_new_worker'):
                demand(proof.get(key) is True, 'overlap changed ownership or target')
        else:
            demand(proof.get('outcome') == 'failed' and proof.get('worker_absent') is True, 'failed workflow falsely succeeded or left worker')
        terminal = proof.get('terminal', {})
        if name in ('worker-create-response-loss','worker-start-response-loss'):
            source = row.get('source',{})
            run = row.get('injection',{}).get('owner_checkpoint',{}).get('runID','')
            demand(re.fullmatch('[a-f0-9]{32}',run) and terminal.get('run_id') == run and
                   terminal.get('daemon') == row['daemon'] and re.fullmatch('[a-f0-9]{64}',terminal.get('container_id','')) and
                   terminal.get('container_id') == source.get('container_id') and bool(terminal.get('started_at')) and
                   terminal.get('started_at') == source.get('started_at'), 'exact launch source/run terminal identity missing')
            demand(all(type(terminal.get(key)) is int and terminal[key] == 0 for key in ('sessions','processes')), 'launch source session/process proof missing')
            execs = terminal.get('execs')
            records = row.get('relay',{}).get('records')
            demand(isinstance(execs,dict) and isinstance(records,list), 'recorded launch exec proof missing')
            expected = set()
            for record in records:
                if (record.get('owner_checkpoint',{}).get('runID') == run and
                        record.get('boundary') in ('dump-create','dump-start') and record.get('forwarded')):
                    eid = record.get('exec_id','')
                    demand(re.fullmatch('[a-f0-9]{64}',eid) and record.get('container_id') == source['container_id'], 'recorded launch exec identity mismatch')
                    expected.add(eid)
            demand(set(execs) == expected and all(type(code) is int and code >= 0 for code in execs.values()), 'recorded launch exec terminal status missing')
        else:
            demand(terminal.get('daemon') == row['daemon'] and re.fullmatch('[a-f0-9]{64}',terminal.get('exec_id','')) and re.fullmatch('[a-f0-9]{64}',terminal.get('container_id','')) and bool(terminal.get('started_at')), 'exact source terminal identity missing')
            demand(type(terminal.get('exec_exit_code')) is int and terminal['exec_exit_code'] >= 0 and terminal.get('sessions') == 0 and terminal.get('processes') == 0, 'source status/session/process proof missing')
        if name != 'backup-vs-restore-and-retention':
            demand(proof.get('last_success_unchanged') is True and proof.get('no_complete_snapshot') is True, 'failure refreshed success or committed complete snapshot')
        if name in STREAMING:
            demand(any(w.get('cpu.max') == '200000 100000' and w.get('memory.max') == '536870912' for w in workers.values()), 'no real kernel worker limits readback')
            count = row.get('injection',{}).get('stdout_bytes_before_fault',proof.get('stdout_bytes',0))
            demand(type(count) is int and count >= 65536, 'no partial source stdout before streaming fault')
        if name.endswith('-response-loss') or name.startswith('docker-stream-drop'):
            demand(proof.get('fault_forwarded') is True and proof.get('actual_response_status') in (101,200,201,204), 'fault did not follow actual Engine response')
        if name == 'docker-stream-drop-status-unavailable-recovery':
            demand(row.get('quarantine_retained_before_recovery') is True and row.get('fresh_cli_recovery') is True, 'unavailable exact status not quarantined/recovered by fresh CLI')
        if name == 'scheduler-restart-original-deadline':
            for key in ('same_job_bytes','same_worker'):
                demand(proof.get(key) is True, 'scheduler restart changed durable job/worker')
            deadline = proof.get('deadline_epoch'); observed = proof.get('observed_terminal_epoch')
            alive = proof.get('alive_until_epoch'); delta = proof.get('seconds_after_original_deadline')
            restarts = proof.get('scheduler_restart_epochs')
            demand(proof.get('scheduler_restarts') == 2 and proof.get('original_timeout_seconds') == 90 and
                   isinstance(restarts,list) and len(restarts) == 2, 'original timeout/restart measurements missing')
            demand(all(type(value) in (int,float) and math.isfinite(value) for value in [deadline,observed,alive,delta,*restarts]), 'invalid original deadline measurement')
            demand(deadline-30 <= restarts[0] <= deadline-20 and deadline-15 <= restarts[1] <= deadline-5 and
                   restarts[0] < restarts[1] <= alive, 'restarts not observed near original deadline')
            # The +10s cap is strictly smaller than either restart's >=60s
            # deadline-renewal shift, unlike the former 18s timeout/+25s cap.
            demand(deadline-2 <= alive <= observed <= deadline+10 and
                   abs(delta-(observed-deadline)) < .000001, 'early terminal or extended original deadline')


def verify_persisted_start(row):
    # This is retained authorization with a nullable unstarted exec, NOT a
    # create-ID gap, successful terminal exit, release or production fencing.
    proof = row['proof']; relay = row.get('relay',{}); injection = row.get('injection',{})
    owner = injection.get('owner_checkpoint',{}); workers = row['workers']; cleanup = row['cleanup']
    demand(proof.get('outcome') == 'quarantined', 'persisted start must remain quarantined')
    for key in ('owner_retained','fresh_cli_blocked','exec_never_started','persisted_exec_id',
                'last_success_unchanged','last_result_unchanged','no_complete_snapshot'):
        demand(proof.get(key) is True, 'persisted start safety proof missing')
    demand(proof.get('fault_forwarded') is False and not proof.get('owner_released') and
           not proof.get('worker_absent') and 'terminal' not in proof and 'actual_response_status' not in proof and
           not row.get('fresh_cli_recovery'), 'unstarted exec falsely claimed terminal/recovered')
    demand(all(type(proof.get(k)) is int and proof[k] == 1 for k in ('cli_exit','fresh_cli_exit')), 'public nonzero CLI proof missing')
    demand(owner.get('phase') == 'exec_started' and owner.get('status') == 'active' and
           owner.get('execKind') == 'dump' and owner.get('workerStartAuthorized') is True and
           owner.get('daemonID') == row['daemon'] and isinstance(owner.get('runID'),str) and re.fullmatch('[a-f0-9]{32}',owner['runID']),
           'durable start authorization missing')
    for key in ('workerContainerID','sourceContainerID','execID','targetID'):
        demand(isinstance(owner.get(key),str) and re.fullmatch('[a-f0-9]{64}',owner[key]), 'durable exact identity missing')
    demand(owner.get('workerName') == 'bakabel-worker-'+owner['runID'] and bool(owner.get('sourceStartedAt')), 'worker/source durable identity missing')
    cid = owner['workerContainerID']; eid = owner['execID']; source = row.get('source',{})
    demand(relay.get('denied_start') == eid, 'exact exec start denial not retained through cleanup')
    demand(source.get('container_id') == owner['sourceContainerID'] and source.get('started_at') == owner['sourceStartedAt'] and
           type(source.get('restart_count')) is int and source['restart_count'] >= 0, 'source incarnation binding missing')
    demand(cid in workers and workers[cid].get('run_id') == owner['runID'] and
           workers[cid].get('cpu.max') == '200000 100000' and workers[cid].get('memory.max') == '536870912', 'exact default worker kernel proof missing')
    keys = ('runID','daemonID','workerContainerID','workerName','workerStartAuthorized','targetID','sourceContainerID','sourceStartedAt','execID','execKind')
    for key in ('owner_before_kill','owner_after_kill','owner_quarantine','owner_fresh'):
        observed = proof.get(key,{})
        demand(all(observed.get(k) == owner[k] for k in keys), 'persisted identity changed across kill/restart')
        if key in ('owner_quarantine','owner_fresh'):
            demand(observed.get('phase') == 'quarantine' and observed.get('status') == 'blocked', 'fresh scheduler quarantine missing')
    demand(proof['owner_before_kill'] == owner, 'prekill checkpoint not identical to held authorization')
    records = relay.get('records')
    demand(isinstance(records,list) and 2 <= len(records) <= 12000 and relay.get('errors') == [], 'bounded relay proof missing')
    held = [r for r in records if r.get('fault') == 'hold-before-forward']
    creates = [r for r in records if r.get('boundary') == 'dump-create' and r.get('exec_id') == eid]
    demand(len(held) == len(creates) == 1, 'unique actual create and held start missing')
    held = held[0]; created = creates[0]
    demand(created.get('producer_contract') == 'wrapped-dump-v1' and created.get('producer_run_id') == owner['runID'] and
           created.get('command_sha256') == held.get('command_sha256'), 'exact wrapped create command binding missing')
    demand(records.index(created) < records.index(held) and created.get('method') == 'POST' and created.get('forwarded') is True and
           type(created.get('status')) is int and created['status'] == 201 and created.get('container_id') == owner['sourceContainerID'], 'real create/201 before hold missing')
    create_owner = created.get('owner_checkpoint',{})
    demand(create_owner.get('phase') == 'creating_exec' and not create_owner.get('execID') and
           all(create_owner.get(k) == owner[k] for k in keys if k != 'execID'), 'create checkpoint not bound to persisted exec')
    demand(held.get('exec_id') == eid and held.get('container_id') == owner['sourceContainerID'],
           'held start not bound to durable exec/source')
    demand(injection == {**held,'hold_state':'held'} and held.get('hold_state') == 'discarded' and
           held.get('boundary') == 'dump-start' and held.get('method') == 'POST' and held.get('forwarded') is False and
           'status' not in held and type(held.get('held_bytes')) is int and 0 < held['held_bytes'] <= 65536+4096 and
           held.get('producer_contract') == 'wrapped-dump-v1' and re.fullmatch('[a-f0-9]{64}',held.get('command_sha256','')),
           'bounded unforwarded discard proof missing')
    for record in records:
        # Only the uniquely verified, causally prior create may carry a returned
        # exec ID without being a start/inspect. Labels alone grant no exemption;
        # a same-run worker launch has no exec ID and is not an exec operation.
        if (record is not created and
                ('exec_id' in record or record.get('boundary') in ('dump-start','restore-start') or
                 record.get('fault') in ('hold-before-forward','start-transport-refused')) and
                (record.get('exec_id') == eid or record.get('owner_checkpoint',{}).get('runID') == owner['runID'] or
                 record.get('command_sha256') == held['command_sha256'])):
            if record.get('method') == 'GET':
                demand(record.get('boundary') == 'other' and 'hold_state' not in record and
                       ((record.get('forwarded') is True and type(record.get('status')) is int and
                         record['status'] == 200 and record.get('fault') is None) or
                        (record.get('forwarded') is False and 'status' not in record and
                         record.get('fault') == 'status-transport-refused')), 'correlated exec inspect contradicts method/response')
                continue
            demand(record.get('method') == 'POST' and record.get('boundary') == 'dump-start' and
                   record.get('exec_id') == eid and record.get('container_id') == owner['sourceContainerID'],
                   'correlated start not bound to durable exec/source')
            demand(record.get('forwarded') is False and 'status' not in record and
                   record.get('fault') in ('hold-before-forward','start-transport-refused'), 'exact start forwarded or answered')
    execution = relay.get('execs',{}).get(eid,{})
    demand(execution.get('kind') == 'dump' and execution.get('container_id') == owner['sourceContainerID'] and
           all(type(execution.get(k)) is int and execution[k] == 0 for k in ('stdin_bytes','stdout_bytes')), 'unstarted exec stream bytes observed')
    observations = proof.get('exec_observations')
    demand(isinstance(observations,list) and len(observations) == 3, 'prekill/postkill/fresh nullable observations missing')
    for obj in observations:
        demand(obj.get('daemon') == row['daemon'] and obj.get('container_id') == owner['sourceContainerID'] and
               type(obj.get('restart_count')) is int and obj['restart_count'] == source['restart_count'] and
               obj.get('started_at') == owner['sourceStartedAt'] and obj.get('exec_id') == eid and
               obj.get('command_sha256') == held['command_sha256'] and obj.get('running') is False and
               'exit_code' in obj and obj['exit_code'] is None and obj.get('exit_state') in ('null','absent') and
               all(type(obj.get(k)) is int and obj[k] == 0 for k in ('pid','sessions','processes')), 'exact nullable-unstarted proof missing')
    observed_workers = proof.get('worker_observations')
    demand(isinstance(observed_workers,list) and len(observed_workers) == 3, 'worker kill readbacks missing')
    for index, obj in enumerate(observed_workers):
        demand(obj.get('container_id') == cid, 'kill targeted wrong worker')
        if index == 0:
            demand(obj.get('running') is True and type(obj.get('pid')) is int and obj['pid'] > 0, 'prekill worker not live')
        else:
            demand(obj.get('running') is False and type(obj.get('pid')) is int and obj['pid'] == 0 and
                   type(obj.get('exit_code')) is int and obj['exit_code'] == 137, 'worker not observed terminal 137')
    before = proof.get('workers_before_fresh'); after = proof.get('workers_after_fresh')
    demand(isinstance(before,list) and cid in before and len(before) == len(set(before)) and
           before == after == relay.get('workers') and set(before) == set(workers), 'fresh scheduler created replacement worker')
    demand(proof.get('events') == ['persisted-start-held','prekill-checked','worker-kill-requested','worker-terminal-137',
           'start-discarded','quarantine-retained','fresh-scheduler-quarantine','source-online-before-cleanup','owned-cleanup'], 'kill/discard/quarantine/cleanup ordering missing')
    demand(cleanup.get('quarantine_state_retained') is True and cleanup.get('source_removed_only_after_gate') is True and
           cleanup['containers_absent'].get(cid) is True and cleanup['containers_absent'].get(owner['sourceContainerID']) is True,
           'cleanup cannot substitute for safe quarantine')


def verify_nonforce_remove(record):
    # RemoveWorker sends DELETE with NO query (worker_remove.go:19); force and
    # volume removal therefore both default false. Retain explicit canonical
    # booleans if present, but never infer safety from a path-only label.
    query = record.get('remove_query')
    demand(record.get('method') == 'DELETE' and isinstance(query,str) and
           record.get('remove_query_valid') is True, 'valid removal query evidence missing')
    options = {}
    for item in query.split('&') if query else ():
        match = re.fullmatch(r'(force|v)=(true|false)',item)
        demand(match is not None and match[1] not in options, 'malformed/duplicate removal query')
        options[match[1]] = match[2] == 'true'
    demand(record.get('remove_force') is False and options.get('force',False) is False and
           type(record.get('remove_volumes')) is bool and record['remove_volumes'] is options.get('v',False),
           'forced or contradictory removal query')


def verify_import_kill(row):
    proof = row.get('proof',{}); injection = row.get('injection',{})
    observed = injection.get('active_import',{}); owner = observed.get('owner',{})
    target = observed.get('target',{}); session = observed.get('session',{})
    token = owner.get('importRunID',''); cid = owner.get('workerContainerID',''); eid = owner.get('execID','')
    demand(re.fullmatch('[a-f0-9]{32}',owner.get('runID','')) and re.fullmatch('restore_[a-f0-9]{48}',token) and
           token != owner['runID'] and owner.get('execKind') == 'restore' and owner.get('phase') == 'exec_started' and
           owner.get('status') == 'active' and owner.get('workerStartAuthorized') is True and owner.get('daemonID') == row['daemon'],
           'independent durable import identity missing')
    for key in ('workerContainerID','sourceContainerID','execID','targetID'):
        demand(re.fullmatch('[a-f0-9]{64}',owner.get(key,'')), 'exact import/worker checkpoint missing')
    demand(owner.get('workerName') == 'bakabel-worker-'+owner['runID'] and bool(owner.get('sourceStartedAt')) and
           target.get('container_id') == owner['sourceContainerID'] and target.get('started_at') == owner['sourceStartedAt'] and
           type(target.get('restart_count')) is int and target['restart_count'] >= 0 and
           target['container_id'] != row.get('source',{}).get('container_id'), 'independent target incarnation missing')
    demand(type(observed.get('exec_pid')) is int and observed['exec_pid'] > 0 and
           type(observed.get('processes')) is int and observed['processes'] == 1 and
           type(session.get('pid')) is int and session['pid'] > 0 and bool(session.get('backend_start')) and
           session.get('application_name') == token and session.get('datname') == 'fixture' and session.get('usename') == 'postgres' and
           session.get('state') == 'active' and session.get('wait_event') == 'PgSleep' and session.get('copy_active') is True,
           'live import COPY/session/process missing; reader progress is insufficient')
    worker = row['workers'].get(cid,{})
    demand(worker.get('run_id') == owner['runID'] and worker.get('cpu.max') == '200000 100000' and
           worker.get('memory.max') == '536870912', 'exact killed ordinary worker kernel proof missing')
    prekill = injection.get('worker_before_kill',{})
    demand(prekill.get('container_id') == cid and prekill.get('running') is True and
           type(prekill.get('pid')) is int and prekill['pid'] > 0, 'fresh prekill worker identity missing')
    demand(re.fullmatch('[a-f0-9]{64}',injection.get('snapshot_id','')) and
           re.fullmatch('[a-f0-9]{64}',injection.get('controller_id','')) and injection['controller_id'] != cid,
           'trusted snapshot and independent public controller binding missing')
    for key in ('owner_released','worker_absent','last_success_unchanged'):
        demand(proof.get(key) is True, 'failed import ownership/result safety missing')
    demand(proof.get('outcome') == 'failed' and type(proof.get('cli_exit')) is int and proof['cli_exit'] == 1 and
           proof.get('recovery_boundary') == 'original public restore CLI controller, independent of killed worker', 'public CLI recovery boundary missing')
    terminal = proof.get('terminal',{})
    demand(terminal.get('daemon') == row['daemon'] and terminal.get('container_id') == target['container_id'] and
           terminal.get('started_at') == target['started_at'] and terminal.get('exec_id') == eid and
           terminal.get('import_run_id') == token and type(terminal.get('exec_exit_code')) is int and terminal['exec_exit_code'] > 0 and
           all(type(terminal.get(k)) is int and terminal[k] == 0 for k in ('sessions','processes')), 'exact nonzero import terminal proof missing')
    partial = proof.get('partial_target',{})
    demand(all(partial.get(k) == target[k] for k in ('container_id','started_at','restart_count')) and
           partial.get('payload_exists') is True and type(partial.get('payload_rows')) is int and partial['payload_rows'] == 0,
           'failed partial destination not retained before cleanup')
    result = proof.get('restore_result',{}); targets = result.get('targets',[])
    # Ground the logical identity in separate public plan and exact complete
    # snapshot readbacks, not in the result or the durable digest under test.
    mapping = injection.get('target_mapping',{}); plan = mapping.get('plan',{})
    snapshot = mapping.get('snapshot',{}); metadata = snapshot.get('metadata',{})
    logical = plan.get('ID'); source = row.get('source',{})
    demand(isinstance(logical,str) and bool(logical) and plan.get('Kind') == 'postgres' and
           plan.get('Source') == {'DaemonID':row['daemon'],'ContainerID':source.get('container_id'),
                                  'StartedAt':source.get('started_at')} and
           re.fullmatch('[a-f0-9]{64}',source.get('container_id','')) and bool(source.get('started_at')),
           'frozen planned logical source identity missing')
    demand(snapshot.get('snapshotID') == injection['snapshot_id'] and snapshot.get('status') == 'complete' and
           snapshot.get('type') == 'postgres' and snapshot.get('source') == logical and
           type(metadata.get('version')) is int and metadata['version'] == 1 and
           metadata.get('kind') == 'postgres' and metadata.get('source') == logical,
           'exact trusted snapshot logical source differs from plan')
    demand(hashlib.sha256(logical.encode('utf-8')).hexdigest() == owner['targetID'],
           'durable target digest differs from trusted logical source')
    demand(result.get('runID') == owner['runID'] and result.get('status') == 'failed' and isinstance(targets,list) and
           len(targets) == 1 and targets[0].get('targetID') == logical and
           targets[0].get('snapshotID') == injection['snapshot_id'] and
           targets[0].get('status') in ('unknown','partial') and targets[0].get('error') == 'restore failed', 'false restored or wrong public restore result')
    relay = row.get('relay',{}); records = relay.get('records')
    demand(isinstance(records,list) and 3 <= len(records) <= 12000 and relay.get('errors') == [], 'bounded actual transport evidence missing')
    def removal_evidence(record):
        # Removal-specific evidence cannot become an inspect/start by changing
        # method or boundary. Field presence matters even when its value is null.
        return (record.get('method') == 'DELETE' or record.get('boundary') == 'worker-remove' or
                any(key.startswith('remove_') or key.endswith('_before_remove') for key in record))

    def correlated_removal(record):
        if record.get('container_id') in (cid,target['container_id']) or record.get('exec_id') == eid:
            return True
        for section in ('owner_checkpoint','owner_before_remove'):
            annotation = record.get(section)
            if isinstance(annotation,dict) and any(annotation.get(key) == owner[key] for key in
                    ('runID','workerContainerID','workerName','sourceContainerID','targetID','execID','importRunID')):
                return True
        for section,identities in (
                ('terminal_before_remove',{'exec_id':eid,'container_id':target['container_id'],
                                          'import_run_id':token,'run_id':owner['runID']}),
                ('worker_before_remove',{'container_id':cid,'run_id':owner['runID']})):
            annotation = record.get(section)
            if isinstance(annotation,dict) and any(annotation.get(key) == value for key,value in identities.items()):
                return True
        return False

    creates = [r for r in records if r.get('boundary') == 'restore-create' and r.get('exec_id') == eid]
    starts = [r for r in records if r.get('boundary') == 'restore-start' and r.get('exec_id') == eid]
    removes = [r for r in records if removal_evidence(r) and correlated_removal(r)]
    demand(len(creates) == len(starts) == len(removes) == 1, 'unique actual import create/start/remove missing')
    created, started, removed = creates[0], starts[0], removes[0]
    demand(removed.get('boundary') == 'worker-remove' and removed.get('container_id') == cid,
           'correlated removal not bound to canonical worker boundary')
    verify_nonforce_remove(removed)
    execution = relay.get('execs',{}).get(eid,{})
    demand(execution.get('kind') == 'restore' and execution.get('container_id') == target['container_id'],
           'durable import not bound to actual relay exec/source')
    for record in records:
        # Removal annotations are semantic evidence, not an exemption from the
        # exec checks below. Actual GET worker inspections have no such fields.
        checkpoint = record.get('owner_checkpoint',{})
        if removal_evidence(record):
            if record.get('container_id') in row['workers']:
                demand(record.get('boundary') == 'worker-remove', 'noncanonical owned worker removal boundary')
                verify_nonforce_remove(record)
            if correlated_removal(record):
                demand(record is removed, 'contradictory correlated worker removal')
        exec_operation = ('exec_id' in record or record.get('boundary') in
                          ('dump-create','dump-start','restore-create','restore-start'))
        correlated = (record.get('exec_id') == eid or checkpoint.get('runID') == owner['runID'] or
                      record.get('container_id') == target['container_id'])
        if not exec_operation or not correlated or record is created or record is started: continue
        demand(record.get('method') == 'GET' and record.get('boundary') == 'other' and
               record.get('exec_id') == eid and record.get('container_id',target['container_id']) == target['container_id'] and
               (not checkpoint or checkpoint == owner) and record.get('forwarded') is True and
               type(record.get('status')) is int and record['status'] == 200 and not record.get('fault'),
               'contradictory correlated import exec operation')
    demand(records.index(created) < records.index(started) < records.index(removed), 'import lifecycle ordering missing')
    for record,method,status in ((created,'POST',201),(started,'POST',101),(removed,'DELETE',204)):
        demand(record.get('method') == method and record.get('forwarded') is True and type(record.get('status')) is int and
               record['status'] == status and not record.get('fault'), 'ordinary actual transport boundary missing')
    keys = ('runID','daemonID','workerContainerID','workerName','workerStartAuthorized','targetID','sourceContainerID','sourceStartedAt','execKind')
    create_owner = created.get('owner_checkpoint',{})
    demand(create_owner.get('phase') == 'creating_exec' and not create_owner.get('execID') and not create_owner.get('importRunID') and
           all(create_owner.get(k) == owner[k] for k in keys) and created.get('container_id') == target['container_id'] and
           started.get('container_id') == target['container_id'] and started.get('owner_checkpoint') == owner and
           removed.get('owner_before_remove') == owner and removed.get('terminal_before_remove') == terminal,
           'import identity/terminal readback not retained before release')
    killed = removed.get('worker_before_remove',{})
    demand(killed.get('container_id') == cid and killed.get('running') is False and type(killed.get('pid')) is int and killed['pid'] == 0 and
           type(killed.get('exit_code')) is int and killed['exit_code'] == 137, 'exact worker not observed killed before removal')
    demand(proof.get('events') == ['active-copy-observed','prekill-rechecked','worker-kill-requested','import-terminal-before-worker-remove',
           'public-restore-failed','partial-target-retained'], 'kill/import terminal/release/partial retention ordering missing')
    demand(all(row['cleanup']['containers_absent'].get(k) is True for k in (cid,target['container_id'],row.get('source',{}).get('container_id'))),
           'exact source/worker/destination cleanup missing')


def verify_report(report, rows):
    demand(report.get('schema') == 1 and report.get('fault_acceptance_pass') is True and report.get('full_plan_acceptance_pass') is False, 'not a complete bounded fault acceptance report')
    names = [row.get('case') for row in rows]
    demand(len(names) == len(CASES) and set(names) == set(CASES) and len(set(names)) == len(names), 'missing/duplicate fault cases')
    demand(report.get('cases') == [{'case':row['case'],'status':row['status']} for row in rows], 'case manifest mismatch')
    for row in rows:
        for key in ('source_sha256','image_id','daemon'):
            demand(row.get(key) == report.get(key), 'case binding drift')
        verify_case(row)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime', type=Path, required=True)
    args = parser.parse_args()
    report = json.loads((args.runtime/'hosted-faults.json').read_text())
    rows = [json.loads((args.runtime/name/'receipt.json').read_text()) for name in CASES]
    verify_report(report, rows)
    print(json.dumps({'fault_acceptance_pass':True, 'cases':len(rows), 'full_plan_acceptance_pass':False}))
