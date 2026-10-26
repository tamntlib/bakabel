#!/usr/bin/env python3
"""Fail-closed, offline verifier for current-workflow hosted fault receipts.

PASS is only this named Compose/local fault suite, never the entire PLAN.
Expected permanent create-gap quarantine is a safety PASS, NOT recovered work.
"""
import argparse
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
    if name in CREATE_GAPS:
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
