#!/usr/bin/env python3
"""Independent additive F19/F20/F22 receipts; NOT the original 14-case suite."""
import argparse
import hashlib
import json
from pathlib import Path
import re
from verify_hosted_faults import demand, verify_nonforce_remove

F19='temp-pack-ENOSPC'
F20='restore-output-ENOSPC'
F22='restore-missing-extension-binary-prerequisites'
CASES=(F19,F20,F22)


def number(value, minimum=0):
    return type(value) is int and value >= minimum


def same_json(left,right):
    return json.dumps(left,sort_keys=True,separators=(',',':')) == json.dumps(right,sort_keys=True,separators=(',',':'))


def fullid(value):
    return isinstance(value,str) and re.fullmatch('[a-f0-9]{64}',value) is not None


def verify_case(row):
    name=row.get('case')
    demand(name in CASES and row.get('schema') == 1 and row.get('status') == 'pass' and row.get('exercised') is True,'unexercised additive gate')
    demand(row.get('ordinary_image') is True and row.get('request_mutations') == [] and row.get('backend') == 'local' and row.get('platform') == 'compose','ordinary runtime scope changed')
    demand(fullid(row.get('source_sha256')) and re.fullmatch('sha256:[a-f0-9]{64}',row.get('image_id','')) and bool(row.get('daemon')),'build/daemon binding missing')
    source=row.get('source',{})
    demand(fullid(source.get('container_id')) and bool(source.get('started_at')) and number(source.get('restart_count')) and row.get('source_unchanged') is True,'online source incarnation missing')
    workers=row.get('workers'); cleanup=row.get('cleanup',{})
    demand(isinstance(workers,dict) and bool(workers),'worker identity missing')
    for cid,w in workers.items():
        demand(fullid(cid) and w.get('container_id') == cid and w.get('image_id') == row['image_id'] and
            w.get('memory_bytes') == 536870912 and w.get('nanocpus') == 2000000000,'ordinary worker limits/image changed')
        binding=w.get('socket',{})
        demand(binding.get('destination') == '/run/bakabel/docker.sock' and binding.get('read_only') is True and str(binding.get('source','')).endswith('/relay.sock'),'worker socket not bound')
    for key in ('containers_absent','volumes_absent'):
        values=cleanup.get(key)
        demand(isinstance(values,dict) and bool(values) and all(v is True for v in values.values()),'exact cleanup missing')
    demand(cleanup.get('private_paths_absent') is True and cleanup.get('source_removed_only_after_gate') is True and
           cleanup['containers_absent'].get(source['container_id']) is True and all(cleanup['containers_absent'].get(k) is True for k in workers),'cleanup/source ordering missing')
    relay=row.get('relay',{}); records=relay.get('records')
    demand(isinstance(records,list) and 1 <= len(records) <= 12000 and relay.get('errors') == [],'transport evidence missing')
    for record in records:
        removal=(record.get('method') == 'DELETE' or record.get('boundary') == 'worker-remove' or
                 any(k.startswith('remove_') or k.endswith('_before_remove') for k in record))
        if removal:
            demand(record.get('method') == 'DELETE' and record.get('boundary') == 'worker-remove' and
                   record.get('container_id') in workers,'disguised or foreign removal evidence')
            verify_nonforce_remove(record)
    plan=row.get('mapping',{}).get('plan',{}); logical=plan.get('ID')
    demand(isinstance(logical,str) and bool(logical) and plan.get('Kind') in ('postgres','volume'),'planned logical identity missing')
    attempts=row.get('attempts')
    demand(isinstance(attempts,list) and len(attempts) == (2 if name == F22 else 1),'missing/duplicate operation attempts')
    runs=[]
    for attempt in attempts:
        a=attempt.get('owner',{}); run=a.get('runID',''); cid=a.get('workerContainerID')
        demand(re.fullmatch('[a-f0-9]{32}',run) and cid in workers and workers[cid].get('run_id') == run and
            a.get('workerName') == 'bakabel-worker-'+run and a.get('daemonID') == row['daemon'] and
            a.get('workerStartAuthorized') is True and (not a.get('targetID') if name == F20 else a.get('targetID') == hashlib.sha256(logical.encode()).hexdigest()),'strict owned operation identity missing')
        demand(attempt.get('owner_released') is True and attempt.get('worker_absent') is True and attempt.get('last_success_unchanged') is True,'release/result safety missing')
        result=attempt.get('result',{}); targets=result.get('targets')
        success=name == F22 and len(runs) == 1
        demand(type(attempt.get('cli_exit')) is int and attempt['cli_exit'] == (0 if success else 1) and
            result.get('runID') == run and result.get('status') == ('restored' if success else 'failed') and isinstance(targets,list) and len(targets) == 1 and
            targets[0].get('targetID') == logical and targets[0].get('status') in (('restored',) if success else ('unknown','partial')),'false success or public logical identity drift')
        if not success: demand(bool(targets[0].get('error')),'failed target omitted error')
        related=[r for r in records if r.get('boundary') == 'worker-remove' and r.get('container_id') == cid]
        demand(len(related) == 1,'unique ordinary worker removal missing')
        removed=related[0]; verify_nonforce_remove(removed)
        demand(removed.get('forwarded') is True and type(removed.get('status')) is int and removed['status'] == 204,'actual removal response missing')
        before=removed.get('owner_before_remove',{}); observed=removed.get('worker_before_remove',{})
        demand(all(before.get(k) == a.get(k) for k in ('runID','daemonID','workerContainerID','workerName','workerStartAuthorized')) and
            before.get('workerStartAuthorized') is True and observed.get('container_id') == cid and observed.get('running') is False and
            type(observed.get('pid')) is int and observed['pid'] == 0 and number(observed.get('exit_code')) and bool(observed.get('started_at')),'terminal worker not observed while strictly owned')
        demand((observed['exit_code'] == 0) if success else (observed['exit_code'] > 0),'worker exit contradicts public disposition')
        if name != F20:
            term=attempt.get('terminal',{})
            demand(removed.get('execution_owner') == a and removed.get('terminal_before_remove') == term and
                fullid(a.get('sourceContainerID')) and fullid(a.get('execID')) and bool(a.get('sourceStartedAt')) and
                term.get('daemon') == row['daemon'] and term.get('container_id') == a['sourceContainerID'] and
                term.get('started_at') == a['sourceStartedAt'] and term.get('exec_id') == a['execID'] and number(term.get('exec_exit_code')) and
                all(type(term.get(k)) is int and term[k] == 0 for k in ('sessions','processes')),'exact exec/session terminal proof missing before release')
            starts=[r for r in records if r.get('boundary') == ('dump-start' if name == F19 else 'restore-start') and r.get('exec_id') == a['execID']]
            demand(len(starts) == 1 and starts[0].get('owner_checkpoint') == a and starts[0].get('forwarded') is True and
                starts[0].get('status') == 101 and records.index(starts[0]) < records.index(removed),'actual persisted start before terminal missing')
        runs.append(run)
    demand(len(runs) == len(set(runs)),'operation identity reused')
    if name == F19: verify_temp(row)
    elif name == F20: verify_output(row)
    else: verify_extension(row)


def verify_fs(value, capacity):
    demand(value.get('type') == 'tmpfs' and type(value.get('capacity_bytes')) is int and value['capacity_bytes'] == capacity and
        number(value.get('available_bytes')) and value['available_bytes'] <= capacity and number(value.get('device'),1) and number(value.get('inode'),1),'bounded owned tmpfs readback missing')


def verify_direct_write(storage):
    row=storage.get('direct_write',{})
    demand(isinstance(row,dict) and row.get('stage') == 'write' and row.get('write_attempted') is True and
           type(row.get('attempt_bytes')) is int and row['attempt_bytes'] == 1 and
           type(row.get('create_errno')) is int and row['create_errno'] == 0 and
           type(row.get('write_errno')) is int and row['write_errno'] == 28 and
           type(row.get('errno')) is int and row['errno'] == 28,'literal one byte write ENOSPC missing')
    demand(row.get('capacity_bytes') == storage['full']['capacity_bytes'] and
           type(row.get('available_bytes')) is int and row['available_bytes'] == 0,'direct write filesystem readback differs')


def verify_trace(row, kind):
    trace=row.get('storage',{}).get('trace',{}); a=row['attempts'][0]['owner']
    removed=next(r for r in row['relay']['records'] if r.get('boundary') == 'worker-remove' and r.get('container_id') == a['workerContainerID'])
    demand(trace.get('attached') is True and trace.get('quiescent') is True and trace.get('errors') == [] and
        trace.get('worker_id') == a['workerContainerID'] and number(trace.get('worker_pid'),1) and
        trace.get('worker_started_at') == removed['worker_before_remove']['started_at'],'exact quiescent worker trace missing')
    roots=trace.get('root_pids'); ticks=trace.get('start_ticks')
    demand(isinstance(roots,list) and 1 <= len(roots) <= 2 and all(number(p,1) for p in roots) and
           trace['worker_pid'] in roots and isinstance(ticks,dict) and set(ticks) == {str(p) for p in roots} and
           all(isinstance(t,str) and t.isascii() and t.isdecimal() for t in ticks.values()),'trace root incarnation missing')
    writes=trace.get('writes')
    demand(isinstance(writes,list) and 1 <= len(writes) <= 128,'actual kernel write ENOSPC absent')
    for w in writes:
        demand(set(w) == {'pid','syscall','fd','errno','path_kind','writer'} and number(w.get('pid'),1) and number(w.get('fd')) and
            w.get('syscall') in ('write','pwrite64','writev') and type(w.get('errno')) is int and w['errno'] == 28 and w.get('path_kind') == kind,'wrong filesystem/syscall failure')

        binding=w['writer']; chain=binding.get('chain',[]) if isinstance(binding,dict) else []
        demand(isinstance(chain,list) and 1 <= len(chain) <= 32 and all(isinstance(c,dict) for c in chain), 'writer ancestry missing')
        demand(chain[0].get('pid') == w['pid'] and binding.get('root_pid') in roots and
               chain[-1].get('pid') == binding['root_pid'] and chain[-1].get('start_ticks') == ticks[str(binding['root_pid'])] and
               len({c.get('pid') for c in chain}) == len(chain),'writer root binding drift')
        for i,c in enumerate(chain):
            demand(set(c) == {'pid','tgid','ppid','start_ticks'} and all(number(c.get(k),1) for k in ('pid','tgid')) and
                   number(c.get('ppid')) and isinstance(c.get('start_ticks'),str) and c['start_ticks'].isascii() and
                   c['start_ticks'].isdecimal(),'writer incarnation missing')
            if i+1 < len(chain):
                demand(chain[i+1]['pid'] == (c['tgid'] if c['tgid'] != c['pid'] else c['ppid']),'writer ancestry drift')


def verify_temp(row):
    s=row.get('storage',{}); verify_fs(s.get('before',{}),67108864); verify_fs(s.get('full',{}),67108864)
    verify_direct_write(s)
    source=row['source']; plan=row['mapping']['plan']; active=row['attempts'][0]['owner']
    demand(plan.get('Kind') == 'postgres' and plan.get('Source') == {'DaemonID':row['daemon'],'ContainerID':source['container_id'],'StartedAt':source['started_at']} and
        active.get('sourceContainerID') == source['container_id'] and active.get('sourceStartedAt') == source['started_at'] and
        active.get('execKind') == 'dump' and active.get('phase') == 'exec_started' and active.get('status') == 'active','temp pressure changed frozen PG source')
    demand(s['before']['device'] == s['full']['device'] and s['before']['inode'] == s['full']['inode'] and
        s['full']['available_bytes'] == 0 and s.get('direct_errno') == 28 and number(s.get('filler_bytes'),1) and s['filler_bytes'] <= 67108864 and
        s.get('repository_device') != s['full']['device'] and number(s.get('repository_device'),1),'not temporary-storage pressure')
    demand(s.get('no_cache') is True and type(s.get('pack_size_mib')) is int and s['pack_size_mib'] == 4 and
        s.get('worker_tmpfs') == 'rw,nosuid,nodev,size=67108864' and s.get('dump_lock_wait_observed') is True and
        s.get('pressure_retained_until_terminal') is True and row.get('no_complete_snapshot') is True,'production defaults or failure safety missing')
    token=active['runID']+'-'+hashlib.sha256(plan['ID'].encode()).hexdigest()
    inventory=row.get('snapshot_inventory')
    demand(row.get('repository_run_token') == token and isinstance(inventory,list) and len(inventory) <= 128,'native owned snapshot inventory missing')
    for snapshot in inventory:
        demand(set(snapshot) == {'snapshot_id','run_tag','status'} and fullid(snapshot.get('snapshot_id')) and
            snapshot.get('run_tag') == 'bakabel.run='+token and snapshot.get('status') in ('unknown','partial'),'failed temp export has complete or ambiguous snapshot')
    verify_trace(row,'temp_pack')


def verify_snapshot(row, kind):
    mapping=row.get('mapping',{}); snapshot=mapping.get('snapshot',{}); metadata=snapshot.get('metadata',{})
    logical=mapping.get('plan',{}).get('ID')
    demand(fullid(snapshot.get('snapshotID')) and snapshot.get('status') == 'complete' and snapshot.get('source') == logical and
           snapshot.get('type') == kind and type(metadata.get('version')) is int and metadata['version'] == 1 and
           metadata.get('source') == logical and metadata.get('kind') == kind,'trusted snapshot/plan source mapping missing')
    for attempt in row['attempts']:
        demand(attempt['result']['targets'][0].get('snapshotID') == snapshot['snapshotID'],'public restore snapshot identity drift')
    return snapshot['snapshotID']


def verify_output(row):
    snapshot=verify_snapshot(row,'volume'); s=row.get('storage',{})
    before=s.get('before',{}); full=s.get('full',{})
    verify_fs(before,8388608); verify_fs(full,8388608)
    verify_direct_write(s)
    demand(before['device'] == full['device'] and before['inode'] == full['inode'] and before['available_bytes'] == 8388608 and
        full['available_bytes'] == 0 and type(s.get('direct_errno')) is int and s['direct_errno'] == 28 and
        number(s.get('repository_device'),1) and s['repository_device'] != before['device'],'not actual empty bounded restore output')
    a=row['attempts'][0]['owner']; job=row['mapping'].get('job',{})
    partial=s.get('partial_retained',{})
    demand(a.get('phase') == 'intent' and not a.get('sourceContainerID') and not a.get('execID') and
        job.get('runID') == a['runID'] and job.get('snapshotID') == snapshot and job.get('targetID') == row['mapping']['plan']['ID'] and
        isinstance(job.get('directory'),str) and job['directory'].startswith('/') and partial.get('directory') == job['directory'] and
        partial.get('device') == before['device'] and partial.get('inode') == before['inode'] and
        number(partial.get('files'),1) and number(partial.get('allocated_bytes'),1) and partial['allocated_bytes'] <= 8388608 and
        s.get('source_file_unchanged') is True and s.get('output_unmounted_after_cleanup') is True,'partial output not retained before owned cleanup')
    verify_trace(row,'restore_output')


def restore_contract():
    # Consume the exact reviewed production inventory/baseline; do not replace
    # its full-catalog contract with hstore/payload counts or a fresh DB oracle.
    text=(Path(__file__).resolve().parents[3]/'internal/platform/docker/restore_catalog.go').read_text()
    def value(name):
        found=re.findall(r'const '+name+r' = `([^`]+)`',text)
        demand(len(found) == 1,'production restore inventory contract unavailable')
        return found[0]
    return json.loads(value('restoreBaseline')),value('restoreInventorySQL')


def verify_restore_provenance(row,start,attempt):
    a=attempt['owner']; records=row['relay']['records']; ext=row['extension']; eid=a['execID']
    creates=[r for r in records if r.get('boundary') == 'restore-create' and
             (r.get('exec_id') == eid or r.get('owner_checkpoint',{}).get('runID') == a['runID'])]
    demand(len(creates) == 1,'unique actual restore create missing')
    create=creates[0]
    owner={**a,'phase':'creating_exec'}; owner.pop('execID',None); owner.pop('importRunID',None)
    removals=[r for r in records if r.get('boundary') == 'worker-remove' and r.get('container_id') == a['workerContainerID']]
    demand(len(removals) == 1,'unique native terminal removal missing')
    removed=removals[0]
    expected={'schema':1,'contract':'f22-native-provenance-v1','run_id':a['runID'],'import_run_id':a['importRunID'],
        'daemon':row['daemon'],'worker_id':a['workerContainerID'],'worker_image':row['image_id'],
        'worker_started_at':removed.get('worker_before_remove',{}).get('started_at'),
        'target':ext['target_before'],'target_image':'sha256:83148c0bc09eac4d598b70a61e1404d0212b76c95c504bfd6c81a4c59ec91792',
        'logical_target':row['mapping']['plan']['ID'],'snapshot_id':row['mapping']['snapshot']['snapshotID'],
        'profile':'pg18.6-fixture-pgEnv-v1','create_exact':True,'effective_environment':True,
        'mounts_owned':True,'native_layer':True,'exec_id':eid}
    demand(bool(expected['worker_started_at']) and create.get('method') == 'POST' and create.get('forwarded') is True and
        type(create.get('status')) is int and create['status'] == 201 and create.get('exec_id') == eid and
        'fault' not in create and 'fault' not in start and
        create.get('container_id') == a['sourceContainerID'] and same_json(create.get('owner_checkpoint'),owner) and
        same_json(create.get('restore_create'),expected) and start.get('method') == 'POST' and
        start.get('container_id') == a['sourceContainerID'] and start.get('exec_id') == eid and
        same_json(start.get('owner_checkpoint'),a) and start.get('forwarded') is True and
        type(start.get('status')) is int and start['status'] == 101 and
        records.index(create) < records.index(start) < records.index(removed) and
        same_json(start.get('restore_start'),{**expected,'inspect_agrees':True}), 'native create/persisted start provenance mismatch')
    terminal={'schema':1,'exec_id':eid,'import_run_id':a['importRunID'],'capture_quiescent':True,
        'target_after':ext['target_before'],'native_layer_after':True,'all_client_sessions':0,'all_import_processes':0,
        'terminal':attempt['terminal']}
    demand(same_json(start.get('native_terminal'),terminal),'native terminal/capture/target binding missing')


def verify_f22_first_failure(row,start,first):
    # Also used by the runner BEFORE library preparation. No future retry or
    # cleanup result is assumed here; those remain separate final obligations.
    ext=row['extension']; a=first['owner']; term=first['terminal']; records=row['relay']['records']
    diagnostic=start.get('import_diagnostic')
    demand(type(term.get('exec_exit_code')) is int and term['exec_exit_code'] == 1 and
        same_json(ext.get('failure_cause'),diagnostic) and start.get('import_contract') == 'pg_restore-fixture-exit-on-error-v1' and
        start.get('container_id') == ext['target_before']['container_id'],'exact finite missing-library exec cause absent')
    expected={'cause':'hstore_binary_load_missing','complete':True,'error_count':1}
    if same_json(diagnostic,expected):
        demand('native_fatal_witness' not in start,'conflicting complete/native failure routes')
        # Legacy EOF receipts remain valid; any additional transport projection
        # must agree rather than let a rewritten summary erase an observed reset.
        if 'capture' in start:
            capture=start['capture']
            demand(isinstance(capture,dict) and capture.get('state') == 'finalized' and
                capture.get('stop_reason') == 'upstream_eof','complete cause contradicts stream capture')
        if 'import_observation' in start:
            demand(isinstance(start['import_observation'],dict) and
                start['import_observation'].get('transport_complete') is True,'complete cause contradicts observed transport')
        if 'native_fatal_observation' in start:
            demand(isinstance(start['native_fatal_observation'],dict) and
                start['native_fatal_observation'].get('reset_candidate') is False,'complete cause contradicts native reset')
        return
    demand(row.get('case') == F22 and row.get('source_unchanged') is True and row.get('relay',{}).get('errors') == [] and
        row.get('attempts',[None])[0] == first,'native route outside first failed F22 import')
    verify_restore_provenance(row,start,first)
    expected_native={'schema':1,'template':'pg18-hstore-devnull-429-v1','observed_bytes':429,'observed_error_count':1,
        'framing_valid':True,'framing_consumed':True,'reset_candidate':True}
    demand(same_json(start.get('native_fatal_observation'),expected_native) and
        same_json(diagnostic,{'cause':'unclassified','complete':False,'error_count':1}) and
        same_json(start.get('import_observation'),{'cause':'hstore_binary_load_missing','message_complete':True,
            'observed_error_count':1,'transport_complete':False}) and
        same_json(start.get('native_fatal_witness'),{'schema':1,'exec_id':a['execID'],'import_run_id':a['importRunID'],
            'stderr_complete':False,'total_error_count':None}), 'native message/framing/unknown-tail receipt absent')
    capture=start.get('capture',{})
    demand(set(capture) == {'state','stop_reason','input_stop','output_stop','stderr_bytes','stdout_observed_bytes'} and
        capture.get('state') == 'aborted' and capture.get('stop_reason') == 'recv_back_reset' and
        capture.get('input_stop') in (None,'client_eof','send_back_broken_pipe') and capture.get('output_stop') is None and
        type(capture.get('stderr_bytes')) is int and capture['stderr_bytes'] == 429 and
        type(capture.get('stdout_observed_bytes')) is int and capture['stdout_observed_bytes'] == 0 and
        'fault' not in start,'native reset transport exclusions not met')
    removed=next(r for r in records if r.get('boundary') == 'worker-remove' and r.get('container_id') == a['workerContainerID'])
    verify_nonforce_remove(removed)
    demand(first.get('cli_exit') == 1 and type(first.get('cli_exit')) is int and
        first.get('owner_released') is True and first.get('worker_absent') is True and first.get('last_success_unchanged') is True and
        first.get('result',{}).get('runID') == a['runID'] and first['result'].get('status') == 'failed' and
        removed.get('execution_owner') == a and removed.get('terminal_before_remove') == term and
        removed.get('forwarded') is True and type(removed.get('status')) is int and removed['status'] == 204 and
        all(type(term.get(k)) is int and term[k] == 0 for k in ('sessions','processes')) and
        term.get('daemon') == row['daemon'] and term.get('exec_id') == a['execID'] and
        term.get('container_id') == a['sourceContainerID'] and term.get('started_at') == a['sourceStartedAt'], 'native failed result/retirement missing')
    before=removed.get('owner_before_remove',{}); worker=removed.get('worker_before_remove',{})
    demand(all(before.get(k) == a.get(k) for k in ('runID','daemonID','workerContainerID','workerName','workerStartAuthorized')) and
        before.get('workerStartAuthorized') is True and worker.get('container_id') == a['workerContainerID'] and
        worker.get('running') is False and type(worker.get('pid')) is int and worker['pid'] == 0 and
        number(worker.get('exit_code'),1),'native terminal worker not strictly owned')
    target=first['result'].get('targets',[])
    demand(len(target) == 1 and target[0].get('targetID') == row['mapping']['plan']['ID'] and
        target[0].get('snapshotID') == row['mapping']['snapshot']['snapshotID'] and
        target[0].get('status') in ('unknown','partial') and bool(target[0].get('error')),'native public failure identity missing')
    baseline,_=restore_contract(); database=ext.get('database_before',{})
    demand(isinstance(database,dict) and set(database) == {'cluster_id','database_oid','database'} and
        database.get('database') == 'fixture' and all(isinstance(database.get(k),str) and
        re.fullmatch('[1-9][0-9]{0,19}',database[k]) for k in ('cluster_id','database_oid')) and
        same_json(ext.get('catalog_before'),baseline) and same_json(ext.get('catalog_after_failure'),baseline) and
        ext.get('database_after_failure') == database and ext.get('target_after_failure') == ext['target_before'] and
        all(type(ext.get(k)) is int and ext[k] == 0 for k in ('installed_before','installed_after_failure')) and
        ext.get('control_present') is True and type(ext.get('library_missing_exit')) is int and ext['library_missing_exit'] == 1 and
        ext.get('roles_prepared_before_failure') is True and ext.get('role_oids_differ') is True and
        ext.get('operator_action') == 'restore-owned-hidden-library' and ext.get('payload_after_failure') is False,
        'native failed baseline guard missing')


def verify_extension(row):
    verify_snapshot(row,'postgres'); ext=row.get('extension',{})
    demand(ext.get('name') == 'hstore' and ext.get('source_major') == ext.get('target_major') == 18 and
        isinstance(ext.get('source_installed_version'),str) and bool(ext['source_installed_version']) and
        ext.get('target_versions') == [ext['source_installed_version']] and
        fullid(ext.get('library_sha256')) and ext.get('library_after_sha256') == ext['library_sha256'] and
        ext.get('control_present') is True and type(ext.get('library_missing_exit')) is int and ext['library_missing_exit'] == 1 and
        type(ext.get('library_present_exit')) is int and ext['library_present_exit'] == 0,'actual unavailable then proper binary prerequisite missing')
    target=ext.get('target_before',{})
    demand(fullid(target.get('container_id')) and bool(target.get('started_at')) and number(target.get('restart_count')) and
        target['container_id'] != row['source']['container_id'] and all(ext.get(k) == target for k in
        ('target_after_failure','target_after_prepare','target_after_restore')) and
        ext.get('roles_prepared_before_failure') is True and ext.get('role_oids_differ') is True and
        ext.get('database_not_deleted') is True and ext.get('operator_action') == 'restore-owned-hidden-library' and
        all(type(ext.get(k)) is int and ext[k] == 0 for k in ('installed_before','installed_after_failure')) and
        ext.get('payload_after_failure') is False,'wrong target, preexisting extension, missing roles or destructive repair')
    for i,attempt in enumerate(row['attempts']):
        a=attempt['owner']; term=attempt['terminal']
        demand(a.get('execKind') == 'restore' and a.get('phase') == 'exec_started' and a.get('status') == 'active' and
            re.fullmatch('restore_[a-f0-9]{48}',a.get('importRunID','')) and a['importRunID'] != a['runID'] and
            a['sourceContainerID'] == target['container_id'] and a['sourceStartedAt'] == target['started_at'] and
            ((term['exec_exit_code'] == 0) if i else (term['exec_exit_code'] > 0)),'missing-binary import did not fail or proper import did not finish')
    baseline,_=restore_contract()
    demand(all(same_json(ext.get(k),baseline) for k in ('catalog_before','catalog_after_failure','catalog_before_retry')),
           'retry target differs from full pinned restore baseline')
    database=ext.get('database_before',{})
    demand(isinstance(database,dict) and set(database) == {'cluster_id','database_oid','database'} and database['database'] == 'fixture' and
           all(isinstance(database[k],str) and re.fullmatch('[1-9][0-9]{0,19}',database[k]) for k in ('cluster_id','database_oid')) and
           all(ext.get(k) == database for k in ('database_after_failure','database_before_retry','database_after_restore')),
           'same cluster/database OID readbacks missing')
    first=row['attempts'][0]; active=first['owner']
    start=next(r for r in row['relay']['records'] if r.get('boundary') == 'restore-start' and r.get('exec_id') == active['execID'])
    verify_f22_first_failure(row,start,first)
    for key in ('importRunID','execID','workerContainerID'):
        demand(len({a['owner'][key] for a in row['attempts']}) == 2,'restore identity reused across attempts')
    second=row['attempts'][1]
    retry=next(r for r in row['relay']['records'] if r.get('boundary') == 'restore-start' and r.get('exec_id') == second['owner']['execID'])
    demand('native_fatal_witness' not in retry,'native failure witness cannot satisfy retry success')
    if 'native_fatal_witness' in start: verify_restore_provenance(row,retry,second)
    data=ext.get('source_data')
    demand(isinstance(data,str) and re.fullmatch(r'300000\|45000150000\|[a-f0-9]{32}',data) and ext.get('target_data') == data and
        ext.get('table_owner') == 'fixture_owner' and ext.get('reader_select') is True and ext.get('database_owner') == 'postgres' and
        ext.get('database_acl_matches') is True and ext.get('extension_function') is True,'extension-dependent data/owner/ACL readback missing')
    demand(row['cleanup']['containers_absent'].get(target['container_id']) is True,'exact extension target cleanup missing')


def verify_report(report, rows):
    demand(report.get('schema') == 1 and report.get('storage_acceptance_pass') is True and report.get('full_plan_acceptance_pass') is False,'not a bounded additive acceptance report')
    names=[row.get('case') for row in rows]
    demand(len(names) == len(CASES) and set(names) == set(CASES) and len(set(names)) == len(names),'missing/duplicate additive gate')
    demand(report.get('cases') == [{'case':row['case'],'status':row['status']} for row in rows],'case manifest mismatch')
    for row in rows:
        demand(all(row.get(k) == report.get(k) for k in ('source_sha256','image_id','daemon')),'additive build/daemon binding drift')
        verify_case(row)


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime',type=Path,required=True)
    args=parser.parse_args(argv)
    report=json.loads((args.runtime/'hosted-storage.json').read_text())
    rows=[json.loads((args.runtime/name/'receipt.json').read_text()) for name in CASES]
    verify_report(report,rows)
    print(json.dumps({'storage_acceptance_pass':True,'cases':len(rows),'full_plan_acceptance_pass':False}))
    return 0


if __name__ == '__main__': raise SystemExit(main())
