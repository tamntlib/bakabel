"""F14 ordinary public CLI contract. Offline validation is not runtime proof."""
import hashlib
import json
import re

CASE = 'restore-reader-failure-importer-zero'


def demand(value, reason):
    if not value: raise ValueError(reason)


def integer(value, expected=None):
    return type(value) is int and (expected is None or value == expected)


def verify_f14(row):
    from verify_hosted_faults import verify_nonforce_remove
    proof = row.get('proof',{}); mapping = proof.get('target_mapping',{})
    plan = mapping.get('plan',{}); snap = mapping.get('snapshot',{}); meta = snap.get('metadata',{})
    logical = plan.get('ID'); source = row.get('source',{})
    demand(isinstance(logical,str) and bool(logical) and plan.get('Kind') == 'postgres' and
           plan.get('Source') == {'DaemonID':row['daemon'],'ContainerID':source.get('container_id'),'StartedAt':source.get('started_at')}, 'F14 frozen public plan binding missing')
    demand(re.fullmatch('[a-f0-9]{64}',snap.get('snapshotID','')) and snap.get('status') == 'complete' and
           snap.get('type') == 'postgres' and snap.get('source') == logical and integer(meta.get('version'),1) and
           meta.get('kind') == 'postgres' and meta.get('source') == logical and
           meta.get('paths') == ['/bakabel/postgres/'+hashlib.sha256(logical.encode()).hexdigest()+'/database.dump'], 'F14 exact trusted complete snapshot binding missing')
    expected = proof.get('source_data',{})
    demand(all(integer(expected.get(k),v) for k,v in {'rows':300000,'min':1,'max':300000,'sum':45000150000}.items()) and
           re.fullmatch('[a-f0-9]{32}',expected.get('digest','')), 'F14 fixed source corpus readback missing')
    attempts = proof.get('attempts')
    demand(isinstance(attempts,list) and len(attempts) == 2 and [x.get('mode') for x in attempts] == ['control','fault'], 'F14 needs control then fault')
    relay = row.get('relay',{}); records = relay.get('records')
    demand(isinstance(records,list) and 6 <= len(records) <= 12000 and relay.get('errors') == [], 'F14 bounded actual relay evidence missing')
    used = {source.get('container_id')}; run_ids = set(); exec_ids = set(); pids = set(); tokens = set()
    for attempt in attempts:
        fault = attempt['mode'] == 'fault'; a = attempt.get('owner',{}); cid = a.get('workerContainerID','')
        eid = a.get('execID',''); target = attempt.get('target',{}); dest = target.get('container_id','')
        controller = attempt.get('controller_id','')
        demand(re.fullmatch('[a-f0-9]{32}',a.get('runID','')) and a['runID'] not in run_ids and
               re.fullmatch('restore_[a-f0-9]{48}',a.get('importRunID','')) and a['importRunID'] not in tokens and
               a.get('workerStartAuthorized') is True and a.get('phase') == 'exec_started' and a.get('status') == 'active' and
               a.get('execKind') == 'restore' and a.get('daemonID') == row['daemon'] and
               a.get('workerName') == 'bakabel-worker-'+a['runID'] and
               a.get('targetID') == hashlib.sha256(logical.encode()).hexdigest(), 'F14 strict active import identity missing')
        demand(all(re.fullmatch('[a-f0-9]{64}',x) for x in (cid,eid,dest,controller)) and
               not (set((cid,dest,controller)) & used) and len({cid,dest,controller}) == 3 and eid not in exec_ids and
               dest == a.get('sourceContainerID') and bool(target.get('started_at')) and target['started_at'] == a.get('sourceStartedAt') and
               integer(target.get('restart_count')) and target['restart_count'] >= 0, 'F14 exact independent target/worker/controller missing')
        used.update((cid,dest,controller)); run_ids.add(a['runID']); exec_ids.add(eid); tokens.add(a['importRunID'])
        worker = row['workers'].get(cid,{})
        demand(worker.get('run_id') == a['runID'] and worker.get('cpu.max') == '200000 100000' and
               worker.get('memory.max') == '536870912', 'F14 exact worker kernel limits missing')
        reader = attempt.get('reader',{}); command = ['/usr/bin/restic','--no-cache','dump',snap['snapshotID'],meta['paths'][0]]
        demand(integer(reader.get('pid')) and reader['pid'] > 1 and reader['pid'] not in pids and
               integer(attempt.get('worker_pid')) and attempt['worker_pid'] > 1 and reader.get('ppid') == attempt['worker_pid'] and
               integer(reader.get('start_ticks')) and reader['start_ticks'] > 0 and
               reader.get('argv_sha256') == hashlib.sha256(json.dumps(command,separators=(',',':')).encode()).hexdigest() and
               integer(reader.get('fresh_authorization_checks')) and reader['fresh_authorization_checks'] >= 3 and
               integer(reader.get('natural_exit_code'),0) and reader.get('injected') is fault,
               'F14 actual reader command/incarnation/late exit authorization missing')
        pids.add(reader['pid'])
        demand((reader.get('terminal_exit_code') is None and integer(reader.get('terminal_signal'),9)) if fault else
               (integer(reader.get('terminal_exit_code'),0) and reader.get('terminal_signal') is None), 'F14 reader natural-zero/control or signal failure not observed')
        terminal = attempt.get('terminal',{})
        demand(terminal.get('daemon') == row['daemon'] and terminal.get('container_id') == dest and
               terminal.get('started_at') == target['started_at'] and terminal.get('exec_id') == eid and
               terminal.get('import_run_id') == a['importRunID'] and
               all(integer(terminal.get(k),0) for k in ('exec_exit_code','sessions','processes')), 'F14 otherwise-valid importer zero terminal proof missing')
        demand(attempt.get('data') == expected and all(attempt.get(k) is True for k in ('owner_released','worker_absent','last_success_unchanged')) and
               integer(attempt.get('cli_exit'),1 if fault else 0), 'F14 public failure/retained valid data/ownership proof missing')
        result = attempt.get('result',{}); targets = result.get('targets')
        demand(result.get('runID') == a['runID'] and result.get('status') == ('failed' if fault else 'restored') and
               isinstance(targets,list) and len(targets) == 1 and targets[0].get('targetID') == logical and
               targets[0].get('snapshotID') == snap['snapshotID'] and
               targets[0].get('status') == ('unknown' if fault else 'restored') and
               (targets[0].get('error') == 'restore failed' if fault else not targets[0].get('error')), 'F14 reader failure masked by importer or public logical identity lost')
        creates = [r for r in records if r.get('boundary') == 'restore-create' and r.get('exec_id') == eid]
        starts = [r for r in records if r.get('boundary') == 'restore-start' and r.get('exec_id') == eid]
        def removal(r):
            return r.get('method') == 'DELETE' or r.get('boundary') == 'worker-remove' or any(k.startswith('remove_') or k.endswith('_before_remove') for k in r)
        def correlated(r):
            if r.get('container_id') in (cid,dest) or r.get('exec_id') == eid: return True
            for key in ('owner_checkpoint','owner_before_remove'):
                obj = r.get(key,{})
                if isinstance(obj,dict) and any(obj.get(k) == a[k] for k in ('runID','workerContainerID','workerName','sourceContainerID','execID','importRunID')): return True
            for key in ('terminal_before_remove','worker_before_remove','reader_before_remove'):
                obj = r.get(key,{})
                if isinstance(obj,dict) and (obj.get('exec_id') == eid or obj.get('container_id') in (cid,dest) or obj.get('pid') == reader['pid']): return True
            return False
        removes = [r for r in records if removal(r) and correlated(r)]
        demand(len(creates) == len(starts) == len(removes) == 1, 'F14 unique actual create/start/nonforce remove missing')
        created,started,removed = creates[0],starts[0],removes[0]
        demand(records.index(created) < records.index(started) < records.index(removed), 'F14 lifecycle ordering missing')
        for r,method,status,boundary,container in ((created,'POST',201,'restore-create',dest),(started,'POST',101,'restore-start',dest),(removed,'DELETE',204,'worker-remove',cid)):
            demand(r.get('method') == method and r.get('boundary') == boundary and r.get('container_id') == container and
                   r.get('forwarded') is True and integer(r.get('status'),status) and not r.get('fault'), 'F14 ordinary actual transport missing')
        verify_nonforce_remove(removed)
        initial = removed.get('owner_before_remove',{})
        identity = ('runID','daemonID','workerContainerID','workerName','workerStartAuthorized')
        demand(all(initial.get(k) == a[k] for k in identity) and initial.get('workerStartAuthorized') is True and
               initial.get('phase') == 'intent' and initial.get('status') == 'active' and
               all(not initial.get(k) for k in ('sourceContainerID','sourceStartedAt','targetID','execID','execKind','importRunID')) and
               removed.get('terminal_before_remove') == terminal and removed.get('reader_before_remove') == reader,
               'F14 terminal readback not retained while owned before removal/release')
        state = removed.get('worker_before_remove',{})
        demand(state.get('container_id') == cid and state.get('running') is False and integer(state.get('pid'),0) and
               integer(state.get('exit_code'),1 if fault else 0), 'F14 exact worker terminal status missing')
        cp = created.get('owner_checkpoint',{})
        demand(cp.get('phase') == 'creating_exec' and not cp.get('execID') and not cp.get('importRunID') and
               all(cp.get(k) == a[k] for k in (*identity,'targetID','sourceContainerID','sourceStartedAt','execKind')) and
               cp.get('workerStartAuthorized') is True and started.get('owner_checkpoint') == a, 'F14 create/persist/start checkpoint mismatch')
        execution = relay.get('execs',{}).get(eid,{})
        demand(execution.get('kind') == 'restore' and execution.get('container_id') == dest and
               integer(execution.get('stdin_bytes')) and execution['stdin_bytes'] > 65536, 'F14 real importer input progress missing')
        for r in records:
            if removal(r) and r.get('container_id') in row['workers']:
                demand(r.get('boundary') == 'worker-remove','F14 noncanonical worker removal')
                verify_nonforce_remove(r)
            if removal(r) and correlated(r): demand(r is removed,'F14 contradictory correlated removal')
            operation = 'exec_id' in r or r.get('boundary') in ('dump-create','dump-start','restore-create','restore-start')
            if not operation or not correlated(r) or r is created or r is started: continue
            demand(r.get('method') == 'GET' and r.get('boundary') == 'other' and r.get('exec_id') == eid and
                   r.get('container_id',dest) == dest and r.get('forwarded') is True and integer(r.get('status'),200) and
                   not r.get('fault') and (not r.get('owner_checkpoint') or r['owner_checkpoint'] == a), 'F14 contradictory correlated exec operation')
    demand(all(row['cleanup']['containers_absent'].get(x) is True for x in used), 'F14 exact source/controller/worker/target cleanup missing')
