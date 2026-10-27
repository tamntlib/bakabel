"""Additional F16/F17/F18/F21 semantics; no runtime inference from fixture labels."""
import hashlib
import re

NATIVE_CASES = ('restic-native-exit3', 'unknown-commit-before-finalize-worker-SIGKILL',
                'finalized-before-report-worker-SIGKILL', 'file-truncate-during-native-read')
CRASH_CASES = NATIVE_CASES[1:3]


def demand(ok, reason):
    if not ok: raise ValueError(reason)


def exact_id(value):
    return isinstance(value,str) and re.fullmatch('[a-f0-9]{64}',value) is not None


def verify_native_case(row):
    p=row.get('proof',{}); name=row.get('case'); run=p.get('run_id'); logical=p.get('logical_target')
    demand(name in NATIVE_CASES and isinstance(run,str) and re.fullmatch('[a-f0-9]{32}',run) and
           isinstance(logical,str) and bool(logical), 'exact run/logical target missing')
    permission=row.get('permission',{})
    demand(permission.get('errors')==[] and type(permission.get('events')) is int and 1<=permission['events']<=4096,
           'bounded error-free native permission evidence missing')
    workers=row.get('workers',{})
    demand(isinstance(workers,dict) and bool(workers) and all(w.get('cpu.max')=='200000 100000' and
           w.get('memory.max')=='536870912' for w in workers.values()), 'exact ordinary native worker kernel proof missing')
    public=p.get('public',{}); targets=public.get('targets',[])
    demand(public.get('runID') == run and isinstance(targets,list) and len(targets)==1 and
           targets[0].get('targetID')==logical, 'public run/target identity mismatch')
    demand(type(p.get('public_exit')) is int and p['public_exit']==(0 if public.get('status')=='complete' else 1),
           'typed public CLI disposition missing')
    target=targets[0]; mapping=p.get('mapping',{}); old=mapping.get('old_id'); new=mapping.get('new_id')
    no_snapshot=name==NATIVE_CASES[3] and new is None
    demand((exact_id(new) or no_snapshot) and (exact_id(old) if name in CRASH_CASES else old is None),
           'exact snapshot mapping or nullable unobserved ID missing')
    token=run+'-'+hashlib.sha256(logical.encode()).hexdigest()
    native=p.get('native_snapshots'); fresh=p.get('fresh_snapshots')
    if no_snapshot:
        demand(native==fresh==[] and p.get('fresh_state_empty_before') is True and
               public.get('status')=='failed' and target.get('status')=='unknown' and not target.get('snapshotID'),
               'no-snapshot mutation failure was invented as committed work')
        status='unknown'
    else:
        demand(isinstance(native,list) and len(native)==1 and native[0].get('id')==new and
               native[0].get('run')==token, 'native repository run/target snapshot binding missing')
        status=native[0].get('status')
        demand(isinstance(fresh,list) and len(fresh)==1 and fresh[0].get('snapshotID')==new and
               fresh[0].get('status')==status and fresh[0].get('source')==logical and
               fresh[0].get('type')=='volume' and p.get('fresh_state_empty_before') is True,
               'state-free public repository classification missing')
    for key in ('owner_released','worker_absent'):
        demand(p.get(key) is True, 'terminal ownership/result safety missing')
    demand(p.get('last_success_matches_complete') is True if name==NATIVE_CASES[3] and public.get('status')=='complete'
           else p.get('last_success_unchanged') is True, 'last backup success disagrees with actual outcome')
    if name in CRASH_CASES:
        expected='unknown' if name==CRASH_CASES[0] else 'complete'
        demand(status==expected and (old==new if expected=='unknown' else old!=new) and
               p.get('unknown_before')=={'id':old,'status':'unknown','run':token} and
               p.get('repository_before_kill')==native, 'genuine unknown/finalized old/new classification missing')
        kill=p.get('kill',{}); cid=kill.get('container_id'); owner=kill.get('owner_before',{})
        demand(exact_id(cid) and row.get('workers',{}).get(cid,{}).get('run_id')==run and
               owner.get('runID')==run and owner.get('workerContainerID')==cid and owner.get('daemonID')==row.get('daemon') and
               owner.get('workerStartAuthorized') is True and owner.get('phase')=='intent' and
               kill.get('authorized') is True and kill.get('running_before') is True and
               type(kill.get('pid_before')) is int and kill['pid_before']>0 and
               kill.get('running_after') is False and type(kill.get('pid_after')) is int and kill['pid_after']==0 and
               type(kill.get('exit_after')) is int and kill['exit_after']==137 and
               kill.get('boundary')==('snapshot-readback' if expected=='unknown' else 'worker-result-create'),
               'actual owned worker SIGKILL boundary/terminal proof missing')
        demand(p.get('result_absent_before_kill') is True and p.get('public_exit')==1 and
               public.get('status')=='failed' and target.get('status')==status and
               target.get('snapshotID')==new and target.get('error')=='backup failed' and
               'resticExitCode' not in target, 'crash was replaced by wrapper failure or falsely reported success')
        observation=kill.get('observation',{});disposition=kill.get('permission_disposition')
        demand(disposition in ('denied','kernel-canceled') and observation.get('mask')==0x10000 and
               observation.get('boundary')==kill['boundary'] and observation.get('worker_id')==cid and
               observation.get('exe')==('restic' if expected=='unknown' else 'bakabel') and
               observation.get('command')==('snapshots' if expected=='unknown' else '_workflow') and
               all(type(observation.get(k)) is int and observation[k]>0 for k in ('pid','start_ticks','file_device','file_inode')) and
               type(observation.get('file_size')) is int and (observation['file_size']>0 if expected=='unknown' else observation['file_size']==0),
               'native permission event/executable/inode boundary missing')
        relay=row.get('relay',{});records=relay.get('records')
        demand(relay.get('errors')==[] and isinstance(records,list) and len(records)<=12000, 'crash removal transport unavailable')
        removes=[r for r in records if r.get('container_id')==cid and
                 (r.get('method')=='DELETE' or r.get('boundary')=='worker-remove' or 'worker_before_remove' in r)]
        demand(len(removes)==1,'unique crash worker removal proof missing')
        removed=removes[0]
        from verify_hosted_faults import verify_nonforce_remove
        verify_nonforce_remove(removed)
        demand(removed.get('boundary')=='worker-remove' and removed.get('forwarded') is True and
               removed.get('status')==204 and removed.get('owner_before_remove')==owner and
               removed.get('worker_before_remove')=={'container_id':cid,'running':False,'pid':0,'exit_code':137},
               'exact terminal crash worker not observed before ownership release')
        events=['unknown-readback-held','unknown-classified']
        if expected=='complete': events+=['unknown-readback-allowed','result-create-held','complete-classified']
        events+=['prekill-rechecked','kill-requested',
                 'permission-denied' if disposition=='denied' else 'permission-canceled-by-kill',
                 'terminal-137-before-remove','public-failed','fresh-classified']
        demand(p.get('events')==events, 'crash/readback/report ordering missing')
        if expected=='unknown':
            demand(p.get('restore_refused') is True and p.get('restore_exit')==1 and p.get('restore_no_worker') is True,
                   'unknown restore not refused')
        return
    read=p.get('native_read',{})
    demand(read.get('exe')=='restic' and read.get('command')=='backup' and
           exact_id(read.get('worker_id')) and row.get('workers',{}).get(read['worker_id'],{}).get('run_id')==run and
           all(type(read.get(k)) is int and read[k]>0 for k in ('pid','start_ticks','inode','device','position','size_before','prior_allowed_reads')) and
           read['position']<read['size_before'] and type(read.get('uid')) is int and read['uid']>=0 and
           isinstance(read.get('cap_eff'),str) and re.fullmatch('[a-f0-9]{16}',read['cap_eff']),
           'native Restic in-progress read/identity/privilege proof missing')
    if name == NATIVE_CASES[0]:
        demand(read.get('operation')=='deny' and read.get('permission_response')==2 and
               read.get('size_after')==read['size_before'], 'real kernel read denial missing')
        demand(public.get('status')=='failed' and type(target.get('resticExitCode')) is int and
               target['resticExitCode']==3 and target.get('failureCode')=='backup', 'native Restic exit 3 missing')
    else:
        demand(name==NATIVE_CASES[3] and read.get('operation')=='truncate' and read.get('permission_response')==1 and
               type(read.get('size_after')) is int and read['size_after']==read['position']<read['size_before'] and
               p.get('application_consistency_claim') is False, 'literal in-read truncation or consistency boundary missing')
        demand(type(p.get('public_exit')) is int and p['public_exit']==(0 if public.get('status')=='complete' else 1),
               'actual mutation public disposition missing')
    demand((not target.get('snapshotID') if no_snapshot else target.get('snapshotID')==new) and
           status==target.get('status'), 'public/native exact disposition mismatch')
    if public.get('status')=='complete':
        demand(name==NATIVE_CASES[3] and status=='complete' and not target.get('error'), 'false mutation success')
    else:
        demand(public.get('status')=='failed' and status in ('partial','unknown') and target.get('error')=='backup failed',
               'native failure must retain snapshot AND error without complete result')
        if not no_snapshot:
            demand(p.get('restore_refused') is True and type(p.get('restore_exit')) is int and p['restore_exit']==1 and
                   p.get('restore_no_worker') is True, 'fresh incomplete restore was not refused before worker creation')
