#!/usr/bin/env python3
"""Additive bounded temp/output and missing-extension hosted experiments.

Exclusive disposable rootful hosted VM ONLY. No production flags/defaults or
images are changed. The existing fourteen fault gates remain independent.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import time
from urllib.parse import quote
from hosted_storage_trace import WriteTrace
from run_hosted_faults import FaultProbe, FROZEN_SOURCE, relay_path, run_case
from run_compose_pg_acceptance import fingerprint
from run_hosted_acceptance import require_hosted_daemon, failure_location
from run_resource_probe import Engine, PG, utc
from run_resource_failures import OwnedSpaceProbe
from verify_hosted_faults import verify_nonforce_remove
from verify_hosted_storage_prereqs import CASES, F19, F20, F22, verify_case, verify_report, restore_contract

PG_PIN='postgres:18.6-alpine3.24@sha256:83148c0bc09eac4d598b70a61e1404d0212b76c95c504bfd6c81a4c59ec91792'
_FAILURE_KINDS=('AssertionError','ValueError','RuntimeError','OSError','FileNotFoundError','PermissionError','TimeoutError','ConnectionError','JSONDecodeError')
_FAILURE_FUNCTIONS={
    'run_hosted_storage_prereqs.py':('main','space','fill_temporary','__init__','run','plan_projection','owned_running','start_trace',
        'observe_transport','finish_attempt','exercise_temp','snapshot_mapping','exercise_output','target_identity','extension_action','library_hash','exercise_extension','cleanup'),
    'hosted_storage_trace.py':('__init__','start','consume','finish','receipt','project_write'),
    'run_hosted_faults.py':('run_case','__init__','prepare','save','finish','wait','capture_owned_worker','worker_proof','worker_identity_proof','terminal_proof','observe_transport','cleanup'),
    'run_resource_probe.py':('call','inspect','exec','create','startpg','controller','restic','sql'),
    'verify_hosted_storage_prereqs.py':('verify_case','verify_fs','verify_trace','verify_temp','verify_snapshot','verify_output','verify_extension','verify_report'),
}


def safe_failure(exc):
    known={str(Path(__file__).with_name(name)):name for name in _FAILURE_FUNCTIONS}
    frames=[]; tb=exc.__traceback__
    while tb is not None:
        frame=tb.tb_frame; file=known.get(frame.f_code.co_filename); function=frame.f_code.co_name
        allowed=file is not None and function in _FAILURE_FUNCTIONS[file]
        frames.append({'file':file if allowed else None,'function':function if allowed else None,
                       'line':tb.tb_lineno if allowed and 0 < tb.tb_lineno <= 1000000 else None})
        del frames[:-8]; tb=tb.tb_next
    kind=type(exc).__name__; code=getattr(exc,'errno',None)
    return {'kind':kind if kind in _FAILURE_KINDS else None,
            'errno':code if type(code) is int and 0 <= code <= 4095 else None,'frames':frames}



def space(path):
    # Numeric statvfs is insufficient on its own: reject ordinary host storage.
    cp=subprocess.run(['stat','-f','-c','%T',str(path)],capture_output=True,text=True,timeout=3)
    if cp.returncode or cp.stdout.strip() != 'tmpfs': raise ValueError('owned tmpfs required')
    st=os.stat(path); fs=os.statvfs(path)
    return {'type':'tmpfs','capacity_bytes':fs.f_blocks*fs.f_frsize,
            'available_bytes':fs.f_bavail*fs.f_frsize,'device':st.st_dev,'inode':st.st_ino}


def output_mount_identity(path):
    # A pathname/dev+ino pair is not mount identity: a same-root bind remount
    # keeps both. Reject stacked or malformed mountinfo instead of guessing.
    text=Path('/proc/self/mountinfo').read_text()
    if len(text)>2097152: raise ValueError('mount inventory bound')
    def decode(value):
        return re.sub(r'\\(040|011|012|134)',lambda m:chr(int(m[1],8)),value)
    rows=[]
    for line in text.splitlines():
        left,right=line.split(' - ',1); fields=left.split(); tail=right.split()
        if len(fields)<6 or len(tail)<3: raise ValueError('mount inventory malformed')
        if decode(fields[4]) != str(path): continue
        rows.append({'mount_id':int(fields[0]),'parent_id':int(fields[1]),'major_minor':fields[2],
                     'root':decode(fields[3]),'mountpoint':decode(fields[4]),'fstype':tail[0],'source':decode(tail[1])})
    if len(rows)>1: raise ValueError('stacked output mount is ambiguous')
    if not rows: return None
    st=os.stat(path,follow_symlinks=False)
    import stat
    if not stat.S_ISDIR(st.st_mode): raise ValueError('output mountpoint is not a directory')
    row=rows[0]
    if row['major_minor'] != f'{os.major(st.st_dev)}:{os.minor(st.st_dev)}':
        raise ValueError('mount/stat identity differs')
    return {**row,'device':st.st_dev,'inode':st.st_ino}


def fill_temporary(path, expected):
    fd=os.dup(path) if type(path) is int else os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        pinned=Path(f'/proc/{os.getpid()}/fd/{fd}'); observed=space(pinned)
        if any(observed.get(k) != expected.get(k) for k in ('type','capacity_bytes','device','inode')) or observed['capacity_bytes'] != 67108864:
            raise ValueError('temporary filesystem identity changed')
        out=os.open('.f19-owned-pressure',os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600,dir_fd=fd)
        written=0
        try:
            while written <= observed['capacity_bytes']:
                try:
                    n=os.write(out,b'\0'*4096)
                    if not n: raise ValueError('zero pressure write')
                    written+=n
                except OSError as exc:
                    if exc.errno != 28: raise
                    return written
            raise ValueError('bounded temporary pressure failed to reach ENOSPC')
        finally: os.close(out)
    finally: os.close(fd)


class MissingLibraryDiagnostic:
    """Transient bounded stderr classifier; no raw line survives finish()."""
    ERROR=b'pg_restore: error: could not execute query: ERROR:  could not access file "$libdir/hstore": No such file or directory'
    COMMAND=b'Command was: CREATE EXTENSION IF NOT EXISTS hstore WITH SCHEMA public;'

    def __init__(self):
        self.buffer=bytearray(); self.total=0; self.errors=0
        self.load=False; self.command=False; self.previous_load=False; self.bounded=True

    def feed(self,data):
        self.total+=len(data)
        if self.total>16384:
            self.bounded=False; self.buffer.clear(); return
        for byte in data:
            if not self.bounded: return
            if byte != 10:
                self.buffer.append(byte)
                if len(self.buffer)>1024: self.bounded=False; self.buffer.clear()
                continue
            line=bytes(self.buffer); self.buffer.clear()
            if line.startswith(b'pg_restore: error:') or b'FATAL:' in line:
                self.errors=min(2,self.errors+1)
            self.command |= self.previous_load and line == self.COMMAND
            self.previous_load=line == self.ERROR
            self.load |= self.previous_load

    def finish(self):
        complete=self.bounded and not self.buffer
        self.buffer.clear()
        return {'cause':'hstore_binary_load_missing' if complete and self.load and self.command and self.errors == 1 else 'unclassified',
                'complete':complete,'error_count':self.errors}


class StorageProbe(FaultProbe):
    def __init__(self,args,case):
        super().__init__(args,case)
        self.tracking=False; self.operations={}; self.removals={}; self.traces=[]
        self.temp_fd=None; self.output_mount=None
        self.result['attempts']=[]
        self.relay.stderr_classifier_factory=self.import_stderr_classifier

    def run(self):
        if self.case == F19:
            self.prepare()
            plan=self.call_cli('plan')['targets'][0]
            self.result['mapping']={'plan':self.plan_projection(plan)}
            self.exercise_temp()
        elif self.case == F20:
            self.exercise_output()
        elif self.case == F22:
            self.prepare()
            plan=self.call_cli('plan')['targets'][0]
            self.result['mapping']={'plan':self.plan_projection(plan)}
            self.exercise_extension()
        else: raise ValueError('unsupported additive case')
        self.verify_source_online(); self.result['exercised']=True

    @staticmethod
    def plan_projection(plan):
        return {'ID':plan['ID'],'Kind':plan['Kind'],'Source':{k:plan['Source'][k] for k in ('DaemonID','ContainerID','StartedAt')}}

    def owned_running(self,active):
        if self.owner() != active or active.get('workerStartAuthorized') is not True:
            raise ValueError('strict owned worker authorization missing')
        obj=self.e.inspect(active['workerContainerID']); self.worker_identity_proof(obj,active)
        if obj['State'].get('Running') is not True or type(obj['State'].get('Pid')) is not int or obj['State']['Pid'] <= 0:
            raise ValueError('exact live worker missing')
        return obj

    def start_trace(self,active,path_kind,restic=False):
        obj=self.owned_running(active); pid=obj['State']['Pid']; roots=[pid]
        if restic:
            candidates=[]
            cg=self.cgroup(pid,strict=True)
            for child in self.pids(pid):
                if self.cgroup(child,strict=True) != cg: raise ValueError('trace cgroup drift')
                argv=Path(f'/proc/{child}/cmdline').read_bytes().split(b'\0')
                if argv[:4] == [b'/usr/bin/restic',b'--no-cache',b'backup',b'--pack-size=4']:
                    if os.readlink(f'/proc/{child}/exe') != '/usr/bin/restic': raise ValueError('wrong Restic executable')
                    candidates.append(child)
            if len(candidates) != 1: raise ValueError('exact ordinary no-cache Restic unavailable')
            roots.extend(candidates)
        cg=self.cgroup(pid,strict=True)
        if obj['Id'] not in str(cg) or os.readlink(f'/proc/{pid}/exe') != '/usr/local/bin/bakabel':
            raise ValueError('strict worker kernel/executable binding missing')
        def authority():
            if self.owned_running(active)['State'] != obj['State']:
                raise ValueError('worker changed before attachment')
            descendants=set(self.pids(pid)) if restic else set()
            for root in roots:
                if self.cgroup(root,strict=True) != cg: raise ValueError('trace cgroup drift')
                if root != pid:
                    argv=Path(f'/proc/{root}/cmdline').read_bytes().split(b'\0')
                    if (root not in descendants or argv[:4] != [b'/usr/bin/restic',b'--no-cache',b'backup',b'--pack-size=4'] or
                            os.readlink(f'/proc/{root}/exe') != '/usr/bin/restic'):
                        raise ValueError('Restic ancestry/executable drift')
                elif os.readlink(f'/proc/{root}/exe') != '/usr/local/bin/bakabel':
                    raise ValueError('worker executable drift')
        trace=WriteTrace(roots,path_kind,authority=authority); self.traces.append(trace); trace.start()
        # Attachment is not permission to rebind an incarnation.
        if self.owned_running(active)['State'] != obj['State']: raise ValueError('worker changed during attachment')
        self.trace_binding={'worker_id':obj['Id'],'worker_pid':pid,'worker_started_at':obj['State']['StartedAt']}
        return trace

    def observe_transport(self,phase,record):
        # Reuse original strict exec persistence and worker capture, unchanged.
        super().observe_transport(phase,record)
        if phase == 'request' and self.tracking and record['boundary'] in ('dump-start','restore-start'):
            a=record['owner_checkpoint']; self.operations[a['runID']]=copy.deepcopy(a)
        if (phase == 'request' and self.case == F20 and self.tracking and record.get('inventory_all') is True and not self.traces):
            active=self.owner()
            if active and active.get('workerStartAuthorized') is True:
                obj=self.e.inspect(active['workerContainerID'])
                if obj['State'].get('Running') is True:
                    job=json.loads((self.root/'state/workflow/job.json').read_text())
                    if job.get('runID') != active['runID']: raise ValueError('frozen file restore job drift')
                    targets=job['targets']; restore=job['restore']
                    if len(targets) != 1 or targets[0]['ID'] != self.target or restore['directory'] != str(self.output_path):
                        raise ValueError('frozen output identity drift')
                    self.result['mapping']['job']={'runID':job['runID'],'targetID':targets[0]['ID'],
                        'snapshotID':restore['snapshotID'],'directory':restore['directory']}
                    prefix=str(self.output_path)+'/.bakabel-restore/'
                    self.start_trace(active,lambda p:'restore_output' if p.startswith(prefix) else None)
        if phase != 'request' or not self.tracking or record['boundary'] != 'worker-remove': return
        verify_nonforce_remove(record)
        a=self.owner()
        if not a or a.get('workerStartAuthorized') is not True or a.get('workerContainerID') != record.get('container_id'):
            raise ValueError('removal lost strict ownership')
        run=a['runID']; obj=self.e.inspect(a['workerContainerID']); self.worker_identity_proof(obj,a)
        state=obj['State']
        if state.get('Running') is not False or type(state.get('Pid')) is not int or state['Pid'] != 0 or type(state.get('ExitCode')) is not int:
            raise ValueError('worker not terminal before nonforce removal')
        observed={**self.worker_observation(obj['Id'],obj,time.monotonic()),'started_at':state['StartedAt']}
        record.update(owner_before_remove=copy.deepcopy(a),worker_before_remove=observed)
        if self.case != F20:
            active=self.operations.get(run)
            if active is None: raise ValueError('exact execution checkpoint missing')
            terminal=self.terminal_proof(active)
            record.update(execution_owner=active,terminal_before_remove=terminal)
        else:
            self.operations[run]=copy.deepcopy(a)
        if self.case == F19:
            current=space(Path(f'/proc/{os.getpid()}/fd/{self.temp_fd}'))
            if current['device'] != self.result['storage']['full']['device'] or current['available_bytes'] != 0:
                raise ValueError('temporary pressure not retained through terminal')
            self.result['storage']['pressure_retained_until_terminal']=True
        for trace in self.traces: trace.finish()
        if self.traces:
            self.result['storage']['trace']={**self.traces[-1].receipt(),**self.trace_binding}
        self.removals[run]=record

    def finish_attempt(self,controller,expect=1):
        rows=self.finish(controller,expect=expect,timeout=85)
        if len(rows) != 1: raise ValueError('one public workflow result required')
        result=rows[0]; run=result['runID']; active=self.operations.get(run)
        if active is None or run not in self.removals or self.owner() is not None or self.e.inspect(active['workerContainerID'],missing=True) is not None:
            raise ValueError('terminal-before-release evidence missing')
        last=self.last()
        if last.get('runID') != run or last.get('lastBackupSuccessAt','') != getattr(self,'baseline_success',''):
            raise ValueError('attempt changed backup success')
        value={'owner':active,'result':result,'cli_exit':expect,'owner_released':True,'worker_absent':True,'last_success_unchanged':True}
        if self.case != F20: value['terminal']=self.removals[run]['terminal_before_remove']
        self.result['attempts'].append(value)
        return value

    def exercise_temp(self):
        self.lock(self.source); self.tracking=True
        controller=self.controller('run'); active=self.blocked(self.source)
        obj=self.owned_running(active)
        if obj['HostConfig']['Tmpfs'] != {'/tmp':'rw,nosuid,nodev,size=67108864'}:
            raise ValueError('ordinary temporary default changed')
        self.temp_fd=os.open(f"/proc/{obj['State']['Pid']}/root/tmp",os.O_RDONLY|os.O_DIRECTORY)
        path=Path(f'/proc/{os.getpid()}/fd/{self.temp_fd}'); before=space(path)
        if before['capacity_bytes'] != 67108864: raise ValueError('bounded ordinary tmpfs missing')
        self.start_trace(active,lambda p:'temp_pack' if re.fullmatch(r'/tmp/restic-(?:temp-pack|index)[^/<>]*',p) else None,restic=True)
        with OwnedSpaceProbe(self.temp_fd) as probe:
            written=fill_temporary(self.temp_fd,before); full=space(path)
            direct=probe.sample()
        self.result['storage']={'before':before,'full':full,'filler_bytes':written,'direct_errno':direct['errno'],'direct_write':direct,
            'repository_device':os.stat(self.root/'backend/local').st_dev,'no_cache':True,'pack_size_mib':4,
            'worker_tmpfs':obj['HostConfig']['Tmpfs']['/tmp'],'dump_lock_wait_observed':True,
            'pressure_retained_until_terminal':False}
        self.unlock(self.source)
        attempt=self.finish_attempt(controller)
        token=attempt['owner']['runID']+'-'+hashlib.sha256(self.target.encode()).hexdigest()
        snapshots=json.loads(self.restic('snapshots','--json'))
        inventory=[]
        for snapshot in snapshots:
            if 'bakabel.run='+token not in snapshot.get('tags',[]): continue
            statuses=[tag.removeprefix('bakabel.status=') for tag in snapshot.get('tags',[]) if tag.startswith('bakabel.status=')]
            if len(statuses) != 1: raise ValueError('ambiguous owned snapshot disposition')
            inventory.append({'snapshot_id':snapshot['id'],'run_tag':'bakabel.run='+token,'status':statuses[0]})
        self.result.update(repository_run_token=token,snapshot_inventory=inventory,
            no_complete_snapshot=not any(s['status'] == 'complete' for s in inventory))
        os.unlink('.f19-owned-pressure',dir_fd=self.temp_fd)
        os.close(self.temp_fd); self.temp_fd=None

    def snapshot_mapping(self,snapshot):
        listed=self.call_cli('snapshots')
        exact=[row for row in listed if row.get('snapshotID') == snapshot]
        if len(exact) != 1 or exact[0].get('status') != 'complete' or exact[0].get('source') != self.target:
            raise ValueError('exact trusted snapshot mapping missing')
        row=exact[0]
        self.result['mapping']['snapshot']={k:row[k] for k in ('snapshotID','source','type','status')}
        self.result['mapping']['snapshot']['metadata']={k:row['metadata'][k] for k in ('version','kind','source')}

    def exercise_output(self):
        self.config(); self.restic('init')
        # Keep an independent read/write application online, without opting it
        # into this FILE-only backup. No application source or volume is stopped.
        self.source=self.startpg('online',False)
        self.sql(self.source,'CREATE TABLE availability_probe(n bigint)')
        obj=self.e.inspect(self.source)
        self.source_before={'container_id':obj['Id'],'started_at':obj['State']['StartedAt'],'restart_count':obj['RestartCount']}
        self.result['source']=self.source_before
        volume=self.prefix+'-files'
        created=self.e.call('POST','/volumes/create',{'Name':volume,'Labels':{'probe.bakabel.owner':self.prefix}})
        if created.get('Name') != volume: raise ValueError('owned file volume identity missing')
        self.volumes.append(volume)
        files=self.create_file_source(volume,900)
        seed=self.e.exec(files,['sh','-c','dd if=/dev/urandom of=/data/payload bs=1048576 count=32 2>/dev/null && chmod 640 /data/payload'])
        if seed['exit'] != 0: raise ValueError('bounded file corpus seed failed')
        digest=self.e.exec(files,['sha256sum','/data/payload'])
        if digest['exit'] or re.fullmatch(r'[a-f0-9]{64}  /data/payload\n?',digest['stdout']) is None: raise ValueError('file checksum unavailable')
        before=self.e.inspect(files)
        plan=self.call_cli('plan')
        if len(plan['targets']) != 1 or plan['targets'][0]['Kind'] != 'volume': raise ValueError('single actual file source required')
        target=plan['targets'][0]; self.target=target['ID']
        self.result['mapping']={'plan':self.plan_projection(target)}
        snapshot=self.success_snapshot(); self.snapshot_mapping(snapshot)
        self.output_path=self.root/'output'; self.output_path.mkdir(mode=0o700)
        self.mount_output()
        fs=space(self.output_path)
        if fs['capacity_bytes'] != 8388608 or fs['available_bytes'] != 8388608: raise ValueError('fresh bounded output readback differs')
        self.result['storage']={'before':fs,'repository_device':os.stat(self.root/'backend/local').st_dev,
            'output_unmounted_after_cleanup':False}
        self.tracking=True
        with OwnedSpaceProbe(self.output_path) as probe:
            probe.unlink_while_open() # Keep the write FD, not a nonempty restore target.
            controller=self.controller('restore','--snapshot',snapshot,'--directory',str(self.output_path))
            self.finish_attempt(controller)
            full=space(self.output_path); direct=probe.sample()
        # Measure retained allocated bytes, not sparse logical sizes. The failed
        # public CLI must leave its partial .bakabel-restore tree intact.
        entries=[p for p in self.output_path.rglob('*') if p.is_file()]
        allocated=sum(p.stat().st_blocks*512 for p in entries)
        after=self.e.inspect(files); new_digest=self.e.exec(files,['sha256sum','/data/payload'])
        unchanged=(after['Id'] == before['Id'] and after['State']['Running'] is True and
            after['State']['StartedAt'] == before['State']['StartedAt'] and after['RestartCount'] == before['RestartCount'] and new_digest == digest)
        self.result['storage'].update(full=full,direct_errno=direct['errno'],direct_write=direct,source_file_unchanged=unchanged,
            partial_retained={'directory':str(self.output_path),'device':full['device'],'inode':full['inode'],
                              'files':len(entries),'allocated_bytes':allocated})

    def target_identity(self,target):
        obj=self.e.inspect(target)
        if (target == self.source or target not in self.containers or self.roles.get(target) != 'restore-pg' or
            obj['Id'] != target or obj.get('Name') != '/'+self.containers[target] or
            (obj.get('Config',{}).get('Labels') or {}).get('probe.bakabel.owner') != self.prefix or
            obj.get('Image') != self.result['images'][PG] or obj['State'].get('Running') is not True):
            raise ValueError('exact owned disposable extension target missing')
        return {'container_id':obj['Id'],'started_at':obj['State']['StartedAt'],'restart_count':obj['RestartCount']}

    def extension_action(self,target,action,identity):
        # Fixed external filesystem fault ONLY in our never-used target layer.
        # No installer/helper image, source edit, production hook or DB deletion.
        if target == self.source or target not in self.containers or action not in ('hide','prepare'):
            raise ValueError('unauthorized extension fixture operation')
        if self.target_identity(target) != identity: raise ValueError('extension target incarnation drift')
        library='/usr/local/lib/postgresql/hstore.so'; hidden=library+'.bakabel-f22-owned'
        script=('test -f '+library+' && test ! -e '+hidden+' && mv '+library+' '+hidden) if action == 'hide' else (
            'test ! -e '+library+' && test -f '+hidden+' && mv '+hidden+' '+library)
        response=self.e.exec(target,['sh','-c',script])
        if response['exit'] != 0 or self.target_identity(target) != identity:
            raise ValueError('exact owned extension filesystem operation failed')
        probe=self.e.exec(target,['test','-f',library])
        expected=1 if action == 'hide' else 0
        if probe['exit'] != expected: raise ValueError('extension filesystem readback differs')
        return probe['exit']

    def library_hash(self,target):
        response=self.e.exec(target,['sha256sum','/usr/local/lib/postgresql/hstore.so'])
        match=re.fullmatch(r'([a-f0-9]{64})  /usr/local/lib/postgresql/hstore.so\n?',response['stdout'])
        if response['exit'] != 0 or match is None: raise ValueError('pinned upstream extension library unavailable')
        return match[1]

    def import_stderr_classifier(self,record):
        if (self.case != F22 or not self.tracking or not getattr(self,'capture_missing_library',False) or
                record.get('boundary') != 'restore-start'): return None
        active=record.get('owner_checkpoint',{})
        if (self.owner() != active or active.get('execKind') != 'restore' or active.get('phase') != 'exec_started' or
                active.get('workerStartAuthorized') is not True or active.get('sourceContainerID') != self.extension_target or
                record.get('container_id') != self.extension_target or active.get('execID') != record.get('exec_id')):
            raise ValueError('missing-library diagnostic ownership mismatch')
        self.target_identity(self.extension_target)
        execution=self.e.call('GET','/exec/'+active['execID']+'/json')
        config=execution.get('ProcessConfig',{})
        if (execution.get('ID') != active['execID'] or execution.get('ContainerID') != self.extension_target or
                config.get('entrypoint') != '/usr/local/bin/pg_restore' or config.get('arguments') !=
                ['--no-password','--exit-on-error','--dbname',"host='/var/run/postgresql' port='5432' user='postgres' dbname='fixture'"]):
            raise ValueError('exact import diagnostic command mismatch')
        record['import_contract']='pg_restore-fixture-exit-on-error-v1'
        return MissingLibraryDiagnostic()

    def database_identity(self,target):
        return json.loads(self.sql(target,"SELECT jsonb_build_object('cluster_id',(SELECT system_identifier::text FROM pg_control_system()),"
            "'database_oid',(SELECT oid::text FROM pg_database WHERE datname=current_database()),'database',current_database())"))

    def catalog(self,target):
        _,inventory=restore_contract()
        return json.loads(self.sql(target,inventory))

    def require_fresh_same_database(self,target,ext):
        ext['database_after_failure']=self.database_identity(target)
        ext['catalog_after_failure']=self.catalog(target)
        baseline,_=restore_contract()
        if (ext['database_after_failure'] != ext['database_before'] or
                ext['catalog_before'] != baseline or ext['catalog_after_failure'] != baseline):
            raise ValueError('failed import changed full target baseline; retry forbidden')

    def exercise_extension(self):
        self.sql(self.source,"CREATE EXTENSION hstore; CREATE ROLE fixture_owner; CREATE ROLE fixture_reader; ALTER TABLE payload ADD COLUMN attrs hstore; UPDATE payload SET attrs=hstore('key',g::text); ALTER TABLE payload OWNER TO fixture_owner; GRANT SELECT ON payload TO fixture_reader")
        expected=self.sql(self.source,"SELECT count(*),sum(g),md5(string_agg(g::text||':'||data||':'||attrs::text,',' ORDER BY g)) FROM payload")
        version=self.sql(self.source,"SELECT extversion FROM pg_extension WHERE extname='hstore'")
        source_hash=self.library_hash(self.source)
        source_roles=self.sql(self.source,"SELECT rolname,oid FROM pg_roles WHERE rolname IN ('fixture_owner','fixture_reader') ORDER BY rolname")
        snapshot=self.success_snapshot(); self.snapshot_mapping(snapshot)
        target=self.startpg('extension-target',False); identity=self.target_identity(target)
        self.sql(target,'CREATE ROLE unrelated_oid_shift; CREATE ROLE fixture_owner; CREATE ROLE fixture_reader')
        target_roles=self.sql(target,"SELECT rolname,oid FROM pg_roles WHERE rolname IN ('fixture_owner','fixture_reader') ORDER BY rolname")
        initial_hash=self.library_hash(target)
        if initial_hash != source_hash: raise ValueError('source/target extension binaries differ from pinned pair')
        source_major=int(self.sql(self.source,"SELECT current_setting('server_version_num')::integer/10000"))
        target_major=int(self.sql(target,"SELECT current_setting('server_version_num')::integer/10000"))
        control=self.e.exec(target,['test','-f','/usr/local/share/postgresql/extension/hstore.control'])
        if control['exit'] != 0: raise ValueError('fixed extension control unavailable')
        initial=int(self.sql(target,"SELECT count(*) FROM pg_extension WHERE extname='hstore'"))
        ext={'name':'hstore','source_major':source_major,'target_major':target_major,'source_installed_version':version,
            'library_sha256':source_hash,'control_present':True,'installed_before':initial,
            'roles_prepared_before_failure':target_roles != source_roles,'role_oids_differ':target_roles != source_roles,
            'target_before':identity,'source_data':expected,'operator_action':'restore-owned-hidden-library',
            'database_before':self.database_identity(target),'catalog_before':self.catalog(target)}
        self.result['extension']=ext
        baseline,_=restore_contract()
        if ext['catalog_before'] != baseline: raise ValueError('initial full target baseline differs')
        self.extension_target=target; self.capture_missing_library=True
        ext['library_missing_exit']=self.extension_action(target,'hide',identity)
        self.tracking=True
        argv=('restore','--snapshot',snapshot,'--postgres-container',target,'--database','fixture','--user','postgres')
        failed=self.finish_attempt(self.controller(*argv))
        self.capture_missing_library=False
        records=self.relay.snapshot()['records']
        starts=[r for r in records if r.get('boundary') == 'restore-start' and r.get('exec_id') == failed['owner']['execID']]
        if len(starts) != 1: raise ValueError('exact diagnostic import missing')
        ext['failure_cause']=starts[0].get('import_diagnostic')
        if (type(failed['terminal']['exec_exit_code']) is not int or failed['terminal']['exec_exit_code'] != 1 or
                ext['failure_cause'] != {'cause':'hstore_binary_load_missing','complete':True,'error_count':1}):
            raise ValueError('exact missing library load failure not observed')
        # The archive may have restored availability_probe before hstore. Do
        # not repair/delete/recreate the DB, restart it or add a transaction to
        # force a pass. A changed baseline is a real failed F22 runtime gate.
        self.require_fresh_same_database(target,ext)
        ext.update(target_after_failure=self.target_identity(target),
            installed_after_failure=int(self.sql(target,"SELECT count(*) FROM pg_extension WHERE extname='hstore'")),
            payload_after_failure=self.sql(target,"SELECT to_regclass('public.payload') IS NOT NULL") == 't')
        # Only put the exact upstream library back. Do not pre-CREATE EXTENSION:
        # that would violate the production empty-catalog preflight contract.
        ext['library_present_exit']=self.extension_action(target,'prepare',identity)
        ext['library_after_sha256']=self.library_hash(target)
        ext['target_after_prepare']=self.target_identity(target)
        ext['database_before_retry']=self.database_identity(target)
        ext['catalog_before_retry']=self.catalog(target)
        if ext['database_before_retry'] != ext['database_before'] or ext['catalog_before_retry'] != baseline:
            raise ValueError('same fresh database lost before retry')
        self.finish_attempt(self.controller(*argv),expect=0)
        ext['database_after_restore']=self.database_identity(target)
        ext['database_not_deleted']=all(ext[k] == ext['database_before'] for k in ('database_after_failure','database_before_retry','database_after_restore'))
        ext.update(target_after_restore=self.target_identity(target),
            target_versions=[self.sql(target,"SELECT extversion FROM pg_extension WHERE extname='hstore'")],
            target_data=self.sql(target,"SELECT count(*),sum(g),md5(string_agg(g::text||':'||data||':'||attrs::text,',' ORDER BY g)) FROM payload"),
            table_owner=self.sql(target,"SELECT tableowner FROM pg_tables WHERE schemaname='public' AND tablename='payload'"),
            reader_select=self.sql(target,"SELECT has_table_privilege('fixture_reader','public.payload','SELECT')") == 't',
            database_owner=self.sql(target,"SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname='fixture'"),
            database_acl_matches=self.sql(target,"SELECT datacl IS NULL FROM pg_database WHERE datname='fixture'") == self.sql(self.source,"SELECT datacl IS NULL FROM pg_database WHERE datname='fixture'"),
            extension_function=self.sql(target,"SELECT ('key=>value'::hstore)->'key'='value'") == 't')

    def mount_output(self):
        if output_mount_identity(self.output_path) is not None: raise ValueError('output mount must be new')
        st=os.stat(self.output_path,follow_symlinks=False)
        self.output_mount={'state':'pending','mountpoint':str(self.output_path),'source':self.prefix+'-output',
                           'fstype':'tmpfs','root':'/','underlying':{'device':st.st_dev,'inode':st.st_ino}}
        self.result['output_mount_recovery']=copy.deepcopy(self.output_mount)
        # Durable intent precedes the subprocess, including its timeout and
        # partial-effect paths. Do not serialize arbitrary command diagnostics.
        with (self.root/'output-mount-intent.json').open('x') as file:
            file.write(json.dumps(self.output_mount)+'\n'); file.flush(); os.fsync(file.fileno())
        try:
            cp=subprocess.run(['mount','-t','tmpfs','-o','size=8388608,nosuid,nodev',self.output_mount['source'],str(self.output_path)],
                              capture_output=True,timeout=5)
            if cp.returncode: raise ValueError('owned bounded output mount failed')
        finally:
            self.reconcile_output_mount()
        if self.output_mount is None: raise ValueError('successful mount has no observed effect')

    def reconcile_output_mount(self):
        intent=self.output_mount
        if intent is None:
            absent=self.result.get('output_mount_recovery',{})
            if absent.get('state') != 'absent': return
            current=output_mount_identity(self.output_path)
            st=os.stat(self.output_path,follow_symlinks=False)
            if current is not None or {'device':st.st_dev,'inode':st.st_ino} != absent['underlying']:
                raise ValueError('previously absent output mount changed; preserve recovery paths')
            return
        current=output_mount_identity(self.output_path)
        if intent['state'] == 'owned':
            if current != intent['identity']: raise ValueError('output mount ownership changed; preserve all recovery paths')
            return
        if current is None:
            st=os.stat(self.output_path,follow_symlinks=False)
            if {'device':st.st_dev,'inode':st.st_ino} != intent['underlying']:
                raise ValueError('pending output absence ambiguous')
            self.result['output_mount_recovery']={**intent,'state':'absent'}
            self.output_mount=None; return
        if any(current[k] != intent[k] for k in ('mountpoint','source','fstype','root')):
            raise ValueError('pending output mount ownership ambiguous')
        self.output_mount={**intent,'state':'owned','identity':current}
        self.result['output_mount_recovery']=copy.deepcopy(self.output_mount)

    def before_private_cleanup(self):
        # FaultProbe invokes this only AFTER exact Engine absence readback and
        # BEFORE deleting credentials/repository/recovery paths. Re-read the
        # entire mount identity immediately before the pathname umount.
        self.reconcile_output_mount()
        if self.output_mount is None: return
        cp=subprocess.run(['umount',str(self.output_path)],capture_output=True,timeout=5)
        if cp.returncode or output_mount_identity(self.output_path) is not None:
            raise ValueError('exact output unmount not observed')
        st=os.stat(self.output_path,follow_symlinks=False)
        if {'device':st.st_dev,'inode':st.st_ino} != self.output_mount['underlying']:
            raise ValueError('output underlying directory changed')
        self.result.setdefault('storage',{})['output_unmounted_after_cleanup']=True
        self.result['output_mount_recovery']={**self.output_mount,'state':'unmounted'}
        self.output_mount=None

    def cleanup(self):
        for trace in self.traces: trace.finish()
        # Pending effects must be owned or proved absent before ANY teardown.
        self.reconcile_output_mount()
        super().cleanup()
        if self.temp_fd is not None: os.close(self.temp_fd); self.temp_fd=None


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--socket',type=Path,required=True)
    parser.add_argument('--runtime',type=Path,required=True)
    parser.add_argument('--source',type=Path)
    parser.add_argument('--image')
    parser.add_argument('--expected-image-id')
    parser.add_argument('--expected-source-sha256')
    parser.add_argument('--exclusive-hosted-daemon',action='store_true')
    parser.add_argument('--case',choices=CASES,action='append')
    args=parser.parse_args(argv)
    if (os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted' or
        os.geteuid() != 0 or not args.exclusive_hosted_daemon):
        parser.error('requires root on an explicitly exclusive GitHub-hosted VM; local/shared use refused')
    if not all((args.source,args.image,args.expected_image_id,args.expected_source_sha256)):
        parser.error('explicit source/image and exact source/image binding required')
    if args.expected_source_sha256 != FROZEN_SOURCE or fingerprint(args.source) != FROZEN_SOURCE:
        parser.error('reviewed production source fingerprint differs')
    if not re.fullmatch('sha256:[a-f0-9]{64}',args.expected_image_id): parser.error('literal full candidate image ID required')
    if not shutil.which('strace'): parser.error('host syscall observer strace unavailable; no stderr-only fallback')
    selected=args.case or list(CASES)
    if len(selected) != len(set(selected)): parser.error('duplicate additive case')
    temporary=Path(os.environ['RUNNER_TEMP']).resolve(); runtime=args.runtime.resolve()
    if runtime == temporary or not runtime.is_relative_to(temporary) or runtime.exists(): parser.error('runtime must be a fresh child of RUNNER_TEMP')
    if max(len(str(relay_path(runtime/name,name)).encode()) for name in selected) >= 104: parser.error('runtime too deep for exact Unix socket')
    engine=Engine(args.socket); info=engine.call('GET','/info')
    require_hosted_daemon(os.environ,os.geteuid(),args.exclusive_hosted_daemon,info,engine.call('GET','/containers/json?all=true'))
    if engine.call('GET','/images/'+quote(args.image,safe='')+'/json')['Id'] != args.expected_image_id:
        parser.error('candidate image ID differs')
    if engine.call('GET','/images/'+quote(PG_PIN,safe='')+'/json')['Id'] != engine.call('GET','/images/'+quote(PG,safe='')+'/json')['Id']:
        parser.error('fixed upstream PostgreSQL fixture differs from pinned digest')
    os.sched_setaffinity(0,{0,1}); runtime.mkdir(mode=0o700)
    rows=[]; receipts=[]
    for case in selected:
        scoped=copy.copy(args); scoped.runtime=runtime/case
        row=run_case(scoped,case,probe_class=StorageProbe,case_verifier=verify_case,failure_projector=safe_failure)
        rows.append(row); print(json.dumps(row),flush=True)
        receipt=json.loads((scoped.runtime/'receipt.json').read_text()); receipts.append(receipt)
        if receipt.get('cleanup_failure'): break
    complete=(len(rows) == len(CASES) and {r['case'] for r in rows} == set(CASES) and all(r['status'] == 'pass' for r in rows))
    report={'schema':1,'source_sha256':args.expected_source_sha256,'image_id':args.expected_image_id,'daemon':info['ID'],
        'cases':rows,'storage_acceptance_pass':complete,'full_plan_acceptance_pass':False,'finished_at':utc(),
        'scope':'additive F19/F20/F22 Compose/local only; original fourteen gates are separate'}
    if complete:
        try: verify_report(report,receipts)
        except Exception as exc:
            report['storage_acceptance_pass']=False; report['verification_failure']=safe_failure(exc)
    (runtime/'hosted-storage.json').write_text(json.dumps(report,indent=2)+'\n')
    if any(r['status'] == 'failed' for r in rows) or report.get('verification_failure'): return 1
    if any(r['status'] == 'blocked' for r in rows) or len(rows) != len(selected): return 2
    return 0


if __name__ == '__main__': raise SystemExit(main())
