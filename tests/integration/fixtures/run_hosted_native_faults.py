"""Additive hosted-only native file/read and crash boundary probes.

Invoked only by run_hosted_faults.run_case after its exclusive-hosted preflight.
These are kernel permission gates around unchanged native binaries, not replaced
Restic/provider implementations. No source image tooling or production knobs.
"""
import os
import hashlib
import json
import threading
from pathlib import Path
import re

from run_hosted_faults import FaultProbe
from verify_hosted_faults import verify_nonforce_remove
from run_resource_probe import PG
from native_permission_fixture import ACCESS_PERM, OPEN_PERM, EVENT_ON_CHILD, PermissionGate, process_identity, read_position
from verify_hosted_native_faults import NATIVE_CASES, CRASH_CASES


class NativeFaultProbe(FaultProbe):
    def __init__(self,args,case):
        super().__init__(args,case)
        self.gate=PermissionGate(self.classify_permission)
        self.kill_answered=threading.Event()

    def cleanup(self):
        # Drain/deny any pending owned permission and remove its marks before
        # ordinary identity-checked fixture teardown, including failed gates.
        failure=None
        try:self.gate.close()
        except Exception as exc:
            # A bounded quiescence failure must NOT tear down files beneath a
            # live classifier. Retain the gate/thread/FD ownership for retry.
            if self.gate.retired is not True:raise
            failure=exc
        self.result['permission']={'errors':list(self.gate.errors),'events':self.gate.count}
        try:super().cleanup()
        except Exception as exc:
            if failure is not None:raise failure from exc
            raise
        if failure is not None:raise failure
        if self.gate.errors:raise ValueError('native permission observation failed')

    def verify_source_online(self):
        obj=self.e.inspect(self.source)
        if (self.e.call('GET','/info')['ID']!=self.daemon or obj.get('Id')!=self.source_before['container_id'] or
                obj['State'].get('Running') is not True or obj['State'].get('StartedAt')!=self.source_before['started_at'] or
                obj.get('RestartCount')!=self.source_before['restart_count'] or
                self.e.exec(self.source,['sh','-c','test -d /data'])['exit']!=0):
            raise ValueError('native file source incarnation/availability changed')
        self.result['source_unchanged']=True

    def run(self):
        if self.case not in NATIVE_CASES:raise ValueError('unknown native fault')
        self.prepare_native()
        if self.case in CRASH_CASES:self.exercise_native_crash()
        else:self.exercise_native_read()
        self.verify_source_online();self.result['exercised']=True

    def prepare_native(self):
        self.allowed_reads=0;self.native_read=None;self.stage='unknown';self.boundary=None
        self.events=[];self.baseline_success=''
        self.config();self.config('fresh.yaml',fresh=True);self.restic('init')
        name=self.prefix+'-files'
        self.e.call('POST','/volumes/create',{'Name':name,'Labels':{'probe.bakabel.owner':self.prefix}})
        self.volumes.append(name)
        volume=self.e.call('GET','/volumes/'+name)
        if (volume.get('Name')!=name or volume.get('Driver')!='local' or volume.get('Scope')!='local' or
                volume.get('Options') not in (None,{}) or (volume.get('Labels') or {}).get('probe.bakabel.owner')!=self.prefix):
            raise ValueError('exact owned native volume unavailable')
        backing=Path(volume['Mountpoint'])
        self.payload=backing/'payload'
        fd=os.open(self.payload,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o640)
        with os.fdopen(fd,'wb') as out:
            for _ in range(16):out.write(os.urandom(1048576))
            out.flush();os.fsync(out.fileno())
        self.source=self.create_file_source(name,600)
        obj=self.e.inspect(self.source)
        self.source_before={'container_id':obj['Id'],'started_at':obj['State']['StartedAt'],'restart_count':obj['RestartCount']}
        plan=self.call_cli('plan')
        if not isinstance(plan,dict) or len(plan.get('targets',[]))!=1:raise ValueError('one exact native file target required')
        target=plan['targets'][0]
        if target.get('Kind')!='volume' or target.get('Source')!={'DaemonID':self.daemon,'ContainerID':self.source,
                'StartedAt':self.source_before['started_at']}:
            raise ValueError('public native source plan mismatch')
        self.target=target['ID'];self.result['source']=self.source_before
        if self.case in CRASH_CASES:self.gate.mark(self.root/'backend/local/snapshots',OPEN_PERM|EVENT_ON_CHILD)
        else:self.gate.mark(self.payload,ACCESS_PERM)
        self.gate.start()

    def exercise_native_read(self):
        controller=self.controller('run');self.gate.await_hold()
        self.active=self.owner();self.capture_owned_worker()
        self.result.setdefault('native_observations',{})['read']=self.native_read
        self.recheck_read()
        deny=self.case==NATIVE_CASES[0]
        if not deny:
            # The next real read is blocked at the kernel permission boundary.
            # Shrink the ONE owned fixture file after a completed native read.
            fd=os.open(self.payload,os.O_WRONLY|os.O_NOFOLLOW)
            try:os.ftruncate(fd,self.native_read['position']);os.fsync(fd)
            finally:os.close(fd)
        self.native_read.update(operation='deny' if deny else 'truncate',
            size_after=self.payload.stat().st_size,permission_response=2 if deny else 1)
        self.gate.release(not deny)
        self.finish_native(controller)

    def exercise_native_crash(self):
        controller=self.controller('run');self.gate.await_hold()
        self.active=self.owner();self.capture_owned_worker()
        self.result['native_events']=self.events
        self.events.append('unknown-readback-held')
        unknown=self.native_snapshots()
        self.result.setdefault('native_observations',{})['unknown_snapshots']=unknown
        if len(unknown)!=1 or unknown[0]['status']!='unknown' or unknown[0]['id']!=self.boundary.get('snapshot_id'):
            raise ValueError('held commit is not one genuine unknown snapshot')
        self.unknown_before=unknown[0];self.events.append('unknown-classified')
        if self.case==CRASH_CASES[1]:
            self.stage='report';self.gate.release(True);self.events.append('unknown-readback-allowed')
            self.gate.await_hold()
            if self.boundary.get('boundary')!='worker-result-create':raise ValueError('native worker report boundary missing')
            self.events.append('result-create-held')
        self.repository_before_kill=self.native_snapshots()
        expected='unknown' if self.case==CRASH_CASES[0] else 'complete'
        if (len(self.repository_before_kill)!=1 or self.repository_before_kill[0]['status']!=expected or
                (self.repository_before_kill[0]['id']==self.unknown_before['id'])!=(expected=='unknown')):
            raise ValueError('native commit/finalization mapping changed before kill')
        if expected=='complete':self.events.append('complete-classified')
        obj=self.recheck_kill()
        self.kill_proof={'container_id':self.active['workerContainerID'],'running_before':True,'pid_before':obj['State']['Pid'],
            'authorized':True,'owner_before':dict(self.active),'boundary':self.boundary['boundary'],
            'observation':dict(self.boundary)}
        self.result['native_observations']['kill']=self.kill_proof
        self.events.extend(('prekill-rechecked','kill-requested'))
        end=self.gate.current_hold()['deadline']
        self.e.call('POST','/containers/'+self.active['workerContainerID']+'/kill?signal=KILL',deadline=end)
        try:
            disposition=self.gate.release_after_kill()
            self.kill_proof['permission_disposition']=disposition
            self.events.append('permission-denied' if disposition=='denied' else 'permission-canceled-by-kill')
        finally:self.kill_answered.set()
        self.finish_native(controller)

    def finish_native(self,controller):
        observed=self.wait(lambda:(lambda obj:obj if obj['State']['Running'] is False else None)(self.e.inspect(controller)),85,'native public CLI exit')
        exit_code=observed['State']['ExitCode']
        rows=self.finish(controller,expect=exit_code,timeout=1)
        if len(rows)!=1 or not isinstance(rows[0],dict):raise ValueError('one native public outcome required')
        raw=rows[0];targets=raw.get('targets',[])
        if (raw.get('runID')!=self.active['runID'] or raw.get('status') not in ('failed','complete') or
                not isinstance(targets,list) or len(targets)!=1 or targets[0].get('targetID')!=self.target):
            raise ValueError('public native outcome identity mismatch')
        target=targets[0]
        if target.get('status') not in ('unknown','partial','complete') or target.get('error','') not in ('','backup failed'):
            raise ValueError('unrecognized native target disposition')
        safe={k:target[k] for k in ('targetID','status','snapshotID','error','failureCode','resticExitCode','resticReason') if k in target}
        if 'snapshotID' in safe and (not isinstance(safe['snapshotID'],str) or
                (safe['snapshotID'] and not re.fullmatch('[a-f0-9]{64}',safe['snapshotID']))):
            raise ValueError('unrecognized native snapshot identifier')
        if safe.get('failureCode','') not in ('','file_preflight','list_before','backup','list_after','source_verification','tag','final_readback','metadata_readback'):
            raise ValueError('unrecognized native failure stage')
        if safe.get('resticReason','') not in ('','enospc','permission','backend','unknown'):
            raise ValueError('unrecognized native failure reason')
        if 'resticExitCode' in safe and (type(safe['resticExitCode']) is not int or not 0<=safe['resticExitCode']<=255):
            raise ValueError('invalid native exit measurement')
        public={'runID':raw['runID'],'status':raw['status'],'targets':[safe]}
        self.result.setdefault('native_observations',{}).update(public=public,public_exit=exit_code)
        if self.owner() is not None or self.e.inspect(self.active['workerContainerID'],missing=True) is not None:
            raise ValueError('native terminal ownership not released')
        last=self.last()
        if last.get('runID')!=self.active['runID'] or last.get('status')!=('success' if public['status']=='complete' else 'failed'):
            raise ValueError('native durable outcome differs from public result')
        unchanged=last.get('lastBackupSuccessAt','')==self.baseline_success
        native=self.native_snapshots()
        self.result['native_observations']['native_snapshots']=native
        if not native and self.case==NATIVE_CASES[3]:
            if public['status']!='failed' or safe.get('status')!='unknown' or safe.get('snapshotID'):
                raise ValueError('mutation falsely reports uncommitted snapshot')
            snapshot=None;status='unknown'
        else:
            if len(native)!=1:raise ValueError('exact native repository disposition unavailable')
            snapshot=native[0]['id'];status=native[0]['status']
            if safe.get('snapshotID')!=snapshot:raise ValueError('public result lost exact native snapshot')
        proof={'run_id':self.active['runID'],'logical_target':self.target,'public':public,'public_exit':exit_code,
            'mapping':{'old_id':None,'new_id':snapshot},'native_snapshots':native,
            'owner_released':True,'worker_absent':True,'last_success_unchanged':unchanged,
            'last_success_matches_complete':public['status']=='complete' and last.get('finishedAt')==last.get('lastBackupSuccessAt')}
        if self.case in CRASH_CASES:
            self.events.append('public-failed')
            proof.update(mapping={'old_id':self.unknown_before['id'],'new_id':snapshot},unknown_before=self.unknown_before,
                repository_before_kill=self.repository_before_kill,kill=self.kill_proof,
                result_absent_before_kill=True,events=self.events)
        else:
            proof.update(native_read=self.native_read,application_consistency_claim=False)
        proof.update(self.fresh_classify(snapshot,status))
        if self.case in CRASH_CASES:self.events.append('fresh-classified')
        self.result['proof']=proof

    def fresh_classify(self,snapshot,status):
        if list((self.root/'fresh-state').iterdir()):raise ValueError('fresh repository classifier has previous state')
        listed=self.call_cli('snapshots',filename='fresh.yaml',fresh=True)
        if not isinstance(listed,list):raise ValueError('fresh public snapshots list unavailable')
        if snapshot is None:
            if self.case!=NATIVE_CASES[3] or listed:raise ValueError('mutation no-snapshot public repository mismatch')
            return {'fresh_state_empty_before':True,'fresh_snapshots':[]}
        exact=[s for s in listed if s.get('snapshotID')==snapshot]
        if len(exact)!=1 or exact[0].get('status')!=status or exact[0].get('source')!=self.target or exact[0].get('type')!='volume':
            raise ValueError('fresh exact snapshot classification mismatch')
        result={'fresh_state_empty_before':True,'fresh_snapshots':[{k:exact[0][k] for k in ('snapshotID','status','source','type')}]}
        if status in ('unknown','partial'):
            name=self.prefix+'-refused-restore'
            self.e.call('POST','/volumes/create',{'Name':name,'Labels':{'probe.bakabel.owner':self.prefix}})
            self.volumes.append(name);obj=self.e.call('GET','/volumes/'+name)
            if (obj.get('Name')!=name or obj.get('Driver')!='local' or obj.get('Scope')!='local' or
                    obj.get('Options') not in (None,{}) or (obj.get('Labels') or {}).get('probe.bakabel.owner')!=self.prefix):
                raise ValueError('owned restore refusal destination unavailable')
            dest=Path(obj['Mountpoint'])
            if list(dest.iterdir()):raise ValueError('refusal destination not empty')
            before=self.relay.snapshot()['workers']
            self.call_cli('restore','--snapshot',snapshot,'--volume',name,filename='fresh.yaml',fresh=True,expect=1)
            if self.relay.snapshot()['workers']!=before or list(dest.iterdir()):
                raise ValueError('incomplete restore launched worker or wrote destination')
            result.update(restore_refused=True,restore_exit=1,restore_no_worker=True)
        return result

    def native_process(self,pid,exe,command):
        active=self.owner()
        if active is None:return None
        if (active.get('workerStartAuthorized') is not True or active.get('daemonID')!=self.daemon or
                active.get('phase')!='intent' or not re.fullmatch('[a-f0-9]{64}',active.get('workerContainerID',''))):
            raise ValueError('strict native worker authorization unavailable')
        return process_identity(pid,active['workerContainerID'],exe,command)

    def recheck_read(self):
        read=self.native_read;held=self.gate.current_hold()
        if held['pid']!=read['pid'] or held['mask']!=ACCESS_PERM:raise ValueError('held native read permission identity changed')
        event_file=os.fstat(held['fd'])
        if (event_file.st_dev,event_file.st_ino)!=(read['device'],read['inode']):
            raise ValueError('held read file changed')
        identity=self.native_process(read['pid'],'/usr/bin/restic','backup')
        if identity is None or any(read.get(k)!=v for k,v in identity.items()):raise ValueError('native reader incarnation changed')
        st=self.payload.stat()
        if ((st.st_dev,st.st_ino,st.st_size)!=(read['device'],read['inode'],read['size_before']) or
                read_position(read['pid'],self.payload)!=read['position']):
            raise ValueError('native in-progress file read boundary changed')

    def native_snapshots(self):
        token=self.active['runID']+'-'+hashlib.sha256(self.target.encode()).hexdigest()
        snapshots=json.loads(self.restic('snapshots','--json'));out=[]
        if not isinstance(snapshots,list):raise ValueError('native snapshot list unavailable')
        for snap in snapshots:
            tags=snap.get('tags',[])
            if 'bakabel.run='+token not in tags:continue
            statuses=[t[len('bakabel.status='):] for t in tags if t.startswith('bakabel.status=')]
            runs=[t for t in tags if t.startswith('bakabel.run=')]
            if (len(statuses)!=1 or statuses[0] not in ('unknown','partial','complete') or runs!=['bakabel.run='+token] or
                    not re.fullmatch('[a-f0-9]{64}',snap.get('id',''))):
                raise ValueError('ambiguous native snapshot status/run identity')
            out.append({'id':snap['id'],'status':statuses[0],'run':token})
        return sorted(out,key=lambda s:s['id'])

    def recheck_kill(self):
        held=self.gate.current_hold();current=self.owner()
        if current!=self.active or current.get('workerStartAuthorized') is not True:
            raise ValueError('strict exact owner lost immediately before kill')
        boundary=self.boundary
        event_file=os.fstat(held['fd']);host_file=self.boundary_path.stat()
        expected=(boundary['file_device'],boundary['file_inode'],boundary['file_size'])
        if (held['pid']!=boundary['pid'] or held['mask']!=OPEN_PERM or
                (event_file.st_dev,event_file.st_ino,event_file.st_size)!=expected or
                (host_file.st_dev,host_file.st_ino,host_file.st_size)!=expected):
            raise ValueError('held native commit/report inode identity changed')
        exe='/usr/bin/restic' if boundary['exe']=='restic' else '/usr/local/bin/bakabel'
        identity=self.native_process(held['pid'],exe,boundary['command'])
        if identity is None or any(boundary.get(k)!=v for k,v in identity.items()):
            raise ValueError('held native process incarnation changed before kill')
        obj=self.e.inspect(current['workerContainerID']);self.worker_identity_proof(obj,current)
        if obj['State'].get('Running') is not True or type(obj['State'].get('Pid')) is not int or obj['State']['Pid']<=0:
            raise ValueError('owned worker not live at kill boundary')
        if (self.root/'state/workflow/output/result.json').exists():raise ValueError('worker result already published')
        self.gate.current_hold()
        final_owner=self.owner()
        if (final_owner!=self.active or final_owner.get('workerStartAuthorized') is not True or
                self.e.call('GET','/info')['ID']!=self.daemon):
            raise ValueError('strict owner/daemon changed at final kill gate')
        return obj

    def observe_transport(self,phase,record):
        if (self.case in CRASH_CASES and record['boundary']=='worker-remove' and phase=='request' and
                hasattr(self,'active') and record.get('container_id')==self.active['workerContainerID']):
            verify_nonforce_remove(record)
            if record.get('forwarded') is not False:raise ValueError('crash terminal observation is not pre-forward removal')
            if not self.kill_answered.wait(1):raise TimeoutError('kill permission disposition unavailable before removal')
            if self.owner()!=self.active:raise ValueError('kill ownership lost before terminal readback')
            obj=self.e.inspect(self.active['workerContainerID']);self.worker_identity_proof(obj,self.active)
            state=obj['State']
            if (state.get('Running') is not False or type(state.get('Pid')) is not int or state['Pid']!=0 or
                    type(state.get('ExitCode')) is not int or state['ExitCode']!=137):
                raise ValueError('exact SIGKILL terminal 137 not observed before removal')
            self.kill_proof.update(running_after=False,pid_after=0,exit_after=137)
            record.update(owner_before_remove=dict(self.active),worker_before_remove={
                'container_id':self.active['workerContainerID'],'running':False,'pid':0,'exit_code':137})
            self.events.append('terminal-137-before-remove')
            return
        super().observe_transport(phase,record)
        if self.case==CRASH_CASES[1] and phase=='response' and record['boundary']=='worker-create':
            # Output exists before ordinary worker start. No broad/recursive
            # mark on state: only child opens in this run's owned output dir.
            self.gate.mark(self.root/'state/workflow/output',OPEN_PERM|EVENT_ON_CHILD)

    def classify_permission(self,event):
        if self.case in (NATIVE_CASES[0],NATIVE_CASES[3]):
            if event['mask']!=ACCESS_PERM:return 'allow'
            st=os.fstat(event['fd']); source=self.payload.stat()
            if (st.st_dev,st.st_ino)!=(source.st_dev,source.st_ino):return 'allow'
            identity=self.native_process(event['pid'],'/usr/bin/restic','backup')
            if identity is None:return 'allow'
            if self.native_read is not None:
                return 'deny' if self.case==NATIVE_CASES[0] else 'allow'
            position=read_position(event['pid'],self.payload)
            if position==0:
                self.allowed_reads+=1;return 'allow'
            if not self.allowed_reads or not 0<position<st.st_size:
                raise ValueError('in-progress native read unavailable')
            self.native_read={**identity,'device':st.st_dev,'inode':st.st_ino,
                'position':position,'size_before':st.st_size,'prior_allowed_reads':self.allowed_reads}
            return 'hold'
        if self.case in CRASH_CASES and event['mask']==OPEN_PERM:
            # fanotify's event fd may retain the worker mount namespace path.
            # A basename only locates a candidate; actual inode/device equality
            # with the owned host-side file is mandatory before classification.
            name=Path(os.readlink('/proc/self/fd/'+str(event['fd']))).name
            spec=None
            if self.stage=='unknown' and re.fullmatch('[a-f0-9]{64}',name):
                spec=(self.root/'backend/local/snapshots'/name,'/usr/bin/restic','snapshots','snapshot-readback')
            elif self.case==CRASH_CASES[1] and self.stage=='report' and re.fullmatch(r'\.record-[0-9]+',name):
                spec=(self.root/'state/workflow/output'/name,'/usr/local/bin/bakabel','_workflow','worker-result-create')
            if spec is None:return 'allow'
            path,exe,command,boundary=spec
            try:host=path.stat()
            except FileNotFoundError:return 'allow'
            actual=os.fstat(event['fd'])
            if (actual.st_dev,actual.st_ino)!=(host.st_dev,host.st_ino):return 'allow'
            identity=self.native_process(event['pid'],exe,command)
            if identity is not None:
                self.boundary={**identity,'boundary':boundary,'mask':event['mask'],
                    'file_device':actual.st_dev,'file_inode':actual.st_ino,'file_size':actual.st_size}
                if boundary=='snapshot-readback':self.boundary['snapshot_id']=name
                self.boundary_path=path
                return 'hold'
        return 'allow'
