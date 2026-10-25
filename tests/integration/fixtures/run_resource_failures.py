#!/usr/bin/env python3
"""Actual candidate PG-stream OOM/ENOSPC, exact owned rootless fixtures only."""
import argparse, datetime, json, math, os, secrets, threading, time, traceback
from pathlib import Path
from run_resource_probe import Probe, PG, worker_owned, sha, utc, kv_numbers


def event_bounds(start,end):
    since=math.floor(datetime.datetime.fromisoformat(start.replace('Z','+00:00')).timestamp())
    until=math.ceil(datetime.datetime.fromisoformat(end.replace('Z','+00:00')).timestamp())
    return str(since),str(until)


def source_dump_exec_seen(events):
    return any('pg_dump' in str(e.get('Action','')) or 'pg_dump' in str(e.get('Actor',{}).get('Attributes',{}).get('execCommand','')) for e in events)


def minimal_space_probe(directory):
    stat=os.statvfs(directory)
    row={'at':utc(),'capacity_bytes':stat.f_blocks*stat.f_frsize,'available_bytes':stat.f_bavail*stat.f_frsize,'free_bytes':stat.f_bfree*stat.f_frsize,'errno':0,'attempt_bytes':1}
    path=Path(directory)/('.owned-space-probe-'+str(os.getpid())+'-'+str(threading.get_ident()))
    fd=None
    try:
        fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
        assert os.write(fd,b'x')==1
    except OSError as exc:
        row['errno']=exc.errno
        if exc.errno!=28:raise
    finally:
        if fd is not None:os.close(fd)
        path.unlink(missing_ok=True)
    return row


def assert_failure_proof(p):
    assert p['status']=='failed' and not p['complete']
    if p['owner_released']:
        assert p['worker_terminal'] and p['exec_terminal'] and p['session_count']==0
    else:
        assert p['guard_blocked']


class FailureProbe(Probe):
    def create(self,suffix,spec,role=None,start=True):
        if getattr(self,'repo_volume',None) and spec.get('Image')==self.image and role in ['controller','scheduler']:
            spec.setdefault('HostConfig',{}).setdefault('Mounts',[]).append({'Type':'volume','Source':self.repo_volume,'Target':'/repository','ReadOnly':False})
        return super().create(suffix,spec,role,start)

    def observe_fast(self,stop):
        seen={}
        while not stop.wait(.005):
            try:
                if self.args.mode=='enospc' and getattr(self,'repository_probe_path',None):
                    self.result['repository_space_samples'].append(minimal_space_probe(self.repository_probe_path))
                path=self.root/'state/owner.json'
                if not path.exists():continue
                owner=json.loads(path.read_text());cid=owner.get('workerContainerID')
                self.result['owner_history'].append({'at':utc(),'owner':owner}) if owner!=getattr(self,'last_owner',None) else None
                self.last_owner=owner
                if not cid:continue
                if cid not in seen:
                    w=self.e.inspect(cid,missing=True)
                    if not w or not worker_owned(w,owner,self.image,self.daemon):continue
                    seen[cid]=True
                w=self.e.inspect(cid,missing=True)
                if not w:continue
                self.result['worker_last_inspect']={k:w[k] for k in ['Id','Image','Name','State','HostConfig','Mounts']}
                pid=w['State']['Pid'];cg=self.cgroup(pid) if pid else None
                if not cg or cid not in str(cg):continue
                row={'at':utc(),'container':cid}
                for f in ['cpu.max','memory.max','memory.current','memory.peak','memory.events']:
                    try:row[f]=(cg/f).read_text().strip()
                    except OSError as exc:
                        if exc.errno not in [2,3,19]:raise
                self.result['failure_cgroup_samples'].append(row)
                for p in self.pids(pid):
                    if self.cgroup(p)!=cg:continue
                    try:
                        comm=Path(f'/proc/{p}/comm').read_text().strip()
                        if comm!='restic':continue
                        env=Path(f'/proc/{p}/environ').read_bytes().split(b'\0')
                        value=[v.decode() for v in env if v.startswith(b'GOMAXPROCS=')]
                        record={'comm':comm,'pid':p,'GOMAXPROCS':value,'affinity':sorted(os.sched_getaffinity(p))}
                        if record not in self.result['restic_effective_env']:self.result['restic_effective_env'].append(record)
                    except (FileNotFoundError,ProcessLookupError,PermissionError):pass
            except (FileNotFoundError,KeyError,json.JSONDecodeError):pass
            except Exception as exc:
                self.result.setdefault('fast_observer_errors',[]).append(repr(exc))

    def run(self):
        self.result['mode']=self.args.mode
        frozen=self.root/'executed_failure_probe.py';frozen.write_bytes(Path(__file__).read_bytes())
        self.result['failure_probe_sha256']=sha(frozen)
        self.result['repository_space_samples']=[]
        self.result['owner_history']=[];self.result['failure_cgroup_samples']=[];self.result['restic_effective_env']=[]
        self.repo_volume=self.prefix+'-bounded-repository'
        size=128*1024*1024 if self.args.mode.startswith('oom') else 8*1024*1024
        vol=self.e.call('POST','/volumes/create',{'Name':self.repo_volume,'Driver':'local','DriverOpts':{'type':'tmpfs','device':'tmpfs','o':'size='+str(size)},'Labels':{'probe.bakabel.owner':self.prefix}})
        self.volumes.append(self.repo_volume)
        keeper=self.create('repo-keeper',{'Image':PG,'Entrypoint':['sh','-c'],'Cmd':['while :; do sleep 3600; done'],'HostConfig':{'Mounts':[{'Type':'volume','Source':self.repo_volume,'Target':'/repository','ReadOnly':False}]}},role='repository-fixture')
        mount=next(m for m in self.e.inspect(keeper)['Mounts'] if m['Destination']=='/repository')
        assert mount['Name']==self.repo_volume and mount['Source']==vol['Mountpoint']
        fs=self.e.exec(keeper,['sh','-c','stat -f -c "%T %S %b %a" /repository; df -k /repository'])
        assert fs['exit']==0 and 'tmpfs' in fs['stdout']
        self.result['bounded_repository']={'volume_inspect':vol,'keeper_mount':mount,'requested_bytes':size,'filesystem_before':fs}
        keeper_pid=self.e.inspect(keeper)['State']['Pid']
        assert keeper in str(self.cgroup(keeper_pid))
        self.repository_probe_path=Path(f'/proc/{keeper_pid}/root/repository')
        assert os.statvfs(self.repository_probe_path).f_blocks*os.statvfs(self.repository_probe_path).f_frsize==size
        self.repository='/repository'
        init=self.create('repo-init',{'Image':self.image,'Entrypoint':['/usr/bin/restic'],'Cmd':['--no-cache','init'],'Env':['RESTIC_REPOSITORY=/repository','RESTIC_PASSWORD_FILE=/password','GOMAXPROCS=2'],'HostConfig':{'Mounts':[{'Type':'volume','Source':self.repo_volume,'Target':'/repository','ReadOnly':False},self.bind(self.root/'private/password','/password',True)],'ReadonlyRootfs':True,'Tmpfs':{'/tmp':'rw,nosuid,nodev,size=67108864'}}},role='operator-restic')
        self.finish(init)
        pg=self.startpg('pg',True)
        self.sql(pg,"CREATE ROLE fixture_owner; CREATE TABLE payload AS SELECT g, md5(g::text)||md5((g*17)::text)||md5((g*31)::text)||md5((g*47)::text) AS data FROM generate_series(1,200000) g; ALTER TABLE payload OWNER TO fixture_owner; ALTER DATABASE fixture OWNER TO fixture_owner; REVOKE CONNECT ON DATABASE fixture FROM PUBLIC; CREATE TABLE availability_probe(n bigint)")
        identity={'StartedAt':self.e.inspect(pg)['State']['StartedAt'],'RestartCount':self.e.inspect(pg)['RestartCount']}
        self.result['source_before']={'container':pg,**identity,'stats':self.source_stats(pg)}
        self.config(timeout='45s')
        cp=self.root/'config.yaml'
        cp.write_text(cp.read_text()+('worker_resources:\n  cpus: 2\n  memory_mib: '+str(self.args.memory_mib)+'\n' if self.args.mode=='oom' else 'worker_resources:\n  cpus: 0\n  memory_mib: 0\n'))
        self.lock(pg)
        observer_stop=threading.Event();observer=threading.Thread(target=self.observe_fast,args=(observer_stop,),daemon=True);observer.start()
        try:
            controller=self.controller('run')
            if self.args.mode=='oom':
                self.finish(controller,expect=1,timeout=20)
                self.wait(lambda:self.result.get('worker_last_inspect',{}).get('State',{}).get('Running') is False,3,'early OOM worker terminal observation')
                owners=[x['owner'] for x in self.result['owner_history']]
                assert owners and all(o['phase']=='intent' and not o.get('execID') and not o.get('sourceContainerID') for o in owners)
                assert max(kv_numbers(r.get('memory.events','')).get('oom_kill',0) for r in self.result['failure_cgroup_samples'])>0
                assert all(r['memory.max']==str(self.args.memory_mib*1048576) for r in self.result['failure_cgroup_samples'])
                last=self.last();assert last['status']=='failed' and not (self.root/'state/owner.json').exists()
                assert self.sql(pg,"SELECT count(*) FROM pg_stat_activity WHERE application_name='"+last['runID']+"'")=='0'
                from urllib.parse import quote
                since,until=event_bounds(self.result['started_at'],utc())
                raw=self.e.call('GET','/events?since='+since+'&until='+until+'&filters='+quote(json.dumps({'container':[pg],'event':['exec_create','exec_start']})),raw=True)
                events=[json.loads(line) for line in raw.splitlines() if line]
                self.result['source_exec_events']=[{'action':x.get('Action'),'timeNano':x.get('timeNano'),'execCommand':x.get('Actor',{}).get('Attributes',{}).get('execCommand')} for x in events]
                assert not source_dump_exec_seen(events)
                self.result['failure_terminal_proof']={'status':'failed','complete':False,'owner_released':True,'worker_terminal':True,'source_never_started':True,'session_count':0,'last_result':last}
                self.result['early_oom_phase']='intent-before-source-exec'
                self.unlock(pg)
                self.final_readback(keeper,pg,identity)
                self.gate('B5-real-configured-small-cap-OOM-before-source-failed-not-complete')
                return
            active=self.blocked(pg)
            self.wait(lambda:active['workerContainerID'] in self.worker_records,5,'exact worker sample')
            w=self.worker_records[active['workerContainerID']]
            assert w['HostConfig']['Memory']==(self.args.memory_mib if self.args.mode=='oom' else 512)*1048576
            assert w['HostConfig']['NanoCpus']==2000000000 and w['HostConfig']['CpusetCpus']==''
            # Leave real worker running after killing only its initiating controller.
            self.e.call('POST','/containers/'+controller+'/kill?signal=KILL');self.finish(controller,137)
            guard=self.controller('run');self.finish(guard,1)
            assert 'state launcher guard is held' in self.logs(guard)
            self.result['active_before_failure']=active
            self.result['frozen_job_before_failure']=json.loads((self.root/'state/workflow/job.json').read_text())
            released=time.monotonic()
            if self.args.mode=='oom-active':
                update={'Memory':self.args.memory_mib*1048576,'MemorySwap':self.args.memory_mib*2097152}
                reply=self.e.call('POST','/containers/'+active['workerContainerID']+'/update',update)
                self.result['injected_memory_update']={'exact_worker':active['workerContainerID'],'request':update,'reply':reply,'at':utc()}
                self.result['updated_worker_hostconfig']=self.e.inspect(active['workerContainerID'])['HostConfig']
            else:
                # Controlled ENOSPC fault on ONLY the exact inspected 8MiB tmpfs.
                # Start after real source exec/Restic pipeline lock-wait is proven.
                self.result['enospc_fill_started_at']=utc()
                filler=self.repository_probe_path/'.owned-enospc-filler'
                filled=0
                with filler.open('xb',buffering=0) as f:
                    while filled<=size:
                        try:filled+=f.write(b'\0'*4096)
                        except OSError as exc:
                            assert exc.errno==28;break
                    else:raise AssertionError('bounded tmpfs did not reach ENOSPC')
                self.result['enospc_filler_bytes']=filled
                direct=minimal_space_probe(self.repository_probe_path)
                assert direct['errno']==28 and direct['capacity_bytes']==size and direct['available_bytes']==0
                self.result['enospc_direct_write_before_release']=direct
                self.unlock(pg)
            terminal=self.wait(lambda:(lambda v:v if not v['State']['Running'] else None)(self.e.inspect(active['workerContainerID'])),65,'worker actual terminal')
            self.result['worker_terminal_before_recovery']={k:terminal[k] for k in ['Id','Image','Name','State','HostConfig','Mounts']}
            self.result['worker_failure_logs']=self.logs(active['workerContainerID'])
            assert terminal['State']['ExitCode']!=0
            recover=self.controller('serve')
            self.wait(lambda:(self.root/'state/last-result.json').exists() and self.last()['runID']==active['runID'] and self.last()['status']=='failed' and not (self.root/'state/owner.json').exists(),35,'ordinary serve bounded recovery')
            self.stop(recover)
            recovered=[json.loads(s)['result'] for s in self.logs(recover).splitlines() if s.startswith('{') and json.loads(s).get('event')=='run_finished']
            self.result['recovery']={'rows':recovered,'seconds_after_unlock':time.monotonic()-released,'log':self.logs(recover)}
            owner=self.root/'state/owner.json';result=self.last()
            execproof=self.e.call('GET','/exec/'+active['execID']+'/json')
            sessions=int(self.sql(pg,"SELECT count(*) FROM pg_stat_activity WHERE application_name='"+active['runID']+"'"))
            proof={'status':result['status'],'complete':any(x.get('status')=='complete' for r in recovered for x in r.get('targets',[])),'owner_released':not owner.exists(),'worker_terminal':not terminal['State']['Running'],'exec_terminal':not execproof['Running'],'session_count':sessions,'guard_blocked':True}
            assert_failure_proof(proof)
            assert result.get('lastBackupSuccessAt') in [None,'0001-01-01T00:00:00Z']
            assert self.e.inspect(active['workerContainerID'],missing=True) is None
            self.result['failure_terminal_proof']={**proof,'last_result':result,'exec':{k:execproof[k] for k in ['ID','Running','ExitCode','Pid']},'worker_removed':True}
            expected=str((self.args.memory_mib if self.args.mode.startswith('oom') else 512)*1048576)
            rows=self.result['failure_cgroup_samples'];assert rows and all(r.get('cpu.max')=='200000 100000' for r in rows)
            assert expected in {r.get('memory.max') for r in rows}
            if self.args.mode.startswith('oom'):
                oom=max(kv_numbers(r.get('memory.events','')).get('oom_kill',0) for r in rows)
                assert oom>0, 'No observed real cgroup oom_kill event'
                self.result['oom_kill_max']=oom
            else:
                full=[r for r in self.result['repository_space_samples'] if r['errno']==28]
                assert full and all(r['capacity_bytes']==size and r['available_bytes']==0 for r in full), 'No real same-repository ENOSPC observed in backup window'
                self.result['enospc_proof']={'observations':len(full),'first':full[0],'last':full[-1],'worker_repository_source':next(m['Source'] for m in terminal['Mounts'] if m['Destination']=='/repository'),'repository_mountpoint':mount['Source']}
                assert self.result['enospc_proof']['worker_repository_source']==mount['Source']
            if self.args.mode=='oom-active':self.unlock(pg)
            else:
                self.result['repository_full_after_exact_terminal_proof']=minimal_space_probe(self.repository_probe_path)
                assert self.result['repository_full_after_exact_terminal_proof']['errno']==28
                (self.repository_probe_path/'.owned-enospc-filler').unlink()
                self.result['pressure_released_after_exact_terminal_proof_at']=utc()
            self.final_readback(keeper,pg,identity)
            self.checkpoint('after-real-'+self.args.mode)
            self.gate('B5-real-'+self.args.mode+'-failed-not-complete-exact-source-terminal-bounded-recovery')
        finally:
            observer_stop.set();observer.join(10)

    def final_readback(self,keeper,pg,identity):
            self.result['bounded_repository']['filesystem_after']=self.e.exec(keeper,['sh','-c','stat -f -c "%T %S %b %a" /repository; df -k /repository; du -sk /repository'])
            snapshot_reader=self.create('repo-snapshots',{'Image':self.image,'Entrypoint':['/usr/bin/restic'],'Cmd':['--no-cache','snapshots','--json'],'Env':['RESTIC_REPOSITORY=/repository','RESTIC_PASSWORD_FILE=/password','GOMAXPROCS=2'],'HostConfig':{'Mounts':[{'Type':'volume','Source':self.repo_volume,'Target':'/repository','ReadOnly':False},self.bind(self.root/'private/password','/password',True)],'ReadonlyRootfs':True,'Tmpfs':{'/tmp':'rw,nosuid,nodev,size=67108864'}}},role='operator-restic')
            snapshot_rows=self.finish(snapshot_reader)
            assert snapshot_rows==[], snapshot_rows
            raw_snapshots=json.loads(self.logs(snapshot_reader));assert raw_snapshots==[]
            self.result['snapshots_after_failure']=raw_snapshots
            self.sql(pg,'INSERT INTO availability_probe VALUES (1)');assert self.sql(pg,'SELECT count(*) FROM availability_probe')=='1'
            obj=self.e.inspect(pg);assert {'StartedAt':obj['State']['StartedAt'],'RestartCount':obj['RestartCount']}==identity
            self.result['source_after']={'identity_unchanged':True,'read_write_ok':True,'stats':self.source_stats(pg)}


def main():
    a=argparse.ArgumentParser(description=__doc__)
    a.add_argument('--source',type=Path,required=True);a.add_argument('--runtime',type=Path,required=True)
    a.add_argument('--minio-binary',type=Path,required=True,help='Fingerprint only; not launched')
    a.add_argument('--image',required=True);a.add_argument('--socket',type=Path)
    a.add_argument('--mode',choices=['oom','oom-active','enospc'],required=True);a.add_argument('--memory-mib',type=int,default=32)
    args=a.parse_args();assert 16<=args.memory_mib<=128;os.sched_setaffinity(0,{0,1});p=FailureProbe(args);code=1
    try:p.run();code=0
    except Exception:p.result['error']=traceback.format_exc();print(p.result['error'],flush=True)
    finally:
        try:p.cleanup()
        except Exception:print('CLEANUP ERROR',traceback.format_exc(),flush=True);code=1
    return code

if __name__=='__main__':raise SystemExit(main())
