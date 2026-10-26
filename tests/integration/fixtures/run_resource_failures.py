#!/usr/bin/env python3
"""Actual candidate PG-stream OOM/ENOSPC, exact owned rootless fixtures only."""
import argparse, datetime, json, math, os, secrets, select, threading, time, traceback
from pathlib import Path
from run_resource_probe import Engine, Probe, PG, worker_owned, sha, utc, kv_numbers


# Fixed diagnostic vocabulary. Never persist arbitrary exception text, source,
# locals, paths or dynamic class/function names, even in the private receipt.
_OBSERVER_CODES=('observer_failure','kernel_reader_failure','observer_shutdown','sampler_failure')
_OBSERVER_TYPES=('AssertionError','OSError','FileNotFoundError','ProcessLookupError','PermissionError',
                 'TimeoutError','RuntimeError','ValueError','KeyError','JSONDecodeError','UnicodeDecodeError')
_OBSERVER_REASONS=('worker_identity','cgroup_identity','kernel_counter_size')
_OBSERVER_FUNCTIONS={
    'run_resource_failures.py':('observe_fast','sample_failure_cgroup','terminal_reinspection','read','stop_failure_observers','call'),
    'run_resource_probe.py':('sampler','measure','cgroup_sample','sampling_identity','valid_kernel_readback',
        'pin_container','cgroup','pids','proc','footprint','call','inspect','_set_remaining','connect','sendall','recv_into','<dictcomp>','<listcomp>'),
}


def observer_error_fields(value):
    """Re-project untrusted receipt rows using only finite, typed fields."""
    if not isinstance(value,dict):value={}
    def enum(item,allowed):return item if isinstance(item,str) and item in allowed else None
    number=value.get('errno')
    out={'code':enum(value.get('code'),_OBSERVER_CODES),'type':enum(value.get('type'),_OBSERVER_TYPES),
         'reason':enum(value.get('reason'),_OBSERVER_REASONS),
         'errno':number if type(number) is int and 0<=number<=4095 else None,'frames':[]}
    frames=value.get('frames',[])
    for frame in frames[-8:] if isinstance(frames,list) else []:
        if not isinstance(frame,dict):continue
        file=frame.get('file');function=frame.get('function');line=frame.get('line')
        known=(isinstance(file,str) and file in _OBSERVER_FUNCTIONS and isinstance(function,str) and function in _OBSERVER_FUNCTIONS[file])
        out['frames'].append({'file':file if known else None,'function':function if known else None,
                              'line':line if known and type(line) is int and 0<line<=1000000 else None})
    return out


def observer_exception(code,exc=None):
    frames=[]
    if exc is not None:
        # Match actual known module paths, not an arbitrary basename lookalike.
        known={str(Path(__file__).with_name(name)):name for name in _OBSERVER_FUNCTIONS}
        tb=exc.__traceback__
        while tb is not None:
            frame=tb.tb_frame
            frames.append({'file':known.get(frame.f_code.co_filename),'function':frame.f_code.co_name,'line':tb.tb_lineno})
            del frames[:-8];tb=tb.tb_next
    args=getattr(exc,'args',())
    return observer_error_fields({'code':code,'type':type(exc).__name__ if exc is not None else None,
        'reason':args[0] if type(exc) is AssertionError and args else None,
        'errno':getattr(exc,'errno',None),'frames':frames})


class _ObserverErrors(list):
    """Retain first 32 errors and total count; truncation never clears failure."""
    def __init__(self,result,key,code):
        super().__init__();self.result=result;self.key=key;self.code=code;self.lock=threading.Lock()

    def append(self,value):
        row=observer_error_fields(value)
        if row['code'] is None:row['code']=self.code
        with self.lock:
            self.result[self.key+'_count']=min(2**63-1,self.result.get(self.key+'_count',0)+1)
            if len(self)<32:super().append(row)


class _ObserverStopped(BaseException):
    """End a sampler pass without turning requested shutdown into corruption."""


class _SamplerEngine(Engine):
    def __init__(self,sock,stop):
        super().__init__(sock);self.observer=threading.get_ident();self.stop=stop

    def call(self,*args,deadline=None,**kwargs):
        if threading.get_ident()==self.observer:
            if self.stop.is_set():raise _ObserverStopped()
            deadline=min(deadline,time.monotonic()+1) if deadline is not None else time.monotonic()+1
        return super().call(*args,deadline=deadline,**kwargs)


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


def assert_oom_proof(rows,state):
    counts=[kv_numbers(row.get('memory.events','')).get('oom_kill') for row in rows]
    observed=[count for count in counts if count is not None]
    assert observed and max(observed)>0, 'No observed real cgroup oom_kill event'
    assert state.get('OOMKilled') is True, 'No terminal OOMKilled proof'
    return max(observed)


class FailureProbe(Probe):
    def observer_errors(self,key):
        code='sampler_failure' if key=='sampler_errors' else 'observer_failure'
        return self.result.setdefault(key,_ObserverErrors(self.result,key,code))

    def sampler(self):
        self.observer_errors('sampler_errors')
        self.e=_SamplerEngine(self.sock,self.stopped)
        try:super().sampler()
        except _ObserverStopped:pass

    def save(self):
        observers=list(getattr(self,'_failure_observers',[]))
        if hasattr(self,'thread'):observers.append((self.stopped,self.thread))
        if any(thread.is_alive() for stop,thread in observers):raise ValueError('observer_not_quiescent')
        super().save()

    def cleanup(self):
        self.stop_failure_observers()
        super().cleanup()

    def gate(self,name,**kwargs):
        self.stop_failure_observers()
        assert not self.result.get('fast_observer_errors') and not self.result.get('sampler_errors'), 'observer_failure'
        super().gate(name,**kwargs)

    def create(self,suffix,spec,role=None,start=True):
        if getattr(self,'repo_volume',None) and spec.get('Image')==self.image and role in ['controller','scheduler']:
            spec.setdefault('HostConfig',{}).setdefault('Mounts',[]).append({'Type':'volume','Source':self.repo_volume,'Target':'/repository','ReadOnly':False})
        return super().create(suffix,spec,role,start)

    def sample_failure_cgroup(self,worker,owner,*,deadline=None,_settling=False):
        """Keep the validated kernel directory identity through terminal Pid=0."""
        def check_deadline():
            assert deadline is None or time.monotonic()<deadline, 'cgroup_identity'
        check_deadline()
        assert worker_owned(worker,owner,self.image,self.daemon), 'worker_identity'
        cid=owner['workerContainerID'];pid=worker['State']['Pid']
        cached=self._cgroup_identities.get(cid)
        row={'at':utc(),'container':cid,'observer_pid':pid,'counter_status':'unavailable','memory.events':''}
        def terminal_reinspection():
            if _settling:return None
            assert cached and pid==cached[3], 'cgroup_identity'
            bound=min(deadline,time.monotonic()+1) if deadline is not None else time.monotonic()+1
            # Same finite settle as the shared sampler: at most 20 exact
            # inspections, one absolute I/O budget, no product deadline change.
            for index in range(20):
                if index:time.sleep(min(.05,max(0,bound-time.monotonic())))
                assert time.monotonic()<bound, 'cgroup_identity'
                after=self.e.inspect(cid,missing=True,deadline=bound)
                assert time.monotonic()<bound, 'cgroup_identity'
                assert after and worker_owned(after,owner,self.image,self.daemon), 'worker_identity'
                assert after['State'].get('StartedAt')==worker['State'].get('StartedAt'), 'worker_identity'
                if after['State']['Running'] is False:
                    assert after['State']['Pid']==0, 'cgroup_identity'
                    return self.sample_failure_cgroup(after,owner,deadline=bound)
                assert after['State']['Running'] is True and after['State']['Pid']==pid, 'cgroup_identity'
                fresh=self.sample_failure_cgroup(after,owner,deadline=bound,_settling=True)
                if fresh is not None:return fresh
            raise AssertionError('cgroup_identity')
        def live_cgroup():
            check_deadline()
            try:return self.cgroup(pid,strict=True)
            except OSError as exc:
                if exc.errno not in (2,3,19):raise
                return None
            finally:check_deadline()
        cg=live_cgroup() if pid else (cached[0] if cached else None)
        if pid:
            if cg is None:return terminal_reinspection()
            assert cid in str(cg), 'cgroup_identity'
            if cached:assert (cg,pid)==(cached[0],cached[3]), 'cgroup_identity'
        if cg is not None:
            check_deadline()
            try:
                stat=cg.stat();check_deadline();identity=(stat.st_dev,stat.st_ino)
                if cached:assert identity==cached[1:3], 'cgroup_identity'
                elif pid:self._cgroup_identities[cid]=(cg,*identity,pid)
                for name in ['cpu.max','memory.max','memory.swap.max','memory.current','memory.peak','memory.events']:
                    check_deadline()
                    try:row[name]=(cg/name).read_text().strip()
                    except OSError as exc:
                        if exc.errno not in ((2,3,19) if pid else (2,3,13,19)):raise
                        row.setdefault('unavailable_errno',{})[name]=exc.errno
                    finally:check_deadline()
                if 'oom_kill' in kv_numbers(row['memory.events']):row['counter_status']='observed'
            except OSError as exc:
                if exc.errno not in ((2,3,19) if pid else (2,3,13,19)):raise
                row['cgroup_errno']=exc.errno
            finally:check_deadline()
        if pid and (row['counter_status']!='observed' or any(name not in row for name in ('cpu.max','memory.max','memory.swap.max'))):
            return terminal_reinspection()
        if _settling:
            # A live recovery is fresh kernel evidence, never a cached/partial
            # row; reject replacement paths/inodes even during the file reads.
            assert cached is not None, 'cgroup_identity'
            number=lambda value:bool(value) and value.isascii() and value.isdecimal()
            cpu=row['cpu.max'].split()
            assert len(cpu)==2 and number(cpu[1]) and int(cpu[1])>0 and (cpu[0]=='max' or number(cpu[0])), 'cgroup_identity'
            assert all(row[name]=='max' or number(row[name]) for name in ('memory.max','memory.swap.max')), 'cgroup_identity'
            events=[line.split() for line in row['memory.events'].splitlines()]
            assert events and all(len(fields)==2 and number(fields[1]) for fields in events), 'cgroup_identity'
            try:stat=cg.stat()
            except OSError as exc:
                if exc.errno not in (2,3,19):raise
                return None  # Still a gap; the outer bounded exact inspection must resolve it.
            resolved=live_cgroup()
            if resolved is None:return None
            assert resolved==cg and (stat.st_dev,stat.st_ino)==cached[1:3], 'cgroup_identity'
            assert deadline is not None and time.monotonic()<deadline, 'cgroup_identity'
        # Keep unavailable terminal reads explicitly, outside the verifier's
        # actual CPU-limit sample set; never fill missing fields from old rows.
        check_deadline()
        if not pid:self.result['terminal_cgroup_sample']=row
        if 'cpu.max' in row:self.result['failure_cgroup_samples'].append(row)
        return row

    def arm_kernel_counter(self,worker,owner):
        """Open only the exact validated cgroup files, before the destructive POST.

        The reader never calls Engine, resolves /proc, or reopens a pathname.
        Each limit attached to a counter is an actual FD read, not a cached limit.
        """
        cid=owner['workerContainerID'];cached=self._cgroup_identities.get(cid)
        assert worker_owned(worker,owner,self.image,self.daemon) and cached, 'worker_identity'
        cg,dev,ino,pid=cached
        assert worker['State']['Running'] is True and worker['State']['Pid']==pid, 'cgroup_identity'
        assert not getattr(self,'_kernel_counter_thread',None), 'kernel_reader_already_armed'
        directory=None;fds={}
        try:
            directory=os.open(cg,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            stat=os.fstat(directory);assert (stat.st_dev,stat.st_ino)==(dev,ino), 'cgroup_identity'
            for name in ('cpu.max','memory.max','memory.swap.max','memory.events'):
                fd=os.open(name,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW,dir_fd=directory);fds[name]=fd
                opened=os.fstat(fd);linked=os.stat(name,dir_fd=directory,follow_symlinks=False)
                assert (opened.st_dev,opened.st_ino)==(linked.st_dev,linked.st_ino), 'cgroup_identity'
            stat=cg.stat();assert (stat.st_dev,stat.st_ino)==(dev,ino), 'cgroup_identity'
        except BaseException:
            for fd in fds.values():os.close(fd)
            raise
        finally:
            if directory is not None:os.close(directory)
        stop=threading.Event();ready=threading.Event()
        def read():
            previous=None
            try:
                poll=select.poll();poll.register(fds['memory.events'],select.POLLPRI|select.POLLERR)
                while True:
                    row={'container':cid,'observer_pid':pid,'counter_status':'unavailable','memory.events':''}
                    for name,fd in fds.items():
                        try:
                            data=os.pread(fd,4097,0)
                            assert len(data)<=4096, 'kernel_counter_size'
                            row[name]=data.decode().strip()
                        except OSError as exc:
                            if exc.errno not in (2,3,13,19):raise
                            row.setdefault('unavailable_errno',{})[name]=exc.errno
                    if 'oom_kill' in kv_numbers(row['memory.events']):row['counter_status']='observed'
                    if row!=previous:
                        previous=row.copy();row['at']=utc()
                        self.result['kernel_counter_sample']=row
                        if 'cpu.max' in row:self.result['failure_cgroup_samples'].append(row)
                    ready.set()
                    if stop.is_set():break
                    poll.poll(2)
                    if row['counter_status']=='unavailable':stop.wait(.002)
            except Exception as exc:
                self.observer_errors('fast_observer_errors').append(observer_exception('kernel_reader_failure',exc))
            finally:
                for fd in fds.values():os.close(fd)
                ready.set()
        thread=threading.Thread(target=read,name='failure-kernel-counter',daemon=True)
        self._kernel_counter_thread=thread
        self._failure_observers=getattr(self,'_failure_observers',[])+[(stop,thread)]
        thread.start()
        assert ready.wait(1) and thread.is_alive() and self.result.get('kernel_counter_sample',{}).get('counter_status')=='observed', 'kernel_reader_unavailable'
        self.result['kernel_counter_armed']=True

    def stop_failure_observers(self):
        observers=list(getattr(self,'_failure_observers',[]))
        if hasattr(self,'thread'):observers.append((self.stopped,self.thread))
        for stop,thread in observers:stop.set()
        deadline=time.monotonic()+3
        for stop,thread in observers:thread.join(max(0,deadline-time.monotonic()))
        if any(thread.is_alive() for stop,thread in observers):
            self.observer_errors('fast_observer_errors').append(observer_exception('observer_shutdown'))
            raise ValueError('observer_shutdown')

    def activate_oom(self,pg,active):
        """Reduce only the proven lock-waiting worker, then permit real dump flow."""
        assert self.args.memory_mib==16
        assert self.blocked(pg)==active, 'active_identity'
        cid=active['workerContainerID'];before=self.e.inspect(cid)
        assert worker_owned(before,active,self.image,self.daemon), 'worker_identity'
        self.sample_failure_cgroup(before,active)
        self.arm_kernel_counter(before,active)
        update={'Memory':16777216,'MemorySwap':16777216}
        diagnostic=self.result.setdefault('failure_diagnostics',{})
        diagnostic.update(failure_code='memory_update',requested_memory_bytes=update['Memory'],requested_swap_total_bytes=update['MemorySwap'],update_status='unavailable')
        try:reply=self.e.call('POST','/containers/'+cid+'/update',update)
        except Exception as exc:
            status=getattr(exc,'http_status',None)
            diagnostic.update(update_status='rejected',update_http_status=status if type(status) is int and 100<=status<=599 else None)
            # A limit update may kill the worker before Engine returns an error.
            # Observe it now, without recovery or treating it as a successful fault.
            try:
                terminal=self.e.inspect(cid,missing=True)
                if terminal and terminal['State']['Running'] is False:self.wait_failure_terminal(active,terminal)
            except Exception:diagnostic['terminal_counter_status']='unavailable'
            raise
        diagnostic.update(update_status='accepted',warning_count=len(reply.get('Warnings') or []),failure_code='effective_limits')
        self.result['injected_memory_update']={'exact_worker':cid,'request':update,'at':utc()}
        after=self.e.inspect(cid)
        assert worker_owned(after,active,self.image,self.daemon), 'worker_identity'
        config=after['HostConfig'];self.result['updated_worker_hostconfig']=config
        row=self.sample_failure_cgroup(after,active)
        def number(key):
            value=row.get(key,'')
            return int(value) if value.isdecimal() else None
        diagnostic.update(host_memory_bytes=config.get('Memory'),host_swap_total_bytes=config.get('MemorySwap'),
                          effective_memory_bytes=number('memory.max'),effective_swap_bytes=number('memory.swap.max'))
        assert config['Memory']==update['Memory'] and config['MemorySwap']==update['MemorySwap'], 'effective_limits'
        assert diagnostic['effective_memory_bytes']==update['Memory'] and diagnostic['effective_swap_bytes']==0, 'effective_limits'
        self.unlock(pg)
        diagnostic.update(source_unlocked=True,failure_code='worker_terminal')

    def wait_failure_terminal(self,active,terminal=None):
        if terminal is None:terminal=self.wait(lambda:(lambda v:v if not v['State']['Running'] else None)(self.e.inspect(active['workerContainerID'])),65,'worker actual terminal')
        row=self.sample_failure_cgroup(terminal,active)
        self.result['worker_terminal_before_recovery']={k:terminal[k] for k in ['Id','Image','Name','HostConfig','Mounts']}
        state=terminal['State']
        self.result['worker_terminal_before_recovery']['State']={k:state[k] for k in ['Status','Running','Pid','ExitCode','OOMKilled','StartedAt','FinishedAt'] if k in state}
        diagnostic=self.result.setdefault('failure_diagnostics',{})
        diagnostic.update(terminal_pid=state.get('Pid'),terminal_exit_code=state.get('ExitCode'),terminal_oom_killed=state.get('OOMKilled'),
                          terminal_counter_status=row['counter_status'],terminal_oom_kill=kv_numbers(row['memory.events']).get('oom_kill'),targets=[])
        path=self.root/'state/workflow/output/result.json'
        try:
            if path.stat().st_size<=262144:
                value=json.loads(path.read_text())
                if isinstance(value,dict) and value.get('runID')==active['runID']:
                    targets=value.get('targets',[])
                    if isinstance(targets,list) and len(targets)<=128:
                        for target in targets:
                            if not isinstance(target,dict):continue
                            def enum(key,allowed):
                                item=target.get(key)
                                return item if isinstance(item,str) and item in allowed else None
                            code=target.get('resticExitCode')
                            diagnostic['targets'].append({'failureCode':enum('failureCode',('file_preflight','list_before','backup','list_after','source_verification','tag','final_readback','metadata_readback')),
                                'resticExitCode':code if type(code) is int and 0<=code<=255 else None,
                                'resticReason':enum('resticReason',('enospc','permission','backend','unknown'))})
        except (OSError,ValueError):pass
        return terminal

    def observe_fast(self,stop):
        seen={}
        while not stop.wait(.005):
            deadline=time.monotonic()+1
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
                    w=self.e.inspect(cid,missing=True,deadline=deadline)
                    if not w or not worker_owned(w,owner,self.image,self.daemon):continue
                    seen[cid]=True
                w=self.e.inspect(cid,missing=True,deadline=deadline)
                if not w:continue
                self.result['worker_last_inspect']={k:w[k] for k in ['Id','Image','Name','HostConfig','Mounts']}
                self.result['worker_last_inspect']['State']={k:w['State'][k] for k in ['Status','Running','Pid','ExitCode','OOMKilled','StartedAt','FinishedAt'] if k in w['State']}
                row=self.sample_failure_cgroup(w,owner,deadline=deadline)
                pid=w['State']['Pid'];cg=self.cgroup(pid) if pid else None
                if not cg:continue
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
                self.observer_errors('fast_observer_errors').append(observer_exception('observer_failure',exc))

    def run(self):
        self.result['mode']=self.args.mode
        self._cgroup_identities={}
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
        observer_stop=threading.Event();observer=threading.Thread(target=self.observe_fast,args=(observer_stop,),daemon=True)
        self._failure_observers=[(observer_stop,observer)];observer.start()
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
                self.activate_oom(pg,active)
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
            terminal=self.wait_failure_terminal(active)
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
                self.result['failure_diagnostics']['failure_code']='oom_proof'
                oom=assert_oom_proof(rows,terminal['State'])
                self.result['oom_kill_max']=oom
            else:
                full=[r for r in self.result['repository_space_samples'] if r['errno']==28]
                assert full and all(r['capacity_bytes']==size and r['available_bytes']==0 for r in full), 'No real same-repository ENOSPC observed in backup window'
                self.result['enospc_proof']={'observations':len(full),'first':full[0],'last':full[-1],'worker_repository_source':next(m['Source'] for m in terminal['Mounts'] if m['Destination']=='/repository'),'repository_mountpoint':mount['Source']}
                assert self.result['enospc_proof']['worker_repository_source']==mount['Source']
            if self.args.mode!='oom-active':
                self.result['repository_full_after_exact_terminal_proof']=minimal_space_probe(self.repository_probe_path)
                assert self.result['repository_full_after_exact_terminal_proof']['errno']==28
                (self.repository_probe_path/'.owned-enospc-filler').unlink()
                self.result['pressure_released_after_exact_terminal_proof_at']=utc()
            self.final_readback(keeper,pg,identity)
            self.stop_failure_observers()
            self.checkpoint('after-real-'+self.args.mode)
            self.gate('B5-real-'+self.args.mode+'-failed-not-complete-exact-source-terminal-bounded-recovery')
            self.result['failure_diagnostics']['failure_code']=None
        finally:
            self.stop_failure_observers()

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
    a.add_argument('--mode',choices=['oom','oom-active','enospc'],required=True);a.add_argument('--memory-mib',type=int)
    args=a.parse_args()
    if args.memory_mib is None:args.memory_mib=16 if args.mode=='oom-active' else 32
    assert 16<=args.memory_mib<=128
    if args.mode=='oom-active':assert args.memory_mib==16
    os.sched_setaffinity(0,{0,1});p=FailureProbe(args);code=1
    try:p.run();code=0
    except Exception as exc:p.result['error']=type(exc).__name__;print(p.result['error'],flush=True)
    finally:
        try:p.cleanup()
        except Exception as exc:print('CLEANUP ERROR',type(exc).__name__,flush=True);code=1
    return code

if __name__=='__main__':raise SystemExit(main())
