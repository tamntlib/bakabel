#!/usr/bin/env python3
"""Disposable OUTER-engine B4/B5 probe. No production volumes or file restore.
All runtime paths must be fresh. All mutable targets are exact recorded IDs.
The ordinary worker configuration is never intercepted or changed.
"""
import argparse, datetime, errno, gzip, hashlib, http.client, io, json, os
from pathlib import Path
import secrets, shutil, socket, struct, subprocess, tarfile, threading, time, traceback
from urllib.parse import quote

PG = 'postgres:18.6-alpine3.24'

def worker_owned(obj, owner, image, daemon):
    labels = obj.get('Config', {}).get('Labels') or {}
    return (obj.get('Id') == owner.get('workerContainerID') and
            obj.get('Name') == '/' + owner.get('workerName', '') and
            obj.get('Image') == image and owner.get('daemonID') == daemon and
            labels.get('bakabel.worker') == '1' and
            labels.get('bakabel.run') == owner.get('runID') and
            labels.get('bakabel.daemon') == daemon)

def kv_numbers(text):
    result = {}
    for line in text.splitlines():
        fields = line.split()
        if len(fields) == 2:
            try: result[fields[0]] = int(fields[1])
            except ValueError: pass
    return result

def rollup(text):
    result = {}
    for line in text.splitlines():
        fields = line.split()
        if len(fields) == 3 and fields[2] == 'kB':
            result[fields[0].rstrip(':')] = int(fields[1]) * 1024
    return result

def utc(): return datetime.datetime.now(datetime.timezone.utc).isoformat()
def sha(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for b in iter(lambda:f.read(1024*1024), b''): h.update(b)
    return h.hexdigest()
def footprint(path):
    path = Path(path)
    out = {'files':0,'bytes':0,'allocated_bytes':0,'unlinked_during_sample':0}
    if not path.exists(): return out
    for p in path.rglob('*'):
        if p.is_file():
            try:s = p.stat()
            except FileNotFoundError:
                out['unlinked_during_sample'] += 1
                continue
            out['files'] += 1; out['bytes'] += s.st_size; out['allocated_bytes'] += s.st_blocks*512
    return out

class _DeadlineSocket(socket.socket):
    """Refresh the remaining budget at each HTTP buffered read/write boundary."""
    def __init__(self, deadline):
        super().__init__(socket.AF_UNIX, socket.SOCK_STREAM)
        self.deadline = deadline
    def _set_remaining(self):
        remaining = self.deadline-time.monotonic()
        if remaining <= 0: raise TimeoutError('Engine deadline exceeded')
        self.settimeout(remaining)
    def connect(self, address):
        self._set_remaining()
        return super().connect(address)
    def sendall(self, data, flags=0):
        self._set_remaining()
        return super().sendall(data, flags)
    def recv_into(self, buffer, nbytes=0, flags=0):
        self._set_remaining()
        return super().recv_into(buffer, nbytes, flags)

class Engine:
    def __init__(self, sock): self.sock = str(sock)
    def call(self, method, path, body=None, raw=False, missing=False, *, deadline=None):
        c = http.client.HTTPConnection('localhost', timeout=45)
        c.sock = (socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) if deadline is None
                  else _DeadlineSocket(deadline))
        try:
            c.sock.settimeout(45); c.sock.connect(self.sock)
            c.request(method, '/v1.55'+path, None if body is None else json.dumps(body), {'Content-Type':'application/json'})
            r = c.getresponse(); b = r.read()
            if r.status == 404 and missing: return None
            if r.status >= 300:
                error=RuntimeError('Engine '+method+' '+path+' HTTP '+str(r.status)+': '+b.decode(errors='replace')[:500])
                error.http_status=r.status
                raise error
            return b if raw else (json.loads(b) if b else None)
        finally: c.close()
    def inspect(self, cid, missing=False, *, deadline=None):
        return self.call('GET','/containers/'+cid+'/json',missing=missing,deadline=deadline)
    def exec(self, cid, argv, detached=False, env=None):
        obj = self.call('POST','/containers/'+cid+'/exec',{'Cmd':argv,'AttachStdout':not detached,'AttachStderr':not detached,'Tty':False,'Env':env or []})
        b = self.call('POST','/exec/'+obj['Id']+'/start',{'Detach':detached,'Tty':False},raw=True)
        if detached: return obj['Id']
        stdout, stderr = b'', b''
        while len(b) >= 8:
            stream = b[0]; n = struct.unpack('>I',b[4:8])[0]; chunk, b = b[8:8+n], b[8+n:]
            if stream == 1: stdout += chunk
            else: stderr += chunk
        status = self.call('GET','/exec/'+obj['Id']+'/json')
        return {'exit':status['ExitCode'],'stdout':stdout.decode(errors='replace'),'stderr':stderr.decode(errors='replace')}

class Probe:
    def __init__(self, args, *, inventory_images=None):
        self.args=args; self.root=args.runtime.resolve(); self.root.mkdir(mode=0o700)
        self.prefix='bakabel-b45-'+secrets.token_hex(6)
        sock=args.socket
        if sock is None:
            sock=json.loads(subprocess.check_output(['docker','context','inspect','--format','{{json .Endpoints.docker.Host}}'],text=True)).removeprefix('unix://')
        self.sock=str(sock); self.e=Engine(sock); inf=self.e.call('GET','/info'); self.daemon=inf['ID']
        assert inf['Swarm']['LocalNodeState']=='inactive', 'scope requires currently inactive Swarm'
        self.containers={}; self.volumes=[]; self.roles={}; self.worker_records={}; self.samples=[]; self.stopped=threading.Event()
        self.result={'started_at':utc(),'prefix':self.prefix,'socket':self.sock,'daemon':self.daemon,'swarm_before':inf['Swarm']['LocalNodeState'], 'commands':[], 'gates':[], 'checkpoints':{}, 'cleanup':{}}
        self.image=self.e.call('GET','/images/'+quote(args.image,safe='')+'/json')['Id']
        self.result['images']={}
        for image in (inventory_images if inventory_images is not None else [args.image,PG,'restic/restic:0.18.1','golang:1.26.8-bookworm']):
            v=self.e.call('GET','/images/'+quote(image,safe='')+'/json')
            self.result['images'][image]={'id':v['Id'],'repo_digests':v.get('RepoDigests'),'engine_reported_size_bytes':v['Size'],'size_semantics':'Engine29 containerd store, NOT unpacked size'}
        self.result['fingerprint']={'source_files':{str(f.relative_to(args.source)):sha(f) for f in sorted(args.source.rglob('*')) if f.is_file() and f.suffix in ['.go','.mod','.sum'] and '.git' not in f.parts},'plan_sha256':sha(args.source/'PLAN.md'),'minio_sha256':sha(args.minio_binary)}
        self.result['fingerprint']['dockerfile_sha256']=sha(args.source/'Dockerfile')
        self.result['fingerprint']['probe_sha256']=sha(Path(__file__))
        self.result['affinity_boundary']='PID1 PG gated as root and pinned before stock entrypoint/UID change; root controller/worker/MinIO threads pinned immediately after start and every sample. Rootless cpuset is not relied on; unavoidable create-to-pin startup gaps and short exec lifetimes are not continuous affinity proof. Actual per-container cpu.max=200000 100000 remains enforced.'
        for d in ['private','state','fresh-state','backend','bin']: (self.root/d).mkdir(mode=0o700)
        self.values=[secrets.token_hex(24) for _ in range(3)]
        user,password,rpass=self.values
        for key,value in {'minio-user':user,'minio-password':password,'password':rpass,'aws':f'[default]\naws_access_key_id = {user}\naws_secret_access_key = {password}\n'}.items():
            file=self.root/'private'/key;file.write_text(value);file.chmod(0o600)
        shutil.copy2(args.minio_binary,self.root/'bin/minio')
        self.thread=threading.Thread(target=self.sampler,daemon=True); self.thread.start()
    def gate(self, name, **kw):
        self.result['gates'].append({'name':name,'time':utc(),**kw}); print('PASS '+name,flush=True); self.save()
    def save(self):
        (self.root/'receipt.json').write_text(json.dumps(self.result,indent=2))
    def create(self, suffix, spec, role=None, start=True, *, record_image_volumes=True):
        name=self.prefix+'-'+suffix
        spec.setdefault('Labels',{})['probe.bakabel.owner']=self.prefix
        h=spec.setdefault('HostConfig',{});h.setdefault('NanoCpus',2000000000);h.setdefault('NetworkMode','none');h.setdefault('RestartPolicy',{'Name':'no'});h.setdefault('AutoRemove',False)
        cid=self.e.call('POST','/containers/create?name='+name,spec)['Id']
        self.containers[cid]=name
        self.result.setdefault('container_specs',{})[cid]={'name':name,'spec':spec}
        if role: self.roles[cid]=role
        if start:
            self.e.call('POST','/containers/'+cid+'/start')
            self.pin_container(cid)
        # Legacy probes record inherited image volumes. Strict fault fixtures
        # opt out and verify their explicit mounts before starting the container.
        obj=self.e.inspect(cid)
        for m in obj['Mounts']:
            if record_image_volumes and m['Type']=='volume' and m['Name'] not in self.volumes:self.volumes.append(m['Name'])
        return cid
    def bind(self, src, dst, ro=False): return {'Type':'bind','Source':str(src),'Target':dst,'ReadOnly':ro}
    def pin_container(self,cid):
        v=self.e.inspect(cid,missing=True)
        if not v or not v['State']['Running']: return
        cg=self.cgroup(v['State']['Pid'])
        if cg is None or cid not in str(cg): return
        for pid in self.pids(v['State']['Pid']):
            if self.cgroup(pid)!=cg:continue
            try:
                for tid in (Path('/proc')/str(pid)/'task').iterdir():
                    try:
                        if self.cgroup(int(tid.name))==cg:os.sched_setaffinity(int(tid.name),{0,1})
                    except (ProcessLookupError,PermissionError): pass
            except OSError as exc:
                if exc.errno not in [2,3,19]:raise
    def cgroup(self,pid,*,strict=False):
        try:
            line=Path(f'/proc/{pid}/cgroup').read_text().strip()
            if line.startswith('0::'): return Path('/sys/fs/cgroup')/line[3:].lstrip('/')
        except (FileNotFoundError,ProcessLookupError,PermissionError):
            if strict:raise
        if strict:raise ValueError('exact sampling cgroup unavailable')
        return None
    def pids(self,pid):
        cg=self.cgroup(pid)
        if cg is None:return []
        try:return [int(x) for x in (cg/'cgroup.procs').read_text().split()]
        except OSError as exc:
            # Deleted cgroups report ENODEV as well as ENOENT/ESRCH during
            # short-lived health-container exit. Never pin a fallback stale PID.
            if exc.errno in [2,3,13,19]:return []
            raise
    def proc(self,pid):
        out={'pid':pid}
        try:
            base=Path('/proc')/str(pid)
            status=base.joinpath('status').read_text()
            out['comm']=base.joinpath('comm').read_text().strip()
            out['uid']=next(l.split()[1] for l in status.splitlines() if l.startswith('Uid:'))
            st=base.joinpath('stat').read_text().rsplit(')',1)[1].split()
            out['starttime_ticks']=int(st[19]);out['cpu_ticks']=int(st[11])+int(st[12])
            out['rss_bytes']=int(st[21])*os.sysconf('SC_PAGE_SIZE')
            out['affinities']=sorted({','.join(map(str,sorted(os.sched_getaffinity(int(t.name))))) for t in (base/'task').iterdir()})
            try: out['memory']=rollup(base.joinpath('smaps_rollup').read_text())
            except PermissionError: out['memory_error']='permission denied (not zero)'
            try: out['io']=kv_numbers(base.joinpath('io').read_text())
            except PermissionError: out['io_error']='permission denied'
        except (FileNotFoundError,ProcessLookupError): out['exited_during_sample']=True
        except PermissionError: out['error']='permission denied'
        return out
    def sampling_identity(self, cid, obj):
        state=obj.get('State',{}) if isinstance(obj,dict) else {}
        if (not isinstance(obj,dict) or obj.get('Id')!=cid or
                not isinstance(obj.get('Image'),str) or not obj['Image'] or
                not isinstance(state.get('StartedAt'),str) or not state['StartedAt'] or
                type(state.get('Running')) is not bool or
                (state['Running'] and (type(state.get('Pid')) is not int or state['Pid']<=0))):
            raise ValueError('exact sampling identity unavailable')
        record=self.worker_records.get(cid)
        if record is not None:
            owner={'workerContainerID':cid,'workerName':record['Name'].lstrip('/'),
                   'runID':record['runID'],'daemonID':self.daemon}
            owned=worker_owned(obj,owner,self.image,self.daemon)
        else:
            owned=(cid in self.containers and obj.get('Name')=='/'+self.containers[cid] and
                   (obj.get('Config',{}).get('Labels') or {}).get('probe.bakabel.owner')==self.prefix)
        if not owned:raise ValueError('exact sampling ownership changed')
        return (obj['Id'],obj['Image'],obj['Name'],state['StartedAt'],dict(obj['Config']['Labels']))

    @staticmethod
    def valid_kernel_readback(kernel):
        number=lambda value:bool(value) and value.isascii() and value.isdecimal()
        cpu=kernel['cpu.max'].split()
        if len(cpu)!=2 or not number(cpu[1]) or int(cpu[1])<=0 or not (cpu[0]=='max' or number(cpu[0])):return False
        for key in ['memory.current','memory.peak','memory.max','pids.current']:
            if key=='memory.max' and kernel[key]=='max':continue
            if not number(kernel[key]):return False
        for key,required in [('cpu.stat','usage_usec'),('memory.events','oom_kill')]:
            rows=[line.split() for line in kernel[key].splitlines()]
            if not rows or any(len(row)!=2 or not number(row[1]) for row in rows):return False
            if required not in {row[0] for row in rows}:return False
        for line in kernel['io.stat'].splitlines():
            row=line.split();device=row[0].split(':')
            if len(device)!=2 or not all(number(part) for part in device) or len(row)<2:return False
            for field in row[1:]:
                pair=field.split('=')
                if len(pair)!=2 or not pair[0] or not number(pair[1]):return False
        return True

    def cgroup_sample(self, cid, initial, cg):
        """Settle only a missing kernel observation, never a product deadline."""
        files=['cpu.max','cpu.stat','memory.current','memory.peak','memory.max','memory.events','io.stat','pids.current']
        gap=None;started=0.0;deadline=0.0;inspections=0;identity=None;cg_identity=None
        try:
            while True:
                try:
                    if gap is None:
                        stat=cg.stat();cg_identity=(stat.st_dev,stat.st_ino)
                    else:
                        current=self.cgroup(initial['State']['Pid'],strict=True)
                        if current is None:raise ProcessLookupError(errno.ESRCH,'sampling cgroup missing')
                        if current!=cg:raise ValueError('exact sampling cgroup changed')
                        stat=cg.stat()
                        if (stat.st_dev,stat.st_ino)!=cg_identity:raise ValueError('exact sampling cgroup changed')
                    # Rebuild every field, including limits, after a gap. No
                    # cached/partially read row is evidence of fresh enforcement.
                    kernel={f:cg.joinpath(f).read_text().strip() for f in files}
                    if gap is not None:
                        stat=cg.stat();current=self.cgroup(initial['State']['Pid'],strict=True)
                        if current is None:raise ProcessLookupError(errno.ESRCH,'sampling cgroup missing')
                        if current!=cg or (stat.st_dev,stat.st_ino)!=cg_identity:
                            raise ValueError('exact sampling cgroup changed')
                        if not self.valid_kernel_readback(kernel):raise ValueError('invalid fresh sampling readback')
                        if time.monotonic()>=deadline:raise TimeoutError('sampling observation deadline exceeded')
                        gap['resolution']='fresh-kernel-read'
                    return kernel
                except OSError as exc:
                    if exc.errno not in (errno.ENODEV,errno.ENOENT,errno.ESRCH):raise
                    if gap is None:
                        started=time.monotonic();deadline=started+1.0
                        gap={'container':cid,'at':utc(),'reason':'cgroup-removed-after-inspection',
                             'errno':exc.errno,'resolution':'failed'}
                        gaps=self.result.setdefault('sampler_gaps',[])
                        gaps.append(gap);del gaps[:-64]
                        identity=self.sampling_identity(cid,initial)
                        if cid not in str(cg):raise ValueError('exact sampling cgroup unavailable')
                    remaining=deadline-time.monotonic()
                    if inspections>=20 or remaining<=0:raise
                    if inspections:time.sleep(min(.05,remaining))
                    if time.monotonic()>=deadline:raise
                    inspections+=1
                    # The shared call boundary also works through wrappers whose
                    # ordinary inspect method has no deadline keyword.
                    after=self.e.call('GET','/containers/'+cid+'/json',missing=True,deadline=deadline)
                    if time.monotonic()>=deadline:raise
                    if after is None:
                        gap['resolution']='terminal_absent'
                        return None
                    if self.sampling_identity(cid,after)!=identity:
                        raise ValueError('exact sampling identity changed')
                    if after['State']['Running'] is False:
                        gap['resolution']='terminal_stopped'
                        return None
                    if after['State']['Pid']!=initial['State']['Pid']:
                        raise ValueError('exact sampling PID changed')
        finally:
            if gap is not None:
                gap.update(inspections=inspections,elapsed_ms=max(0,int((time.monotonic()-started)*1000)))

    def measure(self,cid, role):
        v=self.e.inspect(cid,missing=True)
        if not v or not v['State']['Running']: return None
        pid=v['State']['Pid'];self.pin_container(cid);cg=self.cgroup(pid)
        out={'at':utc(),'monotonic':time.monotonic(),'role':role,'container':cid,'main_pid':pid,'cgroup_path':str(cg),'processes':[self.proc(p) for p in self.pids(pid)]}
        if cg:
            kernel=self.cgroup_sample(cid,v,cg)
            if kernel is None:return None
            out.update(kernel)
        if role=='worker':
            try:out['tmp_cache_footprint']=footprint(Path('/proc')/str(pid)/'root/tmp')
            except PermissionError:out['tmp_cache_footprint_error']='permission denied'
            out['state_footprint']=footprint(self.root/'state')
            logpath=v.get('LogPath')
            if logpath:
                try:out['log_bytes']=Path(logpath).stat().st_size
                except (FileNotFoundError,PermissionError):out['log_bytes']=None
            out['inspect_size_rw_unavailable_without_size_query']=True
        return out
    def sampler(self):
        laststats=0
        while not self.stopped.is_set():
            try:
                for state in ['state','fresh-state']:
                    ownerfile=self.root/state/'owner.json'
                    if ownerfile.exists():
                        owner=json.loads(ownerfile.read_text());cid=owner.get('workerContainerID')
                        if cid and cid not in self.worker_records:
                            v=self.e.inspect(cid,missing=True)
                            if v and worker_owned(v,owner,self.image,self.daemon):
                                self.worker_records[cid]={'runID':owner['runID'],'state':state,'Id':cid,'Image':v['Image'],'Name':v['Name'],'Config':v['Config'],'HostConfig':v['HostConfig'],'Mounts':v['Mounts'],'Created':v['Created'],'State_at_first_sample':v['State']}
                                self.roles[cid]='worker'
                rows=[]
                for cid,role in list(self.roles.items()):
                    row=self.measure(cid,role)
                    if row:rows.append(row)
                if time.monotonic()-laststats>2:
                    for row in rows:
                        row['docker_stats']=self.e.call('GET','/containers/'+row['container']+'/stats?stream=false&one-shot=true')
                    laststats=time.monotonic()
                self.samples.extend(rows)
            except Exception as exc:
                self.result.setdefault('sampler_errors',[]).append({'at':utc(),'type':type(exc).__name__,'message':str(exc)[:200],'http_status':getattr(exc,'http_status',None),'errno':getattr(exc,'errno',None),'frames':[{'file':Path(frame.filename).name,'line':frame.lineno,'function':frame.name} for frame in traceback.extract_tb(exc.__traceback__)]})
            self.stopped.wait(.15)
    def sql(self,cid,q):
        r=self.e.exec(cid,['psql','-XAt','-U','postgres','-d','fixture','-v','ON_ERROR_STOP=1','-c',q])
        if r['exit']: raise RuntimeError('SQL fixture exit '+str(r))
        return r['stdout'].strip()
    def wait(self,fn,seconds=90,label='condition'):
        end=time.monotonic()+seconds;last=None
        while time.monotonic()<end:
            try:
                last=fn()
                if last:return last
            except (FileNotFoundError,KeyError,json.JSONDecodeError): pass
            time.sleep(.1)
        raise RuntimeError('Timeout '+label+' last='+str(last)[:300])
    def startpg(self,suffix,marked):
        labels={'com.docker.compose.project':self.prefix,'com.docker.compose.service':suffix} if marked else {}
        if marked:labels['bakabel.type']='postgres'
        vol=self.prefix+'-'+suffix+'-data';self.e.call('POST','/volumes/create',{'Name':vol,'Labels':{'probe.bakabel.owner':self.prefix}});self.volumes.append(vol)
        gate=self.root/'private'/('start-'+suffix)
        cid=self.create(suffix,{'Image':PG,'Entrypoint':['sh','-c'], 'Cmd':['while [ ! -e /gate/start ]; do sleep .05; done; exec docker-entrypoint.sh postgres'], 'Env':['POSTGRES_HOST_AUTH_METHOD=trust','POSTGRES_DB=fixture','POSTGRES_USER=postgres'], 'Labels':labels,'HostConfig':{'Mounts':[{'Type':'volume','Source':vol,'Target':'/var/lib/postgresql','ReadOnly':False},self.bind(self.root/'private','/gate',True)]}},role='source-pg' if marked else 'restore-pg')
        # The root shell is pinned BEFORE stock entrypoint forks or changes UID.
        v=self.e.inspect(cid);aff=os.sched_getaffinity(v['State']['Pid']);assert aff=={0,1}
        (self.root/'private'/'start').touch()
        self.wait(lambda:self.e.exec(cid,['pg_isready','-h','127.0.0.1','-U','postgres','-d','fixture'])['exit']==0,30,'PG readiness')
        (self.root/'private'/'start').unlink()
        return cid
    def config(self, filename='config.yaml', timeout='120s', fresh=False):
        state='fresh-state' if fresh else 'state'
        (self.root/filename).write_text(f'version: 1\ninstallation: {self.prefix}\nplatform: compose\nscope: [{self.prefix}]\nrepository: {self.repository}\ncredentials:\n  password_file: /password\n  s3_credentials_file: /aws\n  s3_region: us-east-1\nstate_dir: /state\nworker_image: {self.image}\ntimeout: {timeout}\nschedule: "* * * * *"\ntimezone: UTC\n')
        return state
    def controller(self,command,*argv,filename='config.yaml',fresh=False,monitor=False):
        state='fresh-state' if fresh else 'state'
        mounts=[self.bind(self.root/filename,'/config.yaml',True),self.bind(self.root/state,'/state',monitor),self.bind(self.root/'private/password','/password',True),self.bind(self.root/'private/aws','/aws',True)]
        if not monitor:mounts.append(self.bind(self.sock,'/var/run/docker.sock',True))
        cid=self.create(command+'-'+secrets.token_hex(3),{'Image':self.image,'Cmd':['--config','/config.yaml',command,*argv],'Labels':{'bakabel.installation':self.prefix,'bakabel.role':'scheduler'},'Env':['GOMAXPROCS=2'],'HostConfig':{'ReadonlyRootfs':True,'Mounts':mounts,'Tmpfs':{'/tmp':'rw,nosuid,nodev,size=67108864'},'NetworkMode':'none' if monitor else 'bridge'}},role='health-monitor' if monitor else 'scheduler' if command=='serve' else 'controller')
        return cid
    def logs(self,cid):
        b=self.e.call('GET','/containers/'+cid+'/logs?stdout=true&stderr=true',raw=True)
        out=[]
        while len(b)>=8:
            stream=b[0];n=struct.unpack('>I',b[4:8])[0];chunk,b=b[8:8+n],b[8+n:];out.append(chunk.decode(errors='replace'))
        return ''.join(out)
    def finish(self,cid,expect=0,timeout=120):
        v=self.wait(lambda:(lambda x:x if not x['State']['Running'] else None)(self.e.inspect(cid)),timeout,'controller exit')
        log=self.logs(cid);r={'container':cid,'at':utc(),'exit':v['State']['ExitCode'],'stdout_stderr':log};self.result['commands'].append(r)
        print('CLI',self.containers[cid],r['exit'],log.strip(),flush=True)
        assert r['exit']==expect, r
        return [json.loads(s) for s in log.splitlines() if s.startswith('{')]
    def health(self,filename='config.yaml',expect=0):
        before={str(f.relative_to(self.root/'state')):sha(f) for f in (self.root/'state').rglob('*') if f.is_file()}
        cid=self.controller('health',filename=filename,monitor=True);rows=self.finish(cid,expect)
        after={str(f.relative_to(self.root/'state')):sha(f) for f in (self.root/'state').rglob('*') if f.is_file()}
        assert before==after,'health wrote state'
        return rows[0]
    def restic(self,*argv):
        cid=self.create('restic-'+secrets.token_hex(3),{'Image':self.image,'Entrypoint':['/usr/bin/restic'],'Cmd':['--no-cache',*argv],'Env':['RESTIC_REPOSITORY='+self.repository,'RESTIC_PASSWORD_FILE=/password','AWS_SHARED_CREDENTIALS_FILE=/aws','AWS_DEFAULT_REGION=us-east-1','GOMAXPROCS=2'],'HostConfig':{'NetworkMode':'bridge','Mounts':[self.bind(self.root/'private/password','/password',True),self.bind(self.root/'private/aws','/aws',True)],'ReadonlyRootfs':True,'Tmpfs':{'/tmp':'rw,nosuid,nodev,size=67108864'}}},role='operator-restic')
        v=self.wait(lambda:(lambda x:x if not x['State']['Running'] else None)(self.e.inspect(cid)),120,'restic exit');log=self.logs(cid)
        self.result['commands'].append({'operation':'restic','args':argv,'container':cid,'exit':v['State']['ExitCode'],'stdout_stderr':log})
        assert v['State']['ExitCode']==0,log
        return log
    def source_stats(self,cid):
        return {'at':utc(),'metrics':self.measure(cid,self.roles[cid]),'sql':self.sql(cid,"SELECT json_build_object('database_bytes',pg_database_size(current_database()),'wal_lsn',pg_current_wal_lsn(),'wal_bytes',(SELECT wal_bytes FROM pg_stat_wal),'wal_records',(SELECT wal_records FROM pg_stat_wal),'blks_read',blks_read,'blks_hit',blks_hit,'temp_bytes',temp_bytes,'tup_inserted',tup_inserted,'tup_returned',tup_returned) FROM pg_stat_database WHERE datname=current_database()"),'pg_stat_io':json.loads(self.sql(cid,"SELECT coalesce(json_agg(to_jsonb(x)),'[]'::json) FROM pg_stat_io x WHERE backend_type IN ('client backend','checkpointer','background writer')"))}
    def checkpoint(self,name):
        self.result['checkpoints'][name]={'at':utc(),'state':footprint(self.root/'state'),'backend_persistent_not_worker_cache':footprint(self.root/'backend'),'worker_count':len(self.worker_records),'worker_absence':{cid:self.e.inspect(cid,missing=True) is None for cid in self.worker_records}}
        self.save()
    def last(self):return json.loads((self.root/'state/last-result.json').read_text())
    def success(self,previous=None,timeout=100):
        def complete():
            if not (self.root/'state/last-result.json').exists():return None
            r=self.last()
            if r['status']=='success' and (previous is None or previous['runID']!=r['runID']) and not (self.root/'state/owner.json').exists():return r
        return self.wait(complete,timeout,'scheduled success')
    def lock(self,pg):
        self.e.exec(pg,['psql','-XAt','-U','postgres','-d','fixture','-c','BEGIN; LOCK TABLE payload IN ACCESS EXCLUSIVE MODE; SELECT pg_sleep(300)'],True,['PGAPPNAME=fixture-lock-'+self.prefix])
        self.wait(lambda:self.sql(pg,"SELECT count(*) FROM pg_stat_activity WHERE application_name='fixture-lock-"+self.prefix+"' AND wait_event='PgSleep'")=='1',10,'lock held')
    def unlock(self,pg):
        self.sql(pg,"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name='fixture-lock-"+self.prefix+"'")
        assert self.sql(pg,"SELECT count(*) FROM pg_stat_activity WHERE application_name='fixture-lock-"+self.prefix+"'")=='0'
    def blocked(self,pg):
        def pred():
            o=json.loads((self.root/'state/owner.json').read_text())
            if o.get('phase')=='exec_started' and self.e.call('GET','/exec/'+o['execID']+'/json')['Running'] and self.sql(pg,"SELECT count(*) FROM pg_stat_activity WHERE application_name='"+o['runID']+"' AND wait_event_type='Lock'")=='1':return o
        return self.wait(pred,85,'scheduled pg_dump lock wait')
    def kill_scheduler(self,cid):
        assert cid in self.containers and self.roles[cid]=='scheduler'
        v=self.e.inspect(cid);assert v['Config']['Labels']['probe.bakabel.owner']==self.prefix
        self.e.call('POST','/containers/'+cid+'/kill?signal=KILL')
        self.wait(lambda:not self.e.inspect(cid)['State']['Running'],10,'scheduler killed')
        self.finish(cid,137)
    def stop(self,cid):
        self.e.call('POST','/containers/'+cid+'/stop?t=5')
        assert not self.e.inspect(cid)['State']['Running']
        self.result['commands'].append({'container':cid,'operation':'stop','exit':self.e.inspect(cid)['State']['ExitCode'],'stdout_stderr':self.logs(cid)})
    def image_audit(self):
        cid=self.create('image-audit',{'Image':self.image},start=False)
        # Actual export gives merged unpacked payload AND actual allocated files.
        exported=self.root/'image-export.tar'
        cp=subprocess.run(['docker','-H','unix://'+self.sock,'export','--output',str(exported),cid],capture_output=True)
        assert cp.returncode==0,cp.stderr
        unpacked=self.root/'image-unpacked';unpacked.mkdir()
        with tarfile.open(exported) as tar:
            count=sum(1 for m in tar.getmembers() if m.isfile())
            total=sum(m.size for m in tar.getmembers() if m.isfile())
            # Docker injects an absolute /etc/mtab symlink. Do not materialize
            # links/devices at all: regular file allocation is the intended metric.
            tar.extractall(unpacked,members=[m for m in tar.getmembers() if m.isfile()],filter='data')
        allocated=footprint(unpacked);export_bytes=exported.stat().st_size
        exported.unlink();shutil.rmtree(unpacked)
        save=self.root/'image-save.tar'
        with save.open('wb') as out:
            cp=subprocess.run(['docker','-H','unix://'+self.sock,'save',self.image],stdout=out,stderr=subprocess.PIPE)
        assert cp.returncode==0,cp.stderr
        layers=[]
        with tarfile.open(save) as tar:
            members={m.name:m for m in tar.getmembers()}
            index=json.load(tar.extractfile('index.json'))
            def walk(desc):
                obj=json.load(tar.extractfile('blobs/sha256/'+desc['digest'].split(':')[1]))
                if 'manifests' in obj:
                    for d in obj['manifests']:walk(d)
                for layer in obj.get('layers',[]):
                    media=layer['mediaType']
                    if 'image.layer' in media:layers.append({'digest':layer['digest'],'mediaType':media,'bytes':layer['size']})
            for desc in index['manifests']:walk(desc)
        b=self.e.call('GET','/containers/'+cid+'/archive?path=/usr/local/bin/bakabel',raw=True)
        with tarfile.open(fileobj=io.BytesIO(b)) as tar:
            binary=tar.extractfile(next(m for m in tar.getmembers() if m.isfile())).read()
        self.result['fingerprint']['runtime_bakabel_sha256']=hashlib.sha256(binary).hexdigest()
        b=self.e.call('GET','/containers/'+cid+'/archive?path=/usr/bin/restic',raw=True)
        with tarfile.open(fileobj=io.BytesIO(b)) as tar:
            restic=tar.extractfile(next(m for m in tar.getmembers() if m.isfile())).read()
        self.result['fingerprint']['runtime_restic_sha256']=hashlib.sha256(restic).hexdigest()
        self.result['image_measurement']={'actual_save_tar_bytes':save.stat().st_size,'oci_layers':layers,'oci_compressed_layer_bytes':sum(x['bytes'] for x in layers),'actual_merged_export_tar_bytes':export_bytes,'actual_export_extracted_regular_file_allocated_bytes':allocated['allocated_bytes'],'merged_export_regular_file_payload_bytes':total,'merged_export_regular_files':count,'note':'export payload excludes tar padding and metadata; extracted allocation is regular-file blocks on this scratch filesystem, not shared Docker snapshot/overlay allocation'}
        save.unlink()
    def run(self):
        self.image_audit()
        minio=self.create('minio',{'Image':PG,'Entrypoint':['/minio'],'Cmd':['server','/data','--address','0.0.0.0:9000'],'Env':['MINIO_ROOT_USER_FILE=/credentials/user','MINIO_ROOT_PASSWORD_FILE=/credentials/password','MINIO_BROWSER=off','GOMAXPROCS=2'],'HostConfig':{'NetworkMode':'bridge','Mounts':[self.bind(self.root/'bin/minio','/minio',True),self.bind(self.root/'private/minio-user','/credentials/user',True),self.bind(self.root/'private/minio-password','/credentials/password',True),self.bind(self.root/'backend','/data')]}},role='fixture-s3-backend')
        mi=self.e.inspect(minio);ip=mi['NetworkSettings']['Networks']['bridge']['IPAddress'];assert ip and not mi['HostConfig']['PortBindings']
        self.result['s3_backend']={'container':minio,'default_bridge_ip':ip,'published_ports':mi['HostConfig']['PortBindings']}
        self.repository='s3:http://'+ip+':9000/bakabel-resources/repository'
        self.wait(lambda:'9000' in self.logs(minio),30,'MinIO readiness');self.restic('init')
        pg=self.startpg('pg',True)
        self.sql(pg,"CREATE ROLE fixture_owner; CREATE TABLE payload AS SELECT g, md5(g::text)||md5((g*17)::text)||md5((g*31)::text)||md5((g*47)::text) AS data FROM generate_series(1,200000) g; ALTER TABLE payload OWNER TO fixture_owner; ALTER DATABASE fixture OWNER TO fixture_owner; REVOKE CONNECT ON DATABASE fixture FROM PUBLIC; CREATE TABLE availability_probe(n bigint)")
        expected=self.sql(pg,"SELECT count(*),sum(g),md5(string_agg(g::text||':'||data,',' ORDER BY g)) FROM payload")
        self.result['pg_fixture']={'rows':200000,'readback':expected,'before':self.source_stats(pg)}
        vol=self.prefix+'-files';self.e.call('POST','/volumes/create',{'Name':vol,'Labels':{'probe.bakabel.owner':self.prefix}});self.volumes.append(vol)
        filec=self.create('files',{'Image':PG,'Entrypoint':['sh','-c'],'Cmd':['while :; do sleep 3600; done'],'Labels':{'com.docker.compose.project':self.prefix,'com.docker.compose.service':'files','bakabel.type':'volume','bakabel.paths':'/data'},'HostConfig':{'Mounts':[{'Type':'volume','Source':vol,'Target':'/data','ReadOnly':False}]}},role='source-files')
        # One disposable generator; incompressible payload created directly on OWN volume.
        generator=self.e.exec(filec,['sh','-c','while [ ! -e /data/.generate ]; do sleep .05; done; rm /data/.generate; i=0; while [ "$i" -lt 512 ]; do dd if=/dev/urandom of=/data/file-$i bs=524288 count=1 2>/dev/null || exit 1; i=$((i+1)); done; cd /data && sha256sum file-* | sort > SHA256SUMS; chmod 640 file-*'],True)
        self.pin_container(filec)
        ginfo=self.e.call('GET','/exec/'+generator+'/json');assert ginfo['Running']
        assert os.sched_getaffinity(ginfo['Pid'])=={0,1}
        self.e.exec(filec,['touch','/data/.generate'])
        gen=self.wait(lambda:(lambda v:v if not v['Running'] else None)(self.e.call('GET','/exec/'+generator+'/json')),45,'corpus generation')
        assert gen['ExitCode']==0,gen
        file_manifest=self.e.exec(filec,['cat','/data/SHA256SUMS'])['stdout'];self.result['file_corpus']={'payload_bytes':512*524288,'files':512,'manifest_sha256':hashlib.sha256(file_manifest.encode()).hexdigest(),'incompressible':'/dev/urandom'}
        source_identity={c:{'StartedAt':self.e.inspect(c)['State']['StartedAt'],'RestartCount':self.e.inspect(c)['RestartCount']} for c in [pg,filec]}
        self.result['source_identity_before']=source_identity
        self.config();self.config('short.yaml',timeout='18s');self.config('fresh.yaml',fresh=True)
        plan=self.finish(self.controller('plan'))[0];assert len(plan['targets'])==2
        # Start early in a minute so the idle measurement does not include a job.
        self.wait(lambda:time.time()%60<30,65,'early minute for idle sample')
        scheduler=self.controller('serve');idle_start=time.monotonic();time.sleep(20);idle_end=time.monotonic()
        idle=[s for s in self.samples if s['container']==scheduler and idle_start<=s['monotonic']<=idle_end]
        assert len(idle)>10 and not (self.root/'state/owner.json').exists()
        self.result['idle_interval']={'start_monotonic':idle_start,'end_monotonic':idle_end,'seconds':idle_end-idle_start,'container':scheduler,'samples':len(idle),'first':idle[0],'last':idle[-1]}
        first=self.success();self.wait(lambda:len(self.worker_records)>=1,5,'sampler worker record')
        assert first['operation']=='backup' and first['finishedAt']==first['lastBackupSuccessAt']
        assert self.health()['status']=='healthy';self.checkpoint('after-first-success')
        self.result['pg_fixture']['after_first_dump']=self.source_stats(pg)
        self.gate('B4-real-minute-scheduled-mixed-success',last_result=first,scheduler=scheduler)
        # Next real minute: source lock, scheduler-only kill, exact worker adoption.
        self.lock(pg);active=self.blocked(pg)
        self.sql(pg,'INSERT INTO availability_probe VALUES (10)');assert self.sql(pg,'SELECT count(*) FROM availability_probe')=='1'
        job=json.loads((self.root/'state/workflow/job.json').read_text());self.result['adoption_before']={'owner':active,'createdAt':job['createdAt'],'timeout_ns':job['config']['Timeout'],'worker':active['workerContainerID'],'source_read_write_during_dump_wait':True}
        self.kill_scheduler(scheduler);assert self.e.inspect(active['workerContainerID'])['State']['Running']
        blocked_cli=self.finish(self.controller('run'),expect=1);assert self.e.inspect(active['workerContainerID'])['State']['Running']
        scheduler2=self.controller('serve');time.sleep(3)
        current=json.loads((self.root/'state/owner.json').read_text());adopted=json.loads((self.root/'state/workflow/job.json').read_text())
        assert current['runID']==active['runID'] and current['workerContainerID']==active['workerContainerID'] and adopted==job
        workers=self.e.call('GET','/containers/json?all=true&filters='+quote(json.dumps({'label':['bakabel.run='+active['runID']]})))
        assert [w['Id'] for w in workers]==[active['workerContainerID']]
        self.unlock(pg);second=self.success(first,90);assert second['runID']==active['runID']
        self.result['adoption_after']={'owner_released':not (self.root/'state/owner.json').exists(),'same_job_bytes':adopted==job,'last_result':second,'scheduler_events':self.logs(scheduler2)}
        assert self.health()['status']=='healthy';self.checkpoint('after-adopted-success')
        self.gate('B4-scheduler-SIGKILL-same-worker-original-createdAt-adopted-success',runID=active['runID'],worker=active['workerContainerID'])
        # Parent/no-new-data checks and full file content readback, no file restore.
        snaps=json.loads(self.restic('snapshots','--json'));self.result['snapshots_two_successes']=snaps
        groups={}
        for s in snaps:groups.setdefault(tuple(s['paths']),[]).append(s)
        assert len(groups)==2
        for group in groups.values():
            group.sort(key=lambda x:x['time']);assert len(group)==2 and group[1].get('parent')==group[0]['id']
            if group[0]['paths'][0].startswith('/bakabel/files/'):
                assert group[1]['summary']['files_unmodified']==513 and group[1]['summary']['data_blobs']==0
                sid=group[0]['id']
                self.result['file_parent_assertions']={'first':group[0]['id'],'second':group[1]['id'],'summary':group[1]['summary']}
        self.stop(scheduler2)
        self.gate('B5-256MiB-many-files-first-second-parent-no-new-data',files=513,payload_bytes=512*524288)
        # Actual low-level repository data readback; streamed tar never written locally.
        file_snap=next(s for s in snaps if s['id']==sid);prefix=file_snap['paths'][0]
        readback=self.create('readback',{'Image':self.image,'Entrypoint':['/usr/bin/restic'],'Cmd':['--no-cache','dump',sid,prefix], 'Env':['RESTIC_REPOSITORY='+self.repository,'RESTIC_PASSWORD_FILE=/password','AWS_SHARED_CREDENTIALS_FILE=/aws','AWS_DEFAULT_REGION=us-east-1','GOMAXPROCS=2'],'HostConfig':{'NetworkMode':'bridge','LogConfig':{'Type':'none'},'Mounts':[self.bind(self.root/'private/password','/password',True),self.bind(self.root/'private/aws','/aws',True)],'ReadonlyRootfs':True,'Tmpfs':{'/tmp':'rw,nosuid,nodev,size=67108864'}}},role='operator-readback',start=False)
        cp=subprocess.Popen(['docker','-H','unix://'+self.sock,'start','-a',readback],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        expected_files={line.split()[1]:line.split()[0] for line in file_manifest.splitlines()}
        checked={};manifest_read=None
        with tarfile.open(fileobj=cp.stdout,mode='r|') as tar:
            for member in tar:
                if not member.isfile():continue
                f=tar.extractfile(member);name=Path(member.name).name
                if name=='SHA256SUMS':manifest_read=f.read().decode();continue
                h=hashlib.sha256()
                for chunk in iter(lambda:f.read(1024*1024),b''):h.update(chunk)
                checked[name]=h.hexdigest()
        cp.stdout.close();err=cp.communicate(timeout=30)[1]
        assert cp.returncode==0 and self.e.inspect(readback)['State']['ExitCode']==0,err
        assert checked==expected_files and manifest_read==file_manifest
        self.result['file_content_readback']={'snapshot':sid,'files_compared':len(checked),'all_sha256_equal':True,'streamed_no_local_staging':True,'docker_attach_exit':cp.returncode,'restic_exit':self.e.inspect(readback)['State']['ExitCode']}
        self.gate('B5-full-256MiB-S3-readback-512-SHA256s-match')
        # Independent PG restore (same 200k bounded fixture, own fresh target).
        target=self.startpg('restore',False);self.sql(target,'CREATE ROLE fixture_owner; ALTER DATABASE fixture OWNER TO fixture_owner; REVOKE CONNECT ON DATABASE fixture FROM PUBLIC')
        pgid=next(s['id'] for s in snaps if s['paths'][0].startswith('/bakabel/postgres/'))
        restore_before=self.source_stats(target);r=self.finish(self.controller('restore','--snapshot',pgid,'--postgres-container',target,'--database','fixture','--user','postgres',filename='fresh.yaml',fresh=True))
        assert r[0]['status']=='restored'
        actual=self.sql(target,"SELECT count(*),sum(g),md5(string_agg(g::text||':'||data,',' ORDER BY g)) FROM payload");assert actual==expected
        self.result['pg_restore']={'before':restore_before,'after':self.source_stats(target),'readback':actual,'snapshot':pgid}
        self.gate('B5-real-200k-row-fresh-target-streaming-PG-restore',readback=actual)
        # Small original-deadline case; unchanged last backup success on failure.
        self.lock(pg);shortscheduler=self.controller('serve',filename='short.yaml');fault=self.blocked(pg);jshort=json.loads((self.root/'state/workflow/job.json').read_text());deadline=datetime.datetime.fromisoformat(jshort['createdAt'].replace('Z','+00:00')).timestamp()+18
        self.kill_scheduler(shortscheduler);time.sleep(4);replacement=self.controller('serve',filename='short.yaml')
        assert json.loads((self.root/'state/workflow/job.json').read_text())==jshort
        self.result['deadline_before']={'owner':fault,'createdAt':jshort['createdAt'],'deadline_epoch':deadline,'restarted_at':utc()}
        def failed():
            r=self.last()
            return r if r['runID']==fault['runID'] and r['status']=='failed' and not (self.root/'state/owner.json').exists() else None
        failure=self.wait(failed,45,'original deadline cleanup');finished=time.time()
        assert failure['lastBackupSuccessAt']==second['lastBackupSuccessAt'] and finished<=deadline+25
        execproof=self.e.call('GET','/exec/'+fault['execID']+'/json');assert not execproof['Running']
        assert self.sql(pg,"SELECT count(*) FROM pg_stat_activity WHERE application_name='"+fault['runID']+"'")=='0'
        assert self.e.inspect(fault['workerContainerID'],missing=True) is None
        self.unlock(pg);self.stop(replacement);self.result['deadline_after']={'last_result':failure,'observed_terminal_epoch':finished,'seconds_after_original_deadline':finished-deadline,'exec':{k:execproof[k] for k in ['ID','Running','ExitCode','Pid']},'scheduler_events':self.logs(replacement)}
        h=self.health('short.yaml',expect=1);assert h['status']=='failed';self.checkpoint('after-deadline-failure-kill')
        self.gate('B4-original-deadline-bounded-cleanup-no-last-success-refresh',seconds_after_original_deadline=finished-deadline)
        # Monitor with RO private state, no Engine socket, independent of dead scheduler.
        health_deadline=datetime.datetime.fromisoformat(h['deadline'].replace('Z','+00:00')).timestamp()
        if h['overdue']:overdue=h
        else:
            time.sleep(max(0,health_deadline-time.time()+.3));overdue=self.health('short.yaml',expect=1)
        assert overdue['status']=='failed' and overdue['overdue'];self.result['independent_overdue_health']=overdue
        self.gate('B4-independent-readonly-monitor-failed-overdue-no-HTTP-server')
        for c in [pg,filec]:
            v=self.e.inspect(c);assert {'StartedAt':v['State']['StartedAt'],'RestartCount':v['RestartCount']}==source_identity[c]
        self.sql(pg,'INSERT INTO availability_probe VALUES (1)');assert self.sql(pg,'SELECT count(*) FROM availability_probe')=='2'
        self.result['pg_fixture']['after_all']=self.source_stats(pg)
        self.gate('source-startedAt-restartCount-unchanged-read-write-available')
    def cleanup(self):
        self.stopped.set();self.thread.join(timeout=50)
        self.result['workers']=self.worker_records
        # Exact durable fixture workers only. Never inspect arbitrary worker inventory.
        owner=self.root/'state/owner.json'
        if owner.exists():
            o=json.loads(owner.read_text());cid=o.get('workerContainerID')
            if cid:
                v=self.e.inspect(cid,missing=True)
                if v and worker_owned(v,o,self.image,self.daemon):self.containers[cid]=o['workerName']
        for cid,w in self.worker_records.items():self.containers[cid]=w['Name'].lstrip('/')
        absence={}
        for cid in reversed(list(self.containers)):
            self.e.call('DELETE','/containers/'+cid+'?force=true&v=true',missing=True)
            absence[cid]=self.e.inspect(cid,missing=True) is None
        volabsence={}
        for vol in self.volumes:
            self.e.call('DELETE','/volumes/'+vol,missing=True)
            volabsence[vol]=self.e.call('GET','/volumes/'+vol,missing=True) is None
        self.result['cleanup']['containers_absent']=absence;self.result['cleanup']['volumes_absent']=volabsence
        self.result['swarm_after']=self.e.call('GET','/info')['Swarm']['LocalNodeState']
        self.result['cleanup']['scoped_container_summary']=self.e.call('GET','/containers/json?all=true&filters='+quote(json.dumps({'label':['probe.bakabel.owner='+self.prefix]})))
        self.result['cleanup']['scoped_volume_summary']=self.e.call('GET','/volumes?filters='+quote(json.dumps({'label':['probe.bakabel.owner='+self.prefix]})))
        self.result['final_fixture_footprint']={d:footprint(self.root/d) for d in ['state','fresh-state','backend','private','bin']}
        # Keep only evidence; real data, credentials, binary copies all removed.
        for d in ['state','fresh-state','backend','private','bin']:shutil.rmtree(self.root/d)
        if (self.root/'image-unpacked').exists():shutil.rmtree(self.root/'image-unpacked')
        for f in ['image-save.tar','image-export.tar']:(self.root/f).unlink(missing_ok=True)
        self.result['cleanup']['private_paths_absent']=all(not (self.root/d).exists() for d in ['state','fresh-state','backend','private','bin'])
        self.result['finished_at']=utc()
        encoded=json.dumps(self.result)
        assert not any(value in encoded for value in self.values),'synthetic credential leak in receipt'
        (self.root/'metrics.json').write_text(json.dumps(self.samples,indent=2))
        self.save()
        assert all(absence.values()) and all(volabsence.values()) and self.result['swarm_after']=='inactive'

def main():
    a=argparse.ArgumentParser(description=__doc__)
    a.add_argument('--runtime',type=Path,required=True,help='NEW output directory; all fixture data removed on exit')
    a.add_argument('--source',type=Path,required=True)
    a.add_argument('--minio-binary',type=Path,required=True)
    a.add_argument('--image',required=True,help='Explicit ordinary candidate image; never rebuilt or relayed')
    a.add_argument('--socket',type=Path)
    args=a.parse_args();os.sched_setaffinity(0,{0,1});probe=Probe(args);code=1
    try:probe.run();code=0
    except Exception:
        probe.result['error']=traceback.format_exc();print(probe.result['error'],flush=True)
    finally:
        try:probe.cleanup()
        except Exception:print('CLEANUP ERROR',traceback.format_exc(),flush=True);code=1
    return code
if __name__=='__main__':raise SystemExit(main())
