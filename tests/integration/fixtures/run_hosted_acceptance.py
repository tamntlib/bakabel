#!/usr/bin/env python3
"""Destructive acceptance is allowed only on an explicitly exclusive hosted VM."""
import copy
import argparse
import json
import os
from pathlib import Path
import stat
import subprocess
import shutil
import time
import traceback
from urllib.parse import quote
from run_compose_pg_acceptance import ComposeProbe,fingerprint
from run_resource_probe import PG,Engine,utc

def require_hosted_daemon(env,uid,exclusive,info,containers):
    if env.get('GITHUB_ACTIONS')!='true' or env.get('RUNNER_ENVIRONMENT')!='github-hosted' or uid!=0 or not exclusive:
        raise ValueError('requires explicit exclusive GitHub-hosted VM and root; never a shared/local daemon')
    if (not info.get('ID') or info.get('OSType')!='linux' or str(info.get('CgroupVersion'))!='2' or
        not isinstance(info.get('SecurityOptions'),list) or any('rootless' in s for s in info['SecurityOptions']) or
        info.get('Swarm',{}).get('LocalNodeState')!='inactive' or info.get('Containers')!=0 or containers):
        raise ValueError('requires fresh rootful Linux cgroup-v2 daemon with no containers and inactive Swarm')


def required_gates(platform):
    if platform not in ('compose','swarm'):
        raise ValueError('unsupported acceptance platform')
    names=[]
    for backend in ('local','s3'):
        names.extend(backend+'-'+suffix for suffix in (
            'mixed-online-CLI-backup-with-default-worker-limits',
            'file-parent-reused-no-new-data-and-complete-payload-readback',
            'worker-SIGKILL-failed-exact-source-terminal-before-release',
            'empty-source-physical-DB-alias-refused',
            'fresh-source-and-history-absent-PG-restore-different-role-OIDs-owner-ACL-preserved',
            'file-directory-and-unused-default-local-volume-restored',
            'file-source-physical-alias-refused',
            'file-consumer-physical-alias-refused',
            'file-alternate-same-backing-volume-refused',
            'file-unknown-partial-refused'))
        if backend=='s3':names.append('s3-S3-outage-failed-exact-source-terminal-before-release')
        if platform=='swarm':names.append(backend+'-service-labels-running-task-node-identity')
    return names


def verify_matrix(result):
    names=[g['name'] for g in result.get('gates',[])]
    if result.get('error') or set(names)!=set(required_gates(result['platform'])) or len(names)!=len(set(names)):
        raise ValueError('acceptance gates incomplete, duplicated or failed')
    if result.get('cells')!={'local':['postgres','volume'],'s3':['postgres','volume']}:
        raise ValueError('both source kinds and both backends must have actual restore readback')


def service_spec(prefix,suffix,node,spec):
    labels=spec['Labels']
    service_labels={'com.docker.stack.namespace':prefix,**{k:v for k,v in labels.items() if k.startswith('bakabel.')}}
    container={'Image':spec['Image'],'Labels':{'probe.bakabel.owner':prefix},'Mounts':copy.deepcopy(spec['HostConfig']['Mounts'])}
    for source,target in (('Entrypoint','Command'),('Cmd','Args'),('Env','Env')):
        if source in spec:container[target]=list(spec[source])
    return {'Name':prefix+'_'+suffix,'Labels':service_labels,'TaskTemplate':{'ContainerSpec':container,'Placement':{'Constraints':['node.id=='+node]},'Resources':{'Limits':{'NanoCPUs':2000000000}},'RestartPolicy':{'Condition':'none'}},'Mode':{'Replicated':{'Replicas':1}},'Networks':[{'Target':'host'}]}


class HostedProbe(ComposeProbe):
    def __init__(self,args):
        self.platform=args.platform
        self.services={}
        self.source_snapshots={}
        self.restores={}
        self.mounted=[]
        self.owns_swarm=False
        super().__init__(args,inventory_images=(args.image,PG))
        self.result['platform']=self.platform
        self.result['cells']={}
        self.result['direct_engine']=True
        self.result['cpu_fields_omitted']=[]

    def config(self,filename='config.yaml',timeout='120s',fresh=False):
        state=super().config(filename,timeout,fresh)
        path=self.root/filename
        path.write_text(path.read_text().replace('platform: compose\n','platform: '+self.platform+'\n'))
        return state

    def save(self):
        encoded=json.dumps(self.result,indent=2)
        if any(v in encoded for v in self.values):
            raise ValueError('synthetic credential found in evidence; do not export raw result')
        (self.root/'receipt.json').write_text(encoded+'\n')

    def logs(self,cid):
        text=super().logs(cid)
        if any(v in text for v in self.values):
            raise ValueError('synthetic credential found in container logs')
        return text

    def swarm_source(self,suffix,spec,role):
        node=self.e.call('GET','/info')['Swarm']['NodeID']
        service=service_spec(self.prefix,suffix,node,spec)
        sid=self.e.call('POST','/services/create',service)['ID']
        self.services[sid]=None
        def running():
            tasks=self.e.call('GET','/tasks?filters='+quote(json.dumps({'service':[sid]})))
            active=[t for t in tasks if t['Status']['State']=='running']
            if len(active)!=1:return None
            task=active[0]
            if task['NodeID']!=node:raise ValueError('fixture task unexpectedly off-node')
            cid=task['Status']['ContainerStatus']['ContainerID']
            obj=self.e.inspect(cid,missing=True)
            return (task,obj) if obj and obj['State']['Running'] else None
        task,obj=self.wait(running,60,'actual Swarm source task')
        cid=obj['Id'];self.services[sid]=cid;self.containers[cid]=obj['Name'].lstrip('/');self.roles[cid]=role
        self.pin_container(cid)
        for mount in obj['Mounts']:
            if mount['Type']=='volume' and mount['Name'] not in self.volumes:self.volumes.append(mount['Name'])
        self.result.setdefault('swarm_sources',[]).append({'service':sid,'node':node,'task':task['ID'],'container':cid,'service_labels':service['Labels'],'container_has_opt_in':'bakabel.type' in obj['Config']['Labels']})
        if 'bakabel.type' in obj['Config']['Labels']:raise ValueError('fixture copied service opt-in onto task container')
        return cid

    def create(self,suffix,spec,**kw):
        if kw.get('role')=='source-files':
            backend=suffix.removeprefix('files-')
            name=self.prefix+'-restore-'+backend
            self.e.call('POST','/volumes/create',{'Name':name,'Labels':{'probe.bakabel.owner':self.prefix}})
            self.volumes.append(name)
            directory=self.root/'destinations'/backend;directory.mkdir(parents=True,mode=0o700)
            self.restores[backend]={'volume':name,'directory':directory}
            if self.platform=='swarm':return self.swarm_source(suffix,spec,'source-files')
        return super().create(suffix,spec,**kw)

    def startpg(self,suffix,marked):
        if self.platform!='swarm' or not marked:return super().startpg(suffix,marked)
        name=self.prefix+'-'+suffix+'-data'
        self.e.call('POST','/volumes/create',{'Name':name,'Labels':{'probe.bakabel.owner':self.prefix}});self.volumes.append(name)
        spec={'Image':PG,'Entrypoint':['sh','-c'],'Cmd':['while [ ! -e /gate/start ]; do sleep .05; done; exec docker-entrypoint.sh postgres -c listen_addresses=127.0.0.1'],'Labels':{'bakabel.type':'postgres'},'Env':['POSTGRES_HOST_AUTH_METHOD=trust','POSTGRES_DB=fixture','POSTGRES_USER=postgres'],'HostConfig':{'Mounts':[{'Type':'volume','Source':name,'Target':'/var/lib/postgresql'},self.bind(self.root/'private','/gate',True)]}}
        cid=self.swarm_source(suffix,spec,'source-pg')
        if os.sched_getaffinity(self.e.inspect(cid)['State']['Pid'])!={0,1}:raise ValueError('PG startup affinity not enforced')
        gate=self.root/'private/start';gate.touch()
        try:self.wait(lambda:self.e.exec(cid,['pg_isready','-h','127.0.0.1','-U','postgres','-d','fixture'])['exit']==0,30,'Swarm PG readiness')
        finally:gate.unlink(missing_ok=True)
        if self.sql(cid,'SHOW listen_addresses')!='127.0.0.1':raise ValueError('Swarm PostgreSQL listener escaped loopback')
        return cid

    def call_cli(self,command,*argv,**kw):
        result=super().call_cli(command,*argv,**kw)
        if command=='plan' and self.platform=='swarm' and kw.get('expect',0)==0:
            targets=result['targets'];backend='local' if self.repository.startswith('/') else 's3'
            tasks=self.e.call('GET','/tasks');node=self.e.call('GET','/info')['Swarm']['NodeID']
            for target in targets:
                source=target['Source'];obj=self.e.inspect(source['ContainerID'])
                if source['DaemonID']!=self.daemon or source['StartedAt']!=obj['State']['StartedAt'] or not any(t['NodeID']==node and t['Status']['State']=='running' and t['Status'].get('ContainerStatus',{}).get('ContainerID')==source['ContainerID'] for t in tasks):
                    raise ValueError('Swarm plan not bound to actual running local task')
            self.gate(backend+'-service-labels-running-task-node-identity',node=node,targets=len(targets))
        return result

    def bind_alias(self,source,destination):
        destination.mkdir(mode=0o700)
        subprocess.run(['mount','--bind',str(source),str(destination)],check=True,capture_output=True)
        self.mounted.append(destination)

    def unmount(self,destination):
        subprocess.run(['umount',str(destination)],check=True,capture_output=True)
        self.mounted.remove(destination)

    def remove_source(self,cid,keep_volumes=False):
        obj=self.e.inspect(cid)
        sid=next((sid for sid,c in self.services.items() if c==cid),None)
        if sid:
            self.e.call('DELETE','/services/'+sid)
            self.wait(lambda:(lambda v:v is None or not v['State']['Running'])(self.e.inspect(cid,missing=True)),30,'deleted source service terminal')
            del self.services[sid]
        volumes=[m['Name'] for m in obj['Mounts'] if m['Type']=='volume']
        backend=next((b for b,entry in self.restores.items() if any(m.get('Name')==self.prefix+'-files-'+b for m in obj['Mounts'])),None)
        self.e.call('DELETE','/containers/'+cid+'?force=true&v=true',missing=True)
        if backend:
            source=self.e.call('GET','/volumes/'+self.prefix+'-files-'+backend)
            backing=Path(source['Mountpoint']);payload=backing/'payload';payload.unlink()
            alias=self.root/('source-alias-'+backend);self.bind_alias(backing,alias)
            try:
                self.call_cli('restore','--snapshot',self.source_snapshots[backend],'--directory',str(alias),fresh=True,expect=1)
                if list(alias.iterdir()):raise ValueError('physical source alias was written')
                self.gate(backend+'-file-source-physical-alias-refused',different_lexical_path=True,source_consumer_absent=True)
            finally:self.unmount(alias)
        for name in ([] if keep_volumes else volumes):
            if name not in self.volumes:raise ValueError('refusing unowned source volume removal')
            self.e.call('DELETE','/volumes/'+name,missing=True)
            if self.e.call('GET','/volumes/'+name,missing=True) is not None:raise ValueError('source volume removal not observed')
        if self.e.inspect(cid,missing=True) is not None:raise ValueError('source container removal not observed')

    def payload(self,directory):
        path=directory/'payload';st=path.stat()
        if path.read_bytes()!=b'compose-cli-payload\n' or (stat.S_IMODE(st.st_mode),st.st_uid,st.st_gid)!=(0o640,1234,2345):
            raise ValueError('file restore bytes/mode/numeric owner mismatch')

    def restore_files(self,backend,snapshot):
        target=self.restores[backend]
        result=self.call_cli('restore','--snapshot',snapshot,'--directory',str(target['directory']),fresh=True)
        if result['status']!='restored':raise ValueError('directory restore failed')
        self.payload(target['directory'])
        result=self.call_cli('restore','--snapshot',snapshot,'--volume',target['volume'],fresh=True)
        if result['status']!='restored':raise ValueError('unused default-local volume restore failed')
        self.payload(Path(self.e.call('GET','/volumes/'+target['volume'])['Mountpoint']))
        self.gate(backend+'-file-directory-and-unused-default-local-volume-restored',snapshot=snapshot,mode='0640',uid=1234,gid=2345,source_and_old_state_absent=True)
        empty=self.root/('consumer-empty-'+backend);empty.mkdir(mode=0o700)
        alias=self.root/('consumer-alias-'+backend);self.bind_alias(empty,alias)
        consumer=self.create('consumer-'+backend,{'Image':PG,'Entrypoint':['sh','-c'],'Cmd':['true'],'HostConfig':{'Mounts':[self.bind(alias,'/consumer',True)]}},role='negative-consumer',start=False)
        try:
            self.call_cli('restore','--snapshot',snapshot,'--directory',str(empty),fresh=True,expect=1)
            if list(empty.iterdir()):raise ValueError('consumer alias was written')
            self.gate(backend+'-file-consumer-physical-alias-refused',stopped_consumer=True)
        finally:self.remove_source(consumer);self.unmount(alias)
        original=self.prefix+'-original-'+backend;alternate=self.prefix+'-alternate-'+backend
        self.e.call('POST','/volumes/create',{'Name':original});self.volumes.append(original)
        backing=self.e.call('GET','/volumes/'+original)['Mountpoint']
        self.e.call('POST','/volumes/create',{'Name':alternate,'Driver':'local','DriverOpts':{'type':'none','o':'bind','device':backing}});self.volumes.append(alternate)
        checker=self.create('alias-check-'+backend,{'Image':PG,'Entrypoint':['sh','-c'],'Cmd':['stat -c "%d:%i" /original /alternate'],'HostConfig':{'Mounts':[{'Type':'volume','Source':original,'Target':'/original'},{'Type':'volume','Source':alternate,'Target':'/alternate'}]}},role='alias-identity-check')
        self.finish(checker);identities=self.logs(checker).splitlines()
        if len(identities)!=2 or identities[0]!=identities[1]:raise ValueError('alternate-volume fixture is not a physical alias')
        self.remove_source(checker,keep_volumes=True)
        self.call_cli('restore','--snapshot',snapshot,'--volume',alternate,fresh=True,expect=1)
        self.gate(backend+'-file-alternate-same-backing-volume-refused',same_device_inode=True,reason_boundary='aliased non-default driver is inadmissible; not an unmeasured branch claim')
        self.result['backends'][backend]['file_restore_exercised']=True
        self.result['cells'][backend]=['postgres','volume']

    def refuse_incomplete_snapshots(self,backend,current):
        # Retag needs an exclusive repository lock. Do this before deliberate
        # SIGKILL can leave another container's young shared Restic lock behind.
        # Never force-unlock a repository merely to make acceptance pass.
        empty=self.restores[backend]['directory']
        for previous,status in (('complete','unknown'),('unknown','partial')):
            self.restic('tag','--remove','bakabel.status='+previous,'--add','bakabel.status='+status,current)
            snapshots=json.loads(self.restic('snapshots','--json'))
            current=next(s['id'] for s in snapshots if 'bakabel.status='+status in s.get('tags',[]) and s['paths'][0].startswith('/bakabel/files/'))
            self.call_cli('restore','--snapshot',current,'--directory',str(empty),fresh=True,expect=1)
            if list(empty.iterdir()):raise ValueError('incomplete snapshot wrote destination')
        self.gate(backend+'-file-unknown-partial-refused',method='real operator Restic retag; not a generated exit3 claim')

    def gate(self,name,**kw):
        backend=name.split('-',1)[0]
        if name.endswith('-mixed-online-CLI-backup-with-default-worker-limits'):
            self.source_snapshots[backend]=kw['file_snapshot']
        super().gate(name,**kw)
        if name.endswith('-file-parent-reused-no-new-data-and-complete-payload-readback'):
            self.refuse_incomplete_snapshots(backend,kw['second'])
        if name.endswith('-fresh-source-and-history-absent-PG-restore-different-role-OIDs-owner-ACL-preserved'):
            self.restore_files(backend,self.result['backends'][backend]['file_snapshot'])

    def run(self):
        if self.platform=='swarm':
            self.owns_swarm=True
            self.e.call('POST','/swarm/init',{'ListenAddr':'127.0.0.1:2377','AdvertiseAddr':'127.0.0.1','DataPathAddr':'127.0.0.1'})
            if self.e.call('GET','/info')['Swarm']['LocalNodeState']!='active':raise ValueError('Swarm init not observed')
        super().run()
        verify_matrix(self.result)
        for worker in self.worker_records.values():
            if worker['Image']!=self.image or worker['Config']['Cmd']!=['_workflow'] or worker['HostConfig']['NanoCpus']!=2000000000 or worker['HostConfig']['Memory']!=536870912:
                raise ValueError('ordinary worker identity/resource default changed')
        if not any(s.get('memory.max')=='536870912' and s.get('cpu.max')=='200000 100000' for s in self.samples if s['role']=='worker'):
            raise ValueError('no real worker kernel resource enforcement observed')
        self.result.update(runtime_matrix_pass=True,file_restore_exercised=True,swarm_exercised=self.platform=='swarm',full_plan_acceptance_pass=False,coverage_boundary='Core two-source/two-backend CLI matrix, alias/status and SIGKILL/S3 faults; not every PLAN fault/capacity case.')

    def cleanup(self):
        for sid in list(self.services):
            self.e.call('DELETE','/services/'+sid,missing=True)
        self.services.clear()
        if self.owns_swarm:
            if self.e.call('GET','/info')['Swarm']['LocalNodeState']!='inactive':
                self.e.call('POST','/swarm/leave?force=true')
                self.wait(lambda:self.e.call('GET','/info')['Swarm']['LocalNodeState']=='inactive',30,'owned Swarm leave readback')
            self.owns_swarm=False
        for path in list(reversed(self.mounted)):self.unmount(path)
        super().cleanup()
        # Parent cleanup removes its known data subtrees; these are new owned
        # restore destinations, kept out of every repository/source mount.
        import shutil
        for name in ('destinations',):
            if (self.root/name).exists():shutil.rmtree(self.root/name)
        for path in self.root.glob('*-local'):
            if path.name.startswith(('source-alias-','consumer-empty-','consumer-alias-')):path.rmdir()
        for path in self.root.glob('*-s3'):
            if path.name.startswith(('source-alias-','consumer-empty-','consumer-alias-')):path.rmdir()
        self.save()


def failure_location(error):
    return {'kind':type(error).__name__,'frames':[{'file':Path(frame.filename).name,'line':frame.lineno,'function':frame.name} for frame in traceback.extract_tb(error.__traceback__)]}


def run_platform(args,probe_class=None):
    # Construction is inventory + owned file setup only, never Engine writes.
    # Keep the partially initialized object reachable if credential copy fails.
    if args.runtime.exists():raise ValueError('platform runtime must be fresh')
    factory=probe_class or HostedProbe
    probe=factory.__new__(factory)
    initialized=False;error=None
    result={'platform':args.platform,'source_sha256':args.expected_source_sha256,'image_id':args.expected_image_id,'runtime_matrix_pass':False,'full_plan_acceptance_pass':False}
    try:
        probe.__init__(args)
        initialized=True;result=probe.result
        probe.run()
    except Exception as exc:
        error=type(exc).__name__
        result['error']=error
        result['error_frames']=traceback.format_tb(exc.__traceback__)
        result['failure']=failure_location(exc)
        print(json.dumps({'failure':result['failure']}),flush=True)
    finally:
        try:
            if initialized:
                probe.cleanup()
            else:
                if hasattr(probe,'stopped'):probe.stopped.set()
                if hasattr(probe,'thread') and probe.thread.is_alive():probe.thread.join(50)
                if hasattr(probe,'thread') and probe.thread.is_alive():raise ValueError('initialization sampler still active')
                if args.runtime.exists():shutil.rmtree(args.runtime)
                args.runtime.mkdir(mode=0o700)
                result['cleanup']={'private_paths_absent':True,'initialization_only':True}
                (args.runtime/'receipt.json').write_text(json.dumps(result,indent=2)+'\n')
        except Exception as exc:
            error=error or type(exc).__name__
            result['cleanup_error']=type(exc).__name__
            if initialized:
                probe.stopped.set();probe.thread.join(10)
                try:probe.save()
                except ValueError:pass
    return {'platform':args.platform,'runtime':str(args.runtime),'failed':error is not None}


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--socket',required=True,type=Path)
    parser.add_argument('--exclusive-hosted-daemon',action='store_true')
    parser.add_argument('--preflight-only',action='store_true')
    for option in ('source','runtime','minio-binary'):parser.add_argument('--'+option,type=Path)
    for option in ('image','expected-source-sha256','expected-image-id'):parser.add_argument('--'+option)
    parser.add_argument('--platform',choices=('compose','swarm','all'),default='all')
    args=parser.parse_args(argv)
    # Reject a local/shared run BEFORE reading inventory or touching its paths.
    if os.environ.get('GITHUB_ACTIONS')!='true' or os.environ.get('RUNNER_ENVIRONMENT')!='github-hosted' or os.geteuid()!=0 or not args.exclusive_hosted_daemon:
        parser.error('requires root on an explicitly exclusive GitHub-hosted VM; local/shared use refused')
    engine=Engine(args.socket)
    info=engine.call('GET','/info')
    require_hosted_daemon(os.environ,os.geteuid(),args.exclusive_hosted_daemon,info,engine.call('GET','/containers/json?all=true'))
    if args.preflight_only:
        print(json.dumps({'daemon':info['ID'],'rootful':True,'cgroup_version':'2','swarm':'inactive','existing_containers':0}))
        return 0
    if not all((args.source,args.runtime,args.minio_binary,args.image,args.expected_source_sha256,args.expected_image_id)):
        parser.error('source/runtime/minio/image and exact source/image bindings are required')
    temporary=Path(os.environ['RUNNER_TEMP']).resolve()
    runtime=args.runtime.resolve()
    if runtime==temporary or not runtime.is_relative_to(temporary) or runtime.exists():
        parser.error('runtime must be a fresh child of RUNNER_TEMP')
    if fingerprint(args.source)!=args.expected_source_sha256:parser.error('source differs from build binding')
    if engine.call('GET','/images/'+quote(args.image,safe='')+'/json')['Id']!=args.expected_image_id:
        parser.error('image differs from build binding')
    os.sched_setaffinity(0,{0,1})
    runtime.mkdir(mode=0o700)
    selected=('compose','swarm') if args.platform=='all' else (args.platform,)
    results=[]
    for platform in selected:
        scoped=copy.copy(args);scoped.platform=platform;scoped.runtime=runtime/platform
        row=run_platform(scoped)
        results.append(row)
        print(json.dumps(row),flush=True)
        if row['failed']:break
    complete=len(results)==len(selected) and not any(r['failed'] for r in results)
    report={'finished_at':utc(),'daemon':info['ID'],'source_sha256':args.expected_source_sha256,'image_id':args.expected_image_id,'platforms':results,'runtime_matrix_pass':complete,'full_plan_acceptance_pass':False}
    (runtime/'hosted-result.json').write_text(json.dumps(report,indent=2)+'\n')
    return 0 if complete else 1


if __name__=='__main__':raise SystemExit(main())
