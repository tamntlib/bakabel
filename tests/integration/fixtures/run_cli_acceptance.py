#!/usr/bin/env python3
"""Owned real-DinD CLI acceptance: actual production image, Engine and MinIO.
All data synthetic; host Swarm remains inactive. No production code edits.
"""
import argparse,hashlib,http.client,json,os,pathlib,secrets,shutil,subprocess,sys,time,traceback
from cli_relay import Relay,UnixConnection
PG='postgres:18.6-alpine3.24'; DIND='docker:29.6.1-dind'
def parse_args(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime',required=True,type=pathlib.Path)
    parser.add_argument('--image',required=True,help='locally built ordinary runtime image')
    parser.add_argument('--minio',required=True,type=pathlib.Path,help='verified baseline-compatible fixture binary')
    parser.add_argument('--restic',required=True,type=pathlib.Path,help='Restic binary extracted from the pinned image')
    return parser.parse_args(argv)

def api(sock,method,path,body=None):
    c=UnixConnection(sock)
    try:
        c.request(method,'/v1.55'+path,None if body is None else json.dumps(body),{'Content-Type':'application/json'}); r=c.getresponse(); b=r.read()
        if r.status>=300: raise RuntimeError(f'Engine {method} {path} HTTP {r.status}: {b[:2000]!r}')
        return json.loads(b) if b else None
    finally: c.close()

def main():
    args=parse_args()
    MINIO=str(args.minio.resolve(strict=True));RESTIC=str(args.restic.resolve(strict=True));IMAGE=args.image
    root=args.runtime.resolve();root.mkdir(mode=0o700)
    prefix='bakabel-cli-proof-'+secrets.token_hex(4); net=prefix+'-network'; engine=prefix+'-engine'; relay=None; owned=[]
    result={'runtime':str(root),'image':IMAGE,'commands':[],'gates':[],'limits_boundary':'Only outer aggregate quota enforced; relay removes ONLY nested create CPU fields; no per-inner cgroup claim.'}
    def run(argv,check=True,timeout=120):
        r=subprocess.run([str(x) for x in argv],capture_output=True,text=True,timeout=timeout)
        result['commands'].append({'argv':[str(x) for x in argv],'exit':r.returncode,'stdout':r.stdout,'stderr':r.stderr})
        if check and r.returncode: raise RuntimeError(f'{argv[:3]} exit {r.returncode}: {r.stdout[-4000:]} {r.stderr[-4000:]}')
        return r
    def outer(*args,**kw):return run(['docker',*args],**kw)
    def inner(*args,**kw):return run(['docker','-H','unix://'+str(root/'relay.sock'),*args],**kw)
    def info(name):return json.loads(outer('inspect',name).stdout)[0]
    def gate(name,**values):result['gates'].append({'gate':name,**values});print('PASS',name,json.dumps(values),flush=True);(root/'receipt.json').write_text(json.dumps(result,indent=2))
    def load(image):
        a=subprocess.Popen(['docker','save',image],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        b=subprocess.run(['docker','-H','unix://'+str(root/'engine.sock'),'load'],stdin=a.stdout,capture_output=True,text=True,timeout=180);a.stdout.close();err=a.communicate(timeout=180)[1]
        assert b.returncode==a.returncode==0,(b.stderr,err)
    def cli(cfg,command,*args,expect=0,network='none',async_=False):
        name=prefix+'-controller-'+secrets.token_hex(3)
        state='state' if cfg=='config.yaml' else 'fresh-state'
        cmd=['run','--name',name,'--cpus','2','--cpuset-cpus','0,1','--network',network,'--label','bakabel.installation='+prefix,'--label','bakabel.role=scheduler',
             '-v',str(root/state)+':/state','-v',str(root/'password')+':/password:ro','-v',str(root/cfg)+':/config.yaml:ro','-v',str(root/'relay.sock')+':/var/run/docker.sock:ro']
        if result.get('s3'): cmd+=['-v',str(root/'aws')+':/aws:ro']
        else:cmd+=['-v',str(root/'repository')+':/repository']
        cmd += [IMAGE,'--config','/config.yaml',command,*args]
        if async_:
            argv=['docker','-H','unix://'+str(root/'relay.sock'),*cmd]
            return name,subprocess.Popen(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True),argv
        cp=inner(*cmd,check=False,timeout=160)
        inner('rm','-f',name,check=False)
        print('CLI',command,cp.returncode,cp.stdout.strip(),cp.stderr.strip(),flush=True)
        assert cp.returncode==expect,(command,cp.returncode,cp.stderr,cp.stdout)
        return json.loads(cp.stdout) if cp.stdout.strip() else None
    def config(name='config.yaml',platform='compose',repo='/repository',timeout='75s',scope=None):
        state='state' if name=='config.yaml' else 'fresh-state'
        extra='  s3_credentials_file: /aws\n  s3_region: us-east-1\n' if repo.startswith('s3:') else ''
        (root/name).write_text(f'version: 1\ninstallation: {prefix}\nplatform: {platform}\nscope: [{scope or prefix}]\nrepository: {repo}\ncredentials:\n  password_file: /password\n{extra}state_dir: /state\nworker_image: {imageid}\ntimeout: {timeout}\n')
    def sql(name,q):return inner('exec',name,'psql','-XAt','-U','postgres','-d','fixture','-v','ON_ERROR_STOP=1','-c',q).stdout.strip()
    def pgready(name):
        for _ in range(200):
            if inner('exec',name,'pg_isready','-h','127.0.0.1','-U','postgres','-d','fixture',check=False).returncode==0:return
            time.sleep(.1)
        raise RuntimeError('PG readiness')
    def payloadcheck(mount,expected='file-cli-payload\n640 1234 2345'):
        text=inner('run','--rm','--network','none','-v',mount+':/data:ro','--entrypoint','sh',PG,'-c','cat /data/payload; stat -c "%a %u %g" /data/payload').stdout.strip();assert text==expected,text
    def remove_all_inner():
        if api(root/'engine.sock','GET','/info')['Swarm']['LocalNodeState']=='active':
            for s in api(root/'engine.sock','GET','/services'):api(root/'engine.sock','DELETE','/services/'+s['ID'])
        for _ in range(100):
            if not api(root/'engine.sock','GET','/containers/json'):break
            # remove all exact IDs; this daemon is entirely task-owned.
            for c in api(root/'engine.sock','GET','/containers/json?all=1'):api(root/'engine.sock','DELETE','/containers/'+c['Id']+'?force=true&v=true')
            time.sleep(.1)
        for c in api(root/'engine.sock','GET','/containers/json?all=1'):api(root/'engine.sock','DELETE','/containers/'+c['Id']+'?force=true&v=true')
        for v in api(root/'engine.sock','GET','/volumes').get('Volumes') or []:api(root/'engine.sock','DELETE','/volumes/'+v['Name'])
    try:
        before=json.loads(outer('info','--format','{{json .}}').stdout);assert before['Swarm']['LocalNodeState']=='inactive';result['outer_id']=before['ID']
        result['image_inspect']=json.loads(outer('image','inspect',IMAGE).stdout)[0];imageid=result['image_inspect']['Id']
        for d in ['data','bin','state','fresh-state','destination']:(root/d).mkdir(mode=0o700)
        shutil.copy2(MINIO,root/'bin/minio');shutil.copy2(RESTIC,root/'bin/restic')
        (root/'password').write_text(secrets.token_hex(24));os.chmod(root/'password',0o600)
        owned.append(net);outer('network','create','--internal',net)
        owned.append(engine);outer('run','-d','--name',engine,'--privileged','--cpus','2','--network',net,'-v',str(root)+':'+str(root),'-v',str(root/'data')+':/bakabel-data','--entrypoint','sh',DIND,'-c',f'while [ ! -e {root}/start ]; do sleep .1; done; exec dockerd --host=unix://{root}/engine.sock --data-root=/bakabel-data --storage-driver=vfs --iptables=false --ip-forward=false --ip-masq=false')
        outerinfo=info(engine);run(['taskset','-pc','0,1',str(outerinfo['State']['Pid'])]);(root/'start').touch()
        for _ in range(200):
            try: inf=api(root/'engine.sock','GET','/info');break
            except Exception:time.sleep(.1)
        else: raise RuntimeError('engine readiness '+outer('logs',engine).stdout)
        quota=outer('exec',engine,'sh','-c','read x < /sys/fs/cgroup/cpu.max; printf "%s\\n" "$x"').stdout.strip()
        affinity=outer('exec',engine,'sh','-c','while read a b; do case "$a" in Cpus_allowed_list:) printf "%s\\n" "$b";; esac; done < /proc/1/status').stdout.strip()
        relay=Relay(root/'relay.sock',root/'engine.sock',root/'relay.jsonl',inner=inf['ID'],outer=before['ID'],quota=quota,affinity=affinity);relay.start()
        gate('real-isolated-engine-with-aggregate-limits',inner_id=inf['ID'],outer_id=before['ID'],quota=quota,affinity=affinity)
        load(PG);load(IMAGE)
        result['inner_image_inspect']=json.loads(inner('image','inspect',IMAGE).stdout)[0]
        imageid=result['inner_image_inspect']['Id']
        bridge=api(root/'engine.sock','GET','/networks/bridge'); gateway=bridge['IPAM']['Config'][0]['Gateway'];result['bridge']=bridge;result['gateway']=gateway
        config();env=dict(os.environ,RESTIC_REPOSITORY=str(root/'repository'),RESTIC_PASSWORD_FILE=str(root/'password'))
        def localrestic(*args):
            return run(['env','RESTIC_REPOSITORY='+str(root/'repository'),'RESTIC_PASSWORD_FILE='+str(root/'password'),'taskset','-c','0,1',RESTIC,*args],timeout=40)
        localrestic('init')
        volume=prefix+'-source';targetvol=prefix+'-restore'
        inner('volume','create',volume);inner('volume','create',targetvol)
        source=prefix+'-files'
        inner('run','-d','--name',source,'--network','none','--label','com.docker.compose.project='+prefix,'--label','com.docker.compose.service=files','--label','bakabel.type=volume','--label','bakabel.paths=/data','-v',volume+':/data','--entrypoint','sh',PG,'-c','while :; do sleep 3600; done')
        inner('exec',source,'sh','-c','printf "file-cli-payload\\n" > /data/payload; chmod 640 /data/payload; chown 1234:2345 /data/payload')
        plan=cli('config.yaml','plan');assert len(plan['targets'])==1
        a=cli('config.yaml','run');b=cli('config.yaml','run');assert a['status']==b['status']=='complete';sid=a['targets'][0]['snapshotID']
        for r in (a,b):
            workers=[w for w in relay.records if (w.get('labels') or {}).get('bakabel.run')==r['runID']]
            assert len(workers)==1 and workers[0]['cmd']==['_workflow'] and workers[0]['entrypoint']==['/usr/local/bin/bakabel']
            assert workers[0]['omitted']=={'NanoCpus':2000000000,'CpusetCpus':'0,1'}
        actual=json.loads(localrestic('snapshots','--json').stdout);assert len(actual)==2 and actual[1]['parent']==actual[0]['id'] and actual[0]['paths']==actual[1]['paths']
        assert actual[1]['summary']['files_unmodified']==1 and actual[1]['summary']['data_blobs']==0
        # Concrete snapshot-source physical identity: after removing the only
        # source consumer, clear its bytes, bind the same backing under an
        # unrelated native directory, and require the actual CLI to refuse it.
        sourcebacking=inner('volume','inspect',volume,'--format','{{.Mountpoint}}').stdout.strip()
        inner('exec',source,'rm','/data/payload');inner('rm','-f','-v',source)
        physical=root/'physical-source-alias';physical.mkdir()
        outer('exec',engine,'mount','--bind',sourcebacking,str(physical))
        cli('config.yaml','restore','--snapshot',sid,'--directory',str(physical),expect=1)
        assert not list(physical.iterdir())
        outer('exec',engine,'umount',str(physical))
        gate('B2-real-CLI-snapshot-source-physical-alias-refused',lexically_different=True,no_source_consumer=True,destination_unchanged=True)
        inner('volume','rm',volume);shutil.rmtree(root/'state');config('fresh.yaml',scope='no-sources')
        snaps=cli('fresh.yaml','snapshots');assert len(snaps)==2 and all(s['status']=='complete' for s in snaps)
        restored=cli('fresh.yaml','restore','--snapshot',sid,'--directory',str(root/'destination'));assert restored['status']=='restored';payloadcheck(str(root/'destination'))
        restored=cli('fresh.yaml','restore','--snapshot',sid,'--volume',targetvol);assert restored['status']=='restored';payloadcheck(targetvol)
        gate('B2-real-CLI-file-directory-and-unused-default-local-volume',snapshot=sid,source_and_old_state_absent=True,mode='0640',uid=1234,gid=2345,one_workflow_worker_per_run=True,stable_parent=True,zero_new_data_blobs=True)
        # Real bind alias consumer: different native names, identical directory inode.
        alias=root/'alias';alias.mkdir();empty=root/'empty';empty.mkdir()
        outer('exec',engine,'mount','--bind',str(empty),str(alias))
        consumer=prefix+'-alias-consumer'
        inner('create','--name',consumer,'--network','none','-v',str(alias)+':/consumer:ro','--entrypoint','sh',PG,'-c','true')
        cli('fresh.yaml','restore','--snapshot',sid,'--directory',str(empty),expect=1)
        assert not list(empty.iterdir());inner('rm','-f',consumer);outer('exec',engine,'umount',str(alias))
        # Alternate local volume name genuinely bound to same physical backing.
        original=prefix+'-original';alternate=prefix+'-alternate';inner('volume','create',original)
        backing=inner('volume','inspect',original,'--format','{{.Mountpoint}}').stdout.strip()
        inner('volume','create','--opt','type=none','--opt','o=bind','--opt','device='+backing,alternate)
        identities=inner('run','--rm','--network','none','-v',original+':/original','-v',alternate+':/alternate','--entrypoint','sh',PG,'-c','stat -c "%d:%i" /original /alternate').stdout.splitlines()
        assert len(identities)==2 and identities[0]==identities[1]
        cli('fresh.yaml','restore','--snapshot',sid,'--volume',alternate,expect=1)
        gate('B2-real-CLI-consumer-physical-alias-and-differently-named-same-backing-volume-refused',consumer_alias=True,alternate_volume=alternate,backing=backing)
        # Real repository status changes, not fake snapshots; this exercises CLI
        # status refusal, not production generation of Restic exit-3 partials.
        to_tag=b['targets'][0]['snapshotID']
        for previous,status in [('complete','unknown'),('unknown','partial')]:
            localrestic('tag','--remove','bakabel.status='+previous,'--add','bakabel.status='+status,to_tag)
            current=json.loads(localrestic('snapshots','--json').stdout)
            to_tag=next(s['id'] for s in current if 'bakabel.status='+status in s.get('tags',[]))
            cli('fresh.yaml','restore','--snapshot',to_tag,'--directory',str(empty),expect=1);assert not list(empty.iterdir())
        gate('B2-real-CLI-unknown-partial-restore-refused',method='actual operator Restic retag; no fabricated snapshot or exit-3 claim')
        remove_all_inner()
        shutil.rmtree(root/'fresh-state');(root/'fresh-state').mkdir(mode=0o700);(root/'state').mkdir(mode=0o700)
        # Actual Swarm exists only in the owned engine.
        ip=next(iter(info(engine)['NetworkSettings']['Networks'].values()))['IPAddress']
        api(root/'engine.sock','POST','/swarm/init',{'ListenAddr':'0.0.0.0:2377','AdvertiseAddr':ip,'DataPathAddr':ip,'Spec':{'Name':'default'}})
        swarm_info=api(root/'engine.sock','GET','/info');node=swarm_info['Swarm']['NodeID'];result['swarm_node']=node
        user='fixture'+secrets.token_hex(8);password=secrets.token_hex(24)
        (root/'minio-user').write_text(user);(root/'minio-password').write_text(password)
        (root/'aws').write_text(f'[default]\naws_access_key_id = {user}\naws_secret_access_key = {password}\n')
        for pth in ['minio-user','minio-password','aws']:os.chmod(root/pth,0o600)
        minio=prefix+'-minio'
        inner('run','-d','--name',minio,'--network','host','-v',str(root/'bin/minio')+':/minio:ro','-v',str(root/'minio-user')+':/credentials/user:ro','-v',str(root/'minio-password')+':/credentials/password:ro','-e','MINIO_ROOT_USER_FILE=/credentials/user','-e','MINIO_ROOT_PASSWORD_FILE=/credentials/password','-e','MINIO_BROWSER=off','-e','GOMAXPROCS=2','--entrypoint','/minio',PG,'server','/minio-data','--address','0.0.0.0:9000')
        repo='s3:http://'+gateway+':9000/bakabel-cli/repository';result['s3']=True;result['s3_repository']=repo
        def s3restic(*args,check=True):
            return inner('run','--rm','--network','bridge','-v',str(root/'bin/restic')+':/restic:ro','-v',str(root/'password')+':/password:ro','-v',str(root/'aws')+':/aws:ro','-e','RESTIC_REPOSITORY='+repo,'-e','RESTIC_PASSWORD_FILE=/password','-e','AWS_SHARED_CREDENTIALS_FILE=/aws','-e','AWS_DEFAULT_REGION=us-east-1','--entrypoint','/restic',PG,'--no-cache',*args,check=check,timeout=100)
        for _ in range(100):
            logs=inner('logs',minio).stdout
            if '9000' in logs:break
            time.sleep(.1)
        s3restic('init')
        gate('B3-real-MinIO-auth-over-real-inner-bridge',gateway=gateway,network_mode='bridge',no_network_mapping=True)
        def service(name,kind):
            labels={'com.docker.stack.namespace':prefix,'bakabel.type':kind}
            if kind=='volume':labels['bakabel.paths']='/data'
            spec={'Name':prefix+'_'+name.removeprefix(prefix+'-'),'Labels':labels,'TaskTemplate':{'ContainerSpec':{'Image':PG,'Env':['POSTGRES_HOST_AUTH_METHOD=trust','POSTGRES_DB=fixture','POSTGRES_USER=postgres'],'Mounts':[{'Type':'volume','Source':name+'-data','Target':'/var/lib/postgresql' if kind=='postgres' else '/data'}]},'Placement':{'Constraints':['node.id=='+node]},'RestartPolicy':{'Condition':'none'}},'Mode':{'Replicated':{'Replicas':1}},'Networks':[{'Target':'host'}]}
            if kind=='volume':spec['TaskTemplate']['ContainerSpec'].update({'Command':['sh','-c','while :; do sleep 3600; done']})
            sid=api(root/'engine.sock','POST','/services/create',spec)['ID']
            for _ in range(200):
                tasks=api(root/'engine.sock','GET','/tasks?filters='+__import__('urllib.parse',fromlist=['quote']).quote(json.dumps({'service':[sid]})))
                running=[t for t in tasks if t['Status']['State']=='running']
                if len(running)==1:return sid,running[0]['Status']['ContainerStatus']['ContainerID']
                time.sleep(.1)
            raise RuntimeError('Swarm service task readiness '+json.dumps(tasks))
        pgservice,pg=service(prefix+'-pg','postgres');fileservice,filec=service(prefix+'-swarm-files','volume');pgready(pg)
        sql(pg,'CREATE ROLE fixture_owner; CREATE TABLE payload AS SELECT g,md5(g::text) data FROM generate_series(1,20000) g; ALTER TABLE payload OWNER TO fixture_owner; ALTER DATABASE fixture OWNER TO fixture_owner; REVOKE CONNECT ON DATABASE fixture FROM PUBLIC')
        expected=sql(pg,"SELECT count(*),sum(g),md5(string_agg(g::text||':'||data,',' ORDER BY g)) FROM payload")
        inner('exec',filec,'sh','-c','printf "file-cli-payload\\n" > /data/payload; chmod 640 /data/payload; chown 1234:2345 /data/payload')
        config(platform='swarm',repo=repo);config('fresh.yaml',platform='swarm',repo=repo,scope='no-sources')
        plan=cli('config.yaml','plan',network='bridge');assert len(plan['targets'])==2
        # Assert service opt-in labels, not task-container opt-in copies.
        for cid in [pg,filec]:assert 'bakabel.type' not in api(root/'engine.sock','GET','/containers/'+cid+'/json')['Config']['Labels']
        pgstart=api(root/'engine.sock','GET','/containers/'+pg+'/json')['State']['StartedAt']
        outcome=cli('config.yaml','run',network='bridge');assert outcome['status']=='complete' and len(outcome['targets'])==2
        job=json.loads((root/'state/workflow/job.json').read_text());result['frozen_swarm_targets']=job['targets']
        assert {t['Source']['ContainerID'] for t in job['targets']}=={pg,filec}
        assert all(t['Source']['DaemonID']==inf['ID'] and t['Source']['StartedAt']==api(root/'engine.sock','GET','/containers/'+t['Source']['ContainerID']+'/json')['State']['StartedAt'] for t in job['targets'])
        real_tasks=api(root/'engine.sock','GET','/tasks')
        assert all(any(t['NodeID']==node and t['Status'].get('ContainerStatus',{}).get('ContainerID')==cid for t in real_tasks) for cid in [pg,filec])
        creates=[r for r in relay.records if (r.get('labels') or {}).get('bakabel.run')==outcome['runID']];assert len(creates)==1 and creates[0]['cmd']==['_workflow'] and creates[0]['HostConfig']['NetworkMode']=='bridge'
        for target,ref in [('/run/secrets/restic-password',str(root/'password')),('/run/secrets/aws',str(root/'aws'))]:assert any(m['Target']==target and m['Source']==ref and m['ReadOnly'] for m in creates[0]['HostConfig']['Mounts'])
        assert api(root/'engine.sock','GET','/containers/'+pg+'/json')['State']['StartedAt']==pgstart
        s3snaps=json.loads(s3restic('snapshots','--json').stdout);assert len(s3snaps)==2 and all('bakabel.status=complete' in s['tags'] for s in s3snaps)
        pgid=next(s['id'] for s in s3snaps if s['paths'][0].startswith('/bakabel/postgres/'));fileid=next(s['id'] for s in s3snaps if s['paths'][0].startswith('/bakabel/files/'))
        api(root/'engine.sock','DELETE','/services/'+pgservice);api(root/'engine.sock','DELETE','/services/'+fileservice)
        for cid in [pg,filec]:
            for _ in range(100):
                try:
                    obj=api(root/'engine.sock','GET','/containers/'+cid+'/json')
                    if not obj['State']['Running']:break
                except Exception:break
                time.sleep(.1)
            inner('rm','-f','-v',cid,check=False)
        for name in [prefix+'-pg-data',prefix+'-swarm-files-data']:inner('volume','rm',name)
        shutil.rmtree(root/'state');snaps=cli('fresh.yaml','snapshots',network='bridge');assert {s['snapshotID'] for s in snaps}=={pgid,fileid}
        restorepg=prefix+'-pg-restore'
        inner('run','-d','--name',restorepg,'--network','none','-e','POSTGRES_HOST_AUTH_METHOD=trust','-e','POSTGRES_DB=fixture','-e','POSTGRES_USER=postgres',PG);pgready(restorepg)
        cli('fresh.yaml','restore','--snapshot',pgid,'--postgres-container',restorepg,'--database','fixture','--user','postgres',expect=1,network='bridge')
        assert sql(restorepg,"SELECT count(*) FROM pg_class WHERE relname='payload'")=='0'
        sql(restorepg,'CREATE ROLE fixture_owner; ALTER DATABASE fixture OWNER TO fixture_owner; REVOKE CONNECT ON DATABASE fixture FROM PUBLIC')
        assert cli('fresh.yaml','restore','--snapshot',pgid,'--postgres-container',restorepg,'--database','fixture','--user','postgres',network='bridge')['status']=='restored'
        assert sql(restorepg,"SELECT count(*),sum(g),md5(string_agg(g::text||':'||data,',' ORDER BY g)) FROM payload")==expected
        assert sql(restorepg,"SELECT tableowner FROM pg_tables WHERE tablename='payload'")=='fixture_owner'
        assert sql(restorepg,"SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname='fixture'")=='fixture_owner'
        assert sql(restorepg,"SELECT count(*) FROM pg_database d,LATERAL aclexplode(COALESCE(d.datacl,acldefault('d',d.datdba))) a WHERE d.datname='fixture' AND a.grantee=0 AND a.privilege_type='CONNECT'")=='0'
        s3dest=root/'s3destination';s3dest.mkdir(mode=0o700)
        assert cli('fresh.yaml','restore','--snapshot',fileid,'--directory',str(s3dest),network='bridge')['status']=='restored';payloadcheck(str(s3dest))
        gate('B3-real-Swarm-S3-mixed-CLI-independent-restores',postgres_snapshot=pgid,files_snapshot=fileid,postgres_readback=expected,owner_acl_verified=True,source_and_state_absent=True,one_worker=True,service_labels=True,frozen_node=node)
        # Each destructive fault gets a new real Swarm source, its own CLI run,
        # exact durable checkpoint and observed SQL + Engine terminal proof.
        for fault in ['worker-SIGKILL','S3-outage']:
            (root/'state').mkdir(mode=0o700,exist_ok=True)
            config(platform='swarm',repo=repo,timeout='18s')
            fsid,fcid=service(prefix+'-'+fault.lower(),'postgres');pgready(fcid)
            sql(fcid,'CREATE TABLE payload AS SELECT g,md5(g::text) data FROM generate_series(1,20000) g')
            inner('exec','-d','-e','PGAPPNAME=fixture-lock',fcid,'psql','-XAt','-U','postgres','-d','fixture','-v','ON_ERROR_STOP=1','-c','BEGIN; LOCK TABLE payload IN ACCESS EXCLUSIVE MODE; SELECT pg_sleep(90)')
            for _ in range(100):
                if sql(fcid,"SELECT count(*) FROM pg_stat_activity WHERE application_name='fixture-lock' AND wait_event='PgSleep'")=='1':break
                time.sleep(.05)
            else:raise RuntimeError('lock readiness')
            started=time.monotonic();controller,process,argv=cli('config.yaml','run',network='bridge',async_=True)
            for _ in range(160):
                try:
                    active=json.loads((root/'state/owner.json').read_text())
                    if active.get('phase')=='exec_started' and api(root/'engine.sock','GET','/exec/'+active['execID']+'/json')['Running'] and sql(fcid,"SELECT count(*) FROM pg_stat_activity WHERE application_name='"+active['runID']+"' AND wait_event_type='Lock'")=='1':break
                except (FileNotFoundError,KeyError,json.JSONDecodeError):pass
                if process.poll() is not None:raise RuntimeError('fault CLI ended before checkpoint '+str(process.communicate()))
                time.sleep(.05)
            else:raise RuntimeError('actual blocked dump checkpoint not reached')
            result.setdefault('fault_checkpoints',{})[fault]=active
            if fault=='worker-SIGKILL':
                inner('kill','--signal','STOP',controller)
                inner('kill','--signal','KILL',active['workerContainerID'])
                assert (root/'state/owner.json').exists()
                before_creates=len([r for r in relay.records if (r.get('labels') or {}).get('bakabel.worker')=='1'])
                cli('config.yaml','run',expect=1,network='bridge')
                assert len([r for r in relay.records if (r.get('labels') or {}).get('bakabel.worker')=='1'])==before_creates
                assert json.loads((root/'state/owner.json').read_text())['runID']==active['runID']
                inner('kill','--signal','CONT',controller)
            else:
                inner('stop','--time','1',minio)
                assert not api(root/'engine.sock','GET','/containers/'+minio+'/json')['State']['Running']
                cli('config.yaml','run',expect=1,network='bridge')
                # Drop the source lock only after the provider is actually down.
                sql(fcid,"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name='fixture-lock'")
                time.sleep(max(0,started+21-time.monotonic()))
                inner('start',minio)
            out,err=process.communicate(timeout=50)
            elapsed=time.monotonic()-started
            result['commands'].append({'argv':argv,'exit':process.returncode,'stdout':out,'stderr':err,'elapsed_seconds':elapsed})
            inner('rm','-f',controller)
            assert process.returncode!=0 and elapsed<55,(fault,process.returncode,out,err,elapsed)
            failed=json.loads(out);assert failed['status']=='failed'
            assert not (root/'state/owner.json').exists(), 'terminal source proof must release durable ownership'
            execstate=api(root/'engine.sock','GET','/exec/'+active['execID']+'/json');assert not execstate['Running']
            sessions=sql(fcid,"SELECT count(*) FROM pg_stat_activity WHERE application_name='"+active['runID']+"'");assert sessions=='0'
            top=api(root/'engine.sock','GET','/containers/'+fcid+'/top?ps_args=-eo%20pid,args')
            assert not any(active['runID'] in ' '.join(row) for row in top['Processes'])
            actual=json.loads(s3restic('snapshots','--json').stdout)
            assert not any('bakabel.status=complete' in s.get('tags',[]) and any(tag.startswith('bakabel.run='+active['runID']+'-') for tag in s.get('tags',[])) for s in actual)
            gate('B3-real-CLI-'+fault+'-bounded-recovery',run=active['runID'],elapsed_seconds=elapsed,owner_blocked_overlap=True,source_exec_running=execstate['Running'],source_exit=execstate['ExitCode'],source_sessions=sessions,source_processes=0,owner_released=True,no_complete_snapshot=True)
            sql(fcid,"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name='fixture-lock'")
            api(root/'engine.sock','DELETE','/services/'+fsid)
            inner('rm','-f','-v',fcid,check=False)
            # Let asynchronous Swarm deletion stop before removing its exact volume.
            time.sleep(.2);inner('volume','rm',prefix+'-'+fault.lower()+'-data')
        # Secret values are never written into argv, Engine Env or receipts.
        evidence=json.dumps(result)+''.join((root/'relay.jsonl').read_text())
        for value in [user,password,(root/'password').read_text()]:assert value not in evidence
        workers=[r for r in relay.records if (r.get('labels') or {}).get('bakabel.worker')=='1']
        assert len({r['labels']['bakabel.run'] for r in workers})==len(workers)
        assert all(r['cmd']==['_workflow'] and r['entrypoint']==['/usr/local/bin/bakabel'] and r['image']==imageid and r['omitted']=={'NanoCpus':2000000000,'CpusetCpus':'0,1'} for r in workers)
        result['all_worker_create_count']=len(workers)
        gate('all-runtime-workers-uninstrumented-one-per-run-with-production-resource-defaults',worker_creates=len(workers),commands=['_workflow'],inner_image=imageid)
        gate('credential-values-absent-from-argv-EngineEnv-and-evidence')
    except Exception as e:
        result['error']=repr(e);result['traceback']=traceback.format_exc();print(result['traceback'],flush=True)
    finally:
        if relay:
            try:
                remove_all_inner()
                state=api(root/'engine.sock','GET','/info')['Swarm']['LocalNodeState']
                result['inner_cleanup']={'containers':api(root/'engine.sock','GET','/containers/json?all=1'),'services':api(root/'engine.sock','GET','/services') if state=='active' else {'swarm_state':state},'volumes':api(root/'engine.sock','GET','/volumes')}
                assert not result['inner_cleanup']['containers'] and not result['inner_cleanup']['volumes'].get('Volumes')
            except Exception as e:result['cleanup_error']=repr(e)
            relay.close()
        for n in reversed(owned):
            if n==net:outer('network','rm',n,check=False)
            else:outer('rm','-f','-v',n,check=False)
        result['owned_absent']={n:(outer('network' if n==net else 'container','inspect',n,check=False).returncode!=0) for n in owned}
        result['outer_swarm_after']=outer('info','--format','{{.Swarm.LocalNodeState}}').stdout.strip()
        # Root-owned nested data are deleted through an exact owned scratch mount.
        cleaner=prefix+'-clean';outer('run','--name',cleaner,'--network','none','--cpus','2','-v',str(root)+':/cleanup','--entrypoint','sh',PG,'-c','rm -rf /cleanup/data /cleanup/bin /cleanup/state /cleanup/fresh-state /cleanup/destination /cleanup/repository /cleanup/password /cleanup/aws /cleanup/minio-user /cleanup/minio-password /cleanup/minio-data /cleanup/s3destination /cleanup/empty /cleanup/alias /cleanup/physical-source-alias',check=False);outer('rm','-f','-v',cleaner,check=False)
        result['private_data_absent']=not any((root/p).exists() for p in ['data','bin','state','fresh-state','destination','repository','password','aws','minio-user','minio-password','minio-data','s3destination','empty','alias','physical-source-alias'])
        (root/'receipt.json').write_text(json.dumps(result,indent=2));print('RECEIPT',root/'receipt.json',flush=True)
    return 1 if result.get('error') or result.get('cleanup_error') or not result['private_data_absent'] or not all(result['owned_absent'].values()) or result['outer_swarm_after']!='inactive' else 0
if __name__=='__main__':sys.exit(main())
