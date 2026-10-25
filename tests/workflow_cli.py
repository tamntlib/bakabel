#!/usr/bin/env python3
"""Explicit disposable CLI contract. Docker containers/volumes use one random prefix.
Never accepts production IDs/paths/repositories. Run after building BAKABEL_WORKFLOW_IMAGE.
"""
import json,os,pathlib,subprocess,tempfile,time,uuid,shutil
root=pathlib.Path(tempfile.mkdtemp(prefix='bakabel-cli-',dir=os.environ['TMPDIR']))
prefix='bakabel-cli-'+uuid.uuid4().hex[:12]
image=os.environ['BAKABEL_WORKFLOW_IMAGE']
socket=json.loads(subprocess.check_output(['docker','context','inspect','--format','{{json .Endpoints.docker.Host}}'],text=True)).removeprefix('unix://')
containers=[];volumes=[];events=None
def cmd(*args,check=True,env=None):
 p=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=env)
 if check and p.returncode:raise RuntimeError(f'{args[:3]} exit {p.returncode}: {p.stdout} {p.stderr}')
 return p

def docker(*args,**kw):return cmd('docker',*args,**kw)
def startpg(suffix,marked=False):
 name=prefix+'-'+suffix;containers.append(name)
 args=['run','-d','--name',name,'--cpuset-cpus','0,1','--cpus','2','--network','none','-e','POSTGRES_HOST_AUTH_METHOD=trust','-e','POSTGRES_DB=fixture','-e','POSTGRES_USER=postgres']
 if marked:args+=['--label','com.docker.compose.project='+prefix,'--label','com.docker.compose.service='+suffix,'--label','bakabel.type=postgres']
 args+=['--entrypoint','sh','postgres:18.6-alpine3.24','-c','while [ ! -e /tmp/ready ]; do sleep 0.1; done; exec docker-entrypoint.sh postgres']
 docker(*args)
 pid=docker('inspect',name,'--format','{{.State.Pid}}').stdout.strip();cmd('taskset','-pc','0,1',pid)
 docker('exec',name,'touch','/tmp/ready')
 for _ in range(300):
  if docker('exec',name,'pg_isready','-h','127.0.0.1','-U','postgres','-d','fixture',check=False).returncode==0:break
  time.sleep(.1)
 else:raise RuntimeError('PG readiness')
 return name

def sql(name,q):return docker('exec',name,'psql','-XAt','-U','postgres','-d','fixture','-v','ON_ERROR_STOP=1','-c',q).stdout.strip()
def cli(cfg,command,*args,expect=0):
 name=prefix+'-controller-'+uuid.uuid4().hex[:6];containers.append(name)
 p=docker('run','--name',name,'--cpuset-cpus','0,1','--cpus','2','--network','none','--label','bakabel.installation='+prefix,'--label','bakabel.role=scheduler','-v',str(root)+':/fixture','-v',socket+':/var/run/docker.sock:ro',image,'--config','/fixture/'+cfg,command,*args,check=False)
 print(command,p.returncode,p.stdout.strip(),p.stderr.strip(),flush=True)
 if p.returncode!=expect:raise RuntimeError('CLI failed '+p.stderr)
 return json.loads(p.stdout) if p.stdout.strip() else None

try:
 os.chmod(root,0o700);(root/'state').mkdir(mode=0o700);(root/'password').write_text('disposable-fixture-only');os.chmod(root/'password',0o600)
 restic=os.environ['RESTIC_TEST_BINARY'];env=dict(os.environ,RESTIC_REPOSITORY=str(root/'repo'),RESTIC_PASSWORD_FILE=str(root/'password'));cmd(restic,'init',env=env)
 imageid=docker('image','inspect',image,'--format','{{.Id}}').stdout.strip()
 def config(name,state='state',scope=prefix):
  (root/name).write_text(f'version: 1\ninstallation: {prefix}\nplatform: compose\nscope: [{scope}]\nrepository: /fixture/repo\ncredentials:\n  password_file: /fixture/password\nstate_dir: /fixture/{state}\nworker_image: {imageid}\ntimeout: 90s\n')
 config('config.yaml')
 a=startpg('db-a',True);b=startpg('db-b',True)
 for name in [a,b]:sql(name,"CREATE ROLE fixture_owner; CREATE TABLE payload AS SELECT g,md5(g::text) data FROM generate_series(1,20000) g; ALTER TABLE payload OWNER TO fixture_owner; ALTER DATABASE fixture OWNER TO fixture_owner; REVOKE CONNECT ON DATABASE fixture FROM PUBLIC")
 volume=prefix+'-data';volumes.append(volume);docker('volume','create',volume)
 file_source=prefix+'-files';containers.append(file_source)
 docker('run','-d','--name',file_source,'--network','none','--label','com.docker.compose.project='+prefix,'--label','com.docker.compose.service=files','--label','bakabel.type=volume','--label','bakabel.paths=/data','-v',volume+':/data','--entrypoint','sh',image,'-c','while :; do sleep 3600; done')
 docker('exec',file_source,'sh','-c','printf "fixture-file\\n" > /data/payload; chmod 640 /data/payload; chown 1234:2345 /data/payload')
 plan=cli('config.yaml','plan');assert len(plan['targets'])==3
 assert not (root/'state'/'owner.json').exists()
 events=subprocess.Popen(['docker','events','--filter','type=container','--filter','event=create','--filter','label=bakabel.worker=1','--format','{{json .}}'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
 time.sleep(.2)
 result=cli('config.yaml','run');assert result['status']=='complete' and len(result['targets'])==3
 second=cli('config.yaml','run');assert second['status']=='complete' and len(second['targets'])==3
 events.terminate();raw_events,_=events.communicate(timeout=5);events=None
 created=[json.loads(line) for line in raw_events.splitlines()]
 for run in [result['runID'],second['runID']]:assert len([e for e in created if e['Actor']['Attributes'].get('bakabel.run')==run])==1
 actual=json.loads(cmd(restic,'snapshots','--json',env=env).stdout);assert len(actual)==6
 bypath={}
 for s in actual:bypath.setdefault(tuple(s['paths']),[]).append(s)
 assert len(bypath)==3 and len({s['hostname'] for s in actual})==1
 for path,group in bypath.items():
  assert len(group)==2 and group[1].get('parent')==group[0]['id'] and not group[0].get('parent')
  if path[0].startswith('/bakabel/files/'):
   assert group[1]['summary']['files_unmodified']==1 and group[1]['summary']['data_blobs']==0
 workers=docker('ps','-aq','--filter','label=bakabel.run='+result['runID']).stdout.split()
 assert len(workers)==0  # exact terminal cleanup, never auto-remove while running
 ids=[t['snapshotID'] for t in result['targets']];assert len(set(ids))==3
 for name in [a,b,file_source]:docker('rm','-f','-v',name);containers.remove(name)
 docker('volume','rm',volume);volumes.remove(volume)
 shutil.rmtree(root/'state');(root/'fresh-state').mkdir(mode=0o700);config('fresh.yaml','fresh-state',scope='no-sources')
 snaps=cli('fresh.yaml','snapshots');assert {s['snapshotID'] for s in snaps}=={s['id'] for s in actual};assert all(s['status']=='complete' for s in snaps)
 repo_only=prefix+'-repository-only';containers.append(repo_only)
 p=docker('run','--name',repo_only,'--cpuset-cpus','0,1','--cpus','2','--network','none','-v',str(root/'repo')+':/fixture/repo','-v',str(root/'password')+':/fixture/password:ro','-v',str(root/'fresh.yaml')+':/fixture/fresh.yaml:ro',image,'--config','/fixture/fresh.yaml','snapshots')
 assert {s['snapshotID'] for s in json.loads(p.stdout)}=={s['id'] for s in actual}  # no socket, source, or state mounted
 target=startpg('restore')
 cli('fresh.yaml','restore','--snapshot',ids[0],'--postgres-container',target,'--database','fixture','--user','postgres',expect=1)
 assert not (root/'fresh-state'/'owner.json').exists();assert sql(target,"SELECT count(*) FROM pg_class WHERE relname='payload'")=='0'
 sql(target,'CREATE ROLE unrelated; CREATE ROLE fixture_owner; ALTER DATABASE fixture OWNER TO fixture_owner; REVOKE CONNECT ON DATABASE fixture FROM PUBLIC')
 restored=cli('fresh.yaml','restore','--snapshot',ids[0],'--postgres-container',target,'--database','fixture','--user','postgres')
 assert restored['status']=='restored';assert sql(target,'SELECT count(*) FROM payload')=='20000'
 assert sql(target,"SELECT tableowner FROM pg_tables WHERE tablename='payload'")=='fixture_owner'
 assert sql(target,"SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname='fixture'")=='fixture_owner'
 assert sql(target,"SELECT count(*) FROM pg_database d,LATERAL aclexplode(COALESCE(d.datacl,acldefault('d',d.datdba))) a WHERE d.datname='fixture' AND a.grantee=0 AND a.privilege_type='CONNECT'")=='0'
 last=(root/'fresh-state'/'last-result.json').read_bytes();cli('fresh.yaml','run',expect=1);assert (root/'fresh-state'/'last-result.json').read_bytes()==last
 print('PASS sequential one-worker mixed PG/files CLI; distinct stable groups/parents; repository-only PG restore; owner/ACL preserved; rows=20000; no-target leaves last-success unchanged',flush=True)
finally:
 if events is not None:events.terminate();events.communicate(timeout=5)
 # Clean only task-owned random worker labels/names, then exact fixture IDs.
 for name in docker('ps','-a','--format','{{.Names}}').stdout.split():
  if name.startswith('bakabel-worker-'):
   inspect=json.loads(docker('inspect',name).stdout)[0]
   if any(m.get('Source','').startswith(str(root)) for m in inspect.get('Mounts',[])):
    docker('rm','-f',name,check=False)
 for name in reversed(containers):docker('rm','-f','-v',name,check=False)
 for name in volumes:docker('volume','rm',name,check=False)
 print('fixture directory',root,flush=True)
