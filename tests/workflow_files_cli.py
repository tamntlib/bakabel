#!/usr/bin/env python3
"""File CLI positive contract ONLY against a dedicated empty DinD daemon.
Do not point BAKABEL_FILE_DOCKER_SOCKET at the host/production Docker daemon.
Requires only BAKABEL_WORKFLOW_IMAGE loaded in DinD, and this scratch parent
mounted into DinD at the same absolute path. No production storage is mounted.
"""
import json,os,pathlib,subprocess,tempfile,uuid,shutil
socket=os.environ['BAKABEL_FILE_DOCKER_SOCKET']; image=os.environ['BAKABEL_WORKFLOW_IMAGE']
assert socket.endswith('/bakabel-workflow-cli-0akcpf3p/dind.sock'), 'dedicated fixture socket required'
root=pathlib.Path(tempfile.mkdtemp(prefix='files-',dir=pathlib.Path(socket).parent));os.chmod(root,0o700)
prefix='bakabel-files-'+uuid.uuid4().hex[:12];containers=[];volumes=[]
def cmd(*args,check=True,env=None):
 p=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=env)
 if check and p.returncode:raise RuntimeError(str(args[:3])+f' {p.returncode} '+p.stdout+p.stderr)
 return p
def docker(*args,**kw):return cmd('docker','-H','unix://'+socket,*args,**kw)
def cli(config,command,*args,expect=0):
 name=prefix+'-controller-'+uuid.uuid4().hex[:6];containers.append(name)
 state='state' if config=='config.yaml' else 'fresh-state'
 p=docker('run','--name',name,'--cpuset-cpus','0,1','--cpus','2','--network','none','--label','bakabel.installation='+prefix,'--label','bakabel.role=scheduler',
 '-v',str(root/state)+':/state','-v',str(root/'repo')+':/repository','-v',str(root/'password')+':/password:ro','-v',str(root/config)+':/config.yaml:ro','-v',socket+':/var/run/docker.sock:ro',image,'--config','/config.yaml',command,*args,check=False)
 print(command,p.returncode,p.stdout.strip(),p.stderr.strip(),flush=True)
 if p.returncode!=expect:raise RuntimeError('unexpected CLI exit')
 return json.loads(p.stdout) if p.stdout.strip() else None
try:
 (root/'state').mkdir(mode=0o700);(root/'fresh-state').mkdir(mode=0o700);(root/'password').write_text('disposable-fixture-only');os.chmod(root/'password',0o600)
 env=dict(os.environ,RESTIC_REPOSITORY=str(root/'repo'),RESTIC_PASSWORD_FILE=str(root/'password'));cmd(os.environ['RESTIC_TEST_BINARY'],'init',env=env)
 imageid=docker('image','inspect',image,'--format','{{.Id}}').stdout.strip()
 for config in ['config.yaml','fresh.yaml']:(root/config).write_text(f'version: 1\ninstallation: {prefix}\nplatform: compose\nscope: [{prefix}]\nrepository: /repository\ncredentials:\n  password_file: /password\nstate_dir: /state\nworker_image: {imageid}\ntimeout: 60s\n')
 source=prefix+'-source';volume=prefix+'-data';volumes.append(volume);docker('volume','create',volume);containers.append(source)
 docker('run','-d','--name',source,'--network','none','--label','com.docker.compose.project='+prefix,'--label','com.docker.compose.service=files','--label','bakabel.type=volume','--label','bakabel.paths=/data','-v',volume+':/data','--entrypoint','sh',image,'-c','while :; do sleep 3600; done')
 docker('exec',source,'sh','-c','printf "file-cli-payload\\n" > /data/payload; chmod 640 /data/payload; chown 1234:2345 /data/payload')
 targetvol=prefix+'-restore';docker('volume','create',targetvol);volumes.append(targetvol)
 destination=root/'restore';destination.mkdir(mode=0o700)
 plan=cli('config.yaml','plan');assert len(plan['targets'])==1
 result=cli('config.yaml','run');assert result['status']=='complete';sid=result['targets'][0]['snapshotID']
 # New worker/run with unchanged file roots retains stable host,paths grouping.
 second=cli('config.yaml','run');assert second['status']=='complete'
 actual=json.loads(cmd(os.environ['RESTIC_TEST_BINARY'],'snapshots','--json',env=env).stdout);assert len(actual)==2 and actual[0]['paths']==actual[1]['paths'] and actual[0]['hostname']==actual[1]['hostname'];assert actual[1].get('parent')==actual[0]['id']
 for name in list(containers):docker('rm','-f',name);containers.remove(name)
 docker('volume','rm',volume);volumes.remove(volume);shutil.rmtree(root/'state')
 snaps=cli('fresh.yaml','snapshots');assert all(s['status']=='complete' for s in snaps)
 restored=cli('fresh.yaml','restore','--snapshot',sid,'--directory',str(destination));assert restored['status']=='restored'
 assert (destination/'payload').stat().st_mode&0o777==0o640
 # Compare contents/owners inside the daemon's namespace, not host UID mappings.
 ownership=docker('run','--rm','--network','none','-v',str(destination)+':/data:ro','--entrypoint','sh',image,'-c','cat /data/payload; stat -c "%a %u %g" /data/payload').stdout.strip();assert ownership=='file-cli-payload\n640 1234 2345'
 restored=cli('fresh.yaml','restore','--snapshot',sid,'--volume',targetvol);assert restored['status']=='restored'
 # Inspect data only through a task-owned checker after restore released ownership.
 checker=prefix+'-check';containers.append(checker)
 p=docker('run','--name',checker,'--network','none','-v',targetvol+':/data:ro','--entrypoint','sh',image,'-c','cat /data/payload; stat -c "%a %u %g" /data/payload').stdout
 assert 'file-cli-payload\n640 1234 2345' in p
 print('PASS files CLI directory AND new unused local volume; source/state absent; real native consumer preflight; parent reused',flush=True)
finally:
 for name in docker('ps','-a','--format','{{.Names}}').stdout.split():
  if name.startswith('bakabel-worker-'):
   v=json.loads(docker('inspect',name).stdout)[0]
   if any(m.get('Source','').startswith(str(root)) for m in v.get('Mounts',[])):docker('rm','-f',name,check=False)
 for name in reversed(containers):docker('rm','-f','-v',name,check=False)
 for name in volumes:docker('volume','rm',name,check=False)
 print('fixture directory',root,flush=True)
