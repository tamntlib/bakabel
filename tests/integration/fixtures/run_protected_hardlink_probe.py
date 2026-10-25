#!/usr/bin/env python3
"""Owned credential-directory hard-link regression; never read secret bytes."""
import argparse
import json
import os
from pathlib import Path
import traceback
from run_compose_pg_acceptance import ComposeProbe
from run_resource_probe import PG

class HardlinkProbe(ComposeProbe):
    def create(self,suffix,spec,role=None,start=True):
        if role in ('controller','scheduler'):
            mounts=spec['HostConfig']['Mounts']
            mounts[:]=[m for m in mounts if m.get('Target')!='/password']
            mounts.append(self.bind(self.root/'private','/run/secrets',True))
        return super().create(suffix,spec,role=role,start=start)

    def run(self):
        self.repository='/repository'
        (self.root/'backend/local').mkdir(mode=0o700)
        self.config()
        self.restic('init')
        config=self.root/'config.yaml'
        text=config.read_text()
        assert text.count('password_file: /password')==1
        config.write_text(text.replace('password_file: /password','password_file: /run/secrets/password'))
        name=self.prefix+'-source'
        volume=self.e.call('POST','/volumes/create',{'Name':name,'Labels':{'probe.bakabel.owner':self.prefix}})
        self.volumes.append(name)
        assert volume['Driver']=='local' and volume['Labels']['probe.bakabel.owner']==self.prefix
        source=Path(volume['Mountpoint'])
        password=self.root/'private/password'
        assert os.stat(source).st_dev==os.stat(password).st_dev
        os.link(password,source/'credential-alias')
        assert os.stat(password).st_nlink==2
        self.create('source',{'Image':PG,'Entrypoint':['sh','-c'],'Cmd':['exec sleep 300'],'Labels':{'com.docker.compose.project':self.prefix,'com.docker.compose.service':'files','bakabel.type':'volume','bakabel.paths':'/data'},'HostConfig':{'Mounts':[{'Type':'volume','Source':name,'Target':'/data'}]}},role='source-files')
        controller=self.controller('run')
        obj=self.e.inspect(controller)
        mount=next(m for m in obj['Mounts'] if m['Destination']=='/run/secrets')
        self.result['hardlink']={'protected_mount_is_directory':True,'credential_nlink':2,'source_volume':name,'source_backing':str(source),'controller_directory_backing':mount['Source'],'source_lexically_contains_directory':mount['Source'].startswith(str(source)+'/')}
        assert not self.result['hardlink']['source_lexically_contains_directory']
        try:
            self.finish(controller,expect=1)
        except AssertionError:
            self.result['snapshots_on_refusal_failure']=json.loads(self.restic('snapshots','--json'))
            raise
        snapshots=json.loads(self.restic('snapshots','--json'))
        assert snapshots==[]
        self.gate('credential-directory-hardlink-refused-before-snapshot',snapshots=[])

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for option in ('runtime','source','minio-binary'):
        parser.add_argument('--'+option,type=Path,required=True)
    parser.add_argument('--image',required=True)
    parser.add_argument('--socket',type=Path)
    args=parser.parse_args();os.sched_setaffinity(0,{0,1});probe=HardlinkProbe(args);code=1
    try:probe.run();code=0
    except Exception:probe.result['error']=traceback.format_exc();print(probe.result['error'],flush=True)
    finally:
        try:probe.cleanup()
        except Exception:print('CLEANUP ERROR',traceback.format_exc(),flush=True);code=1
    return code

if __name__=='__main__':raise SystemExit(main())
