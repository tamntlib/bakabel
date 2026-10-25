#!/usr/bin/env python3
"""Real owned local-volume/credential bind-alias regression; no private data."""
import argparse
import os
from pathlib import Path
import traceback

from run_compose_pg_acceptance import ComposeProbe
from run_resource_probe import PG


class ProtectionProbe(ComposeProbe):
    def run(self):
        self.repository = '/repository'
        (self.root/'backend/local').mkdir(mode=0o700)
        self.config()
        self.restic('init')
        volume = self.prefix+'-source'
        self.e.call('POST', '/volumes/create', {'Name':volume,'Labels':{'probe.bakabel.owner':self.prefix}})
        self.volumes.append(volume)
        source = self.create('source', {'Image':PG,'Entrypoint':['sh','-c'],'Cmd':['exec sleep 300'],'Labels':{'com.docker.compose.project':self.prefix,'com.docker.compose.service':'files','bakabel.type':'volume','bakabel.paths':'/data'},'HostConfig':{'Mounts':[{'Type':'volume','Source':volume,'Target':'/data'},self.bind(self.root/'private/password','/seed',True),self.bind(self.root/'config.yaml','/seed-config',True)]}}, role='source-files')
        result = self.e.exec(source, ['sh','-c','cp /seed /data/password; cp /seed-config /data/config.yaml; printf harmless > /data/payload'])
        assert result['exit'] == 0
        v = self.e.call('GET', '/volumes/'+volume)
        protected = self.root/'private/password' if self.args.protected_kind == 'password' else self.root/'config.yaml'
        backing = 'password' if self.args.protected_kind == 'password' else 'config.yaml'
        destination = '/password' if self.args.protected_kind == 'password' else '/config.yaml'
        protected.unlink()
        protected.symlink_to(Path(v['Mountpoint'])/backing)
        # The Engine receives a bind-alias path outside the source's lexical
        # root. Kernel mount identity still resolves the actual source file.
        controller = self.controller('run')
        inspected = self.e.inspect(controller)
        password_mount = next(m for m in inspected['Mounts'] if m['Destination'] == destination)
        self.result['alias'] = {'protected_kind':self.args.protected_kind,'source_volume':volume,'source_backing':v['Mountpoint'],'controller_protected_mount_source':password_mount['Source'],'controller_protected_path':destination,'source_lexically_contains_alias':password_mount['Source'].startswith(v['Mountpoint']+'/')}
        assert not self.result['alias']['source_lexically_contains_alias'], 'Fixture did not create a lexical bind alias'
        self.finish(controller, expect=1)
        import json
        snapshots = json.loads(self.restic('snapshots','--json'))
        assert snapshots == [], 'A protected source file must not be published'
        self.gate('physical-protected-bind-alias-refused-before-snapshot', snapshots=[], alias_inspect_preserved=True, protected_kind=self.args.protected_kind)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime',type=Path,required=True)
    parser.add_argument('--source',type=Path,required=True)
    parser.add_argument('--minio-binary',type=Path,required=True)
    parser.add_argument('--image',required=True)
    parser.add_argument('--socket',type=Path)
    parser.add_argument('--protected-kind',choices=['password','config'],default='password')
    args = parser.parse_args()
    os.sched_setaffinity(0,{0,1})
    probe = ProtectionProbe(args)
    code = 1
    try:
        probe.run()
        code = 0
    except Exception:
        probe.result['error'] = traceback.format_exc()
        print(probe.result['error'],flush=True)
    finally:
        try:
            probe.cleanup()
        except Exception:
            print('CLEANUP ERROR',traceback.format_exc(),flush=True)
            code = 1
    return code


if __name__ == '__main__':
    raise SystemExit(main())
