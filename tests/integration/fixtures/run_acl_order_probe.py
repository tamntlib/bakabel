#!/usr/bin/env python3
"""Real operator metadata-order regression on an owned PostgreSQL fixture."""
import argparse
import base64
import json
import os
from pathlib import Path
import traceback

from run_compose_pg_acceptance import ComposeProbe


class ACLProbe(ComposeProbe):
    def run(self):
        self.repository = '/repository'
        (self.root/'backend/local').mkdir(mode=0o700)
        self.config()
        self.config('fresh.yaml', fresh=True)
        self.restic('init')
        source = self.startpg('source', True)
        self.sql(source, 'CREATE ROLE fixture_owner; CREATE TABLE payload AS SELECT generate_series(1,100) n; ALTER DATABASE fixture OWNER TO fixture_owner; REVOKE CONNECT ON DATABASE fixture FROM PUBLIC')
        result = self.call_cli('run')
        assert result['status'] == 'complete'
        sid = result['targets'][0]['snapshotID']
        snapshot = next(s for s in json.loads(self.restic('snapshots','--json')) if s['id'] == sid)
        original = next(t for t in snapshot['tags'] if t.startswith('bakabel.meta='))
        wire = original.split('=', 1)[1]
        metadata = json.loads(base64.urlsafe_b64decode(wire+'='*((-len(wire))%4)))
        before = metadata['postgres']['acl']
        metadata['postgres']['acl'] = list(reversed(before))
        assert metadata['postgres']['acl'] != before
        updated = 'bakabel.meta='+base64.urlsafe_b64encode(json.dumps(metadata,separators=(',',':')).encode()).decode().rstrip('=')
        self.restic('tag','--remove',original,'--add',updated,sid)
        exact = [s for s in json.loads(self.restic('snapshots','--json')) if updated in s['tags']]
        assert len(exact) == 1
        sid = exact[0]['id']
        target = self.startpg('target', False)
        self.sql(target, 'CREATE ROLE fixture_owner; ALTER DATABASE fixture OWNER TO fixture_owner; REVOKE CONNECT ON DATABASE fixture FROM PUBLIC')
        # Metadata remains otherwise identical and valid; it represents the
        # same grant set. No fake repository response or import is supplied.
        restored = self.call_cli('restore','--snapshot',sid,'--postgres-container',target,'--database','fixture','--user','postgres',fresh=True)
        assert restored['status'] == 'restored'
        assert self.sql(target,'SELECT count(*) FROM payload') == '100'
        self.gate('valid-metadata-ACL-order-independent-public-restore',snapshot=sid,metadata_reordered_only=True,rows=100)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--runtime',type=Path,required=True)
    p.add_argument('--source',type=Path,required=True)
    p.add_argument('--minio-binary',type=Path,required=True)
    p.add_argument('--image',required=True)
    p.add_argument('--socket',type=Path)
    args = p.parse_args()
    os.sched_setaffinity(0,{0,1})
    probe = ACLProbe(args)
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
