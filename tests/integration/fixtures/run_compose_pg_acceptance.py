#!/usr/bin/env python3
"""Owned Compose/local+S3 CLI proof on the existing Engine, without file restore.

Uses only synthetic scoped sources. Never initializes Swarm or changes runtime
policy. File restore is deliberately NOT run: its consumer identity preflight
would inspect/mount unrelated daemon consumers. This is NOT the 11-gate matrix.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import time
import traceback

from run_resource_probe import PG, Probe

EXPECTED_SOURCE = '2fd683f92a52b244ac452356cb4fd6de3567366348259ece09619c912e8b07ee'
EXPECTED_IMAGE = 'sha256:ff1a6cd8e122b14c80da66396c6d14f06c22cc4c130e769def3a50520e9afca8'


def fingerprint(root):
    paths = sorted([*root.rglob('*.go'), root/'go.mod', root/'go.sum', root/'Dockerfile'], key=lambda p: str(p.relative_to(root)))
    h = hashlib.sha256()
    for p in paths:
        h.update(str(p.relative_to(root)).encode()+b'\0'+hashlib.sha256(p.read_bytes()).digest())
    return h.hexdigest()


class ComposeProbe(Probe):
    def create(self, suffix, spec, **kw):
        # Only our operator/controller specs get this mount. Ordinary workers
        # are constructed by the unchanged production binary, not this helper.
        if getattr(self, 'repository', '').startswith('/') and kw.get('role') in ('controller', 'scheduler', 'operator-restic'):
            spec.setdefault('HostConfig', {}).setdefault('Mounts', []).append(self.bind(self.root/'backend/local', '/repository'))
        return super().create(suffix, spec, **kw)

    def call_cli(self, command, *argv, fresh=False, expect=0):
        cid = self.controller(command, *argv, filename='fresh.yaml' if fresh else 'config.yaml', fresh=fresh)
        self.finish(cid, expect=expect)
        lines = self.logs(cid).splitlines()
        rows = [json.loads(line) for line in lines if line.startswith(('{', '['))]
        return rows[0] if rows else None

    def reset_state(self):
        for name in ('state', 'fresh-state'):
            p = self.root/name
            assert not (p/'owner.json').exists(), 'Do not erase active ownership'
            shutil.rmtree(p)
            p.mkdir(mode=0o700)

    def remove_source(self, cid):
        assert cid in self.containers
        v = self.e.inspect(cid)
        assert v['Config']['Labels'].get('probe.bakabel.owner') == self.prefix
        named = [m['Name'] for m in v['Mounts'] if m['Type'] == 'volume']
        self.e.call('DELETE', '/containers/'+cid+'?force=true&v=true')
        assert self.e.inspect(cid, missing=True) is None
        for name in named:
            assert name in self.volumes
            self.e.call('DELETE', '/volumes/'+name, missing=True)
            assert self.e.call('GET', '/volumes/'+name, missing=True) is None

    def fault(self, backend, kind, pg, minio, pg_target):
        self.config(timeout='18s')
        self.lock(pg)
        begin = time.monotonic()
        controller = self.controller('run')
        active = self.blocked(pg)
        job = json.loads((self.root/'state/workflow/job.json').read_text())
        assert job['runID'] == active['runID']
        if kind == 'worker-SIGKILL':
            self.e.call('POST', '/containers/'+controller+'/kill?signal=STOP')
            self.e.call('POST', '/containers/'+active['workerContainerID']+'/kill?signal=KILL')
            assert (self.root/'state/owner.json').exists()
            self.call_cli('run', expect=1)
            assert json.loads((self.root/'state/owner.json').read_text())['runID'] == active['runID']
            self.e.call('POST', '/containers/'+controller+'/kill?signal=CONT')
        else:
            assert backend == 's3' and minio
            self.e.call('POST', '/containers/'+minio+'/stop?t=1')
            assert not self.e.inspect(minio)['State']['Running']
            self.call_cli('run', expect=1)
            self.unlock(pg)
            deadline = datetime.datetime.fromisoformat(job['createdAt'].replace('Z', '+00:00')).timestamp()+18
            time.sleep(max(0, deadline+3-time.time()))
            self.e.call('POST', '/containers/'+minio+'/start')
            self.pin_container(minio)
        rows = self.finish(controller, expect=1, timeout=55)
        elapsed = time.monotonic()-begin
        assert rows[0]['status'] == 'failed' and elapsed < 55
        assert not (self.root/'state/owner.json').exists()
        execution = self.e.call('GET', '/exec/'+active['execID']+'/json')
        assert not execution['Running']
        assert self.sql(pg, "SELECT count(*) FROM pg_stat_activity WHERE application_name='"+active['runID']+"'") == '0'
        self.unlock(pg)
        snapshots = json.loads(self.restic('snapshots', '--json'))
        token = active['runID']+'-'+hashlib.sha256(pg_target.encode()).hexdigest()
        assert not any('bakabel.run='+token in s.get('tags', []) and 'bakabel.status=complete' in s.get('tags', []) for s in snapshots)
        self.gate(backend+'-'+kind+'-failed-exact-source-terminal-before-release', runID=active['runID'], elapsed_seconds=elapsed, source_exec_terminal=True, source_sessions=0, owner_released=True, pg_complete_snapshot=False, earlier_file_target_may_be_complete=True)
        self.config()

    def run(self):
        expected_source = self.args.expected_source_sha256
        assert fingerprint(self.args.source) == expected_source
        assert self.image == self.args.expected_image_id
        self.result['source_sha256'] = expected_source
        self.result['image_id'] = self.image
        self.result['runner_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        self.result['coverage_boundary'] = 'Real Compose local/S3 PostgreSQL independent restore and mixed backups; NO file restore, Swarm, private consumer inventory, or complete 11-gate certification.'
        self.result['backends'] = {}
        minio = self.create('minio', {'Image':PG, 'Entrypoint':['/minio'], 'Cmd':['server', '/data', '--address', '0.0.0.0:9000'], 'Env':['MINIO_ROOT_USER_FILE=/credentials/user', 'MINIO_ROOT_PASSWORD_FILE=/credentials/password', 'MINIO_BROWSER=off', 'GOMAXPROCS=2'], 'HostConfig':{'NetworkMode':'bridge', 'Mounts':[self.bind(self.root/'bin/minio', '/minio', True), self.bind(self.root/'private/minio-user', '/credentials/user', True), self.bind(self.root/'private/minio-password', '/credentials/password', True), self.bind(self.root/'backend', '/data')]}}, role='fixture-s3-backend')
        mi = self.e.inspect(minio)
        ip = mi['NetworkSettings']['Networks']['bridge']['IPAddress']
        assert ip and not mi['HostConfig']['PortBindings']
        self.wait(lambda:'9000' in self.logs(minio), 30, 'MinIO readiness')
        (self.root/'backend/local').mkdir(mode=0o700)
        for backend in ('local', 's3'):
            self.reset_state()
            self.repository = '/repository' if backend == 'local' else 's3:http://'+ip+':9000/bakabel-compose/repository'
            self.config()
            self.config('fresh.yaml', fresh=True)
            self.restic('init')
            pg = self.startpg('pg-'+backend, True)
            self.sql(pg, 'CREATE ROLE fixture_owner; CREATE ROLE fixture_reader; CREATE TABLE payload AS SELECT g,md5(g::text) AS data FROM generate_series(1,20000) g; ALTER TABLE payload OWNER TO fixture_owner; GRANT SELECT ON payload TO fixture_reader; ALTER DATABASE fixture OWNER TO fixture_owner; CREATE TABLE availability_probe(n bigint)')
            if backend == 's3':
                self.sql(pg, 'REVOKE CONNECT ON DATABASE fixture FROM PUBLIC; GRANT CONNECT ON DATABASE fixture TO fixture_reader WITH GRANT OPTION')
            else:
                assert self.sql(pg, "SELECT datacl IS NULL FROM pg_database WHERE datname='fixture'") == 't'
            source_oids = self.sql(pg, "SELECT rolname,oid FROM pg_roles WHERE rolname IN ('fixture_owner','fixture_reader') ORDER BY rolname")
            expected = self.sql(pg, "SELECT count(*),sum(g),md5(string_agg(g::text||':'||data,',' ORDER BY g)) FROM payload")
            volume = self.prefix+'-files-'+backend
            self.e.call('POST', '/volumes/create', {'Name':volume, 'Labels':{'probe.bakabel.owner':self.prefix}})
            self.volumes.append(volume)
            filec = self.create('files-'+backend, {'Image':PG, 'Entrypoint':['sh','-c'], 'Cmd':['exec sleep 900'], 'Labels':{'com.docker.compose.project':self.prefix, 'com.docker.compose.service':'files-'+backend, 'bakabel.type':'volume', 'bakabel.paths':'/data'}, 'HostConfig':{'Mounts':[{'Type':'volume','Source':volume,'Target':'/data','ReadOnly':False}]}}, role='source-files')
            assert self.e.exec(filec, ['sh','-c','printf "compose-cli-payload\\n" > /data/payload; chmod 640 /data/payload; chown 1234:2345 /data/payload'])['exit'] == 0
            identities = {cid:{'StartedAt':self.e.inspect(cid)['State']['StartedAt'], 'RestartCount':self.e.inspect(cid)['RestartCount']} for cid in (pg, filec)}
            plan = self.call_cli('plan')
            assert len(plan['targets']) == 2
            pg_target = next(t['ID'] for t in plan['targets'] if t['Kind'] == 'postgres')
            self.lock(pg)
            controller = self.controller('run')
            active = self.blocked(pg)
            self.sql(pg, 'INSERT INTO availability_probe VALUES (10)')
            assert self.sql(pg, 'SELECT count(*) FROM availability_probe') == '1'
            self.unlock(pg)
            outcome = self.finish(controller)[0]
            assert outcome['status'] == 'complete' and len(outcome['targets']) == 2
            worker = self.worker_records[active['workerContainerID']]
            assert worker['HostConfig']['Memory'] == 536870912 and worker['HostConfig']['NanoCpus'] == 2000000000
            assert worker['Config']['Cmd'] == ['_workflow'] and worker['Config']['Entrypoint'] == ['/usr/local/bin/bakabel']
            pgid = next(t['snapshotID'] for t in outcome['targets'] if t['targetID'] == pg_target)
            fileid = next(t['snapshotID'] for t in outcome['targets'] if t['targetID'] != pg_target)
            self.gate(backend+'-mixed-online-CLI-backup-with-default-worker-limits', runID=outcome['runID'], postgres_snapshot=pgid, file_snapshot=fileid, memory_bytes=536870912, nanocpus=2000000000, source_read_write_during_dump_wait=True)
            second = self.call_cli('run')
            assert second['status'] == 'complete'
            snapshots = json.loads(self.restic('snapshots','--json'))
            first_file = next(s for s in snapshots if s['id'] == fileid)
            second_file_id = next(t['snapshotID'] for t in second['targets'] if t['targetID'] != pg_target)
            second_file = next(s for s in snapshots if s['id'] == second_file_id)
            assert second_file['parent'] == fileid and second_file['summary']['files_unmodified'] == 1 and second_file['summary']['data_blobs'] == 0
            assert self.restic('dump', fileid, first_file['paths'][0]+'/payload') == 'compose-cli-payload\n'
            self.gate(backend+'-file-parent-reused-no-new-data-and-complete-payload-readback', first=fileid, second=second_file_id, files_unmodified=1, new_data_blobs=0, file_restore_exercised=False)
            self.fault(backend, 'worker-SIGKILL', pg, minio, pg_target)
            if backend == 's3':
                self.fault(backend, 'S3-outage', pg, minio, pg_target)
            for cid, before in identities.items():
                v = self.e.inspect(cid)
                assert {'StartedAt':v['State']['StartedAt'], 'RestartCount':v['RestartCount']} == before
            # This mutation is a deliberate disposable restore-negative stage,
            # NOT a backup quiesce/stop mechanism.
            self.sql(pg, 'DROP TABLE payload, availability_probe')
            rejected = self.call_cli('restore', '--snapshot', pgid, '--postgres-container', pg, '--database', 'fixture', '--user', 'postgres', fresh=True, expect=1)
            assert self.sql(pg, "SELECT count(*) FROM pg_class WHERE relname='payload'") == '0'
            self.gate(backend+'-empty-source-physical-DB-alias-refused', source_database_empty=True, destination_unchanged=True, result=rejected)
            self.remove_source(pg)
            self.remove_source(filec)
            self.reset_state()
            assert not list((self.root/'state').iterdir()) and not list((self.root/'fresh-state').iterdir())
            listed = self.call_cli('snapshots', fresh=True)
            assert any(s['snapshotID'] == pgid and s['status'] == 'complete' for s in listed)
            target = self.startpg('restore-'+backend, False)
            self.call_cli('restore', '--snapshot', pgid, '--postgres-container', target, '--database', 'fixture', '--user', 'postgres', fresh=True, expect=1)
            assert self.sql(target, "SELECT count(*) FROM pg_class WHERE relname='payload'") == '0'
            self.sql(target, 'CREATE ROLE unrelated_role_for_oid_shift; CREATE ROLE fixture_owner; CREATE ROLE fixture_reader; ALTER DATABASE fixture OWNER TO fixture_owner')
            if backend == 's3':
                self.sql(target, 'REVOKE CONNECT ON DATABASE fixture FROM PUBLIC; GRANT CONNECT ON DATABASE fixture TO fixture_reader WITH GRANT OPTION')
            target_oids = self.sql(target, "SELECT rolname,oid FROM pg_roles WHERE rolname IN ('fixture_owner','fixture_reader') ORDER BY rolname")
            assert source_oids != target_oids
            restored = self.call_cli('restore', '--snapshot', pgid, '--postgres-container', target, '--database', 'fixture', '--user', 'postgres', fresh=True)
            assert restored['status'] == 'restored'
            actual = self.sql(target, "SELECT count(*),sum(g),md5(string_agg(g::text||':'||data,',' ORDER BY g)) FROM payload")
            assert actual == expected
            assert self.sql(target, "SELECT tableowner FROM pg_tables WHERE tablename='payload'") == 'fixture_owner'
            assert self.sql(target, "SELECT has_table_privilege('fixture_reader','payload','SELECT')") == 't'
            assert self.sql(target, "SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname='fixture'") == 'fixture_owner'
            public_connect = self.sql(target, "SELECT count(*) FROM pg_database d,LATERAL aclexplode(COALESCE(d.datacl,acldefault('d',d.datdba))) a WHERE d.datname='fixture' AND a.grantee=0 AND a.privilege_type='CONNECT'")
            assert public_connect == ('1' if backend == 'local' else '0')
            if backend == 's3':
                assert self.sql(target, "SELECT count(*) FROM pg_database d,LATERAL aclexplode(COALESCE(d.datacl,acldefault('d',d.datdba))) a JOIN pg_roles r ON r.oid=a.grantee WHERE d.datname='fixture' AND r.rolname='fixture_reader' AND a.privilege_type='CONNECT' AND a.is_grantable") == '1'
            self.result['backends'][backend] = {'postgres_snapshot':pgid, 'file_snapshot':fileid, 'data_readback':actual, 'source_role_oids':source_oids, 'target_role_oids':target_oids, 'source_containers_and_volumes_absent':True, 'backup_history_absent':True, 'owner_acl_readback':True, 'database_acl_mode':'NULL/default' if backend == 'local' else 'PUBLIC CONNECT revoked; named role grant option', 'initial_wrong_database_owner_acl_refused_before_import':True, 'file_restore_exercised':False}
            self.gate(backend+'-fresh-source-and-history-absent-PG-restore-different-role-OIDs-owner-ACL-preserved', snapshot=pgid, readback=actual, database_acl_mode=self.result['backends'][backend]['database_acl_mode'])
            self.remove_source(target)
        assert fingerprint(self.args.source) == expected_source
        self.result['full_11_gate_matrix_pass'] = False
        self.result['file_restore_exercised'] = False
        self.result['swarm_exercised'] = False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime', type=Path, required=True)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--minio-binary', type=Path, required=True)
    parser.add_argument('--image', required=True)
    parser.add_argument('--socket', type=Path)
    parser.add_argument('--expected-source-sha256', default=EXPECTED_SOURCE)
    parser.add_argument('--expected-image-id', default=EXPECTED_IMAGE)
    args = parser.parse_args()
    os.sched_setaffinity(0, {0, 1})
    assert fingerprint(args.source) == args.expected_source_sha256
    probe = ComposeProbe(args)
    code = 1
    try:
        probe.run()
        code = 0
    except Exception:
        probe.result['error'] = traceback.format_exc()
        print(probe.result['error'], flush=True)
    finally:
        try:
            probe.cleanup()
        except Exception:
            print('CLEANUP ERROR', traceback.format_exc(), flush=True)
            code = 1
    return code


if __name__ == '__main__':
    raise SystemExit(main())
