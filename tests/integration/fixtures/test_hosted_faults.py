"""Offline contracts only. Protocol peers below are NOT Docker/runtime evidence."""
import importlib
import contextlib
import io
import unittest
from unittest.mock import patch


class SafetyTests(unittest.TestCase):
    def test_lost_fixture_create_response_preserves_private_paths(self):
        from types import SimpleNamespace
        from unittest.mock import Mock
        m=self.module();engine=Mock();relay=Mock();relay.snapshot.return_value={'errors':[]}
        def call(method,path,body=None,**kwargs):
            if path=='/info':return {'ID':'unit-daemon'}
            if path.startswith('/images/'):return {'Id':'sha256:'+'b'*64}
            if method=='POST' and path.startswith('/containers/create?'):raise ConnectionError('unit-only lost create response')
            raise AssertionError('unexpected unit transport call')
        engine.call.side_effect=call
        with tempfile.TemporaryDirectory() as directory:
            args=SimpleNamespace(runtime=Path(directory)/'run',socket=Path('/unit-no-engine.sock'),image='sha256:'+'b'*64,expected_image_id='sha256:'+'b'*64,expected_source_sha256='a'*64)
            with patch.object(m,'Engine',return_value=engine),patch.object(m,'FaultRelay',return_value=relay):
                probe=m.FaultProbe(args,'worker-create-response-loss')
            with self.assertRaises(ConnectionError):probe.create('lost',{'Image':args.image})
            with self.assertRaises(ValueError):probe.cleanup()
            self.assertTrue((args.runtime/'private/password').exists())
            self.assertFalse(any(c.args[0]=='DELETE' for c in engine.call.call_args_list))

    def module(self):
        try:
            m = importlib.import_module('run_hosted_faults')
        except ModuleNotFoundError:
            m = None
        self.assertIsNotNone(m, 'new faults runner must reject non-hosted execution before socket access')
        return m

    def test_local_invocation_rejected_before_engine_or_paths(self):
        m = self.module()
        with patch.dict(m.os.environ, {}, clear=True), patch.object(m, 'Engine') as engine, contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as stopped:
                m.main(['--socket', '/not-a-socket', '--runtime', '/must-not-be-created'])
            self.assertEqual(stopped.exception.code, 2)
            engine.assert_not_called()


import json
import socket
import threading
import tempfile
from pathlib import Path


# Independent literal of the producer contract, not imported from the classifier.
DUMP_SCRIPT = r'''run=$1
shift
BAKABEL_RUN_ID="$run" PGAPPNAME="$run" /usr/local/bin/pg_dump "$@"
code=$?
[ "$code" -eq 0 ] || exit "$code"
printf '\000BAKABEL_EXPORT_COMPLETE_V1:%s\000' "$run"'''


def wrapped_dump(run='c'*32):
    return {'User': '0', 'AttachStdout': True, 'AttachStderr': True,
            'AttachStdin': False, 'Tty': False,
            'Cmd': ['/bin/sh', '-c', DUMP_SCRIPT, 'bakabel-export-v1', run,
                    '--no-password', '--dbname',
                    "host='/var/run/postgresql' port='5432' user='postgres' dbname='fixture'",
                    '--format=custom', '--compress=gzip:9'],
            'Env': ['PGAPPNAME=', 'BAKABEL_RUN_ID=', 'PGHOSTADDR=', 'PGPASSWORD=',
                    'PGPASSFILE=/dev/null', 'PGSERVICEFILE=/dev/null', 'PGOPTIONS=', 'PGCONNECT_TIMEOUT=10']}


class RelayTests(unittest.TestCase):
    def module(self):
        m = importlib.import_module('run_hosted_faults')
        self.assertTrue(hasattr(m, 'FaultRelay'), 'need byte-preserving Unix transport fault injection')
        return m

    def exchange(self, relay, path, body=b''):
        client = socket.socket(socket.AF_UNIX); client.settimeout(3); client.connect(str(relay.path))
        with client:
            client.sendall(b'POST '+path.encode()+b' HTTP/1.1\r\nHost: local\r\nConnection: close\r\nContent-Length: '+str(len(body)).encode()+b'\r\n\r\n'+body)
            out = b''
            while True:
                data = client.recv(65536)
                if not data: return out
                out += data

    def scripted(self, root, replies):
        server = socket.socket(socket.AF_UNIX); server.bind(str(root/'back')); server.listen(); server.settimeout(4)
        seen = []
        def peer():
            try:
                for reply in replies:
                    conn, _ = server.accept()
                    with conn:
                        head, line, headers = self.module().read_headers(conn)
                        body = self.module().read_exact(conn, int(headers.get('content-length', 0)))
                        seen.append((line, body)); conn.sendall(reply)
            except (OSError, EOFError): pass
        thread = threading.Thread(target=peer); thread.start()
        self.addCleanup(server.close); self.addCleanup(thread.join, 5)
        return seen

    def test_wrapper_fixture_tracks_fixed_go_script(self):
        import re
        source = Path(__file__).resolve().parents[3]/'internal/platform/docker/dump_command.go'
        script = re.search(r'const dumpScript = `([^`]*)`', source.read_text())
        self.assertIsNotNone(script)
        self.assertEqual(DUMP_SCRIPT, script.group(1))

    def test_exact_wrapper_classifies_valid_positional_run_and_legacy_execs_still_match(self):
        m = self.module(); relay = m.FaultRelay.__new__(m.FaultRelay)
        relay.workers = set(); relay.execs = {}
        path = '/v1.55/containers/'+'b'*64+'/exec'
        for run in ('a'*16, 'c'*32, 'A0_-'+'x'*59):
            with self.subTest(run=run):
                record = relay.classify('POST', path, json.dumps(wrapped_dump(run)).encode())
                self.assertEqual(record, {'method':'POST', 'boundary':'dump-create', 'forwarded':False, 'container_id':'b'*64})
        for user, database in (("o'brien", r'back\slash'), ('é'*128, 'x'*256), ('user', 'private $(literal);\nname')):
            with self.subTest(user=user):
                quote = lambda name: "'"+name.replace('\\', '\\\\').replace("'", "\\'")+"'"
                spec = wrapped_dump()
                spec['Cmd'][7] = "host='/var/run/postgresql' port='5432' user="+quote(user)+' dbname='+quote(database)
                self.assertEqual(relay.classify('POST', path, json.dumps(spec).encode())['boundary'], 'dump-create')
        for cmd, kind in ((['/usr/local/bin/pg_dump','--format=custom'], 'dump'),
                          (['pg_restore','--exit-on-error'], 'restore')):
            self.assertEqual(relay.classify('POST', path, json.dumps({'Cmd':cmd}).encode())['boundary'], kind+'-create')

    def test_wrapper_lookalikes_fail_closed_without_exporting_request_values(self):
        m = self.module(); relay = m.FaultRelay.__new__(m.FaultRelay)
        relay.workers = set(); relay.execs = {}
        variants = []
        def changed(label, key, value):
            spec = wrapped_dump(); spec[key] = value; variants.append((label, spec))
        for index, values in {
                0: ['sh', '/usr/bin/sh', '/bin/bash', '/bin/sh-extra'],
                1: ['-ec', '-c '],
                2: ['pg_dump --format=custom', DUMP_SCRIPT+'\n', DUMP_SCRIPT+'\n# private-script',
                    DUMP_SCRIPT.replace('exit "$code"', 'true'), DUMP_SCRIPT.replace('run=$1', 'run=$2')],
                3: ['bakabel-export', 'bakabel-export-v1-private'],
                4: ['', 'short', 'a'*15, 'a'*64, 'a'*31+';', 'a'*31+'\n', 'a'*31+'\0', 'a'*31+'é'],
                5: ['--no-password-private', '--password'],
                6: ['--dbname=private'],
                7: ['', '--format=custom', 'postgresql://private',
                    "host='remote' port='5432' user='postgres' dbname='fixture'",
                    "host='/var/run/postgresql' port='5432' user='' dbname='fixture'",
                    wrapped_dump()['Cmd'][7]+' password=private',
                    wrapped_dump()['Cmd'][7].replace('fixture', 'x'*257),
                    wrapped_dump()['Cmd'][7].replace('fixture', 'é'*129),
                    wrapped_dump()['Cmd'][7].replace('fixture', '\ud800'),
                    wrapped_dump()['Cmd'][7].replace('fixture', '\\q'),
                    wrapped_dump()['Cmd'][7]+'\0'],
                8: ['--format=custom-private', '--format=plain'],
                9: ['--compress=gzip:0', '--compress=gzip:9-private']}.items():
            for value in values:
                cmd = wrapped_dump()['Cmd']; cmd[index] = value
                changed('argv-'+str(index)+'-'+repr(value), 'Cmd', cmd)
        for cmd in (wrapped_dump()['Cmd'][:-1], wrapped_dump()['Cmd']+['--private'],
                    ['env']+wrapped_dump()['Cmd'], {'0':'/bin/sh'}, '/bin/sh', [None],
                    ['/bin/sh', None], ['/bin/sh', '-c', DUMP_SCRIPT, 'bakabel-export-v1', 123]):
            changed('malformed-argv-'+repr(cmd), 'Cmd', cmd)
        for env in (None, [], 'PGAPPNAME=', {'PGAPPNAME':''},
                    wrapped_dump()['Env']+['PRIVATE=do-not-log'],
                    ['PGAPPNAME='+'c'*32]+wrapped_dump()['Env'][1:],
                    [e for e in wrapped_dump()['Env'] if not e.startswith('BAKABEL_RUN_ID=')],
                    ['BAKABEL_RUN_ID='+'c'*32 if e.startswith('BAKABEL_RUN_ID=') else e for e in wrapped_dump()['Env']]):
            changed('environment-'+repr(env), 'Env', env)
        for key, value in (('User','postgres'), ('AttachStdout',False), ('AttachStderr',False),
                           ('AttachStdin',True), ('Tty',True), ('Tty',0)):
            changed('exec-config-'+key, key, value)
        variants.extend([('non-object', []), ('null', None)])
        for label, spec in variants:
            with self.subTest(variant=label):
                record = relay.classify('POST', '/containers/'+'b'*64+'/exec', json.dumps(spec).encode())
                self.assertEqual(record, {'method':'POST', 'boundary':'other', 'forwarded':False, 'container_id':'b'*64})

    def test_exec_create_response_loss_keeps_real_forwarded_id_but_sends_no_reply(self):
        m = self.module()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); eid = 'a'*64
            body = json.dumps({'Id': eid}).encode()
            seen = self.scripted(root, [b'HTTP/1.1 201 Created\r\nContent-Length: '+str(len(body)).encode()+b'\r\n\r\n'+body])
            relay = m.FaultRelay(root/'front', root/'back'); relay.start()
            try:
                self.assertTrue(hasattr(relay, 'arm'), 'response loss must follow actual side effect, never synthesize its ID')
                observed = []
                relay.observer = lambda phase, record: observed.append((phase, record['boundary']))
                relay.arm('dump-create', 'response-loss')
                request = json.dumps(wrapped_dump()).encode()
                result = self.exchange(relay, '/v1.55/containers/'+'b'*64+'/exec', request)
                self.assertEqual(result, b''); self.assertEqual(len(seen), 1)
                self.assertEqual(seen[0][1], request)
                record = relay.snapshot()['records'][-1]
                self.assertEqual(record['exec_id'], eid); self.assertEqual(record['fault'], 'response-loss')
                self.assertTrue(record['forwarded']); self.assertEqual(record['status'], 201)
                self.assertEqual(observed, [('request','dump-create'),('response','dump-create')])
            finally: relay.close()

    def test_stream_drop_counts_only_demultiplexed_stdout_and_denies_exact_status(self):
        m = self.module()
        import struct
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); eid = 'a'*64; cid = 'b'*64
            created = json.dumps({'Id':eid}).encode()
            frame = lambda stream, data: bytes([stream,0,0,0])+struct.pack('>I',len(data))+data
            replies = [b'HTTP/1.1 201 Created\r\nContent-Length: '+str(len(created)).encode()+b'\r\n\r\n'+created,
                       b'HTTP/1.1 101 UPGRADED\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n'+frame(2,b'ignored-stderr')+frame(1,b'x'*96)]
            seen = self.scripted(root, replies)
            relay = m.FaultRelay(root/'front', root/'back'); relay.start()
            try:
                self.assertTrue(hasattr(relay, 'arm'), 'need exact stream drop not a generated failed export')
                request = json.dumps(wrapped_dump()).encode()
                self.exchange(relay, '/v1.55/containers/'+cid+'/exec', request)
                relay.arm('dump-start', 'stream-drop', after_stdout=32, deny_status=True)
                result = self.exchange(relay, '/v1.55/exec/'+eid+'/start', b'{"Detach":false,"Tty":false}')
                self.assertTrue(result.startswith(b'HTTP/1.1 101'))
                snap = relay.snapshot(); record = snap['records'][-1]
                self.assertEqual(seen[0][1], request)
                self.assertEqual(snap['execs'][eid]['kind'], 'dump')
                self.assertEqual(record['boundary'], 'dump-start'); self.assertEqual(record['container_id'], cid)
                for private in ('Cmd', 'Env', 'run=$1', 'bakabel-export-v1', "dbname='fixture'", 'ignored-stderr', 'c'*32):
                    self.assertNotIn(private, json.dumps(snap))
                self.assertEqual(snap['errors'], [])
                self.assertGreaterEqual(record['stdout_bytes'], 32); self.assertEqual(record['fault'], 'stream-drop')
                self.assertEqual(snap['denied_exec'], eid)
                self.assertFalse(relay.status_allowed(eid)); self.assertTrue(relay.status_allowed('d'*64))
                relay.recover_transport(); self.assertTrue(relay.status_allowed(eid))
            finally: relay.close()

    def test_unknown_shell_wrapper_is_forwarded_unchanged_without_consuming_fault(self):
        m = self.module()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            reply = b'HTTP/1.1 201 Created\r\nContent-Length: 2\r\n\r\n{}'
            seen = self.scripted(root, [reply])
            relay = m.FaultRelay(root/'front', root/'back'); relay.start()
            try:
                spec = wrapped_dump(); spec['Cmd'][2] += '\n# private-do-not-log'
                request = json.dumps(spec).encode()
                relay.arm('dump-create', 'response-loss')
                self.assertEqual(self.exchange(relay, '/containers/'+'b'*64+'/exec', request), reply)
                self.assertEqual(seen[0][1], request)
                self.assertFalse(relay.hit.is_set()); self.assertIsNotNone(relay.rule)
                snap = relay.snapshot()
                self.assertEqual(snap['records'][-1]['boundary'], 'other')
                self.assertEqual(snap['execs'], {}); self.assertEqual(snap['errors'], [])
                for private in ('Cmd', 'Env', 'private-do-not-log', 'c'*32):
                    self.assertNotIn(private, json.dumps(snap))
            finally: relay.close()

    def test_chunked_reply_and_keepalive_front_can_issue_a_second_request(self):
        m = self.module()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.scripted(root, [b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n', b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}'])
            relay = m.FaultRelay(root/'front', root/'back'); relay.start()
            client = socket.socket(socket.AF_UNIX); client.settimeout(3); client.connect(str(root/'front'))
            try:
                client.sendall(b'GET /v1.55/info HTTP/1.1\r\nHost: local\r\n\r\n')
                header, _, fields = m.read_headers(client)
                self.assertEqual(fields['transfer-encoding'], 'chunked')
                self.assertEqual(m.read_exact(client,12), b'2\r\n{}\r\n0\r\n\r\n')
                try:
                    client.sendall(b'GET /v1.55/info HTTP/1.1\r\nHost: local\r\nConnection: close\r\n\r\n')
                    _, line, _ = m.read_headers(client)
                except (OSError, EOFError) as exc:
                    self.fail('relay closed healthy keepalive transport: '+type(exc).__name__)
                self.assertEqual(line, 'HTTP/1.1 200 OK'); self.assertEqual(m.read_exact(client,2),b'{}')
            finally: client.close(); relay.close()

    def test_bodyless_worker_start_reply_does_not_wait_for_engine_keepalive_eof(self):
        m = self.module()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.scripted(root,[b'HTTP/1.1 204 No Content\r\n\r\n',b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}'])
            relay = m.FaultRelay(root/'front',root/'back'); relay.start()
            client = socket.socket(socket.AF_UNIX); client.settimeout(3); client.connect(str(relay.path))
            try:
                client.sendall(b'POST /v1.55/containers/'+b'a'*64+b'/start HTTP/1.1\r\nHost: local\r\nContent-Length: 0\r\n\r\n')
                _,line,_ = m.read_headers(client); self.assertEqual(line,'HTTP/1.1 204 No Content')
                try:
                    client.sendall(b'GET /v1.55/info HTTP/1.1\r\nHost: local\r\nConnection: close\r\n\r\n')
                    _,line,_ = m.read_headers(client)
                except (OSError,EOFError) as exc: self.fail('bodyless worker start stalled transport: '+type(exc).__name__)
                self.assertEqual(line,'HTTP/1.1 200 OK')
            finally: client.close(); relay.close()

    def test_real_forwarded_request_and_response_are_unmodified_and_receipts_redact(self):
        m = self.module()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            request = (b'POST /v1.55/containers/create HTTP/1.1\r\nHost: local\r\nConnection: close\r\nContent-Length: %d\r\n\r\n' % len(b'{"HostConfig":{"NanoCpus":2000000000,"Memory":536870912},"Env":["CANARY=do-not-log"]}')) + b'{"HostConfig":{"NanoCpus":2000000000,"Memory":536870912},"Env":["CANARY=do-not-log"]}'
            reply = b'HTTP/1.1 201 Created\r\nContent-Length: 12\r\n\r\n{"Id":"abc"}'
            seen = []
            server = socket.socket(socket.AF_UNIX); server.bind(str(root/'back')); server.listen()
            def peer():
                conn, _ = server.accept()
                with conn:
                    data = b''
                    while len(data) < len(request): data += conn.recv(4096)
                    seen.append(data); conn.sendall(reply)
            thread = threading.Thread(target=peer); thread.start()
            relay = m.FaultRelay(root/'front', root/'back'); relay.start()
            try:
                client = socket.socket(socket.AF_UNIX); client.settimeout(2); client.connect(str(root/'front'))
                with client:
                    client.sendall(request); got = b''
                    while True:
                        chunk = client.recv(4096)
                        if not chunk: break
                        got += chunk
                self.assertEqual(got, reply); self.assertEqual(seen, [request])
                self.assertNotIn('do-not-log', json.dumps(relay.snapshot()))
                self.assertNotIn('Env', json.dumps(relay.snapshot()))
            finally:
                relay.close(); thread.join(2); server.close()


class FixtureContracts(unittest.TestCase):
    def module(self):
        m = importlib.import_module('run_hosted_faults')
        self.assertTrue(hasattr(m, 'FaultProbe'), 'need real public CLI fixture wiring, not protocol-only gates')
        return m

    def test_local_config_retains_candidate_defaults_without_minio_or_s3(self):
        m = self.module()
        with tempfile.TemporaryDirectory() as directory:
            probe = m.FaultProbe.__new__(m.FaultProbe)
            probe.root = Path(directory); probe.prefix = 'owned'; probe.image = 'sha256:'+'a'*64
            probe.config(timeout='35s')
            text = (probe.root/'config.yaml').read_text()
            self.assertIn('repository: /repository\n', text)
            self.assertIn('worker_image: '+probe.image+'\n', text)
            self.assertNotIn('worker_resources', text)
            self.assertNotIn('s3_', text)

    def test_constructor_is_local_only_and_keeps_relay_separate_from_control_socket(self):
        m = self.module()
        self.assertIn('__init__', m.FaultProbe.__dict__, 'local-only constructor must replace S3 bootstrap')
        from types import SimpleNamespace
        class Engine:
            def __init__(self, path): self.sock = str(path)
            def call(self, method, path):
                if path == '/info': return {'ID':'owned-daemon'}
                if path.startswith('/images/'): return {'Id':'sha256:'+'a'*64}
                raise AssertionError('constructor attempted Engine write')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)/'case'
            args = SimpleNamespace(runtime=root, socket=Path(directory)/'real.sock', image='candidate', expected_image_id='sha256:'+'a'*64, expected_source_sha256='b'*64)
            with patch.object(m, 'Engine', Engine): probe = m.FaultProbe(args, 'producer-failure-after-output')
            try:
                self.assertEqual(probe.e.sock, str(args.socket))
                self.assertEqual(probe.sock, str(m.relay_path(root,'producer-failure-after-output')))
                self.assertTrue((root/'private/password').is_file())
                self.assertEqual(set(probe.result['images']), {'candidate', m.PG})
                self.assertNotIn('minio', json.dumps(probe.result).lower())
            finally: probe.relay.close()

    def test_worker_resource_or_socket_drift_is_refused(self):
        m = self.module()
        self.assertTrue(hasattr(m.FaultProbe, 'worker_proof'), 'ordinary worker and real cgroup binding must be audited')
        from run_resource_probe import worker_owned
        owner = {'runID':'a'*32,'workerContainerID':'b'*64,'workerName':'bakabel-worker-'+'a'*32,'daemonID':'daemon'}
        obj = {'Id':owner['workerContainerID'],'Name':'/'+owner['workerName'],'Image':'sha256:'+'c'*64,
               'Config':{'Labels':{'bakabel.worker':'1','bakabel.run':owner['runID'],'bakabel.daemon':'daemon'},'Cmd':['_workflow'],'Entrypoint':['/usr/local/bin/bakabel']},
               'HostConfig':{'Memory':536870912,'NanoCpus':2000000000},'State':{'Running':False},
               'Mounts':[{'Type':'bind','Source':'/owned/relay.sock','Destination':'/run/bakabel/docker.sock','RW':False}]}
        self.assertTrue(worker_owned(obj, owner, obj['Image'], 'daemon'))
        probe = m.FaultProbe.__new__(m.FaultProbe); probe.image = obj['Image']; probe.daemon = 'daemon'; probe.sock = '/owned/relay.sock'
        self.assertEqual(probe.worker_proof(obj, owner)['memory_bytes'], 536870912)
        wrong = json.loads(json.dumps(obj)); wrong['HostConfig']['NanoCpus'] = 0
        with self.assertRaises(ValueError): probe.worker_proof(wrong, owner)
        wrong = json.loads(json.dumps(obj)); wrong['Mounts'][0]['Source'] = '/var/run/docker.sock'
        with self.assertRaises(ValueError): probe.worker_proof(wrong, owner)

    @contextlib.contextmanager
    def worker_observation_probe(self):
        # Local files model a disappearing kernel view; not hosted evidence.
        from unittest.mock import Mock
        m = self.module()
        with tempfile.TemporaryDirectory() as directory:
            probe = m.FaultProbe.__new__(m.FaultProbe)
            owner = {'runID':'a'*32,'workerContainerID':'b'*64,'workerName':'bakabel-worker-'+'a'*32,'daemonID':'daemon'}
            probe.image = 'sha256:'+'c'*64; probe.daemon = 'daemon'; probe.sock = '/owned/relay.sock'
            obj = {'Id':'b'*64,'Name':'/'+owner['workerName'],'Image':probe.image,
                   'Config':{'Labels':{'bakabel.worker':'1','bakabel.run':owner['runID'],'bakabel.daemon':'daemon'},'Cmd':['_workflow'],'Entrypoint':['/usr/local/bin/bakabel']},
                   'HostConfig':{'Memory':536870912,'NanoCpus':2000000000},'State':{'Running':True,'Pid':123},
                   'Mounts':[{'Type':'bind','Source':probe.sock,'Destination':'/run/bakabel/docker.sock','RW':False}]}
            cgroup = Path(directory)/('b'*64); cgroup.mkdir()
            for key,value in (('cpu.max','200000 100000'),('memory.max','536870912'),('memory.peak','4096')):
                (cgroup/key).write_text(value)
            probe.owner = Mock(return_value=owner); probe.e = Mock(); probe.e.inspect.return_value = obj
            probe.e.call.return_value = {'ID': probe.daemon}
            probe.pin_container = Mock(); probe.cgroup = Mock(return_value=cgroup)
            probe.worker_records = {}; probe.worker_owners = {}; probe.roles = {}
            probe.clock = 0.0; probe.sleeps = []
            def sleep(seconds):
                self.assertGreater(seconds, 0)
                self.assertLessEqual(seconds, .05)
                probe.sleeps.append(seconds); probe.clock += seconds
            with patch.object(m.time, 'monotonic', side_effect=lambda: probe.clock), patch.object(m.time, 'sleep', side_effect=sleep):
                yield probe, obj, owner, cgroup

    def test_worker_cgroup_delayed_terminal_settles_with_exact_safe_readback_sequence(self):
        for terminal_kind in ('stopped', 'absent'):
            with self.subTest(terminal=terminal_kind), self.worker_observation_probe() as (probe,obj,_,__):
                probe.capture_owned_worker()
                stopped = json.loads(json.dumps(obj))
                stopped['State'] = {'Running':False, 'Pid':0, 'ExitCode':137,
                                    'StartedAt':'private-timestamp', 'FinishedAt':'private-timestamp'}
                probe.e.inspect.side_effect = [obj, obj, stopped if terminal_kind == 'stopped' else None]
                probe.cgroup.return_value = None
                probe.capture_owned_worker()
                record = probe.worker_records[obj['Id']]
                self.assertEqual(record['cpu.max'], '200000 100000')
                self.assertEqual(record['kernel_readback_state'], 'historical')
                gap = record['observation_gaps'][-1]
                self.assertEqual(gap['reason'], 'unavailable')
                self.assertEqual(gap['resolution'], 'terminal_'+terminal_kind)
                self.assertEqual(len(gap['rows']), 3)
                self.assertEqual([row['running'] for row in gap['rows']], [True, True, False if terminal_kind == 'stopped' else None])
                self.assertEqual(gap['rows'][-1]['exit_code'], 137 if terminal_kind == 'stopped' else None)
                self.assertEqual(gap['rows'][-1]['observation_state'], 'observed' if terminal_kind == 'stopped' else 'missing')
                self.assertTrue(probe.sleeps)
                self.assertLessEqual(probe.clock, 1)
                self.assertEqual([call.args for call in probe.e.inspect.call_args_list], [(obj['Id'],)]*4)
                self.assertEqual([call.kwargs for call in probe.e.inspect.call_args_list],
                                 [{'missing':True}]*2+[{'missing':True, 'deadline':1.0}]*2)
                self.assertTrue(all(call.args == ('GET', '/info') and call.kwargs == {'deadline':1.0}
                                    for call in probe.e.call.call_args_list))
                with tempfile.TemporaryDirectory() as directory:
                    probe.root = Path(directory); probe.values = []; probe.result = {}
                    probe.save()
                    receipt = json.loads((probe.root/'receipt.json').read_text())
                    self.assertEqual(receipt['workers'][obj['Id']], record)
                    self.assertNotIn('private-timestamp', json.dumps(receipt))

    def test_worker_cgroup_permission_failure_is_retained_before_fail_closed(self):
        for source in ('lookup', 'kernel-file'):
            with self.subTest(source=source), self.worker_observation_probe() as (probe,obj,_,__):
                probe.capture_owned_worker()
                if source == 'lookup':
                    probe.cgroup.side_effect = PermissionError('private-permission-path')
                    manager = contextlib.nullcontext()
                else:
                    manager = patch.object(Path, 'read_text', side_effect=PermissionError('private-permission-path'))
                with manager, self.assertRaisesRegex(ValueError, 'exact worker cgroup unavailable'):
                    probe.capture_owned_worker()
                record = probe.worker_records[obj['Id']]
                self.assertEqual(record['kernel_readback_state'], 'historical')
                self.assertEqual(record['observation_gaps'][-1]['resolution'], 'failed')
                self.assertEqual(record['observation_gaps'][-1]['reason'], 'unavailable')
                self.assertEqual(probe.sleeps, [])
                self.assertNotIn('private-permission-path', json.dumps(record))

    def test_worker_gap_unknown_readback_is_retained_and_never_resolves_as_terminal(self):
        variants = ('transport', 'permission', 'null-state', 'unknown-running', 'numeric-running', 'invalid-pid')
        for variant in variants:
            with self.subTest(unknown=variant), self.worker_observation_probe() as (probe,obj,_,__):
                unknown = json.loads(json.dumps(obj))
                if variant == 'null-state': unknown['State'] = None
                elif variant == 'unknown-running': unknown['State']['Running'] = None
                elif variant == 'numeric-running': unknown['State']['Running'] = 0
                elif variant == 'invalid-pid': unknown['State']['Pid'] = 'private-pid'
                elif variant == 'transport': unknown = ConnectionError('private-error-path')
                else: unknown = PermissionError('private-error-path')
                probe.e.inspect.side_effect = [obj, obj, unknown]
                probe.cgroup.return_value = None
                with self.assertRaises((ValueError, ConnectionError, PermissionError)):
                    probe.capture_owned_worker()
                record = probe.worker_records[obj['Id']]
                gap = record['observation_gaps'][-1]
                self.assertEqual(gap['resolution'], 'failed')
                self.assertEqual(len(gap['rows']), 3)
                self.assertEqual(gap['rows'][-1]['observation_state'], 'unavailable')
                self.assertNotIn('private-', json.dumps(record))
                self.assertFalse(any(key in record for key in ('cpu.max', 'memory.max', 'memory.peak')))

    def test_worker_gap_cannot_resolve_absence_on_changed_daemon(self):
        with self.worker_observation_probe() as (probe,obj,_,__):
            probe.e.inspect.side_effect = [obj, None]
            probe.e.call.return_value = {'ID': 'private-replacement-daemon'}
            probe.cgroup.return_value = None
            with self.assertRaisesRegex(ValueError, 'daemon'):
                probe.capture_owned_worker()
            gap = probe.worker_records[obj['Id']]['observation_gaps'][-1]
            self.assertEqual(gap['resolution'], 'failed')
            self.assertEqual(gap['rows'][-1]['observation_state'], 'unavailable')
            self.assertNotIn('private-replacement-daemon', json.dumps(gap))

    def test_stopped_worker_marks_prior_kernel_proof_historical_without_opening_gap(self):
        with self.worker_observation_probe() as (probe,obj,_,__):
            probe.capture_owned_worker()
            stopped = json.loads(json.dumps(obj)); stopped['State'] = {'Running':False, 'Pid':0, 'ExitCode':0}
            probe.e.inspect.return_value = stopped
            probe.capture_owned_worker()
            record = probe.worker_records[obj['Id']]
            self.assertEqual(record['cpu.max'], '200000 100000')
            self.assertEqual(record['kernel_readback_state'], 'historical')
            self.assertNotIn('observation_gaps', record)
            self.assertEqual(probe.sleeps, [])

    def test_worker_gap_does_not_accept_terminal_readback_after_monotonic_budget(self):
        with self.worker_observation_probe() as (probe,obj,_,__):
            probe.cgroup.return_value = None
            stopped = json.loads(json.dumps(obj)); stopped['State'] = {'Running':False, 'Pid':0}
            calls = []
            def inspect(cid, **kwargs):
                calls.append(cid)
                if len(calls) == 1: return obj
                probe.clock += 1.01
                return stopped
            probe.e.inspect.side_effect = inspect
            with self.assertRaisesRegex(ValueError, 'exact worker cgroup unavailable'):
                probe.capture_owned_worker()
            self.assertEqual(probe.worker_records[obj['Id']]['observation_gaps'][-1]['resolution'], 'failed')

    def test_worker_gap_does_not_accept_kernel_recovery_after_monotonic_budget(self):
        with self.worker_observation_probe() as (probe,obj,_,cgroup):
            calls = []
            def kernel(pid):
                calls.append(pid)
                if len(calls) == 1: return None
                probe.clock += 1.01
                return cgroup
            probe.cgroup.side_effect = kernel
            with self.assertRaisesRegex(ValueError, 'exact worker cgroup unavailable'):
                probe.capture_owned_worker()
            record = probe.worker_records[obj['Id']]
            self.assertEqual(record['observation_gaps'][-1]['resolution'], 'failed')
            self.assertNotIn('cpu.max', record)

    def test_worker_gap_wrong_cgroup_identity_cannot_be_excused_by_later_stop(self):
        with self.worker_observation_probe() as (probe,obj,_,cgroup):
            stopped = json.loads(json.dumps(obj)); stopped['State'] = {'Running':False, 'Pid':0}
            probe.e.inspect.side_effect = [obj, obj, stopped]
            probe.cgroup.side_effect = [None, cgroup.parent/'private-other-worker']
            with self.assertRaisesRegex(ValueError, 'cgroup identity'):
                probe.capture_owned_worker()
            record = probe.worker_records[obj['Id']]
            self.assertEqual(record['observation_gaps'][-1]['resolution'], 'failed')
            self.assertNotIn('private-other-worker', json.dumps(record))
            self.assertEqual(probe.e.inspect.call_count, 2)

    def test_worker_gap_live_recovery_requires_fresh_pid_bound_kernel_readback(self):
        for cached in (False, True):
            with self.subTest(cached=cached), self.worker_observation_probe() as (probe,obj,_,cgroup):
                if cached: probe.capture_owned_worker()
                recovered = json.loads(json.dumps(obj)); recovered['State']['Pid'] = 456
                (cgroup/'memory.peak').write_text('8192')
                probe.pin_container.reset_mock()
                probe.e.inspect.side_effect = [obj, obj, recovered]
                probe.cgroup.side_effect = [None, None, cgroup]
                probe.capture_owned_worker()
                probe.pin_container.assert_called_once_with(obj['Id'])
                record = probe.worker_records[obj['Id']]
                self.assertEqual(record['kernel_readback_state'], 'observed')
                self.assertEqual(record['memory.peak'], 8192)
                self.assertEqual(record['cpu.max'], '200000 100000')
                self.assertEqual(record['memory.max'], '536870912')
                self.assertEqual(record['observation_gaps'][-1]['resolution'], 'kernel_observed')
                self.assertEqual([row['pid'] for row in record['observation_gaps'][-1]['rows']], [123,123,456])
                self.assertEqual(probe.cgroup.call_args.args, (456,))
                self.assertLessEqual(probe.clock, 1)

    def test_worker_gap_live_recovery_does_not_use_cached_kernel_limits(self):
        for field,value in (('cpu.max','max 100000'), ('memory.max','max')):
            with self.subTest(field=field), self.worker_observation_probe() as (probe,obj,_,cgroup):
                probe.capture_owned_worker()
                (cgroup/field).write_text(value)
                probe.cgroup.side_effect = [None, None, cgroup]
                with self.assertRaisesRegex(ValueError, 'kernel worker limits differ'):
                    probe.capture_owned_worker()
                record = probe.worker_records[obj['Id']]
                self.assertEqual(record['kernel_readback_state'], 'historical')
                self.assertEqual(record['observation_gaps'][-1]['resolution'], 'failed')
                self.assertEqual(record[field], {'cpu.max':'200000 100000', 'memory.max':'536870912'}[field])

    def test_worker_gap_revalidates_every_intermediate_and_terminal_worker_snapshot(self):
        for running in (False, True):
            for field in ('Id','Image','Name','run','daemon','Cmd','Entrypoint','Memory','NanoCpus','socket'):
                with self.subTest(running=running,field=field), self.worker_observation_probe() as (probe,obj,_,__):
                    changed = json.loads(json.dumps(obj))
                    changed['State'] = {'Running':running, 'Pid':123 if running else 0, 'ExitCode':137}
                    if field in ('Id','Image','Name'): changed[field] = 'private-drift'
                    elif field in ('run','daemon'): changed['Config']['Labels']['bakabel.'+field] = 'private-drift'
                    elif field in ('Cmd','Entrypoint'): changed['Config'][field] = ['private-drift']
                    elif field == 'socket': changed['Mounts'][0]['Source'] = '/private-drift.sock'
                    else: changed['HostConfig'][field] = 0
                    probe.e.inspect.side_effect = [obj, obj, changed]
                    probe.cgroup.return_value = None
                    with self.assertRaises(ValueError): probe.capture_owned_worker()
                    record = probe.worker_records[obj['Id']]
                    gap = record['observation_gaps'][-1]
                    self.assertEqual(gap['resolution'], 'failed')
                    self.assertEqual(len(gap['rows']), 3)
                    self.assertEqual(gap['rows'][-1]['container_id'], obj['Id'])
                    self.assertNotIn('private-drift', json.dumps(record))
                    self.assertEqual(probe.e.inspect.call_count, 3)

    def test_worker_gap_receipt_caps_history_at_64_gaps(self):
        with self.worker_observation_probe() as (probe,obj,_,__):
            probe.cgroup.return_value = None
            for index in range(66):
                obj['State']['Pid'] = index+1
                probe.e.inspect.side_effect = [obj, None]
                probe.capture_owned_worker()
            gaps = probe.worker_records[obj['Id']]['observation_gaps']
            self.assertEqual(len(gaps), 64)
            self.assertEqual(gaps[0]['rows'][0]['pid'], 3)
            self.assertEqual(gaps[-1]['rows'][0]['pid'], 66)
            self.assertTrue(all(gap['resolution'] == 'terminal_absent' and len(gap['rows']) == 2 for gap in gaps))
            self.assertEqual(probe.sleeps, [])

    def test_initial_unknown_worker_state_cannot_produce_live_kernel_proof(self):
        for field,value in (('Running',None), ('Running',0), ('Pid',True), ('Pid',0), ('Pid','private-pid')):
            with self.subTest(field=field,value=value), self.worker_observation_probe() as (probe,obj,_,__):
                obj['State'][field] = value
                with self.assertRaisesRegex(ValueError, 'worker state unavailable'):
                    probe.capture_owned_worker()
                self.assertEqual(probe.worker_records, {})
                self.assertEqual(probe.sleeps, [])

    def test_worker_cgroup_exit_race_requires_exact_terminal_readback_preserves_cached_limits(self):
        for terminal_kind in ('stopped','absent'):
            with self.subTest(terminal=terminal_kind), self.worker_observation_probe() as (probe,obj,owner,_):
                probe.capture_owned_worker()
                cached = dict(probe.worker_records[obj['Id']])
                stopped = json.loads(json.dumps(obj)); stopped['State'] = {'Running':False,'Pid':0}
                probe.e.inspect.side_effect = [obj, stopped if terminal_kind == 'stopped' else None]
                probe.cgroup.return_value = None
                probe.capture_owned_worker()
                retained = probe.worker_records[obj['Id']]
                self.assertEqual({key: retained[key] for key in cached if key != 'kernel_readback_state'},
                                 {key: value for key, value in cached.items() if key != 'kernel_readback_state'})
                self.assertEqual(retained['kernel_readback_state'], 'historical')
                self.assertEqual(retained['observation_gaps'][-1]['resolution'], 'terminal_'+terminal_kind)
                self.assertEqual(probe.e.inspect.call_args.kwargs, {'missing':True, 'deadline':1.0})
                self.assertEqual(probe.worker_owners[obj['Id']], owner)

    def test_worker_cgroup_unexplained_live_failure_is_not_hidden_by_cached_proof(self):
        for cached in (False, True):
            with self.subTest(cached=cached), self.worker_observation_probe() as (probe,obj,_,__):
                if cached: probe.capture_owned_worker()
                probe.cgroup.return_value = None
                with self.assertRaisesRegex(ValueError, 'exact worker cgroup unavailable'):
                    probe.capture_owned_worker()
                record = probe.worker_records[obj['Id']]
                self.assertEqual(record['kernel_readback_state'], 'historical' if cached else 'unavailable')
                gap = record['observation_gaps'][-1]
                self.assertEqual(gap['resolution'], 'failed')
                self.assertEqual(len(gap['rows']), 20)
                self.assertTrue(all(row['running'] is True and row['pid'] == 123 and row['observation_state'] == 'observed' for row in gap['rows']))
                self.assertTrue(probe.sleeps)
                self.assertLessEqual(probe.clock, 1)
                self.assertEqual([row['elapsed_ms'] for row in gap['rows']], sorted(row['elapsed_ms'] for row in gap['rows']))
                with tempfile.TemporaryDirectory() as directory:
                    probe.root = Path(directory); probe.values = []; probe.result = {}
                    probe.save()
                    self.assertEqual(json.loads((probe.root/'receipt.json').read_text())['workers'][obj['Id']], record)

    def test_worker_disappearing_cgroup_files_do_not_invent_kernel_readback(self):
        for terminal_kind in ('stopped','absent','live'):
            with self.subTest(terminal=terminal_kind), self.worker_observation_probe() as (probe,obj,_,cgroup):
                (cgroup/'memory.max').unlink()
                stopped = json.loads(json.dumps(obj)); stopped['State'] = {'Running':False,'Pid':0}
                terminal = {'stopped':stopped,'absent':None,'live':obj}[terminal_kind]
                probe.e.inspect.side_effect = None if terminal_kind == 'live' else [obj, terminal]
                if terminal_kind == 'live':
                    with self.assertRaisesRegex(ValueError, 'exact worker cgroup unavailable'):
                        probe.capture_owned_worker()
                else:
                    probe.capture_owned_worker()
                    self.assertFalse(any(key in probe.worker_records[obj['Id']] for key in ('cpu.max','memory.max','memory.peak')))

    def test_worker_terminal_reread_refuses_identity_or_limits_drift(self):
        for key in ('Id','Image','Name','Memory','NanoCpus','socket'):
            with self.subTest(drift=key), self.worker_observation_probe() as (probe,obj,_,__):
                terminal = json.loads(json.dumps(obj)); terminal['State'] = {'Running':False,'Pid':0}
                if key in ('Id','Image','Name'): terminal[key] = 'wrong'
                elif key == 'socket': terminal['Mounts'][0]['Source'] = '/var/run/docker.sock'
                else: terminal['HostConfig'][key] = 0
                probe.e.inspect.side_effect = [obj, terminal]; probe.cgroup.return_value = None
                with self.assertRaises(ValueError): probe.capture_owned_worker()

    def test_worker_live_kernel_limit_drift_is_never_an_exit_race(self):
        for key,value in (('cpu.max','max 100000'),('memory.max','max')):
            with self.subTest(limit=key), self.worker_observation_probe() as (probe,obj,_,cgroup):
                probe.capture_owned_worker()
                (cgroup/key).write_text(value)
                with self.assertRaisesRegex(ValueError, 'kernel worker limits differ'):
                    probe.capture_owned_worker()

    def test_producer_fault_terminates_exact_observed_backend_only_after_partial_output(self):
        m = self.module()
        self.assertIn('exercise_stream_fault', m.FaultProbe.__dict__, 'real producer failure must use observed streaming export identity')
        events = []
        probe = m.FaultProbe.__new__(m.FaultProbe); probe.case = 'producer-failure-after-output'; probe.source = 'b'*64
        probe.controller = lambda *args: (events.append(('cli', args)) or 'controller')
        active = {'runID':'a'*32,'execID':'c'*64,'workerContainerID':'d'*64}
        session = {'pid':123,'backend_start':'2026-01-01 00:00:00+00','application_name':'a'*32}
        probe.await_stream = lambda pg, **kw: (events.append(('stream', pg)) or (active, session, 65536))
        probe.sql = lambda cid, q: (events.append(('sql', q)) or 't')
        probe.finish_failure = lambda cid, owner: events.append(('terminal', cid, owner))
        probe.result = {}
        probe.exercise_stream_fault()
        self.assertEqual(events[0], ('cli', ('run',)))
        self.assertEqual(events[1], ('stream', probe.source))
        query = events[2][1]
        self.assertIn('pg_terminate_backend(pid)', query)
        self.assertIn('pid=123', query); self.assertIn("backend_start='2026-01-01 00:00:00+00'::timestamptz", query)
        self.assertIn("application_name='"+'a'*32+"'", query)
        self.assertEqual(events[3], ('terminal', 'controller', active))

    def test_streaming_worker_kill_targets_only_frozen_worker(self):
        m = self.module()
        self.assertIn('exercise_stream_fault', m.FaultProbe.__dict__, 'streaming kill must not be lock-wait kill relabeled')
        from unittest.mock import Mock
        probe = m.FaultProbe.__new__(m.FaultProbe); probe.case = 'streaming-worker-SIGKILL'; probe.source = 'b'*64
        active = {'runID':'a'*32,'execID':'c'*64,'workerContainerID':'d'*64}
        probe.controller = lambda *args: 'controller'; probe.await_stream = lambda pg, **kw: (active, {'pid':123}, 65536)
        probe.e = Mock(); probe.result = {}; probe.finish_failure = Mock()
        probe.exercise_stream_fault()
        probe.e.call.assert_called_once_with('POST', '/containers/'+'d'*64+'/kill?signal=KILL')
        probe.finish_failure.assert_called_once_with('controller', active)

    def test_terminal_proof_refuses_live_exec_or_wrong_container(self):
        m = self.module()
        self.assertIn('terminal_proof', m.FaultProbe.__dict__, 'owner release requires exact daemon/source/exec/session proof')
        from unittest.mock import Mock
        probe = m.FaultProbe.__new__(m.FaultProbe); probe.daemon = 'daemon'; probe.source = 'b'*64
        probe.e = Mock(); probe.sql = Mock(return_value='0'); probe.process_count = Mock(return_value=0)
        active = {'runID':'a'*32,'execID':'c'*64,'sourceContainerID':probe.source,'sourceStartedAt':'start','daemonID':'daemon'}
        probe.e.inspect.return_value = {'Id':probe.source,'State':{'Running':True,'StartedAt':'start'}}
        probe.e.call.side_effect = lambda method, path: {'ID':'daemon'} if path == '/info' else {'ID':'c'*64,'ContainerID':probe.source,'Running':True,'ExitCode':0}
        with self.assertRaises(ValueError): probe.terminal_proof(active)
        probe.e.call.side_effect = lambda method, path: {'ID':'daemon'} if path == '/info' else {'ID':'c'*64,'ContainerID':'d'*64,'Running':False,'ExitCode':137}
        with self.assertRaises(ValueError): probe.terminal_proof(active)
        probe.e.call.side_effect = lambda method, path: {'ID':'daemon'} if path == '/info' else {'ID':'c'*64,'ContainerID':probe.source,'Running':False,'ExitCode':137}
        proof = probe.terminal_proof(active)
        self.assertEqual(proof['exec_exit_code'],137); self.assertEqual(proof['sessions'],0); self.assertEqual(proof['processes'],0)
        active['importRunID'] = 'restore_'+'a'*48; active['execKind'] = 'restore'
        try: probe.terminal_proof(active)
        except ValueError as exc: self.fail('real current restore token was rejected: '+str(exc))
        probe.process_count.assert_called_with(probe.source,active['importRunID'],'pg_restore')

    def test_process_proof_still_selects_tagged_pg_dump_child_not_untagged_wrapper(self):
        from unittest.mock import Mock
        m = self.module(); probe = m.FaultProbe.__new__(m.FaultProbe)
        probe.e = Mock(); probe.e.exec.return_value = {'exit':0, 'stdout':'0\n'}
        token = 'a'*32
        self.assertEqual(probe.process_count('b'*64, token, 'pg_dump'), 0)
        cid, argv = probe.e.exec.call_args.args
        self.assertEqual(cid, 'b'*64); self.assertEqual(argv[:2], ['sh','-c'])
        self.assertIn('[ "$x" = "/usr/local/bin/pg_dump" ] || continue', argv[2])
        self.assertIn('grep -Fxq "PGAPPNAME='+token+'"', argv[2])
        self.assertNotIn('bakabel-export-v1', argv[2])
        self.assertNotIn('BAKABEL_RUN_ID=', argv[2])
        # A failed proc read is not evidence of zero activity.
        probe.e.exec.return_value = {'exit':9, 'stdout':'0\n'}
        with self.assertRaisesRegex(ValueError, 'process terminal proof unavailable'):
            probe.process_count('b'*64, token, 'pg_dump')

    def test_raw_container_logs_containing_synthetic_secret_are_refused_before_export(self):
        m = self.module()
        from unittest.mock import Mock
        import struct
        probe = m.FaultProbe.__new__(m.FaultProbe); probe.values = ['synthetic-canary']; probe.e = Mock()
        payload = b'synthetic-canary'
        probe.e.call.return_value = bytes([1,0,0,0])+struct.pack('>I',len(payload))+payload
        with self.assertRaises(ValueError): probe.logs('a'*64)

    def test_save_does_not_export_raw_specs_commands_logs_or_credentials(self):
        m = self.module()
        self.assertIn('save', m.FaultProbe.__dict__, 'raw inherited helper evidence must never be uploaded')
        with tempfile.TemporaryDirectory() as directory:
            probe = m.FaultProbe.__new__(m.FaultProbe); probe.root = Path(directory); probe.values = ['synthetic-secret']
            probe.result = {'schema':1,'case':'unit','status':'blocked','commands':[{'stdout_stderr':'synthetic-secret','args':['secret argv']}], 'container_specs':{'Env':['synthetic-secret']}}
            probe.worker_records = {}; probe.samples = []
            probe.save()
            exported = (probe.root/'receipt.json').read_text()
            self.assertNotIn('synthetic-secret',exported); self.assertNotIn('secret argv',exported)
            self.assertNotIn('container_specs',exported); self.assertNotIn('stdout_stderr',exported)

    def test_run_dispatches_only_named_current_workflow_cases(self):
        m = self.module()
        self.assertIn('run', m.FaultProbe.__dict__, 'do not inherit/relabel the old 44-core matrix')
        from verify_hosted_faults import CASES
        for case in CASES:
            probe = m.FaultProbe.__new__(m.FaultProbe); probe.case = case; probe.result = {}
            events = []
            probe.prepare = lambda: events.append('prepare')
            probe.verify_source_online = lambda: events.append('source-online')
            for name in ('exercise_stream_fault','exercise_stream_drop','exercise_response_loss','exercise_overlap','exercise_restart'):
                setattr(probe, name, lambda name=name: events.append(name))
            probe.run()
            self.assertEqual(events[0], 'prepare'); self.assertEqual(events[-1], 'source-online')
            self.assertEqual(len(events),3); self.assertTrue(probe.result['exercised'])

    def test_streaming_observation_requires_live_session_and_partial_stdout(self):
        m = self.module()
        self.assertIn('await_stream', m.FaultProbe.__dict__, 'partial-output producer gate needs actual live stream readback')
        from unittest.mock import Mock
        probe = m.FaultProbe.__new__(m.FaultProbe)
        active = {'runID':'a'*32,'phase':'exec_started','execID':'b'*64,'workerContainerID':'c'*64,'sourceContainerID':'d'*64}
        probe.owner = lambda: active
        probe.relay = Mock(); probe.relay.snapshot.return_value = {'execs':{active['execID']:{'stdout_bytes':65536}}}
        probe.e = Mock(); probe.e.call.return_value = {'Running':True,'ContainerID':'d'*64}
        probe.sql = lambda *args: json.dumps([{'pid':123,'backend_start':'start','application_name':'a'*32}])
        probe.wait = lambda fn, *args: fn()
        self.assertEqual(probe.await_stream('d'*64)[2],65536)
        probe.relay.snapshot.return_value = {'execs':{active['execID']:{'stdout_bytes':0}}}
        self.assertIsNone(probe.await_stream('d'*64))
        probe.relay.snapshot.return_value = {'execs':{active['execID']:{'stdout_bytes':65536}}}
        probe.e.call.return_value = {'Running':False,'ContainerID':'d'*64}
        self.assertIsNone(probe.await_stream('d'*64))

    def test_streaming_observation_waits_through_owner_not_yet_created(self):
        from unittest.mock import Mock
        m = self.module(); probe = m.FaultProbe.__new__(m.FaultProbe)
        active = {'runID':'a'*32,'phase':'exec_started','execID':'b'*64}
        probe.owner = Mock(side_effect=[None, active]); probe.capture_owned_worker = Mock()
        probe.relay = Mock(); probe.relay.snapshot.return_value = {'execs':{'b'*64:{'stdout_bytes':65536}}}
        probe.e = Mock(); probe.e.call.return_value = {'Running':True,'ContainerID':'d'*64}
        probe.sql = Mock(return_value=json.dumps([{'pid':123,'backend_start':'start','application_name':'a'*32}]))
        with patch.object(m.time, 'sleep'):
            self.assertEqual(probe.await_stream('d'*64), (active, {'pid':123,'backend_start':'start','application_name':'a'*32}, 65536))
        self.assertEqual(probe.owner.call_count, 2)

    def test_streaming_gate_missed_by_terminal_cli_is_blocked_without_injection(self):
        from unittest.mock import Mock
        m = self.module()
        for active in (None, {'runID':'a'*32,'phase':'exec_started','execID':'b'*64}):
            with self.subTest(owner=active):
                probe = m.FaultProbe.__new__(m.FaultProbe)
                probe.case = 'streaming-worker-SIGKILL'; probe.source = 'd'*64
                probe.result = {'commands':[]}; probe.controller = Mock(return_value='c'*64)
                probe.owner = Mock(return_value=active); probe.capture_owned_worker = Mock()
                probe.e = Mock(); probe.e.inspect.return_value = {'Id':'c'*64,'State':{'Running':False,'ExitCode':0}}
                probe.relay = Mock(); probe.relay.snapshot.return_value = {'execs':{'b'*64:{'stdout_bytes':65535}}}
                probe.e.call.return_value = {'Running':False,'ContainerID':probe.source}
                # Exercise exactly one poll; the real path must detect terminal
                # completion itself, not wait out a wall-clock timeout.
                probe.wait = lambda fn, *args: fn()
                with self.assertRaisesRegex(TimeoutError, 'CLI exited before live pg_dump after 64KiB stdout'):
                    probe.exercise_stream_fault()
                self.assertEqual(probe.result['commands'], [{'container':'c'*64,'exit':0}])
                self.assertNotIn('injection', probe.result)
                self.assertFalse(any(call.args[0] == 'POST' for call in probe.e.call.call_args_list))

    def test_prepare_uses_real_cli_plan_on_one_disposable_pg_source(self):
        m = self.module()
        self.assertIn('prepare',m.FaultProbe.__dict__, 'need actual local repository initialization and public discovery')
        from unittest.mock import Mock
        probe = m.FaultProbe.__new__(m.FaultProbe); probe.source = None; probe.result = {}; probe.daemon = 'daemon'
        probe.config = Mock(); probe.restic = Mock(); probe.startpg = Mock(return_value='b'*64)
        probe.sql = Mock(return_value=''); probe.call_cli = Mock(return_value={'targets':[{'ID':'literal-source','Kind':'postgres','Source':{'DaemonID':'daemon','ContainerID':'b'*64,'StartedAt':'start'}}]})
        probe.e = Mock(); probe.e.inspect.return_value = {'Id':'b'*64,'RestartCount':0,'State':{'StartedAt':'start','Running':True}}
        probe.prepare()
        probe.restic.assert_called_once_with('init'); probe.call_cli.assert_called_once_with('plan')
        self.assertEqual(probe.source,'b'*64); self.assertEqual(probe.target,'literal-source')

    def test_failure_receipt_requires_error_exit_terminal_source_and_unchanged_last_success(self):
        m = self.module()
        self.assertIn('finish_failure',m.FaultProbe.__dict__,'failure proof must not stop at CLI exit')
        from unittest.mock import Mock
        probe = m.FaultProbe.__new__(m.FaultProbe); probe.result = {}; probe.baseline_success = 'previous-success'
        active = {'runID':'a'*32,'workerContainerID':'b'*64}
        probe.finish = Mock(return_value=[{'runID':active['runID'],'status':'failed'}]); probe.terminal_proof = Mock(return_value={'exec_exit_code':1,'sessions':0,'processes':0})
        probe.owner = Mock(return_value=None); probe.e = Mock(); probe.e.inspect.return_value = None
        probe.no_complete_snapshot = Mock(return_value=True); probe.last = Mock(return_value={'runID':active['runID'],'status':'failed','lastBackupSuccessAt':'previous-success'})
        probe.finish_failure('controller', active)
        self.assertEqual(probe.result['proof']['outcome'],'failed'); self.assertTrue(probe.result['proof']['owner_released'])
        probe.last.return_value['lastBackupSuccessAt'] = 'new-wrong-success'
        with self.assertRaises(ValueError): probe.finish_failure('controller',active)

    def test_no_complete_lookup_matches_exact_run_and_target_not_newest(self):
        m = self.module()
        self.assertIn('no_complete_snapshot',m.FaultProbe.__dict__,'repository readback must bind exact fault run and target')
        probe = m.FaultProbe.__new__(m.FaultProbe); probe.target = 'literal-source'
        import hashlib
        run = 'a'*32; token = run+'-'+hashlib.sha256(probe.target.encode()).hexdigest()
        snapshots = [{'id':'b'*64,'tags':['bakabel.run='+token,'bakabel.status=unknown']}, {'id':'c'*64,'tags':['bakabel.run=unrelated','bakabel.status=complete']}]
        probe.restic = lambda *args: json.dumps(snapshots)
        self.assertTrue(probe.no_complete_snapshot({'runID':run}))
        snapshots[0]['tags'][-1] = 'bakabel.status=complete'
        self.assertFalse(probe.no_complete_snapshot({'runID':run}))

    def test_owner_observation_and_cli_finish_export_no_raw_logs(self):
        m = self.module()
        for method in ('owner','finish','wait','capture_owned_worker','process_count','verify_source_online'):
            self.assertIn(method,m.FaultProbe.__dict__,'bounded current-workflow helper required: '+method)
        from unittest.mock import Mock
        with tempfile.TemporaryDirectory() as directory:
            probe = m.FaultProbe.__new__(m.FaultProbe); probe.root = Path(directory); (probe.root/'state').mkdir()
            probe.result = {'commands':[]}; probe.values = ['must-not-upload']; probe.capture_owned_worker = lambda: None
            self.assertIsNone(probe.owner())
            (probe.root/'state/owner.json').write_text(json.dumps({'runID':'a'*32}))
            self.assertEqual(probe.owner()['runID'],'a'*32)
            probe.e = Mock(); probe.e.inspect.return_value = {'State':{'Running':False,'ExitCode':1}}
            probe.logs = lambda cid: '{"runID":"'+'a'*32+'","status":"failed"}\ninternal diagnostics\n'
            rows = probe.finish('b'*64, expect=1)
            self.assertEqual(rows[0]['status'],'failed')
            self.assertNotIn('internal diagnostics',json.dumps(probe.result))

    def test_unexpected_cli_success_stays_failed_with_numeric_redacted_diagnostics(self):
        from unittest.mock import Mock
        m = self.module()
        with tempfile.TemporaryDirectory() as directory:
            probe = m.FaultProbe.__new__(m.FaultProbe); probe.root = Path(directory)
            probe.values = []; probe.result = {'commands':[]}; probe.worker_records = {}
            probe.capture_owned_worker = Mock(); probe.e = Mock()
            probe.e.inspect.return_value = {'State':{'Running':False,'ExitCode':0}}
            probe.logs = Mock(return_value='{"status":"complete","message":"private-do-not-export","Env":["PRIVATE=value"]}\n')
            with self.assertRaisesRegex(ValueError, 'unexpected CLI exit'):
                probe.finish('b'*64, expect=1)
            probe.save()
            exported = (probe.root/'receipt.json').read_text()
            command = json.loads(exported)['commands'][0]
            self.assertEqual(command, {'container':'b'*64,'exit':0,'expected_exit':1,'complete_rows':1,'failed_rows':0})
            for secret in ('private-do-not-export','PRIVATE=value','Env','message'):
                self.assertNotIn(secret, exported)

    def test_transport_response_loss_dispatch_uses_public_restore_and_real_fault_record(self):
        m = self.module()
        for method in ('exercise_response_loss','fault_record','observe_transport','fresh_recovery','success_snapshot'):
            self.assertIn(method,m.FaultProbe.__dict__,'response loss needs public lifecycle helper: '+method)
        from unittest.mock import Mock
        probe = m.FaultProbe.__new__(m.FaultProbe); probe.case = 'restore-start-response-loss'; probe.result = {'proof':{}}
        probe.success_snapshot = Mock(return_value='a'*64); probe.startpg = Mock(return_value='b'*64)
        probe.relay = Mock(); probe.relay.hit.wait.return_value = True
        active = {'runID':'c'*32,'execID':'d'*64,'workerContainerID':'e'*64,'execKind':'restore'}
        record = {'boundary':'restore-start','fault':'response-loss','forwarded':True,'status':101,'owner_checkpoint':active}
        probe.fault_record = Mock(return_value=record); probe.controller = Mock(return_value='controller'); probe.finish_failure = Mock()
        probe.exercise_response_loss()
        probe.relay.arm.assert_called_once_with('restore-start','response-loss')
        probe.controller.assert_called_once_with('restore','--snapshot','a'*64,'--postgres-container','b'*64,'--database','fixture','--user','postgres')
        probe.finish_failure.assert_called_once_with('controller',active)

    def worker_launch_probe(self, boundary):
        # Offline seam: these doubles are not Engine/runtime evidence.
        m = self.module()
        from unittest.mock import Mock
        probe = m.FaultProbe.__new__(m.FaultProbe)
        probe.case = boundary+'-response-loss'; probe.result = {}; probe.daemon = 'daemon'
        probe.source = 'b'*64; probe.source_before = {'container_id':probe.source,'started_at':'source-start'}
        active = {'runID':'a'*32,'daemonID':'daemon'}  # Product never persisted source/exec ID.
        record = {'boundary':boundary,'container_id':'c'*64,'status':201 if boundary == 'worker-create' else 204,'owner_checkpoint':active}
        probe.relay = Mock(); probe.relay.hit.wait.return_value = True
        probe.relay.snapshot.return_value = {'records':[], 'execs':{}}
        probe.fault_record = Mock(return_value=record); probe.controller = Mock(return_value='controller')
        probe.finish = Mock(return_value=[{'runID':active['runID'],'status':'failed'}])
        probe.owner = Mock(return_value=None); probe.e = Mock()
        probe.e.inspect.side_effect = lambda cid, **kw: None if cid == record['container_id'] else {'Id':probe.source,'State':{'Running':True,'StartedAt':'source-start'}}
        probe.e.call.side_effect = lambda method, path: {'ID':'daemon'} if path == '/info' else {'ID':'d'*64,'ContainerID':probe.source,'Running':False,'ExitCode':137}
        probe.sql = Mock(return_value='0'); probe.process_count = Mock(return_value=0)
        probe.last = Mock(return_value={'runID':active['runID'],'status':'failed','lastBackupSuccessAt':''})
        probe.no_complete_snapshot = Mock(return_value=True)
        return probe, active

    def test_worker_launch_loss_rejects_live_export_without_persisted_exec_id(self):
        for boundary in ('worker-create','worker-start'):
            for activity in ('process','session'):
                with self.subTest(boundary=boundary,activity=activity):
                    probe, active = self.worker_launch_probe(boundary)
                    if activity == 'process': probe.process_count.return_value = 1
                    else: probe.sql.return_value = '1'
                    with self.assertRaisesRegex(ValueError, 'source.*activity'):
                        probe.exercise_response_loss()
                    probe.process_count.assert_called_once_with(probe.source,active['runID'],'pg_dump')

    def test_worker_launch_loss_requires_every_recorded_source_exec_terminal(self):
        from unittest.mock import Mock
        for boundary in ('worker-create','worker-start'):
            with self.subTest(boundary=boundary):
                probe, active = self.worker_launch_probe(boundary)
                records = [{'boundary':'dump-create','container_id':probe.source,'exec_id':eid,
                            'owner_checkpoint':active,'forwarded':True,'status':201} for eid in ('d'*64,'e'*64)]
                probe.relay.snapshot.return_value = {'records':records}
                def status(method, path):
                    if path == '/info': return {'ID':'daemon'}
                    eid = path.split('/')[2]
                    return {'ID':eid,'ContainerID':probe.source,'Running':eid == 'e'*64,'ExitCode':0}
                probe.e.call.side_effect = status
                with self.assertRaisesRegex(ValueError, 'source exec terminal'):
                    probe.exercise_response_loss()
                probe.e.call.side_effect = lambda method, path: {'ID':'daemon'} if path == '/info' else {'ID':path.split('/')[2],'ContainerID':probe.source,'Running':False,'ExitCode':137}
                probe.exercise_response_loss()
                self.assertEqual(probe.result['proof']['terminal']['execs'], {'d'*64:137,'e'*64:137})
                # An explicit empty set is valid only when no actual exec was recorded.
                probe.relay.snapshot.return_value = {'records':[]}
                probe.exercise_response_loss()
                self.assertEqual(probe.result['proof']['terminal']['execs'], {})
                probe.e.inspect.side_effect = lambda cid, **kw: None if cid == 'c'*64 else {'Id':probe.source,'State':{'Running':True,'StartedAt':'replacement'}}
                with self.assertRaisesRegex(ValueError, 'source identity'):
                    probe.exercise_response_loss()

    def test_worker_launch_loss_rejects_complete_snapshot_or_success_refresh(self):
        for boundary in ('worker-create','worker-start'):
            for violation in ('snapshot','success','wrong-run'):
                with self.subTest(boundary=boundary,violation=violation):
                    probe, active = self.worker_launch_probe(boundary)
                    if violation == 'snapshot': probe.no_complete_snapshot.return_value = False
                    elif violation == 'success': probe.last.return_value['lastBackupSuccessAt'] = 'new-success'
                    else: probe.finish.return_value[0]['runID'] = 'f'*32
                    with self.assertRaises(ValueError): probe.exercise_response_loss()
            probe, active = self.worker_launch_probe(boundary)
            probe.exercise_response_loss()
            self.assertTrue(probe.result['proof'].get('no_complete_snapshot'))
            self.assertTrue(probe.result['proof'].get('last_success_unchanged'))
            probe.no_complete_snapshot.assert_called_once_with(active)

    def test_stream_drop_unavailable_status_is_retained_then_fresh_cli_recovers(self):
        m = self.module()
        self.assertIn('exercise_stream_drop',m.FaultProbe.__dict__,'stream drop must exercise quarantine plus fresh CLI recovery')
        from unittest.mock import Mock
        probe = m.FaultProbe.__new__(m.FaultProbe); probe.case = 'docker-stream-drop-status-unavailable-recovery'; probe.result = {'proof':{}}; probe.source = 'a'*64
        active = {'runID':'b'*32,'execID':'c'*64}
        probe.relay = Mock(); probe.relay.hit.wait.return_value = True
        probe.controller = Mock(return_value='controller'); probe.finish = Mock(); probe.fresh_recovery = Mock(); probe.finish_failure = Mock()
        probe.fault_record = Mock(return_value={'boundary':'dump-start','fault':'stream-drop','forwarded':True,'status':101,'stdout_bytes':65536,'owner_checkpoint':active})
        probe.assert_quarantine = Mock(return_value=active)
        probe.exercise_stream_drop()
        probe.relay.arm.assert_called_once_with('dump-start','stream-drop',after_stdout=65536,deny_status=True)
        self.assertEqual(probe.fresh_recovery.call_args_list[0].kwargs,{'blocked':True})
        self.assertEqual(probe.fresh_recovery.call_args_list[1].kwargs,{'blocked':False})
        probe.relay.recover_transport.assert_called_once()
        probe.finish_failure.assert_called_once_with('controller',active)

    def test_overlap_uses_same_installation_mutex_not_direct_restic_maintenance(self):
        m = self.module()
        self.assertIn('exercise_overlap',m.FaultProbe.__dict__,'need public backup vs restore/retention overlap')
        from unittest.mock import Mock
        with tempfile.TemporaryDirectory() as directory:
            probe = m.FaultProbe.__new__(m.FaultProbe); probe.root = Path(directory); probe.source = 'a'*64; probe.result = {}
            probe.success_snapshot = Mock(return_value='b'*64); probe.startpg = Mock(return_value='c'*64)
            probe.lock = Mock(); probe.unlock = Mock(); probe.controller = Mock(return_value='controller')
            active = {'runID':'d'*32,'workerContainerID':'e'*64}
            probe.blocked = Mock(return_value=active); probe.owner = Mock(side_effect=[active,None])
            probe.relay = Mock(); probe.relay.snapshot.return_value = {'workers':['e'*64]}
            probe.call_cli = Mock(return_value=None); probe.sql = Mock(return_value='0')
            probe.config = lambda filename='config.yaml', **kw: (probe.root/filename).write_text('version: 1\n')
            probe.finish = Mock(return_value=[{'status':'complete'}]); probe.terminal_proof = Mock(return_value={'exec_exit_code':0,'sessions':0,'processes':0})
            probe.exercise_overlap()
            calls = probe.call_cli.call_args_list
            self.assertEqual(calls[0].args[0],'restore'); self.assertEqual(calls[0].kwargs,{'expect':1})
            self.assertEqual(calls[1].args,('run',)); self.assertEqual(calls[1].kwargs,{'filename':'retention.yaml','expect':1})
            self.assertIn('retention:\n  daily: 1\n',(probe.root/'retention.yaml').read_text())
            self.assertTrue(probe.result['proof']['same_owner'])

    def test_restart_deadline_is_taken_from_original_durable_created_at(self):
        m = self.module()
        self.assertIn('exercise_restart',m.FaultProbe.__dict__,'scheduler restart needs real durable deadline and last-success gate')
        self.assertTrue(hasattr(m,'deadline_epoch'))
        job = {'createdAt':'2026-01-01T00:00:00Z','config':{'Timeout':18000000000}}
        import datetime
        expected = datetime.datetime(2026,1,1,tzinfo=datetime.timezone.utc).timestamp()+18
        self.assertEqual(m.deadline_epoch(job),expected)

    @contextlib.contextmanager
    def restart_clock_probe(self, failure):
        # Deterministic offline clock, not a hosted scheduler timing result.
        from unittest.mock import Mock
        import datetime
        m = self.module()
        with tempfile.TemporaryDirectory() as directory:
            probe = m.FaultProbe.__new__(m.FaultProbe); probe.root = Path(directory)
            (probe.root/'state/workflow').mkdir(parents=True)
            probe.source = 'b'*64; probe.result = {}; probe.baseline_success = 'baseline'
            active = {'runID':'a'*32,'workerContainerID':'c'*64,'execID':'d'*64}
            clock = [1000.0]; timeout = [18]; restarts = []
            def terminal_at():
                if failure == 'early': return 1010
                if failure == 'renewed' and restarts: return restarts[-1]+timeout[0]
                return 1000+timeout[0]
            def config(**kw): timeout[0] = int(kw['timeout'].removesuffix('s'))
            def controller(command):
                if command == 'run':
                    created = datetime.datetime.fromtimestamp(1000,datetime.timezone.utc).isoformat()
                    (probe.root/'state/workflow/job.json').write_text(json.dumps({'createdAt':created,'config':{'Timeout':timeout[0]*1000000000}}))
                else: restarts.append(clock[0])
                return 'controller-'+str(len(restarts))
            def wait(fn, seconds=90, label='condition'):
                end = clock[0]+seconds
                while clock[0] < end:
                    value = fn()
                    if value: return value
                    clock[0] += .05
                raise TimeoutError(label)
            probe.success_snapshot = Mock(); probe.config = config; probe.controller = controller
            probe.lock = Mock(); probe.unlock = Mock(); probe.blocked = Mock(return_value=active)
            probe.owner = lambda: active if clock[0] < terminal_at() else None
            probe.last = lambda: {'runID':active['runID'],'status':'failed','lastBackupSuccessAt':'baseline'} if clock[0] >= terminal_at() else {'runID':'previous','status':'success','lastBackupSuccessAt':'baseline'}
            probe.e = Mock()
            probe.e.inspect.side_effect = lambda cid, **kw: None if kw.get('missing') and clock[0] >= terminal_at() else {'State':{'Running':clock[0] < terminal_at()}}
            probe.e.call.side_effect = lambda *a, **kw: {'Running':clock[0] < terminal_at(),'ContainerID':probe.source}
            probe.sql = Mock(return_value='1'); probe.finish = Mock(); probe.wait = wait; probe.stop = Mock()
            probe.terminal_proof = Mock(return_value={}); probe.no_complete_snapshot = Mock(return_value=True)
            with patch.object(m.time,'time',side_effect=lambda:clock[0]), patch.object(m.time,'sleep',side_effect=lambda n:clock.__setitem__(0,clock[0]+n)):
                yield probe, clock, timeout, restarts

    def test_restart_rejects_materially_early_terminal_failure(self):
        with self.restart_clock_probe('early') as (probe, *_):
            with self.assertRaisesRegex(ValueError, 'original deadline|still live'):
                probe.exercise_restart()

    def test_restart_rejects_renewed_timeout_after_second_restart(self):
        with self.restart_clock_probe('renewed') as (probe, *_):
            with self.assertRaises((ValueError,TimeoutError)):
                probe.exercise_restart()

    def test_restart_original_timeout_stays_live_near_deadline_and_finishes_bounded(self):
        with self.restart_clock_probe('original') as (probe, clock, timeout, restarts):
            probe.exercise_restart()
            proof = probe.result['proof']
            self.assertEqual(timeout[0],90)
            self.assertEqual(restarts,[1060,1075])
            self.assertGreaterEqual(proof['alive_until_epoch'],1088)
            self.assertGreaterEqual(proof['observed_terminal_epoch'],1088)
            self.assertLessEqual(proof['observed_terminal_epoch'],1100)

    def test_runner_socket_host_bind_propagates_to_ordinary_worker_source(self):
        m = self.module()
        self.assertTrue(hasattr(m, 'socket_binding_proof'), 'must prove inspected relay bind propagated, not assume worker uses controller socket')
        mounts = [{'Type':'bind','Source':'/owned/relay.sock','Destination':'/run/bakabel/docker.sock','RW':False}]
        proof = m.socket_binding_proof(mounts, '/owned/relay.sock')
        self.assertTrue(proof['read_only']); self.assertEqual(proof['source'], '/owned/relay.sock')
        with self.assertRaises(ValueError): m.socket_binding_proof(mounts, '/var/run/docker.sock')
        with self.assertRaises(ValueError): m.socket_binding_proof([{**mounts[0], 'RW':True}], '/owned/relay.sock')


class VerifierTests(unittest.TestCase):
    def module(self):
        try: m = importlib.import_module('verify_hosted_faults')
        except ModuleNotFoundError: m = None
        self.assertIsNotNone(m, 'fault receipts need independent fail-closed acceptance validation')
        return m

    def test_no_partial_or_blocked_suite_is_a_fault_acceptance_pass(self):
        m = self.module()
        self.assertGreaterEqual(len(m.CASES), 10)
        report = {'schema':1,'source_sha256':'a'*64,'image_id':'sha256:'+'b'*64,'daemon':'daemon','cases':[],'fault_acceptance_pass':True,'full_plan_acceptance_pass':False}
        with self.assertRaises(ValueError): m.verify_report(report, [])
        with self.assertRaises(ValueError): m.verify_report({**report,'fault_acceptance_pass':False}, [])

    def test_streaming_receipt_requires_real_stdout_kernel_limits_and_exact_terminal_proof(self):
        m = self.module()
        row = {'case':'streaming-worker-SIGKILL','status':'pass','exercised':True,'ordinary_image':True,'request_mutations':[],
               'backend':'local','platform':'compose','source_unchanged':True,'daemon':'daemon','image_id':'sha256:'+'b'*64,'source_sha256':'a'*64,
               'workers':{'b'*64:{'container_id':'b'*64,'image_id':'sha256:'+'b'*64,'memory_bytes':536870912,'nanocpus':2000000000,'cpu.max':'200000 100000','memory.max':'536870912','socket':{'source':'/owned/relay.sock','destination':'/run/bakabel/docker.sock','read_only':True}}},
               'cleanup':{'containers_absent':{'b'*64:True},'volumes_absent':{'owned-volume':True},'private_paths_absent':True},
               'injection':{'stdout_bytes_before_fault':65536},
               'proof':{'outcome':'failed','owner_released':True,'worker_absent':True,'last_success_unchanged':True,'no_complete_snapshot':True,'terminal':{'daemon':'daemon','container_id':'c'*64,'started_at':'start','exec_id':'d'*64,'exec_exit_code':137,'sessions':0,'processes':0}}}
        m.verify_case(row)
        edits = [('injection','stdout_bytes_before_fault',0),('proof','owner_released',False),('proof','no_complete_snapshot',False)]
        for section,key,value in edits:
            broken = json.loads(json.dumps(row)); broken[section][key] = value
            with self.subTest(key=key),self.assertRaises(ValueError): m.verify_case(broken)
        broken = json.loads(json.dumps(row)); broken['proof']['terminal']['exec_exit_code'] = None
        with self.assertRaises(ValueError): m.verify_case(broken)
        broken = json.loads(json.dumps(row)); del broken['workers']['b'*64]['cpu.max']
        with self.assertRaises(ValueError): m.verify_case(broken)

    def worker_loss_receipt(self, case='worker-create-response-loss'):
        return {'case':case,'status':'pass','exercised':True,'ordinary_image':True,'request_mutations':[],
                'backend':'local','platform':'compose','source_unchanged':True,'daemon':'daemon','image_id':'sha256:'+'b'*64,'source_sha256':'a'*64,
                'source':{'container_id':'c'*64,'started_at':'source-start'},
                'workers':{'b'*64:{'container_id':'b'*64,'image_id':'sha256:'+'b'*64,'memory_bytes':536870912,'nanocpus':2000000000,'socket':{'source':'/owned/relay.sock','destination':'/run/bakabel/docker.sock','read_only':True}}},
                'cleanup':{'containers_absent':{'b'*64:True},'volumes_absent':{'owned-volume':True},'private_paths_absent':True},
                'injection':{'owner_checkpoint':{'runID':'e'*32}},'relay':{'records':[]},
                'proof':{'outcome':'failed','owner_released':True,'worker_absent':True,'fault_forwarded':True,'actual_response_status':201 if case == 'worker-create-response-loss' else 204,
                         'last_success_unchanged':True,'no_complete_snapshot':True,
                         'terminal':{'daemon':'daemon','container_id':'c'*64,'started_at':'source-start','run_id':'e'*32,'execs':{},'sessions':0,'processes':0}}}

    def test_worker_loss_verifier_requires_source_terminal_snapshot_and_success_proofs(self):
        m = self.module()
        for case in ('worker-create-response-loss','worker-start-response-loss'):
            row = self.worker_loss_receipt(case); m.verify_case(row)
            for key in ('terminal','no_complete_snapshot','last_success_unchanged'):
                broken = json.loads(json.dumps(row)); del broken['proof'][key]
                with self.subTest(case=case,key=key), self.assertRaises(ValueError): m.verify_case(broken)
            for key,value in (('processes',1),('sessions',1),('processes',False),('sessions',False),('started_at','replacement'),('execs',None)):
                broken = json.loads(json.dumps(row)); broken['proof']['terminal'][key] = value
                with self.subTest(case=case,key=key), self.assertRaises(ValueError): m.verify_case(broken)
            row['relay']['records'] = [{'boundary':'dump-create','container_id':'c'*64,'exec_id':'d'*64,'forwarded':True,'owner_checkpoint':{'runID':'e'*32}}]
            with self.assertRaises(ValueError): m.verify_case(row)
            row['proof']['terminal']['execs'] = {'d'*64:137}; m.verify_case(row)
            row['proof']['terminal']['execs']['d'*64] = None
            with self.assertRaises(ValueError): m.verify_case(row)

    def test_scheduler_verifier_rejects_early_renewed_or_unmeasured_deadline(self):
        m = self.module()
        row = self.worker_loss_receipt('scheduler-restart-original-deadline')
        row['proof']['terminal'] = {'daemon':'daemon','container_id':'c'*64,'started_at':'source-start','exec_id':'d'*64,'exec_exit_code':137,'sessions':0,'processes':0}
        row['proof'].update(same_job_bytes=True,same_worker=True,scheduler_restarts=2,original_timeout_seconds=90,
                            deadline_epoch=1090,scheduler_restart_epochs=[1060,1075],alive_until_epoch=1088,
                            observed_terminal_epoch=1091,seconds_after_original_deadline=1)
        m.verify_case(row)
        for observed in (1010,1087,1101,1110,float('nan')):
            broken = json.loads(json.dumps(row))
            broken['proof'].update(observed_terminal_epoch=observed,seconds_after_original_deadline=observed-1090)
            with self.subTest(observed=observed), self.assertRaises(ValueError): m.verify_case(broken)
        for key in ('alive_until_epoch','scheduler_restart_epochs','deadline_epoch','observed_terminal_epoch','original_timeout_seconds'):
            broken = json.loads(json.dumps(row)); del broken['proof'][key]
            with self.subTest(missing=key), self.assertRaises(ValueError): m.verify_case(broken)
        for key,value in (('scheduler_restart_epochs',[1001,1003]),('alive_until_epoch',1070),
                          ('seconds_after_original_deadline',-100),('original_timeout_seconds',18)):
            broken = json.loads(json.dumps(row)); broken['proof'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): m.verify_case(broken)

    def test_expected_unknown_quarantine_is_not_reported_as_recovered_or_failed_cleanup(self):
        m = self.module()
        record = {'case':'dump-create-response-loss','status':'pass','exercised':True,'ordinary_image':True,'request_mutations':[],
                  'backend':'local','platform':'compose','source_unchanged':True,'daemon':'daemon','image_id':'sha256:'+'b'*64,'source_sha256':'a'*64,
                  'workers':{'b'*64:{'container_id':'b'*64,'image_id':'sha256:'+'b'*64,'memory_bytes':536870912,'nanocpus':2000000000,'socket':{'source':'/owned/relay.sock','destination':'/run/bakabel/docker.sock','read_only':True}}},
                  'cleanup':{'containers_absent':{'b'*64:True},'volumes_absent':{'owned-volume':True},'private_paths_absent':True},
                  'proof':{'outcome':'quarantined','owner_retained':True,'fresh_cli_blocked':True,'exec_never_started':True,'fault_forwarded':True,'actual_response_status':201,'persisted_exec_id':False}}
        m.verify_case(record)
        for key in ('owner_retained','fresh_cli_blocked','fault_forwarded','exec_never_started'):
            broken = json.loads(json.dumps(record)); broken['proof'][key] = False
            with self.subTest(key=key), self.assertRaises(ValueError): m.verify_case(broken)
        broken = json.loads(json.dumps(record)); broken['status'] = 'blocked'
        with self.assertRaises(ValueError): m.verify_case(broken)
        broken = json.loads(json.dumps(record)); broken['proof']['outcome'] = 'recovered'
        with self.assertRaises(ValueError): m.verify_case(broken)


class CompletionTests(unittest.TestCase):
    def test_partial_constructor_failure_is_blocked_and_receipt_never_contains_error_message(self):
        m = importlib.import_module('run_hosted_faults')
        self.assertTrue(hasattr(m,'run_case'),'need guarded construction, exact cleanup and structured failed evidence')
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as directory:
            args = SimpleNamespace(runtime=Path(directory)/'case',expected_source_sha256='a'*64,expected_image_id='sha256:'+'b'*64)
            class Broken:
                def __init__(self,args,case):
                    private = args.runtime/'private'; private.mkdir(parents=True)
                    (private/'password').write_text('do-not-export-constructor-secret')
                    raise ValueError('do-not-export-constructor-secret')
            row = m.run_case(args,'producer-failure-after-output',probe_class=Broken)
            self.assertEqual(row['status'],'blocked')
            text = (args.runtime/'receipt.json').read_text()
            self.assertNotIn('do-not-export-constructor-secret',text)
            self.assertFalse((args.runtime/'private').exists())

    def test_hosted_diagnostic_selection_is_explicitly_not_full_suite_acceptance(self):
        m = importlib.import_module('run_hosted_faults')
        from types import SimpleNamespace
        self.assertTrue(hasattr(m,'select_cases'),'CLI must wire executable cases without claiming omitted gates')
        self.assertEqual(m.select_cases(None),list(m.CASES))
        self.assertEqual(m.select_cases(['producer-failure-after-output']),['producer-failure-after-output'])
        with self.assertRaises(ValueError): m.select_cases(['producer-failure-after-output']*2)
        info = {'ID':'daemon','OSType':'linux','CgroupVersion':'2','SecurityOptions':['name=seccomp'],'Swarm':{'LocalNodeState':'inactive'},'Containers':0}
        class Engine:
            def __init__(self,socket): pass
            def call(self,method,path):
                if path == '/info': return info
                if path.startswith('/containers/'): return []
                return {'Id':'sha256:'+'b'*64}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); runtime = root/'faults'
            env = {'GITHUB_ACTIONS':'true','RUNNER_ENVIRONMENT':'github-hosted','RUNNER_TEMP':directory}
            def blocked(args,case):
                args.runtime.mkdir(); (args.runtime/'receipt.json').write_text(json.dumps({'case':case,'status':'blocked'}))
                return {'case':case,'status':'blocked'}
            with patch.dict(m.os.environ,env,clear=True),patch.object(m.os,'geteuid',return_value=0),patch.object(m.os,'sched_setaffinity'),patch.object(m,'Engine',Engine),patch.object(m,'fingerprint',return_value=m.FROZEN_SOURCE),patch.object(m,'run_case',blocked),contextlib.redirect_stdout(io.StringIO()):
                code = m.main(['--socket','/unit-only.sock','--runtime',str(runtime),'--source',directory,'--image','candidate','--expected-image-id','sha256:'+'b'*64,'--expected-source-sha256',m.FROZEN_SOURCE,'--exclusive-hosted-daemon','--case','producer-failure-after-output'])
            self.assertEqual(code,2)
            report = json.loads((runtime/'hosted-faults.json').read_text())
            self.assertFalse(report['fault_acceptance_pass']); self.assertFalse(report['full_plan_acceptance_pass'])
            self.assertEqual(report['cases'],[{'case':'producer-failure-after-output','status':'blocked'}])

    def test_receipt_save_failure_falls_back_to_structured_failure_without_message(self):
        m = importlib.import_module('run_hosted_faults')
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as directory:
            args = SimpleNamespace(runtime=Path(directory)/'case',expected_source_sha256='a'*64,expected_image_id='sha256:'+'b'*64)
            class BadEvidence:
                def __init__(self,args,case): args.runtime.mkdir(); self.result = {'case':case,'status':'blocked'}
                def run(self): raise ValueError('unit runtime failure')
                def cleanup(self): pass
                def save(self): raise ValueError('do-not-export-save-secret')
            try: row = m.run_case(args,'producer-failure-after-output',probe_class=BadEvidence)
            except Exception as exc: self.fail('structured failure reporting escaped: '+type(exc).__name__)
            self.assertEqual(row['status'],'failed')
            text = (args.runtime/'receipt.json').read_text()
            self.assertNotIn('do-not-export-save-secret',text); self.assertIn('evidence_failure',text)

    def test_cleanup_prevalidates_all_owned_ids_before_any_delete(self):
        m = importlib.import_module('run_hosted_faults')
        self.assertIn('cleanup',m.FaultProbe.__dict__,'must not inherit force-delete-all-known cleanup without exact identity revalidation')
        from unittest.mock import Mock
        probe = m.FaultProbe.__new__(m.FaultProbe); probe.daemon = 'daemon'; probe.prefix = 'owned'; probe.containers = {'a'*64:'owned-first','b'*64:'owned-second'}
        probe.worker_owners = {}; probe.volumes = []; probe.owner = lambda: None
        probe.e = Mock(); probe.e.call.return_value = {'ID':'daemon'}
        probe.e.inspect.side_effect = lambda cid, **kw: {'Id':cid,'Name':'/'+probe.containers[cid],'Config':{'Labels':{'probe.bakabel.owner':'owned' if cid=='a'*64 else 'foreign'}}}
        with self.assertRaises(ValueError): probe.cleanup()
        self.assertFalse(any(call.args[0] == 'DELETE' for call in probe.e.call.call_args_list))
    @contextlib.contextmanager
    def cleanup_probe(self):
        m = importlib.import_module('run_hosted_faults')
        from unittest.mock import Mock
        with tempfile.TemporaryDirectory() as directory:
            probe = m.FaultProbe.__new__(m.FaultProbe); probe.root = Path(directory)
            for name in ('private','backend','fresh-state','state'):
                (probe.root/name).mkdir(); (probe.root/name/'keep').write_text('owned-private-data')
            probe.daemon = 'daemon'; probe.prefix = 'owned'; probe.image = 'sha256:'+'e'*64
            probe.containers = {'a'*64:'owned-fixture'}; probe.volumes = ['owned-volume']
            owner = {'runID':'c'*32,'workerContainerID':'b'*64,'workerName':'bakabel-worker-'+'c'*32,'daemonID':'daemon'}
            probe.worker_owners = {'b'*64:owner}; probe.roles = {}; probe.result = {}; probe.owner = lambda: None
            objects = {'a'*64:{'Id':'a'*64,'Name':'/owned-fixture','Config':{'Labels':{'probe.bakabel.owner':'owned'}}},
                       'b'*64:{'Id':'b'*64,'Name':'/'+owner['workerName'],'Image':probe.image,
                                'Config':{'Labels':{'bakabel.worker':'1','bakabel.run':owner['runID'],'bakabel.daemon':'daemon'}}}}
            volume = {'Name':'owned-volume','Labels':{'probe.bakabel.owner':'owned'},'Driver':'local','Options':None}
            remaining = set(); deleted = set(); volume_deleted = []
            def call(method, path, **kw):
                if path == '/info': return {'ID':'daemon'}
                if method == 'DELETE' and path.startswith('/containers/'):
                    deleted.add(path.split('/')[2].split('?')[0]); return None
                if method == 'DELETE': volume_deleted.append(path); return None
                if path.startswith('/volumes/'): return None if volume_deleted else volume
                raise AssertionError('unexpected offline cleanup operation')
            probe.e = Mock(); probe.e.call.side_effect = call
            probe.e.inspect.side_effect = lambda cid, **kw: objects[cid] if cid not in deleted or cid in remaining else None
            probe.relay = Mock(); probe.relay.snapshot.return_value = {'errors':[]}
            yield probe, volume, remaining

    def test_cleanup_keeps_all_private_paths_when_exact_worker_or_volume_remains(self):
        m = importlib.import_module('run_hosted_faults')
        for retained in ('worker','volume'):
            with self.subTest(retained=retained), self.cleanup_probe() as (probe,volume,remaining):
                if retained == 'worker': remaining.add('b'*64)
                else:
                    original_call = probe.e.call.side_effect
                    probe.e.call.side_effect = lambda method, path, **kw: volume if method == 'GET' and path.startswith('/volumes/') else original_call(method,path,**kw)
                with patch.object(m.shutil,'rmtree',wraps=m.shutil.rmtree) as remove:
                    with self.assertRaisesRegex(ValueError,'absence not observed'): probe.cleanup()
                    remove.assert_not_called()
                for name in ('private','backend','fresh-state','state'):
                    self.assertEqual((probe.root/name/'keep').read_text(),'owned-private-data')

    def test_cleanup_deletes_private_paths_only_after_all_exact_absence_readbacks(self):
        for quarantine in (False,True):
            with self.subTest(quarantine=quarantine), self.cleanup_probe() as (probe,_,__):
                if quarantine: probe.owner = lambda: {'runID':'c'*32,'status':'blocked','phase':'quarantine'}
                probe.cleanup()
                self.assertTrue(all(probe.result['cleanup']['containers_absent'].values()))
                self.assertTrue(all(probe.result['cleanup']['volumes_absent'].values()))
                for name in ('private','backend','fresh-state'):
                    self.assertFalse((probe.root/name).exists())
                self.assertEqual((probe.root/'state').exists(),quarantine)
                self.assertEqual(probe.result['cleanup']['quarantine_state_retained'],quarantine)

    def test_cleanup_replaced_or_nondefault_volume_refuses_every_delete(self):
        m = importlib.import_module('run_hosted_faults')
        for key,value in (('Labels',{'probe.bakabel.owner':'foreign'}),('Labels',None),('Driver','nfs'),('Options',{'device':'/foreign'})):
            with self.subTest(key=key,value=value), self.cleanup_probe() as (probe,volume,_):
                volume[key] = value
                with patch.object(m.shutil,'rmtree',wraps=m.shutil.rmtree) as remove:
                    with self.assertRaisesRegex(ValueError,'volume identity'): probe.cleanup()
                    remove.assert_not_called()
                self.assertFalse(any(call.args[0] == 'DELETE' for call in probe.e.call.call_args_list))


if __name__ == '__main__':
    unittest.main()
