"""Local synthetic Unix peers only; not Docker or hosted runtime evidence."""
import contextlib
import json
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import run_resource_probe as resource
from run_resource_probe import Engine


@contextlib.contextmanager
def peer(scripts):
    """Finite, stoppable peers; every server thread is joined on exit."""
    with tempfile.TemporaryDirectory() as directory:
        path = str(Path(directory)/'engine.sock')
        stopped = threading.Event()
        requests = []
        errors = []
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
            server.bind(path); server.listen(); server.settimeout(.1)
            def serve():
                try:
                    for script in scripts:
                        while not stopped.is_set():
                            try:
                                conn, _ = server.accept()
                                break
                            except socket.timeout:
                                continue
                        else:
                            return
                        with conn:
                            conn.settimeout(2)
                            request = b''
                            while b'\r\n\r\n' not in request:
                                data = conn.recv(4096)
                                if not data: return
                                request += data
                            requests.append(request.split(b'\r\n', 1)[0])
                            script(conn, stopped)
                except (BrokenPipeError, ConnectionResetError):
                    pass  # Expected when a deadline closes a live response.
                except Exception as exc:
                    errors.append(exc)
            thread = threading.Thread(target=serve)
            thread.start()
            try:
                yield Engine(path), requests
            finally:
                stopped.set(); thread.join(3)
                if thread.is_alive(): raise AssertionError('synthetic peer did not stop')
                if errors: raise AssertionError(errors)


def reply(body, delay=0, status=200):
    encoded = json.dumps(body).encode()
    def send(conn, stopped):
        if not stopped.wait(delay):
            conn.sendall(b'HTTP/1.1 '+str(status).encode()+b' Synthetic\r\nContent-Length: '+
                         str(len(encoded)).encode()+b'\r\n\r\n'+encoded)
    return send


def trickle(data, prefix=b''):
    def send(conn, stopped):
        conn.sendall(prefix)
        for byte in data:
            if stopped.wait(.04): return
            conn.sendall(bytes([byte]))
    return send


class EngineDeadlineTests(unittest.TestCase):
    def assert_bounded_timeout(self, action, budget=.2, slack=.2):
        started = time.monotonic()
        with self.assertRaises(TimeoutError):
            action(started+budget)
        elapsed = time.monotonic()-started
        self.assertGreaterEqual(elapsed, budget*.8)
        self.assertLess(elapsed, budget+slack)

    def test_stalled_header_and_body_use_absolute_deadline(self):
        def stall(conn, stopped): stopped.wait(2)
        def body_stall(conn, stopped):
            conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\n{')
            stopped.wait(2)
        for script in (stall, body_stall):
            with self.subTest(script=script.__name__), peer([script]) as (engine, _):
                self.assert_bounded_timeout(lambda deadline: engine.call('GET', '/info', deadline=deadline))

    def test_drip_fed_header_cannot_renew_absolute_deadline(self):
        with peer([trickle(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}')]) as (engine, _):
            self.assert_bounded_timeout(lambda deadline: engine.call('GET', '/info', deadline=deadline))

    def test_drip_fed_body_cannot_renew_absolute_deadline(self):
        for header, body in ((b'Content-Length: 20', b'"'+b'x'*18+b'"'),
                             (b'Transfer-Encoding: chunked', b'2\r\n{}\r\n0\r\n\r\n'),
                             (b'Connection: close', b'"'+b'x'*18+b'"')):
            with self.subTest(header=header), peer([trickle(body, b'HTTP/1.1 200 OK\r\n'+header+b'\r\n\r\n')]) as (engine, _):
                self.assert_bounded_timeout(lambda deadline: engine.call('GET', '/info', deadline=deadline))

    def test_info_and_inspect_share_one_absolute_budget(self):
        with peer([reply({'ID':'daemon'}, delay=.15), reply(None, delay=.45, status=404)]) as (engine, requests):
            def calls(deadline):
                self.assertEqual(engine.call('GET', '/info', deadline=deadline), {'ID':'daemon'})
                engine.inspect('b'*64, missing=True, deadline=deadline)
            self.assert_bounded_timeout(calls, budget=.3, slack=.1)
            self.assertEqual(requests, [b'GET /v1.55/info HTTP/1.1',
                                        b'GET /v1.55/containers/'+b'b'*64+b'/json HTTP/1.1'])

    def test_blocked_request_send_uses_remaining_budget(self):
        def unread_body(conn, stopped): stopped.wait(2)
        with peer([unread_body]) as (engine, _):
            self.assert_bounded_timeout(lambda deadline: engine.call('POST', '/synthetic', 'x'*(4*1024*1024), deadline=deadline))

    def test_unix_connect_backlog_is_deadline_bounded_and_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory)/'full.sock')
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
                server.bind(path); server.listen(0)
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as queued:
                    queued.settimeout(1); queued.connect(path)
                    sockets = []
                    socket_type = resource._DeadlineSocket
                    def capture(deadline):
                        sock = socket_type(deadline); sockets.append(sock); return sock
                    started = time.monotonic()
                    with patch.object(resource, '_DeadlineSocket', side_effect=capture), self.assertRaises(OSError):
                        Engine(path).call('GET', '/info', deadline=started+.2)
                    # Linux may fail a full Unix backlog immediately with EAGAIN.
                    self.assertLess(time.monotonic()-started, .4)
                    self.assertEqual([sock.fileno() for sock in sockets], [-1])

    def test_expired_deadline_fails_before_connect_and_closes_socket(self):
        sockets = []
        socket_type = resource._DeadlineSocket
        def capture(deadline):
            sock = socket_type(deadline); sockets.append(sock); return sock
        with patch.object(resource, '_DeadlineSocket', side_effect=capture):
            with self.assertRaises(TimeoutError):
                Engine('/nonexistent-synthetic.sock').call('GET', '/info', deadline=time.monotonic()-1)
        self.assertEqual([sock.fileno() for sock in sockets], [-1])

    def test_ordinary_connect_failure_closes_socket_and_keeps_45s_default(self):
        sockets = []; timeouts = []
        class RecordingSocket(socket.socket):
            def connect(self, address):
                timeouts.append(self.gettimeout()); return super().connect(address)
        def capture(*args):
            sock = RecordingSocket(*args); sockets.append(sock); return sock
        with tempfile.TemporaryDirectory() as directory, patch.object(resource.socket, 'socket', side_effect=capture):
            with self.assertRaises(FileNotFoundError):
                Engine(Path(directory)/'absent.sock').call('GET', '/info')
        self.assertEqual(timeouts, [45])
        self.assertEqual([sock.fileno() for sock in sockets], [-1])

    def test_healthy_json_raw_missing_and_http_error_semantics_unchanged(self):
        scripts = [reply({'ID':'daemon'}), reply({'raw':True}), reply(None, status=404), reply({}, status=503)]
        for deadline_mode in (False, True):
            with self.subTest(deadline=deadline_mode), peer(scripts) as (engine, _):
                kwargs = {'deadline':time.monotonic()+1} if deadline_mode else {}
                self.assertEqual(engine.call('GET', '/info', **kwargs), {'ID':'daemon'})
                self.assertEqual(engine.call('GET', '/info', raw=True, **kwargs), b'{"raw": true}')
                self.assertIsNone(engine.inspect('b'*64, missing=True, **kwargs))
                with self.assertRaises(RuntimeError) as failure:
                    engine.call('GET', '/info', **kwargs)
                self.assertEqual(failure.exception.http_status, 503)


class FaultGapDeadlineTests(unittest.TestCase):
    def test_missing_cgroup_rereads_share_bounded_failure_and_safe_diagnostics(self):
        from run_hosted_faults import FaultProbe
        from run_hosted_capacity import CapacityEngine
        owner = {'runID':'a'*32, 'workerContainerID':'b'*64,
                 'workerName':'bakabel-worker-'+'a'*32, 'daemonID':'daemon'}
        probe = FaultProbe.__new__(FaultProbe)
        probe.image = 'sha256:'+'c'*64; probe.daemon = 'daemon'; probe.sock = '/owned/relay.sock'
        obj = {'Id':owner['workerContainerID'], 'Name':'/'+owner['workerName'], 'Image':probe.image,
               'Config':{'Labels':{'bakabel.worker':'1', 'bakabel.run':owner['runID'],
                                   'bakabel.daemon':'daemon'}, 'Cmd':['_workflow'],
                         'Entrypoint':['/usr/local/bin/bakabel']},
               'HostConfig':{'Memory':536870912, 'NanoCpus':2000000000},
               'State':{'Running':True, 'Pid':123},
               'Mounts':[{'Type':'bind', 'Source':probe.sock,
                          'Destination':'/run/bakabel/docker.sock', 'RW':False}]}
        probe.pin_container = lambda cid: None
        probe.cgroup = lambda pid: None
        cases = {
            'info-stall': [reply({'ID':'daemon'}, delay=1.35)],
            'inspect-shared-budget': [reply({'ID':'daemon'}, delay=.6), reply(None, delay=.75, status=404)],
            'inspect-body-trickle': [reply({'ID':'daemon'}, delay=.4),
                trickle(b'"'+b'x'*38+b'"', b'HTTP/1.1 200 OK\r\nContent-Length: 40\r\n\r\n')],
        }
        for name, scripts in cases.items():
            probe.worker_records = {}
            with self.subTest(phase=name), peer(scripts) as (engine, requests):
                probe.e = CapacityEngine(engine, probe)
                started = time.monotonic()
                with self.assertRaises((TimeoutError, ValueError)):
                    probe.worker_proof(obj, owner)
                elapsed = time.monotonic()-started
                self.assertLess(elapsed, 1.2, 'gap must stop Engine I/O, not merely reject its late reply')
                self.assertGreaterEqual(elapsed, .9)
                expected = [b'GET /v1.55/info HTTP/1.1']
                if name != 'info-stall':
                    expected.append(b'GET /v1.55/containers/'+b'b'*64+b'/json HTTP/1.1')
                self.assertEqual(requests, expected)
                record = probe.worker_records[obj['Id']]
                self.assertEqual(record['kernel_readback_state'], 'unavailable')
                gap = record['observation_gaps'][-1]
                self.assertEqual(gap['resolution'], 'failed')
                self.assertEqual(gap['rows'][-1]['observation_state'], 'unavailable')
                self.assertEqual(len(gap['rows']), 2)
                self.assertFalse(any(key in record for key in ('cpu.max', 'memory.max', 'memory.peak')))
                self.assertNotIn('engine.sock', json.dumps(record))


if __name__ == '__main__':
    unittest.main()