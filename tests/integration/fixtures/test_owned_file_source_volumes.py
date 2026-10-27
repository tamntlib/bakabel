"""Offline Engine composition, NOT Docker/kernel/native-fault acceptance.

Config bytes fetched read-only from the public pinned linux/amd64 image. The
Engine double implements image-inherited volumes from those actual bytes.
"""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace
from urllib.parse import parse_qs, unquote, urlsplit

from run_hosted_capacity import CapacityEngine
from run_hosted_native_faults import NativeFaultProbe
from run_hosted_faults import run_case
from run_hosted_storage_prereqs import StorageProbe, PG_PIN
from run_resource_probe import PG, Probe
from verify_hosted_native_faults import NATIVE_CASES


CONFIG_BYTES = Path(__file__).with_name('postgres18-image-config.json').read_bytes()
CONFIG_DIGEST = 'sha256:57b23a0326ee442e83b3d3fa027c5a148be0a392d7c91d1ca4e1e70131ee859a'
IMAGE_CONFIG = json.loads(CONFIG_BYTES)['config']


class Gate:
    errors = ()
    count = 0
    retired = False
    def mark(self, *args): pass
    def start(self): pass
    def close(self): self.retired = True


class Relay:
    def snapshot(self): return {'errors': [], 'workers': {}, 'records': []}
    def close(self): pass


class StopBeforeSeed(Exception): pass


class OfflineEngine:
    """Only the external Engine/kernel boundaries are doubled."""
    def __init__(self, root):
        self.root = root
        self.config = copy.deepcopy(IMAGE_CONFIG)
        self.volumes = {}
        self.containers = {}
        self.calls = []
        self.next_id = 1
        self.extra_mount = None
        self.drift_mount = None
        self.stop_seed = False
        self.image_id = CONFIG_DIGEST
        self.pin_id = CONFIG_DIGEST

    def call(self, method, path, body=None, **kwargs):
        self.calls.append((method, path, copy.deepcopy(body)))
        uri = urlsplit(path)
        if method == 'GET' and uri.path == '/info': return {'ID': 'offline-daemon'}
        if method == 'GET' and uri.path.startswith('/images/'):
            ref = unquote(uri.path[len('/images/'):-len('/json')])
            return {'Id': self.pin_id if ref == PG_PIN else self.image_id,
                    'Config': copy.deepcopy(self.config)}
        if method == 'POST' and uri.path == '/volumes/create':
            name = body['Name']
            if name in self.volumes: return copy.deepcopy(self.volumes[name])
            mount = self.root / ('backing-' + str(len(self.volumes)))
            mount.mkdir()
            self.volumes[name] = {'Name': name, 'Labels': copy.deepcopy(body.get('Labels')),
                'Driver': body.get('Driver', 'local'), 'Scope': 'local', 'Options': body.get('DriverOpts'),
                'Mountpoint': str(mount)}
            return copy.deepcopy(self.volumes[name])
        if uri.path.startswith('/volumes/'):
            name = unquote(uri.path[len('/volumes/'):])
            if method == 'GET': return copy.deepcopy(self.volumes.get(name))
            if method == 'DELETE': self.volumes.pop(name, None); return None
        if method == 'POST' and uri.path == '/containers/create':
            cid = f'{self.next_id:064x}'; self.next_id += 1
            mounts = [{'Type': m['Type'], 'Name': m['Source'], 'Destination': m['Target'],
                       'RW': not m.get('ReadOnly', False)} for m in body['HostConfig'].get('Mounts', [])]
            destinations = {m['Destination'] for m in mounts}
            for destination in self.config['Volumes']:
                if destination not in destinations:
                    name = hashlib.sha256((cid + destination).encode()).hexdigest()
                    # Docker does NOT inherit the container's labels here.
                    self.volumes[name] = {'Name': name, 'Labels': None, 'Driver': 'local', 'Options': None}
                    mounts.append({'Type': 'volume', 'Name': name, 'Destination': destination, 'RW': True})
            if self.extra_mount: mounts.append(copy.deepcopy(self.extra_mount))
            if self.drift_mount: self.drift_mount(mounts)
            self.containers[cid] = {'Id': cid, 'Name': '/' + parse_qs(uri.query)['name'][0],
                'Image': self.image_id, 'Config': {'Labels': copy.deepcopy(body['Labels'])},
                'State': {'Running': False, 'StartedAt': 'offline-start', 'Pid': 0},
                'RestartCount': 0, 'Mounts': mounts}
            return {'Id': cid}
        if uri.path.startswith('/containers/'):
            cid, _, op = uri.path[len('/containers/'):].partition('/')
            if method == 'POST' and op == 'start':
                self.containers[cid]['State']['Running'] = True; return None
            if method == 'DELETE': self.containers.pop(cid, None); return None
        raise AssertionError(('unexpected offline call', method, path))

    def inspect(self, cid, **kwargs):
        self.calls.append(('GET', '/containers/' + cid + '/json', None))
        return copy.deepcopy(self.containers.get(cid))

    def exec(self, cid, argv, **kwargs):
        if argv[0] == 'pg_isready': return {'exit': 0}
        if self.stop_seed: raise StopBeforeSeed()
        raise AssertionError('unexpected exec')


def probe_at(root, cls=NativeFaultProbe, case=NATIVE_CASES[0]):
    for name in ('private', 'backend', 'state', 'fresh-state'): (root / name).mkdir()
    p = cls.__new__(cls)
    p.root = root; p.prefix = 'bakabel-fault-0123456789ab'; p.daemon = 'offline-daemon'; p.image = 'offline-image'
    p.case = case; p.containers = {}; p.volumes = []; p.roles = {}; p.worker_owners = {}; p.worker_records = {}
    p.unresolved_creates = set(); p.result = {'cleanup': {}}; p.repository = '/repository'
    raw = OfflineEngine(root)
    p.e = CapacityEngine(raw, p); p.gate = Gate(); p.relay = Relay()
    p.pin_container = lambda cid: None
    p.config = lambda *args, **kwargs: None
    p.restic = lambda *args, **kwargs: None
    p.owner = lambda: None
    p.call_cli = lambda *args, **kwargs: {'targets': [{'ID': 'offline/files', 'Kind': 'volume',
        'Source': {'DaemonID': p.daemon, 'ContainerID': p.source, 'StartedAt': 'offline-start'}}]}
    if cls is StorageProbe:
        p.traces = []; p.output_mount = None; p.temp_fd = None
        # Keep actual startpg/create; only SQL and Engine readiness are doubled.
        raw.stop_seed = True
        p.sql = lambda *args: '1'
    return p, raw


class OwnedFileSourceVolumeTests(unittest.TestCase):
    def test_strict_image_volume_requires_explicit_options_in_post_and_get(self):
        for seam in ('post-only', 'get-only', 'all-responses'):
            for options in ('missing', [], False, 0, ''):
                with self.subTest(seam=seam, options=options), tempfile.TemporaryDirectory() as directory:
                    p, raw = probe_at(Path(directory)); original = raw.call
                    name = p.prefix+'-files-image-data'
                    def changed(method, path, *args, **kwargs):
                        obj: dict | None = original(method, path, *args, **kwargs)
                        selected = ((method == 'POST' and path == '/volumes/create' and seam != 'get-only') or
                                    (method == 'GET' and path == '/volumes/'+name and seam != 'post-only'))
                        if selected and isinstance(obj, dict) and obj.get('Name') == name:
                            if options == 'missing': obj.pop('Options', None)
                            else: obj['Options'] = copy.deepcopy(options)
                        return obj
                    raw.call = changed
                    with self.assertRaisesRegex(ValueError, 'owned file fixture image volume'): p.prepare_native()
                    self.assertTrue(p.unresolved_creates)
                    self.assertFalse(raw.containers)
                    self.assertFalse(any(m == 'POST' and path.endswith('/start') for m, path, _ in raw.calls))
                    with self.assertRaisesRegex(ValueError, 'unresolved fixture create'): p.cleanup()
                    self.assertFalse(any(m == 'DELETE' for m, _, _ in raw.calls))
                    for path in ('private', 'backend', 'state', 'fresh-state'):
                        self.assertTrue((p.root/path).exists())

    def test_strict_cleanup_rechecks_options_after_valid_admission_before_any_delete(self):
        for options in ('missing', [], False, 0, '', {'device': 'PRIVATE-OPTIONS-CANARY'}):
            with self.subTest(options=options), tempfile.TemporaryDirectory() as directory:
                p, raw = probe_at(Path(directory)); p.prepare_native()
                name = p.prefix+'-files-image-data'
                self.assertFalse(p.unresolved_creates)
                self.assertTrue(raw.containers[p.source]['State']['Running'])
                if options == 'missing': raw.volumes[name].pop('Options')
                else: raw.volumes[name]['Options'] = copy.deepcopy(options)
                raw.volumes[name]['Mountpoint'] = '/PRIVATE-MOUNTPOINT-CANARY'
                raw.volumes[name]['Env'] = ['PRIVATE-ENV-CANARY']
                with self.assertRaisesRegex(ValueError, 'cleanup volume identity mismatch'): p.cleanup()
                check = p.result['cleanup']['volume_identity_mismatch']
                self.assertEqual(check, {'volume': name, 'observation': 'observed', 'name_matches': True,
                    'owner_matches': True, 'driver_local': True,
                    'options_empty': None if options == 'missing' else False, 'before_delete': True})
                self.assertTrue(all(v is None or type(v) is bool for k, v in check.items()
                    if k in ('name_matches', 'owner_matches', 'driver_local', 'options_empty', 'before_delete')))
                self.assertLess(len(json.dumps(check)), 400)
                self.assertNotIn('PRIVATE-', json.dumps(check))
                self.assertFalse(any(m == 'DELETE' for m, _, _ in raw.calls))
                for path in ('private', 'backend', 'state', 'fresh-state'):
                    self.assertTrue((p.root/path).exists())

    def test_strict_explicit_null_and_empty_dict_admit_start_and_cleanup(self):
        for options in (None, {}):
            with self.subTest(options=options), tempfile.TemporaryDirectory() as directory:
                p, raw = probe_at(Path(directory)); original = raw.call
                name = p.prefix+'-files-image-data'
                def changed(method, path, *args, **kwargs):
                    obj: dict | None = original(method, path, *args, **kwargs)
                    if isinstance(obj, dict) and obj.get('Name') == name: obj['Options'] = copy.deepcopy(options)
                    return obj
                raw.call = changed
                p.prepare_native()
                self.assertTrue(raw.containers[p.source]['State']['Running'])
                self.assertFalse(p.unresolved_creates)
                p.cleanup()
                self.assertFalse(raw.containers); self.assertFalse(raw.volumes)
                self.assertFalse((p.root/'private').exists())

    def test_legacy_cleanup_options_guard_retains_existing_compatibility(self):
        for options in ('missing', [], False, 0, ''):
            with self.subTest(options=options), tempfile.TemporaryDirectory() as directory:
                p, raw = probe_at(Path(directory))
                name = p.prefix+'-legacy'
                p.e.call('POST', '/volumes/create', {'Name': name, 'Labels': {'probe.bakabel.owner': p.prefix}})
                if options == 'missing': raw.volumes[name].pop('Options')
                else: raw.volumes[name]['Options'] = copy.deepcopy(options)
                p.cleanup()
                self.assertFalse(raw.volumes)
                self.assertFalse((p.root/'private').exists())

    def test_image_or_name_collision_refuses_entire_cleanup_without_adoption(self):
        for mutation in ('extra-declaration', 'missing-declaration', 'pin-drift', 'collision'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                p, raw = probe_at(Path(directory))
                name = p.prefix+'-files-image-data'
                if mutation == 'extra-declaration': raw.config['Volumes']['/unexpected'] = {}
                elif mutation == 'missing-declaration': raw.config['Volumes'] = {}
                elif mutation == 'pin-drift': raw.pin_id = 'sha256:'+'e'*64
                else:
                    raw.volumes[name] = {'Name': name, 'Driver': 'local', 'Options': {},
                        'Labels': {'probe.bakabel.owner': p.prefix}}
                with self.assertRaises(ValueError): p.prepare_native()
                self.assertNotIn(name, p.volumes)
                self.assertFalse(raw.containers)
                with self.assertRaises(ValueError): p.cleanup()
                self.assertFalse(any(m == 'DELETE' for m, _, _ in raw.calls))
                self.assertTrue((p.root/'private').exists())

    def test_unexpected_mounts_never_start_or_gain_volume_cleanup_authority(self):
        for mutation in ('unexpected', 'name', 'destination', 'readonly', 'type', 'duplicate'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                p, raw = probe_at(Path(directory))
                foreign = 'f'*64
                if mutation == 'unexpected':
                    raw.extra_mount = {'Type': 'volume', 'Name': foreign, 'Destination': '/unexpected', 'RW': True}
                else:
                    def drift(mounts):
                        if mutation == 'name': mounts[0]['Name'] = foreign
                        elif mutation == 'destination': mounts[0]['Destination'] = '/unexpected'
                        elif mutation == 'readonly': mounts[0]['RW'] = False
                        elif mutation == 'type': mounts[0]['Type'] = 'bind'
                        else: mounts[1] = copy.deepcopy(mounts[0])
                    raw.drift_mount = drift
                with self.assertRaisesRegex(ValueError, 'mount identity mismatch'): p.prepare_native()
                self.assertNotIn(foreign, p.volumes)
                self.assertFalse(any(m == 'POST' and path.endswith('/start') for m, path, _ in raw.calls))
                with self.assertRaisesRegex(ValueError, 'unresolved fixture create'): p.cleanup()
                self.assertFalse(any(m == 'DELETE' for m, _, _ in raw.calls))
                self.assertTrue((p.root/'private').exists())

    def test_cleanup_each_metadata_predicate_refuses_all_deletes_and_redacts_values(self):
        for key, value, predicate in (
            ('Name', 'PRIVATE-NAME-CANARY', 'name_matches'),
            ('Labels', {'probe.bakabel.owner': 'PRIVATE-OWNER-CANARY'}, 'owner_matches'),
            ('Driver', 'PRIVATE-DRIVER-CANARY', 'driver_local'),
            ('Options', {'device': 'PRIVATE-OPTIONS-CANARY'*10000}, 'options_empty')):
            with self.subTest(key=key), tempfile.TemporaryDirectory() as directory:
                p, raw = probe_at(Path(directory)); p.prepare_native()
                name = p.volumes[-1]; raw.volumes[name][key] = value
                with self.assertRaisesRegex(ValueError, 'cleanup volume identity mismatch'): p.cleanup()
                check = p.result['cleanup']['volume_identity_mismatch']
                self.assertIs(check[predicate], False)
                self.assertEqual(set(check), {'volume', 'observation', 'name_matches', 'owner_matches',
                                             'driver_local', 'options_empty', 'before_delete'})
                self.assertLess(len(json.dumps(check)), 400)
                self.assertNotIn('PRIVATE-', json.dumps(check))
                self.assertFalse(any(m == 'DELETE' for m, _, _ in raw.calls))
                self.assertTrue((p.root/'private').exists())

    def test_cleanup_unavailable_readback_keeps_unknown_predicates_null(self):
        with tempfile.TemporaryDirectory() as directory:
            p, raw = probe_at(Path(directory)); p.prepare_native()
            name = p.volumes[-1]; original = raw.call
            def unavailable(method, path, *args, **kwargs):
                if method == 'GET' and path == '/volumes/'+name: raise OSError('PRIVATE-ERROR-CANARY')
                return original(method, path, *args, **kwargs)
            raw.call = unavailable
            with self.assertRaises(OSError): p.cleanup()
            check = p.result['cleanup']['volume_identity_mismatch']
            self.assertEqual(check['observation'], 'unavailable')
            for key in ('name_matches', 'owner_matches', 'driver_local', 'options_empty'): self.assertIsNone(check[key])
            self.assertNotIn('PRIVATE-', json.dumps(check))
            self.assertFalse(any(m == 'DELETE' for m, _, _ in raw.calls))

    def test_new_volume_readback_drift_keeps_entire_plan_and_no_foreign_adoption(self):
        for key, value in (('Name', 'foreign'), ('Labels', None), ('Driver', 'nfs'),
                           ('Options', {'device': '/foreign'}), ('Scope', 'global')):
            with self.subTest(key=key), tempfile.TemporaryDirectory() as directory:
                p, raw = probe_at(Path(directory)); original = raw.call
                name = p.prefix+'-files-image-data'
                def changed(method, path, *args, **kwargs):
                    obj = original(method, path, *args, **kwargs)
                    if method == 'GET' and path == '/volumes/'+name and obj is not None: obj[key] = value
                    return obj
                raw.call = changed
                with self.assertRaisesRegex(ValueError, 'owned file fixture image volume'): p.prepare_native()
                self.assertNotIn('foreign', p.volumes)
                self.assertFalse(raw.containers)
                with self.assertRaisesRegex(ValueError, 'unresolved fixture create'): p.cleanup()
                self.assertFalse(any(m == 'DELETE' for m, _, _ in raw.calls))
                self.assertTrue((p.root/'private').exists())

    def test_cleanup_missing_and_malformed_metadata_never_fabricates_predicate_evidence(self):
        for shape in ({}, {'Name': None, 'Labels': ['PRIVATE-CANARY'], 'Driver': None}, ['PRIVATE-CANARY']):
            with self.subTest(shape=type(shape).__name__), tempfile.TemporaryDirectory() as directory:
                p, raw = probe_at(Path(directory)); p.prepare_native()
                raw.volumes[p.volumes[-1]] = shape
                with self.assertRaisesRegex(ValueError, 'cleanup volume identity mismatch'): p.cleanup()
                check = p.result['cleanup']['volume_identity_mismatch']
                for key in ('name_matches', 'owner_matches', 'driver_local', 'options_empty'): self.assertIsNone(check[key])
                self.assertNotIn('PRIVATE-', json.dumps(check))
                self.assertFalse(any(m == 'DELETE' for m, _, _ in raw.calls))

    def test_cleanup_diagnostic_does_not_export_invalid_or_unbounded_volume_ids(self):
        for name in ('PRIVATE/ID-CANARY', 'PRIVATE-'*10000):
            with self.subTest(length=len(name)), tempfile.TemporaryDirectory() as directory:
                p, raw = probe_at(Path(directory)); p.prepare_native()
                original = p.volumes[-1]
                raw.volumes[name] = raw.volumes.pop(original)
                p.volumes[-1] = name
                with self.assertRaises(ValueError): p.cleanup()
                check = p.result['cleanup']['volume_identity_mismatch']
                self.assertIsNone(check['volume'])
                self.assertLess(len(json.dumps(check)), 300)
                self.assertNotIn('PRIVATE-', json.dumps(check))
                self.assertFalse(any(m == 'DELETE' for m, _, _ in raw.calls))

    def test_whole_run_case_persists_failed_cleanup_diagnostic_without_verifier_credit(self):
        instances = []; verified = []
        class Harness(NativeFaultProbe):
            def __init__(self, args, case):
                args.runtime.mkdir()
                p, raw = probe_at(args.runtime, Harness, case)
                self.__dict__.update(p.__dict__)
                # Rebind the real wrapper to this initialized case instance.
                self.e = CapacityEngine(raw, self)
                self.values = ['PRIVATE-SECRET-CANARY']
                self.call_cli = lambda *a, **k: {'targets': [{'ID': 'offline/files', 'Kind': 'volume',
                    'Source': {'DaemonID': self.daemon, 'ContainerID': self.source, 'StartedAt': 'offline-start'}}]}
                instances.append((self, raw))
            def run(self):
                self.prepare_native()
                self.e.engine.volumes[self.volumes[-1]]['Options'] = {'device': 'PRIVATE-SECRET-CANARY'}
        with tempfile.TemporaryDirectory() as directory:
            args = SimpleNamespace(runtime=Path(directory)/'case', expected_source_sha256='a'*64, expected_image_id='sha256:'+'b'*64)
            result = run_case(args, NATIVE_CASES[0], probe_class=Harness, case_verifier=lambda row: verified.append(row))
            saved = (args.runtime/'receipt.json').read_text(); row = json.loads(saved)
            self.assertEqual(result['status'], 'failed'); self.assertEqual(row['status'], 'failed')
            self.assertIn('cleanup_failure', row); self.assertNotIn('evidence_failure', row)
            self.assertIs(row['cleanup']['volume_identity_mismatch']['options_empty'], False)
            self.assertNotIn('PRIVATE-', saved); self.assertNotIn('container_specs', row)
            self.assertFalse(verified)
            p, raw = instances[0]
            self.assertTrue(p.gate.retired); self.assertTrue((p.root/'private').exists())
            self.assertFalse(any(m == 'DELETE' for m, _, _ in raw.calls))

    def test_actual_f20_exercise_create_cleanup_uses_owned_declared_volume(self):
        with tempfile.TemporaryDirectory() as directory:
            p, raw = probe_at(Path(directory), StorageProbe, 'restore-output-ENOSPC')
            with patch('run_resource_probe.os.sched_getaffinity', return_value={0, 1}):
                with self.assertRaises(StopBeforeSeed): p.exercise_output()
            files = next(cid for cid, role in p.roles.items() if role == 'source-files')
            self.assertEqual({m['Destination'] for m in raw.containers[files]['Mounts']}, {'/data', *IMAGE_CONFIG['Volumes']})
            p.cleanup()
            self.assertFalse(raw.containers); self.assertFalse(raw.volumes)
            self.assertFalse((p.root / 'private').exists())

    def test_cleanup_owner_mismatch_records_only_finite_predicates_before_any_delete(self):
        with tempfile.TemporaryDirectory() as directory:
            p, raw = probe_at(Path(directory)); p.prepare_native()
            name = p.volumes[-1]
            raw.volumes[name]['Labels'] = {'probe.bakabel.owner': 'PRIVATE-OWNER-CANARY'}
            raw.volumes[name]['Mountpoint'] = '/PRIVATE-MOUNTPOINT-CANARY'
            raw.volumes[name]['Env'] = ['PRIVATE-ENV-CANARY']
            with self.assertRaisesRegex(ValueError, 'cleanup volume identity mismatch'): p.cleanup()
            self.assertFalse(any(m == 'DELETE' for m, _, _ in raw.calls))
            self.assertEqual(p.result['cleanup'].get('volume_identity_mismatch'), {
                'volume': name, 'observation': 'observed', 'name_matches': True, 'owner_matches': False,
                'driver_local': True, 'options_empty': True, 'before_delete': True})
            self.assertNotIn('PRIVATE-', json.dumps(p.result['cleanup']))
            self.assertTrue((p.root / 'private').exists())

    def test_actual_native_prepare_create_cleanup_has_no_inherited_anonymous_volume(self):
        self.assertEqual('sha256:' + hashlib.sha256(CONFIG_BYTES).hexdigest(), CONFIG_DIGEST)
        for case in NATIVE_CASES:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                p, raw = probe_at(Path(directory), case=case)
                p.prepare_native()
                self.assertIs(NativeFaultProbe.create, __import__('run_compose_pg_acceptance').ComposeProbe.create)
                mounts = raw.containers[p.source]['Mounts']
                self.assertEqual({m['Destination'] for m in mounts}, {'/data', *IMAGE_CONFIG['Volumes']})
                labelled = all((raw.volumes[m['Name']]['Labels'] or {}).get('probe.bakabel.owner') == p.prefix for m in mounts)
                failure = None
                try: p.cleanup()
                except ValueError as exc: failure = str(exc)
                self.assertIsNone(failure, 'actual prepare/create/cleanup composition must accept its own volumes')
                self.assertTrue(labelled, 'image volume must be explicitly precreated and labelled, not anonymously adopted')
                self.assertFalse(raw.containers); self.assertFalse(raw.volumes)
                self.assertTrue(p.gate.retired); self.assertFalse((p.root / 'private').exists())
                self.assertTrue(all(p.result['cleanup']['volumes_absent'].values()))


if __name__ == '__main__': unittest.main()
