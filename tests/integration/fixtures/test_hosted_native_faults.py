"""Offline semantic/protocol tests. None are Docker, fanotify or Restic evidence."""
import copy
import importlib
import json
import unittest


F16 = 'restic-native-exit3'
F17 = 'unknown-commit-before-finalize-worker-SIGKILL'
F18 = 'finalized-before-report-worker-SIGKILL'
F21 = 'file-truncate-during-native-read'


def receipt(case=F16):
    return {'case': case, 'proof': {
        'run_id': 'a'*32, 'logical_target': 'unit/logical/files', 'public_exit':1,
        'native_read': {'operation':'deny', 'pid':123, 'start_ticks':456,
            'worker_id':'b'*64, 'exe':'restic', 'command':'backup',
            'uid':0, 'cap_eff':'00000000a80425fb', 'device':1, 'inode':2,
            'position':131072, 'size_before':16777216, 'size_after':16777216,
            'prior_allowed_reads':1, 'permission_response':2},
        'public': {'runID':'a'*32, 'status':'failed', 'targets':[
            {'targetID':'unit/logical/files', 'status':'partial',
             'snapshotID':'d'*64, 'error':'backup failed',
             'failureCode':'backup', 'resticExitCode':3, 'resticReason':'permission'}]},
        'mapping': {'old_id':None, 'new_id':'d'*64},
        'native_snapshots':[{'id':'d'*64,'status':'partial','run':'a'*32+'-'+__import__('hashlib').sha256(b'unit/logical/files').hexdigest()}],
        'fresh_snapshots':[{'snapshotID':'d'*64,'status':'partial','source':'unit/logical/files','type':'volume'}],
        'fresh_state_empty_before':True, 'restore_refused':True,
        'restore_exit':1, 'restore_no_worker':True,
        'owner_released':True, 'worker_absent':True,
        'last_success_unchanged':True,
    }, 'workers':{'b'*64:{'run_id':'a'*32,'cpu.max':'200000 100000','memory.max':'536870912'}},
        'daemon':'unit-daemon','permission':{'errors':[],'events':2}}


class NativeSemanticTests(unittest.TestCase):
    def verifier(self):
        try:
            module = importlib.import_module('verify_hosted_native_faults')
        except ModuleNotFoundError:
            module = None
        self.assertIsNotNone(module, 'native fault semantic verifier is missing')
        return module.verify_native_case

    def test_exit3_requires_native_error_snapshot_and_independent_fresh_classification(self):
        verify = self.verifier()
        row = json.loads(json.dumps(receipt()))
        verify(row)
        for path, value in [
            (('proof','public','targets',0,'resticExitCode'),0),
            (('proof','public','targets',0,'error'),''),
            (('proof','public','targets',0,'snapshotID'),''),
            (('proof','public','targets',0,'status'),'complete'),
            (('proof','fresh_snapshots',0,'status'),'complete'),
            (('proof','native_read','position'),0),
            (('proof','native_read','permission_response'),1),
            (('proof','restore_no_worker'),False),
            (('proof','mapping','new_id'),'e'*64),
            (('proof','native_snapshots',0,'run'),'e'*32),
            (('proof','public_exit'),True),
            (('permission','errors'),['permission-hold-expired']),
            (('workers','b'*64,'cpu.max'),None),
        ]:
            bad=copy.deepcopy(row); node=bad
            for key in path[:-1]: node=node[key]
            node[path[-1]]=value
            with self.subTest(path=path),self.assertRaises(ValueError):verify(bad)

    def test_truncate_keeps_actual_native_disposition_not_a_consistency_claim(self):
        verify=self.verifier(); row=receipt(F21); p=row['proof']; t=p['public']['targets'][0]
        p['native_read'].update(operation='truncate',permission_response=1,size_after=131072)
        p['public']['status']='complete'; t.update(status='complete',error='')
        del t['resticExitCode']; del t['failureCode']; del t['resticReason']
        p['native_snapshots'][0]['status']=p['fresh_snapshots'][0]['status']='complete'
        p.update(public_exit=0,application_consistency_claim=False,last_success_unchanged=False,last_success_matches_complete=True)
        for key in ('restore_refused','restore_exit','restore_no_worker'):del p[key]
        verify(json.loads(json.dumps(row)))
        for key,value in [('size_after',16777216),('position',0),('permission_response',2)]:
            bad=copy.deepcopy(row);bad['proof']['native_read'][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):verify(bad)
        bad=copy.deepcopy(row);bad['proof']['application_consistency_claim']=True
        with self.assertRaises(ValueError):verify(bad)
        # A real exit 3 is also a valid observed disposition for this mutation.
        failed=receipt(F21);failed['proof']['native_read'].update(p['native_read'])
        failed['proof'].update(public_exit=1,application_consistency_claim=False)
        verify(json.loads(json.dumps(failed)))

    def test_truncate_can_report_observed_failure_without_inventing_a_snapshot(self):
        row=receipt(F21);p=row['proof'];p['native_read'].update(operation='truncate',permission_response=1,size_after=131072)
        p.update(native_snapshots=[],fresh_snapshots=[],mapping={'old_id':None,'new_id':None},
                 public_exit=1,application_consistency_claim=False)
        p['public']['targets'][0].pop('snapshotID');p['public']['targets'][0]['status']='unknown'
        for key in ('restore_refused','restore_exit','restore_no_worker'):p.pop(key)
        self.verifier()(json.loads(json.dumps(row)))
        row['proof']['public']['targets'][0]['status']='complete'
        with self.assertRaises(ValueError):self.verifier()(row)

    def test_actual_crashes_require_old_new_repository_mapping_and_terminal_kill(self):
        verify=self.verifier()
        for name,status in ((F17,'unknown'),(F18,'complete')):
            row=receipt(name); p=row['proof']; t=p['public']['targets'][0]
            del p['native_read']
            old='d'*64 if name==F17 else 'c'*64
            p['mapping']['old_id']=old
            t.update(status=status); t.pop('resticExitCode');t.pop('failureCode');t.pop('resticReason')
            p['native_snapshots'][0]['status']=p['fresh_snapshots'][0]['status']=status
            token=p['native_snapshots'][0]['run']
            p.update(unknown_before={'id':old,'status':'unknown','run':token},
                repository_before_kill=copy.deepcopy(p['native_snapshots']),
                public_exit=1, result_absent_before_kill=True,
                kill={'container_id':'b'*64,'running_before':True,'pid_before':123,
                      'running_after':False,'pid_after':0,'exit_after':137,
                      'authorized':True,'owner_before':{'runID':'a'*32,'workerContainerID':'b'*64,
                          'workerStartAuthorized':True,'daemonID':'unit-daemon','phase':'intent'},
                      'boundary':'snapshot-readback' if name==F17 else 'worker-result-create',
                      'permission_disposition':'denied',
                      'observation':{'pid':123,'start_ticks':456,'worker_id':'b'*64,'uid':0,'cap_eff':'00000000a80425fb',
                          'exe':'restic' if name==F17 else 'bakabel','command':'snapshots' if name==F17 else '_workflow',
                          'boundary':'snapshot-readback' if name==F17 else 'worker-result-create','mask':0x10000,
                          'file_device':1,'file_inode':2,'file_size':100 if name==F17 else 0}},
                events=['unknown-readback-held','unknown-classified']+
                    ([] if name==F17 else ['unknown-readback-allowed','result-create-held','complete-classified'])+
                    ['prekill-rechecked','kill-requested','permission-denied','terminal-137-before-remove','public-failed','fresh-classified'])
            row['relay']={'errors':[],'records':[{'method':'DELETE','boundary':'worker-remove','container_id':'b'*64,
                'forwarded':True,'status':204,'remove_query':'','remove_query_valid':True,'remove_force':False,'remove_volumes':False,
                'owner_before_remove':p['kill']['owner_before'],
                'worker_before_remove':{'container_id':'b'*64,'running':False,'pid':0,'exit_code':137}}]}
            if name==F18:
                for key in ('restore_refused','restore_exit','restore_no_worker'):del p[key]
            verify(json.loads(json.dumps(row)))
            canceled=copy.deepcopy(row);canceled['proof']['kill']['permission_disposition']='kernel-canceled'
            index=canceled['proof']['events'].index('permission-denied');canceled['proof']['events'][index]='permission-canceled-by-kill'
            verify(json.loads(json.dumps(canceled)))
            for path,value in [
                (('kill','exit_after'),1),(('kill','authorized'),False),
                (('result_absent_before_kill',),False),
                (('unknown_before','id'),'f'*64),
                (('repository_before_kill',0,'status'),'partial'),
                (('kill','owner_before','workerContainerID'),'e'*64),
                (('public','status'),'complete'),
                (('kill','observation','command'),'tag'),
                (('kill','observation','file_inode'),None),
                (('kill','permission_disposition'),'invented'),
                (('events',),p['events'][::-1]),
            ]:
                bad=copy.deepcopy(row); node=bad['proof']
                for key in path[:-1]:node=node[key]
                node[path[-1]]=value
                with self.subTest(case=name,path=path),self.assertRaises(ValueError):verify(bad)


class PermissionProtocolTests(unittest.TestCase):
    def module(self):
        try: module=importlib.import_module('native_permission_fixture')
        except ModuleNotFoundError:module=None
        self.assertIsNotNone(module,'bounded native permission transport missing')
        return module

    def test_kernel_packets_roundtrip_and_reject_overflow_version_and_truncation(self):
        import struct
        m=self.module()
        raw=struct.pack('=IBBHQii',24,3,0,24,0x20000,7,123)
        self.assertEqual(m.decode_events(raw),[{'mask':0x20000,'fd':7,'pid':123}])
        directory=struct.pack('=IBBHQii',24,3,0,24,0x40010000,8,123)
        self.assertEqual(m.decode_events(directory),[{'mask':0x40010000,'fd':8,'pid':123}],
                         'marked-directory opens must be allowed through, not poison a child-file gate')
        self.assertEqual(m.permission_response(7,True),struct.pack('=iI',7,1))
        self.assertEqual(m.permission_response(7,False),struct.pack('=iI',7,2))
        for bad in (raw[:-1],struct.pack('=IBBHQii',24,2,0,24,0x20000,7,123),
                    struct.pack('=IBBHQii',24,3,0,24,0x4000,-1,0),
                    struct.pack('=IBBHQii',24,3,0,24,0x20000,-1,123)):
            with self.assertRaises(ValueError):m.decode_events(bad)

    def test_kernel_canceled_permission_after_sigkill_is_not_fabricated_as_a_denial(self):
        import errno,os,socket,tempfile,time
        from pathlib import Path
        from unittest.mock import patch
        m=self.module();front,back=socket.socketpair(socket.AF_UNIX,socket.SOCK_DGRAM)
        self.addCleanup(front.close);self.addCleanup(back.close)
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'payload';path.touch();fd=os.open(path,os.O_RDONLY)
            gate=m.PermissionGate.from_fd(os.dup(front.fileno()),lambda event:'hold')
            self.addCleanup(gate.close)
            gate.dispatch([{'fd':fd,'pid':123,'mask':0x10000}])
            with patch.object(m.os,'write',side_effect=OSError(errno.ENOENT,'unit-kernel-canceled')):
                self.assertEqual(gate.release_after_kill(),'kernel-canceled')
            self.assertIsNone(gate.held)
            with self.assertRaises(OSError):os.fstat(fd)
            self.assertEqual(gate.errors,[])

    def test_libc_setup_and_threaded_permission_transport_with_an_offline_socket_peer(self):
        import os,socket,struct,tempfile
        from pathlib import Path
        from unittest.mock import Mock,patch
        m=self.module();front,back=socket.socketpair(socket.AF_UNIX,socket.SOCK_DGRAM)
        self.addCleanup(front.close);self.addCleanup(back.close);back.settimeout(2)
        libc=Mock();libc.fanotify_init.return_value=os.dup(front.fileno());libc.fanotify_mark.return_value=0
        with patch.object(m.ctypes,'CDLL',return_value=libc):gate=m.PermissionGate(lambda event:'allow')
        self.addCleanup(gate.close)
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'payload';path.touch();gate.mark(path,0x20000)
            libc.fanotify_init.assert_called_once_with(7,os.O_RDONLY|os.O_CLOEXEC|os.O_LARGEFILE)
            libc.fanotify_mark.assert_called_once_with(gate.fd,1,0x20000,-100,os.fsencode(path))
            fd=os.open(path,os.O_RDONLY);gate.start()
            back.send(struct.pack('=IBBHQii',24,3,0,24,0x20000,fd,os.getpid()))
            self.assertEqual(back.recv(8),struct.pack('=iI',fd,1))
            libc.fanotify_mark.return_value=-1
            with self.assertRaises(TimeoutError):gate.mark(path,0x20000)
        libc.fanotify_init.return_value=-1
        with patch.object(m.ctypes,'CDLL',return_value=libc),self.assertRaises(PermissionError):m.PermissionGate(lambda event:'allow')

    def test_native_fd_position_requires_real_prior_read_and_inode_match(self):
        import os,tempfile
        from pathlib import Path
        m=self.module()
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/'payload';p.write_bytes(b'x'*1048576)
            with p.open('rb',buffering=0) as src:
                self.assertEqual(m.read_position(os.getpid(),p),0)
                self.assertEqual(len(src.read(131072)),131072)
                self.assertEqual(m.read_position(os.getpid(),p),131072)
                other=Path(directory)/'other';other.write_bytes(b'x')
                with self.assertRaises(ValueError):m.read_position(os.getpid(),other)

    def test_hold_allows_other_events_and_watchdog_denies_without_granting_crash_authority(self):
        import os,socket,tempfile,struct,time
        from pathlib import Path
        m=self.module()
        front,back=socket.socketpair(socket.AF_UNIX,socket.SOCK_DGRAM)
        self.addCleanup(front.close);self.addCleanup(back.close)
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'payload';path.write_bytes(b'data')
            fd=os.open(path,os.O_RDONLY);other=os.open(path,os.O_RDONLY)
            gate=m.PermissionGate.from_fd(os.dup(front.fileno()),lambda event:'hold' if event['pid']==123 else 'allow',hold_seconds=.1)
            self.addCleanup(gate.close)
            gate.dispatch([{'fd':fd,'pid':123,'mask':0x10000},{'fd':other,'pid':124,'mask':0x10000}])
            self.assertEqual(back.recv(8),struct.pack('=iI',other,1))
            held=gate.await_hold(.1);self.assertEqual(held['pid'],123)
            gate.expire(now=time.monotonic()+1)
            self.assertEqual(back.recv(8),struct.pack('=iI',fd,2))
            with self.assertRaises(TimeoutError):gate.current_hold()
            self.assertEqual(gate.errors,['permission-hold-expired'])


class RunnerBoundaryTests(unittest.TestCase):
    def module(self):
        try: module=importlib.import_module('run_hosted_native_faults')
        except ModuleNotFoundError:module=None
        self.assertIsNotNone(module,'native fault runner route missing')
        return module

    def test_source_gate_is_an_actual_descriptor_read_boundary_not_before_start_mutation(self):
        import os,tempfile
        from pathlib import Path
        m=self.module()
        for name in (F16,F21):
            with tempfile.TemporaryDirectory() as directory:
                path=Path(directory)/'payload';path.write_bytes(b'x'*1048576)
                probe=m.NativeFaultProbe.__new__(m.NativeFaultProbe)
                probe.case=name;probe.payload=path;probe.allowed_reads=0;probe.native_read=None
                probe.native_process=lambda pid,exe,command:{'pid':pid,'exe':Path(exe).name,'command':command}
                with path.open('rb',buffering=0) as src:
                    event={'fd':src.fileno(),'pid':os.getpid(),'mask':0x20000}
                    self.assertEqual(probe.classify_permission(event),'allow')
                    self.assertIsNone(probe.native_read)
                    self.assertEqual(path.stat().st_size,1048576)
                    src.read(131072)
                    self.assertEqual(probe.classify_permission(event),'hold')
                    self.assertEqual(probe.native_read['position'],131072)
                    self.assertEqual(probe.native_read['prior_allowed_reads'],1)
                    self.assertEqual(path.stat().st_size,1048576,'classifier must not mutate before main readback gate')

    def test_crash_classifier_holds_committed_unknown_then_only_result_create(self):
        import os,tempfile
        from pathlib import Path
        m=self.module()
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'backend/local/snapshots').mkdir(parents=True)
            output=root/'state/workflow/output';output.mkdir(parents=True)
            original=root/'backend/local/snapshots'/('c'*64);original.write_bytes(b'encrypted-unit-fixture')
            result=output/'.record-123';result.touch()
            for name in (F17,F18):
                probe=m.NativeFaultProbe.__new__(m.NativeFaultProbe);probe.case=name;probe.root=root
                probe.stage='unknown';probe.boundary=None
                probe.native_process=lambda pid,exe,cmd:{'exe':Path(exe).name,'command':cmd}
                with original.open('rb') as src:
                    event={'fd':src.fileno(),'pid':os.getpid(),'mask':0x10000}
                    self.assertEqual(probe.classify_permission(event),'hold')
                    self.assertEqual(probe.boundary['snapshot_id'],'c'*64)
                    probe.stage='report'
                    self.assertEqual(probe.classify_permission(event),'allow')
                with result.open('rb') as src:
                    event={'fd':src.fileno(),'pid':os.getpid(),'mask':0x10000}
                    self.assertEqual(probe.classify_permission(event),'hold' if name==F18 else 'allow')
                    if name==F18:self.assertEqual(probe.boundary['boundary'],'worker-result-create')

    def test_read_exercise_mutates_only_after_live_read_and_preserves_exit3_diagnostics(self):
        import os,tempfile
        from pathlib import Path
        from unittest.mock import Mock
        from types import SimpleNamespace
        m=self.module()
        for name in (F16,F21):
            with tempfile.TemporaryDirectory() as directory:
                p=m.NativeFaultProbe.__new__(m.NativeFaultProbe);p.case=name;p.payload=Path(directory)/'payload'
                p.payload.write_bytes(b'x'*1048576);p.gate=Mock();p.gate.await_hold.return_value={'pid':123}
                p.native_read={'position':131072,'size_before':1048576,'pid':123}
                p.controller=Mock(return_value='controller');p.owner=Mock(return_value={'runID':'a'*32})
                p.capture_owned_worker=Mock();p.recheck_read=Mock();p.finish_native=Mock()
                p.result={};p.exercise_native_read()
                if name==F16:
                    self.assertEqual(p.payload.stat().st_size,1048576);p.gate.release.assert_called_once_with(False)
                else:
                    self.assertEqual(p.payload.stat().st_size,131072);p.gate.release.assert_called_once_with(True)
                self.assertEqual(p.native_read['operation'],'deny' if name==F16 else 'truncate')
                self.assertEqual(p.result['native_observations']['read'],p.native_read)
                p.finish_native.assert_called_once_with('controller')

    def test_prepare_uses_exact_owned_option_free_volume_and_unchanged_source(self):
        import tempfile
        from pathlib import Path
        from types import SimpleNamespace
        from unittest.mock import Mock
        from test_owned_file_source_volumes import probe_at
        m=self.module()
        with tempfile.TemporaryDirectory() as directory:
            p, raw=probe_at(Path(directory)); p.gate=Mock()
            p.prepare_native()
            self.assertEqual(p.target,'offline/files')
            self.assertEqual(p.payload.stat().st_size,16777216)
            p.gate.mark.assert_called_once_with(p.payload,0x20000)
            spec=next(body for method,path,body in raw.calls if method=='POST' and path.startswith('/containers/create'))
            self.assertEqual(spec['Image'],m.PG)
            self.assertEqual(spec['Cmd'],['exec sleep 600'])
            self.assertEqual(spec['HostConfig']['Mounts'][0]['Source'],p.prefix+'-files')
            self.assertEqual(p.source_before,{'container_id':p.source,'started_at':'offline-start','restart_count':0})

    def test_finish_preserves_real_public_target_fields_and_classifies_from_repository(self):
        from unittest.mock import Mock
        m=self.module();p=m.NativeFaultProbe.__new__(m.NativeFaultProbe)
        p.case=F16;p.active={'runID':'a'*32,'workerContainerID':'b'*64};p.target='unit/logical/files'
        p.native_read=receipt()['proof']['native_read'];p.result={};p.baseline_success=''
        p.e=Mock();p.e.inspect.side_effect=[{'State':{'Running':False,'ExitCode':1}},None]
        p.wait=lambda fn,*args:fn();p.finish=Mock(return_value=[receipt()['proof']['public']])
        p.owner=Mock(return_value=None);p.last=Mock(return_value={'runID':'a'*32,'status':'failed','lastBackupSuccessAt':''})
        p.native_snapshots=Mock(return_value=receipt()['proof']['native_snapshots'])
        p.fresh_classify=Mock(return_value={'fresh_snapshots':receipt()['proof']['fresh_snapshots'],
            'fresh_state_empty_before':True,'restore_refused':True,'restore_exit':1,'restore_no_worker':True})
        p.finish_native('controller')
        self.assertEqual(p.result['proof']['public'],receipt()['proof']['public'])
        self.assertEqual(p.result['proof']['native_snapshots'],receipt()['proof']['native_snapshots'])
        self.assertEqual(p.result['proof']['mapping'],{'old_id':None,'new_id':'d'*64})
        self.assertTrue(p.result['proof']['last_success_unchanged'])
        self.assertEqual(p.result['native_observations']['public'],receipt()['proof']['public'])
        self.assertEqual(p.result['native_observations']['native_snapshots'],receipt()['proof']['native_snapshots'])
        p.fresh_classify.assert_called_once_with('d'*64,'partial')
        p.case=F21;p.e.inspect.side_effect=[{'State':{'Running':False,'ExitCode':1}},None]
        p.native_snapshots.return_value=[]
        p.finish.return_value[0]['targets'][0].pop('snapshotID')
        p.finish.return_value[0]['targets'][0]['status']='unknown'
        p.fresh_classify.return_value={'fresh_snapshots':[],'fresh_state_empty_before':True}
        p.finish_native('controller')
        self.assertEqual(p.result['proof']['mapping'],{'old_id':None,'new_id':None})
        p.fresh_classify.assert_called_with(None,'unknown')

    def test_fresh_classifier_refuses_partial_exact_id_without_worker_or_destination_write(self):
        import tempfile
        from pathlib import Path
        from unittest.mock import Mock
        m=self.module()
        with tempfile.TemporaryDirectory() as directory:
            p=m.NativeFaultProbe.__new__(m.NativeFaultProbe);p.root=Path(directory);(p.root/'fresh-state').mkdir()
            dest=p.root/'empty-destination';dest.mkdir();p.prefix='unit-owned';p.volumes=[];p.target='unit/logical/files'
            p.call_cli=Mock(side_effect=[receipt()['proof']['fresh_snapshots'],None])
            p.relay=Mock();p.relay.snapshot.return_value={'workers':['b'*64]}
            p.e=Mock();p.e.call.return_value={'Name':'unit-owned-refused-restore','Driver':'local','Scope':'local',
                'Options':{},'Mountpoint':str(dest),'Labels':{'probe.bakabel.owner':p.prefix}}
            got=p.fresh_classify('d'*64,'partial')
            self.assertTrue(got['restore_refused']);self.assertTrue(got['restore_no_worker'])
            self.assertEqual(p.call_cli.call_args.args,('restore','--snapshot','d'*64,'--volume','unit-owned-refused-restore'))
            self.assertTrue(p.call_cli.call_args.kwargs['fresh'])
            (p.root/'fresh-state/owner.json').write_text('unit-only-owner')
            with self.assertRaises(ValueError):p.fresh_classify('d'*64,'partial')
            (p.root/'fresh-state/owner.json').unlink();p.case=F21;p.call_cli.side_effect=None;p.call_cli.return_value=[]
            self.assertEqual(p.fresh_classify(None,'unknown'),{'fresh_state_empty_before':True,'fresh_snapshots':[]})

    def test_crash_exercise_signals_owned_worker_only_after_real_boundary_classification(self):
        from unittest.mock import Mock
        import threading
        m=self.module()
        for name in (F17,F18):
            p=m.NativeFaultProbe.__new__(m.NativeFaultProbe);p.case=name;p.events=[];p.result={};p.kill_answered=threading.Event()
            p.active={'runID':'a'*32,'workerContainerID':'b'*64,'workerStartAuthorized':True}
            p.owner=Mock(return_value=p.active);p.controller=Mock(return_value='controller');p.capture_owned_worker=Mock()
            p.boundary={'snapshot_id':'c'*64,'boundary':'snapshot-readback'}
            p.gate=Mock();p.gate.current_hold.return_value={'deadline':999999999999}
            def held(*args):
                if p.stage=='report':p.boundary={'boundary':'worker-result-create'}
                return {'deadline':999999999999}
            p.stage='unknown';p.gate.await_hold.side_effect=held;p.gate.release_after_kill.return_value='denied'
            unknown={'id':'c'*64,'status':'unknown','run':'unit-token'}
            final={'id':'d'*64,'status':'complete','run':'unit-token'}
            p.native_snapshots=Mock(side_effect=[[unknown],[final if name==F18 else unknown]])
            p.recheck_kill=Mock(return_value={'State':{'Pid':123,'Running':True}})
            p.e=Mock();p.finish_native=Mock();p.exercise_native_crash()
            p.e.call.assert_called_once_with('POST','/containers/'+'b'*64+'/kill?signal=KILL',deadline=999999999999)
            self.assertEqual(p.unknown_before,unknown)
            self.assertEqual(p.repository_before_kill,[final if name==F18 else unknown])
            self.assertEqual(p.events[-3:],['prekill-rechecked','kill-requested','permission-denied'])
            self.assertTrue(p.kill_answered.is_set());p.finish_native.assert_called_once_with('controller')
            p.gate.release_after_kill.assert_called_once_with()
            self.assertEqual(p.kill_proof['permission_disposition'],'denied')
            self.assertEqual(p.kill_proof['observation'],p.boundary)
            self.assertEqual(p.result['native_observations']['unknown_snapshots'],[unknown])
            self.assertEqual(p.result['native_observations']['kill'],p.kill_proof)
            self.assertEqual(p.result['native_events'],p.events)

    def test_native_snapshot_projection_uses_exact_run_target_never_latest(self):
        import hashlib,json
        from unittest.mock import Mock
        m=self.module();p=m.NativeFaultProbe.__new__(m.NativeFaultProbe)
        p.active={'runID':'a'*32};p.target='unit/logical/files'
        token='a'*32+'-'+hashlib.sha256(p.target.encode()).hexdigest()
        p.restic=Mock(return_value=json.dumps([
            {'id':'c'*64,'time':'2099','tags':['bakabel.run=foreign','bakabel.status=complete']},
            {'id':'d'*64,'time':'2000','tags':['bakabel.run='+token,'bakabel.status=unknown']},
        ]))
        self.assertEqual(p.native_snapshots(),[{'id':'d'*64,'status':'unknown','run':token}])
        p.restic.return_value=json.dumps([{'id':'d'*64,'tags':['bakabel.run='+token,'bakabel.status=unknown','bakabel.status=complete']}])
        with self.assertRaises(ValueError):p.native_snapshots()

    def test_native_process_requires_strict_owner_authorization_and_rechecks_read(self):
        import tempfile
        from pathlib import Path
        from unittest.mock import Mock,patch
        m=self.module();p=m.NativeFaultProbe.__new__(m.NativeFaultProbe)
        owner={'workerStartAuthorized':True,'workerContainerID':'b'*64,'runID':'a'*32,'phase':'intent','daemonID':'unit-daemon'}
        p.owner=Mock(return_value=owner);p.daemon='unit-daemon'
        ident=receipt()['proof']['native_read'];ident={k:ident[k] for k in ('pid','start_ticks','worker_id','exe','command','uid','cap_eff')}
        with patch.object(m,'process_identity',return_value=ident):
            self.assertEqual(p.native_process(123,'/usr/bin/restic','backup'),ident)
            owner['workerStartAuthorized']=1
            with self.assertRaises(ValueError):p.native_process(123,'/usr/bin/restic','backup')
        with tempfile.TemporaryDirectory() as directory:
            p.payload=Path(directory)/'payload';p.payload.write_bytes(b'x'*1048576)
            p.native_read={**ident,'device':p.payload.stat().st_dev,'inode':p.payload.stat().st_ino,
                'position':131072,'size_before':1048576}
            import os
            held_fd=os.open(p.payload,os.O_RDONLY);self.addCleanup(os.close,held_fd)
            p.native_process=Mock(return_value=ident);p.gate=Mock();p.gate.current_hold.return_value={'pid':123,'fd':held_fd,'mask':0x20000}
            with patch.object(m,'read_position',return_value=131072):p.recheck_read()
            p.gate.current_hold.return_value['pid']=999
            with patch.object(m,'read_position',return_value=131072),self.assertRaises(ValueError):p.recheck_read()
            p.gate.current_hold.return_value['pid']=123
            p.native_process.return_value={**ident,'start_ticks':999}
            with self.assertRaises(ValueError):p.recheck_read()

    def test_kill_gate_refuses_drift_and_captures_terminal_before_nonforce_remove(self):
        import tempfile,threading
        from pathlib import Path
        from unittest.mock import Mock
        m=self.module()
        with tempfile.TemporaryDirectory() as directory:
            p=m.NativeFaultProbe.__new__(m.NativeFaultProbe);p.root=Path(directory);p.case=F17
            p.active={'runID':'a'*32,'workerContainerID':'b'*64,'workerStartAuthorized':True,'phase':'intent','daemonID':'unit-daemon'}
            p.owner=Mock(return_value=dict(p.active));p.worker_identity_proof=Mock()
            import os
            p.daemon='unit-daemon';p.boundary_path=p.root/'committed';p.boundary_path.write_bytes(b'encrypted-unit-only')
            held_fd=os.open(p.boundary_path,os.O_RDONLY);self.addCleanup(os.close,held_fd);st=os.fstat(held_fd)
            p.boundary={'pid':123,'exe':'restic','command':'snapshots','start_ticks':456,
                'file_device':st.st_dev,'file_inode':st.st_ino,'file_size':st.st_size}
            p.native_process=Mock(return_value=dict(p.boundary));p.gate=Mock();p.gate.current_hold.return_value={'pid':123,'fd':held_fd,'mask':0x10000}
            p.e=Mock();p.e.inspect.return_value={'State':{'Running':True,'Pid':123}};p.e.call.return_value={'ID':p.daemon}
            self.assertTrue(p.recheck_kill()['State']['Running'])
            p.owner.side_effect=[dict(p.active),{**p.active,'workerStartAuthorized':1}]
            with self.assertRaises(ValueError):p.recheck_kill()
            p.owner.side_effect=None
            p.owner.return_value={**p.active,'workerStartAuthorized':1}
            with self.assertRaises(ValueError):p.recheck_kill()
            p.owner.return_value=dict(p.active);p.kill_answered=threading.Event();p.kill_answered.set()
            p.e.inspect.return_value={'State':{'Running':False,'Pid':0,'ExitCode':137}}
            p.kill_proof={};p.events=[]
            record={'method':'DELETE','boundary':'worker-remove','container_id':'b'*64,'forwarded':False,
                'remove_query':'','remove_query_valid':True,'remove_force':False,'remove_volumes':False}
            p.observe_transport('request',record)
            self.assertEqual(p.kill_proof['exit_after'],137)
            self.assertEqual(p.events,['terminal-137-before-remove'])
            record['forwarded']=True
            with self.assertRaises(ValueError):p.observe_transport('request',record)
            record['forwarded']=False
            record['remove_query']='force=true';record['remove_force']=True
            with self.assertRaises(ValueError):p.observe_transport('request',record)

    def test_native_lifecycle_closes_permission_authority_before_owned_cleanup_and_keeps_source_online(self):
        from unittest.mock import Mock,patch
        m=self.module();p=m.NativeFaultProbe.__new__(m.NativeFaultProbe)
        with patch.object(m.FaultProbe,'__init__',return_value=None),patch.object(m,'PermissionGate') as factory:
            p.__init__(object(),F16);self.assertIs(p.gate,factory.return_value)
        p.case=F16;p.source='c'*64;p.daemon='unit-daemon';p.result={}
        p.source_before={'container_id':p.source,'started_at':'start','restart_count':0}
        p.e=Mock();p.e.call.return_value={'ID':p.daemon};p.e.exec.return_value={'exit':0}
        p.e.inspect.return_value={'Id':p.source,'State':{'StartedAt':'start','Running':True},'RestartCount':0}
        p.verify_source_online();self.assertTrue(p.result['source_unchanged'])
        p.e.inspect.return_value['RestartCount']=1
        with self.assertRaises(ValueError):p.verify_source_online()
        p.gate=Mock();p.gate.errors=[];p.gate.count=3
        order=[];p.gate.close.side_effect=lambda:order.append('permission-closed')
        with patch.object(m.FaultProbe,'cleanup',side_effect=lambda:order.append('owned-cleanup')):
            p.cleanup()
        self.assertEqual(order,['permission-closed','owned-cleanup'])
        self.assertEqual(p.result['permission'],{'errors':[],'events':3})

    def test_crash_permission_binding_uses_inode_not_worker_namespace_path_spelling(self):
        import os,tempfile
        from pathlib import Path
        from unittest.mock import patch
        m=self.module()
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);snapshots=root/'backend/local/snapshots';snapshots.mkdir(parents=True)
            path=snapshots/('c'*64);path.write_bytes(b'encrypted-unit-only')
            p=m.NativeFaultProbe.__new__(m.NativeFaultProbe);p.root=root;p.case=F17;p.stage='unknown';p.boundary=None
            p.native_process=lambda *args:{'pid':123,'exe':'restic','command':'snapshots','start_ticks':456}
            with path.open('rb') as source,patch.object(m.os,'readlink',return_value='/repository/snapshots/'+'c'*64):
                self.assertEqual(p.classify_permission({'mask':0x10000,'fd':source.fileno(),'pid':123}),'hold')
                self.assertEqual(p.boundary['file_inode'],path.stat().st_ino)
                self.assertEqual(p.boundary['mask'],0x10000)
            wrong=root/('c'*64);wrong.write_bytes(b'not-owned-snapshot')
            with wrong.open('rb') as source,patch.object(m.os,'readlink',return_value='/repository/snapshots/'+'c'*64):
                self.assertEqual(p.classify_permission({'mask':0x10000,'fd':source.fileno(),'pid':123}),'allow')

    def test_unrecognized_snapshot_or_diagnostic_text_is_never_exported(self):
        from unittest.mock import Mock
        m=self.module()
        for key,value in (('snapshotID','unit-private-marker'),('resticReason','unit-private-marker'),('error','unit-private-marker')):
            p=m.NativeFaultProbe.__new__(m.NativeFaultProbe);p.case=F16;p.result={};p.active={'runID':'a'*32};p.target='unit/logical/files'
            p.e=Mock();p.owner=Mock(return_value={'unit':'owner'});p.wait=lambda *args:{'State':{'ExitCode':1}}
            rows=[receipt()['proof']['public']];rows[0]['targets'][0][key]=value;p.finish=Mock(return_value=rows)
            with self.assertRaises(ValueError):p.finish_native('controller')
            self.assertNotIn('unit-private-marker',json.dumps(p.result))

    def test_public_run_route_dispatches_each_native_case_without_original_pg_prepare(self):
        from unittest.mock import Mock
        m=self.module()
        self.assertIn('run',m.NativeFaultProbe.__dict__,'must not inherit the PG-only original run path')
        for name in (F16,F17,F18,F21):
            p=m.NativeFaultProbe.__new__(m.NativeFaultProbe);p.case=name;p.result={}
            p.prepare_native=Mock();p.exercise_native_read=Mock();p.exercise_native_crash=Mock();p.verify_source_online=Mock()
            p.run()
            p.prepare_native.assert_called_once_with();p.verify_source_online.assert_called_once_with()
            (p.exercise_native_crash if name in (F17,F18) else p.exercise_native_read).assert_called_once_with()
            self.assertTrue(p.result['exercised'])


class NativeRegistrationTests(unittest.TestCase):
    def test_real_run_case_selects_native_runner_and_serialized_independent_verifier(self):
        import tempfile
        from pathlib import Path
        from types import SimpleNamespace
        from unittest.mock import patch
        import run_hosted_faults as runner
        import run_hosted_native_faults as native
        import verify_hosted_faults as verifier
        self.assertTrue(set((F16,F17,F18,F21))<=set(verifier.CASES),'new gates missing from full hosted case manifest')
        class UnitNative:
            def __init__(self,args,case):
                self.root=args.runtime;self.root.mkdir();self.result=receipt(case)
                self.result.update(schema=1,status='blocked',ordinary_image=True,request_mutations=[],
                    backend='local',platform='compose',source_unchanged=True,source_sha256='a'*64,image_id='sha256:'+'b'*64,
                    cleanup={'containers_absent':{'b'*64:True},'volumes_absent':{'unit-owned':True},'private_paths_absent':True},
                    permission={'errors':[],'events':2},relay={'errors':[],'records':[]})
                self.result['workers']['b'*64].update(container_id='b'*64,image_id='sha256:'+'b'*64,
                    memory_bytes=536870912,nanocpus=2000000000,**{'cpu.max':'200000 100000','memory.max':'536870912'},
                    socket={'source':'/owned/relay.sock','destination':'/run/bakabel/docker.sock','read_only':True})
            def run(self):self.result['exercised']=True
            def cleanup(self):pass
            def save(self):(self.root/'receipt.json').write_text(json.dumps(self.result))
        with tempfile.TemporaryDirectory() as directory:
            args=SimpleNamespace(runtime=Path(directory)/'run',expected_source_sha256='a'*64,expected_image_id='sha256:'+'b'*64)
            with patch.object(native,'NativeFaultProbe',UnitNative),patch.object(runner,'FaultProbe',side_effect=AssertionError('wrong original route')):
                outcome=runner.run_case(args,F16)
            self.assertEqual(outcome,{'case':F16,'status':'pass'})
            row=json.loads((args.runtime/'receipt.json').read_text());verifier.verify_case(row)
            row['proof']['public']['targets'][0]['resticExitCode']=0
            with self.assertRaises(ValueError):verifier.verify_case(json.loads(json.dumps(row)))


if __name__ == '__main__': unittest.main()
