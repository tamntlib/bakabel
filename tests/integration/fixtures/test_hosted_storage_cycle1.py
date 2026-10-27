"""Causal cycle-1 regressions; offline controls, not hosted acceptance."""
import copy
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
import hosted_storage_trace as trace
import run_hosted_storage_prereqs as runner
from run_hosted_faults import FaultProbe


class AuthorityTests(unittest.TestCase):
    def test_preexisting_incarnation_drift_never_launches_attachment(self):
        t=trace.WriteTrace([os.getpid()],lambda p:None)
        t.identities[os.getpid()]='0'
        with patch.object(trace.subprocess,'Popen') as launch:
            with self.assertRaises(ValueError): t.start()
        launch.assert_not_called()

    def test_owner_authority_is_rechecked_before_any_numeric_attach(self):
        events=[]
        def refused(): events.append('authority'); raise ValueError('owner drift')
        t=trace.WriteTrace([os.getpid()],lambda p:None,authority=refused)
        with patch.object(trace.subprocess,'Popen') as launch:
            with self.assertRaises(ValueError): t.start()
        launch.assert_not_called(); self.assertEqual(events,['authority'])

    def test_saved_cgroup_or_executable_drift_refuses_before_launch(self):
        for cgroup,exe in [('foreign','same'),('same','foreign')]:
            t=trace.WriteTrace([os.getpid()],lambda p:None)
            t.bindings[os.getpid()]=(cgroup,exe)
            with patch.object(trace.subprocess,'Popen') as launch:
                with self.assertRaises(ValueError): t.start()
            launch.assert_not_called()

    def test_postattach_drift_still_detaches_observer_and_cannot_credit_attachment(self):
        t=trace.WriteTrace([os.getpid()],lambda p:None)
        t.validate=Mock(side_effect=[None,ValueError('post drift')])
        proc=Mock(pid=999,stderr=io.BytesIO(b'')); proc.poll.return_value=None; proc.returncode=0
        original=Path.read_text
        def read(path,*args,**kwargs):
            if str(path)=='/unit/task/status': return 'TracerPid:\t999\n'
            return original(path,*args,**kwargs)
        with patch.object(trace.subprocess,'Popen',return_value=proc),patch.object(Path,'iterdir',return_value=[Path('/unit/task')]),patch.object(Path,'read_text',read):
            with self.assertRaisesRegex(ValueError,'post drift'): t.start()
        proc.send_signal.assert_called_once_with(__import__('signal').SIGINT)
        self.assertEqual(t.validate.call_count,2); self.assertFalse(t.attached)

    def test_storage_runner_preattach_owner_recheck_cannot_be_deferred_to_postattach(self):
        p=runner.StorageProbe.__new__(runner.StorageProbe); p.traces=[]
        obj={'Id':'b'*64,'State':{'Pid':os.getpid(),'Running':True,'StartedAt':'unit'}}
        p.owned_running=Mock(side_effect=[obj,ValueError('owner replaced')])
        p.cgroup=lambda pid,strict:Path('/scope/'+'b'*64)
        with patch.object(runner.os,'readlink',return_value='/usr/local/bin/bakabel'),patch.object(trace.subprocess,'Popen') as launch:
            with self.assertRaises(ValueError): p.start_trace({'workerStartAuthorized':True},lambda p:None)
        self.assertEqual(p.owned_running.call_count,2); launch.assert_not_called()

    def test_unfinished_eof_is_not_success(self):
        s=trace.WriteStream(10,lambda p:'temp_pack')
        s.feed('[pid 12] write(4</tmp/a>, ""..., 1 <unfinished ...>')
        with self.assertRaisesRegex(ValueError,'trace_incomplete'): s.finish()

    def test_verifier_rejects_writer_with_no_owned_ancestry_after_json_roundtrip(self):
        from test_hosted_storage_prereqs import synthetic
        from verify_hosted_storage_prereqs import verify_case
        row=json.loads(json.dumps(synthetic()))
        row['storage']['trace']['writes'][0]['pid']=2147483647
        with self.assertRaises(ValueError): verify_case(row)

    def test_reader_projects_live_owned_tid_binding(self):
        # A real self /proc identity, with only the tracer status boundary doubled.
        t=trace.WriteTrace([os.getpid()],lambda p:None)
        t.proc=Mock(pid=777)
        original=Path.read_text
        def read(path,*args,**kwargs):
            text=original(path,*args,**kwargs)
            if path.name=='status':
                import re
                text=re.sub(r'TracerPid:\s*\d+', 'TracerPid:\t777',text)
            return text
        with patch.object(Path,'read_text',read): binding=t.writer_binding(os.getpid())
        self.assertEqual(binding['chain'][-1]['pid'],os.getpid())
        self.assertEqual(binding['chain'][-1]['start_ticks'],t.identities[os.getpid()])

    def test_eof_reader_records_finite_incomplete_error(self):
        t=trace.WriteTrace([os.getpid()],lambda p:'temp_pack')
        proc=Mock(pid=999,stderr=io.BytesIO(b'write(4</tmp/a>, ""..., 1 <unfinished ...>\n'))
        proc.poll.return_value=0; proc.returncode=0
        with patch.object(trace.subprocess,'Popen',return_value=proc):
            with self.assertRaises(ValueError): t.start()
        self.assertIn('trace_incomplete',t.errors)


class MountTests(unittest.TestCase):
    def probe(self,root):
        p=runner.StorageProbe.__new__(runner.StorageProbe)
        p.root=root; p.prefix='unit-owned'; p.output_path=root/'output'; p.output_path.mkdir()
        p.traces=[]; p.temp_fd=None; p.output_mount=None; p.result={'storage':{}}
        return p

    def identity(self,p,**changes):
        return dict({'mount_id':101,'parent_id':1,'major_minor':'0:55','root':'/',
                     'mountpoint':str(p.output_path),'fstype':'tmpfs','source':'unit-owned-output',
                     'device':55,'inode':1},**changes)

    def test_mount_drift_after_engine_absence_never_unmounts_or_deletes_recovery(self):
        for field,value in [('mount_id',102),('source','foreign'),('fstype','ext4'),('root','/bind'),('device',99),('inode',2)]:
            with self.subTest(field=field),tempfile.TemporaryDirectory() as directory:
                p=self.probe(Path(directory)); original=self.identity(p); p.output_mount={'state':'owned','identity':original,**original}
                state=copy.deepcopy(original); events=[]
                def cleanup(_):
                    events.append('engine-absent'); state[field]=value
                    if hasattr(p,'before_private_cleanup'): p.before_private_cleanup()
                    events.append('private-delete')
                with patch.object(runner,'output_mount_identity',side_effect=lambda path:copy.deepcopy(state),create=True), \
                     patch.object(runner,'space',return_value=original),patch.object(runner.os.path,'ismount',side_effect=[True,False]), \
                     patch.object(FaultProbe,'cleanup',cleanup),patch.object(runner.subprocess,'run',return_value=Mock(returncode=0)) as umount:
                    with self.assertRaises(ValueError): p.cleanup()
                umount.assert_not_called(); self.assertNotIn('private-delete',events)
                self.assertIsNotNone(p.output_mount)

    def test_real_supercleanup_retains_private_paths_when_mount_drifts_during_engine_delete(self):
        with tempfile.TemporaryDirectory() as directory:
            p=self.probe(Path(directory)); identity=self.identity(p); state=copy.deepcopy(identity)
            p.output_mount={'state':'owned','identity':identity}
            p.containers={'c'*64:'fixture'}; p.worker_owners={}; p.volumes=[]; p.roles={}; p.daemon='unit'
            p.owner=lambda:None; p.relay=Mock(); p.e=Mock(); p.e.inspect.return_value=None
            for name in ('private','backend','fresh-state','state'): (p.root/name).mkdir()
            def call(method,path,**kwargs):
                if method=='GET' and path=='/info': return {'ID':'unit'}
                if method=='DELETE': state['mount_id']=102; return None
                raise AssertionError('unexpected Engine route')
            p.e.call.side_effect=call
            with patch.object(runner,'output_mount_identity',side_effect=lambda path:copy.deepcopy(state)),patch.object(runner.subprocess,'run') as command:
                with self.assertRaises(ValueError): p.cleanup()
            command.assert_not_called()
            self.assertTrue(all((p.root/name).is_dir() for name in ('private','backend','fresh-state','state')))

    def test_pending_timeout_can_only_adopt_exact_owned_mount_or_prove_absence(self):
        for effect in ('owned','absent'):
            with self.subTest(effect=effect),tempfile.TemporaryDirectory() as directory:
                p=self.probe(Path(directory)); identity=self.identity(p)
                with patch.object(runner,'output_mount_identity',side_effect=[None,identity if effect=='owned' else None]), \
                     patch.object(runner.subprocess,'run',side_effect=runner.subprocess.TimeoutExpired('mount',5)):
                    with self.assertRaises(runner.subprocess.TimeoutExpired): p.mount_output()
                if effect=='owned': self.assertEqual(p.output_mount['identity'],identity)
                else: self.assertIsNone(p.output_mount)

    def test_absence_after_timeout_is_rechecked_after_engine_teardown(self):
        with tempfile.TemporaryDirectory() as directory:
            p=self.probe(Path(directory)); identity=self.identity(p)
            with patch.object(runner,'output_mount_identity',side_effect=[None,None]), \
                 patch.object(runner.subprocess,'run',side_effect=runner.subprocess.TimeoutExpired('mount',5)):
                with self.assertRaises(runner.subprocess.TimeoutExpired): p.mount_output()
            state=[None]; events=[]
            def cleanup(_):
                state[0]={**identity,'source':'foreign'}; events.append('engine-absent')
                p.before_private_cleanup(); events.append('private-delete')
            with patch.object(runner,'output_mount_identity',side_effect=lambda path:state[0]), \
                 patch.object(FaultProbe,'cleanup',cleanup),patch.object(runner.subprocess,'run') as command:
                with self.assertRaises(ValueError): p.cleanup()
            self.assertNotIn('private-delete',events); command.assert_not_called()

    def test_mountinfo_parser_binds_mount_id_root_source_and_rejects_stacked_mounts(self):
        import stat
        line='101 1 0:55 / /owned/output rw,nosuid,nodev - tmpfs owned-output rw,size=8192k\n'
        with patch.object(Path,'read_text',return_value=line),patch.object(runner.os,'stat',return_value=Mock(st_dev=os.makedev(0,55),st_ino=1,st_mode=stat.S_IFDIR)):
            identity=runner.output_mount_identity(Path('/owned/output'))
        self.assertEqual(identity['mount_id'],101); self.assertEqual(identity['source'],'owned-output'); self.assertEqual(identity['root'],'/')
        with patch.object(Path,'read_text',return_value=line+line.replace('101 ','102 ',1)):
            with self.assertRaises(ValueError): runner.output_mount_identity(Path('/owned/output'))

    def test_success_path_unmount_is_after_engine_absence_before_private_delete(self):
        with tempfile.TemporaryDirectory() as directory:
            p=self.probe(Path(directory)); identity=self.identity(p); p.output_mount={'state':'owned','identity':identity,**identity,'underlying':{'device':p.output_path.stat().st_dev,'inode':p.output_path.stat().st_ino}}
            state=[identity]; events=[]
            def cleanup(_):
                events.append('engine-absent'); p.before_private_cleanup(); events.append('private-delete')
            def command(argv,**kwargs):
                events.append('umount'); state[0]=None; return Mock(returncode=0)
            with patch.object(runner,'output_mount_identity',side_effect=lambda path:copy.deepcopy(state[0]),create=True), \
                 patch.object(runner,'space',return_value=identity),patch.object(runner.os.path,'ismount',side_effect=[True,False]), \
                 patch.object(FaultProbe,'cleanup',cleanup),patch.object(runner.subprocess,'run',side_effect=command):
                p.cleanup()
            self.assertEqual(events,['engine-absent','umount','private-delete'])
            self.assertTrue(p.result['storage']['output_unmounted_after_cleanup'])

    def test_mount_intent_survives_timeout_and_ambiguous_readback_blocks_supercleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            p=self.probe(Path(directory)); events=[]
            def command(argv,**kwargs):
                intent=json.loads((p.root/'output-mount-intent.json').read_text())
                self.assertEqual(intent['state'],'pending'); self.assertEqual(intent['source'],'unit-owned-output')
                events.append('mount-called'); raise runner.subprocess.TimeoutExpired(argv,5)
            with patch.object(runner,'output_mount_identity',side_effect=[None,PermissionError(13,'ambiguous')],create=True), \
                 patch.object(runner.subprocess,'run',side_effect=command):
                with self.assertRaises((PermissionError,runner.subprocess.TimeoutExpired)): p.mount_output()
            self.assertEqual(events,['mount-called']); self.assertIsNotNone(p.output_mount)
            with patch.object(runner,'output_mount_identity',side_effect=PermissionError(13,'ambiguous'),create=True), \
                 patch.object(FaultProbe,'cleanup') as cleanup:
                with self.assertRaises(PermissionError): p.cleanup()
            cleanup.assert_not_called()

    def test_mount_success_first_stat_failure_is_pending_not_absent(self):
        with tempfile.TemporaryDirectory() as directory:
            p=self.probe(Path(directory)); identity=self.identity(p)
            with patch.object(runner,'output_mount_identity',side_effect=[None,PermissionError(13,'first stat')],create=True), \
                 patch.object(runner.subprocess,'run',return_value=Mock(returncode=0)):
                with self.assertRaises(PermissionError): p.mount_output()
            self.assertEqual(p.output_mount['state'],'pending')
            with patch.object(runner,'output_mount_identity',return_value={**identity,'source':'foreign'},create=True), \
                 patch.object(FaultProbe,'cleanup') as cleanup,patch.object(runner.subprocess,'run') as command:
                with self.assertRaises(ValueError): p.cleanup()
            cleanup.assert_not_called(); command.assert_not_called()


class SpaceProbeTests(unittest.TestCase):
    def test_f20_actual_output_exercise_keeps_strict_empty_target_with_real_probe(self):
        import run_resource_failures as resource
        with tempfile.TemporaryDirectory() as directory:
            p=runner.StorageProbe.__new__(runner.StorageProbe); p.root=Path(directory); p.prefix='cycle2-owned'; p.result={}
            (p.root/'backend/local').mkdir(parents=True)
            p.config=lambda:None; p.restic=lambda *args:None; p.startpg=lambda *args:'c'*64; p.sql=lambda *args:None
            obj={'Id':'c'*64,'State':{'Running':True,'StartedAt':'unit'},'RestartCount':0}
            p.e=Mock(); p.e.inspect.return_value=obj; p.e.call.return_value={'Name':'cycle2-owned-files'}
            p.e.exec.side_effect=lambda cid,argv:{'exit':0,'stdout':'1'*64+'  /data/payload\n'} if argv[0]=='sha256sum' else {'exit':0}
            # This test isolates output/empty-target behavior; the separate
            # Engine composition regression exercises the real mount helper.
            p.volumes=[]; p.create_file_source=lambda *args,**kwargs:'d'*64
            p.call_cli=lambda *args:{'targets':[{'ID':'unit/files','Kind':'volume'}]}
            p.plan_projection=lambda target:{'ID':target['ID']}; p.success_snapshot=lambda:'f'*64
            p.snapshot_mapping=lambda snapshot:None; p.mount_output=lambda:None
            probes=[]; events=[]
            def create_probe(path):
                value=resource.OwnedSpaceProbe(path); probes.append(value); return value
            def controller(*argv):
                self.assertEqual(list(p.output_path.iterdir()),[], 'production rejects every destination entry')
                self.assertEqual(os.fstat(probes[0].fd).st_nlink,0)
                self.assertEqual(argv,('restore','--snapshot','f'*64,'--directory',str(p.output_path)))
                events.append('restore'); return 'controller'
            def finish(cid):
                self.assertEqual(cid,'controller'); self.assertEqual(os.fstat(probes[0].fd).st_nlink,0)
                self.assertEqual(probes[0].sample()['write_errno'],0); events.append('terminal')
            p.controller=controller; p.finish_attempt=finish
            with patch.object(runner,'OwnedSpaceProbe',side_effect=create_probe),patch.object(runner,'space',return_value={'capacity_bytes':8388608,'available_bytes':8388608,'device':55,'inode':1}):
                p.exercise_output()
            self.assertEqual(events,['restore','terminal']); self.assertIsNone(probes[0].fd)
            self.assertEqual(list(p.output_path.iterdir()),[])
            self.assertEqual(p.result['storage']['direct_write']['write_errno'],0) # No pressure claim.

    def test_open_unlinked_probe_retains_owned_fd_for_typed_write_enospc(self):
        import run_resource_failures as resource
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            with resource.OwnedSpaceProbe(root) as probe:
                self.assertTrue(callable(getattr(probe,'unlink_while_open',None)), 'missing owned unlink operation')
                probe.unlink_while_open()
                self.assertEqual(list(root.iterdir()),[]); self.assertEqual(os.fstat(probe.fd).st_nlink,0)
                self.assertEqual(probe.sample()['write_errno'],0)
                with patch.object(resource.os,'write',side_effect=OSError(28,'write only')):
                    self.assertTrue(resource.is_write_enospc(json.loads(json.dumps(probe.sample()))))
                replacement=root/probe.name; replacement.write_bytes(b'FOREIGN')
            self.assertEqual(replacement.read_bytes(),b'FOREIGN')

    def test_unlink_while_open_rejects_entry_drift_and_preserves_foreign_replacement(self):
        import run_resource_failures as resource
        for kind in ('foreign','symlink','hardlink'):
            with self.subTest(kind=kind),tempfile.TemporaryDirectory() as directory:
                root=Path(directory); probe=resource.OwnedSpaceProbe(root); entry=root/probe.name
                if kind=='hardlink': os.link(entry,root/'extra')
                else:
                    entry.unlink()
                    if kind=='foreign': entry.write_bytes(b'FOREIGN')
                    else:
                        (root/'foreign').write_bytes(b'FOREIGN'); entry.symlink_to(root/'foreign')
                with patch.object(resource.os,'unlink',wraps=os.unlink) as unlink:
                    with self.assertRaises(ValueError): probe.unlink_while_open()
                    unlink.assert_not_called()
                    with self.assertRaises(ValueError): probe.close()
                    unlink.assert_not_called()
                self.assertIsNone(probe.fd); self.assertTrue(entry.exists())
                if kind!='hardlink': self.assertEqual(entry.read_bytes(),b'FOREIGN')

    def test_unlink_while_open_rejects_directory_path_drift_but_cleanup_stays_pinned(self):
        import run_resource_failures as resource
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); original=root/'output'; original.mkdir()
            probe=resource.OwnedSpaceProbe(original); original.rename(root/'old')
            original.mkdir(); replacement=original/probe.name; replacement.write_bytes(b'FOREIGN')
            with self.assertRaisesRegex(ValueError,'directory changed'): probe.unlink_while_open()
            probe.close()
            self.assertEqual(replacement.read_bytes(),b'FOREIGN'); self.assertEqual(list((root/'old').iterdir()),[])

    def test_open_unlinked_probe_rechecks_zero_links_before_sample_and_close(self):
        import run_resource_failures as resource
        with tempfile.TemporaryDirectory() as directory:
            probe=resource.OwnedSpaceProbe(Path(directory)); probe.unlink_while_open()
            with patch.object(resource.os,'fstat',return_value=Mock(st_nlink=1)), \
                 patch.object(resource.os,'write') as write,patch.object(resource.os,'unlink') as unlink:
                with self.assertRaisesRegex(ValueError,'relinked'): probe.sample()
                with self.assertRaisesRegex(ValueError,'relinked'): probe.close()
                write.assert_not_called(); unlink.assert_not_called()
            self.assertIsNone(probe.fd)
            with self.assertRaisesRegex(ValueError,'closed'): probe.unlink_while_open()

    def test_open_unlinked_probe_uses_duplicated_directory_fd_and_rejects_second_unlink(self):
        import run_resource_failures as resource
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); directory_fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
            try: probe=resource.OwnedSpaceProbe(directory_fd)
            finally: os.close(directory_fd)
            with probe:
                probe.unlink_while_open()
                with self.assertRaisesRegex(ValueError,'already unlinked'): probe.unlink_while_open()
                self.assertEqual(probe.sample()['write_errno'],0); self.assertEqual(list(root.iterdir()),[])

    def test_create_enospc_never_claims_write_attempt(self):
        import run_resource_failures as resource
        with tempfile.TemporaryDirectory() as directory:
            original=os.open
            def opening(path,*args,**kwargs):
                if args and args[0] & os.O_CREAT: raise OSError(28,'create only')
                return original(path,*args,**kwargs)
            with patch.object(resource.os,'open',side_effect=opening),patch.object(resource.os,'write') as write:
                row=resource.minimal_space_probe(Path(directory))
            write.assert_not_called(); self.assertIs(row.get('write_attempted'),False)
            self.assertEqual(row.get('attempt_bytes'),0); self.assertEqual(row.get('create_errno'),28)
            self.assertIsNone(row.get('write_errno'))

    def test_exclusive_collision_never_unlinks_unowned_entry(self):
        import run_resource_failures as resource
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            # Preserve a collision under both the old deterministic name and
            # the new bounded random-name strategy.
            old=root/('.owned-space-probe-'+str(os.getpid())+'-'+str(__import__('threading').get_ident()))
            collision=root/('.owned-space-probe-'+'a'*24)
            old.write_bytes(b'UNOWNED'); collision.write_bytes(b'UNOWNED')
            with patch.object(resource.secrets,'token_hex',return_value='a'*24):
                with self.assertRaises(FileExistsError): resource.minimal_space_probe(root)
            self.assertTrue(old.exists()); self.assertEqual(old.read_bytes(),b'UNOWNED')
            self.assertEqual(collision.read_bytes(),b'UNOWNED')

    def test_precreated_descriptor_proves_literal_write_errno_and_owns_cleanup(self):
        import run_resource_failures as resource
        with tempfile.TemporaryDirectory() as directory:
            probe=resource.OwnedSpaceProbe(Path(directory))
            with patch.object(resource.os,'write',side_effect=OSError(28,'write only')) as write:
                row=probe.sample()
            write.assert_called_once(); self.assertIs(row['write_attempted'],True)
            self.assertEqual(row['write_errno'],28); self.assertEqual(row['create_errno'],0)
            self.assertEqual(row['attempt_bytes'],1); self.assertTrue(resource.is_write_enospc(json.loads(json.dumps(row))))
            probe.close(); self.assertEqual(list(Path(directory).iterdir()),[])

    def test_storage_verifier_rejects_creation_only_and_bool_write_claims(self):
        from test_hosted_storage_prereqs import synthetic
        from verify_hosted_storage_prereqs import verify_case
        row=synthetic()
        row['storage']['direct_write']={'stage':'create','write_attempted':False,'attempt_bytes':0,'create_errno':28,'write_errno':None,'errno':28}
        with self.assertRaises(ValueError): verify_case(json.loads(json.dumps(row)))
        for key,value in [('write_attempted',1),('attempt_bytes',True),('create_errno',False),('write_errno',True),('errno',True),('stage','create')]:
            row=synthetic(); row['storage']['direct_write'][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError): verify_case(json.loads(json.dumps(row)))

    def test_pinned_directory_cleanup_does_not_follow_replaced_entry(self):
        import run_resource_failures as resource
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); probe=resource.OwnedSpaceProbe(root)
            owned=next(root.iterdir()); owned.unlink(); owned.write_bytes(b'FOREIGN')
            with self.assertRaises(ValueError): probe.close()
            self.assertEqual(owned.read_bytes(),b'FOREIGN')


def extension_receipt():
    import test_hosted_storage_prereqs as fixtures
    captured=[]
    class Captured(Exception): pass
    def capture(row): captured.append(copy.deepcopy(row)); raise Captured()
    case=fixtures.StorageVerifierTests('test_f22_missing_binary_is_not_missing_role_or_nonempty_extension_and_same_target_recovers')
    case.module=lambda:Mock(verify_case=capture)
    try: case.test_f22_missing_binary_is_not_missing_role_or_nonempty_extension_and_same_target_recovers()
    except Captured: pass
    return json.loads(json.dumps(captured[0]))


class ExtensionTests(unittest.TestCase):
    def test_killed_timeout_and_unrelated_error_do_not_prove_missing_library(self):
        from verify_hosted_storage_prereqs import verify_case
        for code in (137,143,124,2,True):
            row=extension_receipt(); row['attempts'][0]['terminal']['exec_exit_code']=code
            # Keep correlated record consistent: rejection must be causal.
            a=row['attempts'][0]['owner']
            record=next(r for r in row['relay']['records'] if r.get('container_id')==a['workerContainerID'] and r.get('boundary')=='worker-remove')
            record['terminal_before_remove']=copy.deepcopy(row['attempts'][0]['terminal'])
            with self.subTest(code=code),self.assertRaises(ValueError): verify_case(row)
        for path,value in [(('complete',),False),(('complete',),1),(('error_count',),True),(('cause',),'unclassified')]:
            row=extension_receipt()
            record=row['relay']['records'][0]
            record['import_diagnostic'][path[0]]=value
            row['extension']['failure_cause']=copy.deepcopy(record['import_diagnostic'])
            with self.subTest(diagnostic=path,value=value),self.assertRaises(ValueError): verify_case(row)
        row=extension_receipt(); row['extension']['failure_cause']={'cause':'unclassified','complete':True}
        with self.assertRaises(ValueError): verify_case(row)

    def test_catalog_boolean_and_cause_types_are_not_python_equality_aliases(self):
        from verify_hosted_storage_prereqs import verify_case
        row=extension_receipt()
        row['extension']['catalog_after_failure']['namespace_policies'][0]['acl'][0]['grant_option']=0
        with self.assertRaises(ValueError): verify_case(row)
        row=extension_receipt(); row['extension']['failure_cause']['error_count']=True
        with self.assertRaises(ValueError): verify_case(row)

    def test_same_container_is_not_same_database_or_fresh_full_catalog(self):
        from verify_hosted_storage_prereqs import verify_case
        for key,value in [('database_after_failure',{'cluster_id':'2','database_oid':'999','database':'fixture'}),
                          ('catalog_after_failure',{'objects':[{'name':'availability_probe'}]}),
                          ('catalog_before_retry',{'objects':[]}),('catalog_before',{})]:
            row=extension_receipt(); row['extension'][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError): verify_case(row)

    def test_actual_extension_runner_checks_full_baseline_before_restoring_library(self):
        from verify_hosted_storage_prereqs import restore_contract
        baseline,_=restore_contract(); database={'cluster_id':'123','database_oid':'16384','database':'fixture'}
        for fault in ('catalog','database'):
            with self.subTest(fault=fault):
                p=runner.StorageProbe.__new__(runner.StorageProbe); p.source='c'*64; p.result={}; events=[]
                p.success_snapshot=lambda:'f'*64; p.snapshot_mapping=lambda value:None; p.startpg=lambda *args:'e'*64
                p.target_identity=lambda target:{'container_id':target,'started_at':'target','restart_count':0}
                p.library_hash=lambda target:'6'*64; p.e=Mock(); p.e.exec.return_value={'exit':0}
                def sql(target,query):
                    if 'server_version_num' in query:return '18'
                    if 'SELECT rolname,oid' in query:return 'source' if target==p.source else 'target'
                    if 'SELECT count(*) FROM pg_extension' in query:return '0'
                    if 'SELECT extversion' in query:return '1.8'
                    return 'fixed-fixture-data'
                p.sql=sql
                def action(target,operation,identity):
                    events.append(operation)
                    if operation=='prepare': raise AssertionError('library restored before fresh DB proof')
                    return 1
                p.extension_action=action; p.controller=lambda *args:'controller'
                receipt=extension_receipt(); failed=receipt['attempts'][0]; p.finish_attempt=lambda *args,**kwargs:failed
                p.relay=Mock(); p.relay.snapshot.return_value=receipt['relay']
                bad=copy.deepcopy(baseline); bad['objects']=[{'name':'availability_probe'}]
                p.database_identity=Mock(side_effect=[database,{**database,'database_oid':'999'} if fault=='database' else database])
                p.catalog=Mock(side_effect=[copy.deepcopy(baseline),bad if fault=='catalog' else copy.deepcopy(baseline)])
                with self.assertRaisesRegex(ValueError,'retry forbidden'): p.exercise_extension()
                self.assertEqual(events,['hide']); self.assertEqual(p.catalog.call_count,2)
                self.assertEqual(p.database_identity.call_count,2)
                self.assertNotIn('database_not_deleted',p.result['extension'])

    def test_actual_runner_relay_classifies_only_exact_stderr_and_forwards_identical_bytes(self):
        import socket
        import threading
        import time
        from run_hosted_faults import FaultRelay,read_headers,read_exact
        row=extension_receipt(); active=row['attempts'][0]['owner']; eid=active['execID']; target=active['sourceContainerID']
        p=runner.StorageProbe.__new__(runner.StorageProbe)
        p.case=runner.F22; p.tracking=True; p.capture_missing_library=True; p.extension_target=target
        p.owner=lambda:copy.deepcopy(active); p.operations={}; p.removals={}; p.traces=[]
        p.target_identity=lambda cid:row['extension']['target_before']
        p.e=Mock(); p.e.call.return_value={'ID':eid,'ContainerID':target,'ProcessConfig':{'entrypoint':'/usr/local/bin/pg_restore',
            'arguments':['--no-password','--exit-on-error','--dbname',"host='/var/run/postgresql' port='5432' user='postgres' dbname='fixture'"]}}
        message=runner.MissingLibraryDiagnostic.ERROR+b'\n'+runner.MissingLibraryDiagnostic.COMMAND+b'\n'
        def frame(stream,data):return bytes([stream,0,0,0])+len(data).to_bytes(4,'big')+data
        payload=frame(1,b'PRIVATE_STDOUT_CANARY')+frame(2,message)
        reply=b'HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n'+payload
        body=b'{"Detach":false,"Tty":false}'
        request=('POST /v1.47/exec/'+eid+'/start HTTP/1.1\r\nHost: docker\r\nContent-Length: '+str(len(body))+'\r\n\r\n').encode()+body
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); server=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
            server.bind(str(root/'up.sock')); server.listen(1); wire=[]
            def peer():
                conn,_=server.accept()
                with conn:
                    head,_,fields=read_headers(conn); wire.append(head+read_exact(conn,int(fields['content-length'])))
                    for byte in reply: conn.sendall(bytes([byte]))
                    conn.shutdown(socket.SHUT_WR)
                    while conn.recv(4096): pass
            worker=threading.Thread(target=peer); worker.start()
            relay=FaultRelay(root/'relay.sock',root/'up.sock'); relay.execs[eid]={'kind':'restore','container_id':target,'stdout_bytes':0,'stdin_bytes':0}
            relay.observer=p.observe_transport; relay.stderr_classifier_factory=p.import_stderr_classifier; relay.start()
            try:
                with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as client:
                    client.settimeout(3); client.connect(str(root/'relay.sock')); client.sendall(request); client.shutdown(socket.SHUT_WR)
                    received=b''
                    while True:
                        chunk=client.recv(4096)
                        if not chunk:break
                        received+=chunk
                worker.join(3)
                end=time.monotonic()+2
                while time.monotonic()<end and 'import_diagnostic' not in relay.snapshot()['records'][0]: time.sleep(.01)
                snapshot=relay.snapshot(); record=snapshot['records'][0]
                self.assertEqual(received,reply); self.assertEqual(wire,[request]); self.assertEqual(snapshot['errors'],[])
                self.assertEqual(record.get('import_diagnostic'),{'cause':'hstore_binary_load_missing','complete':True,'error_count':1})
                self.assertEqual(record.get('import_contract'),'pg_restore-fixture-exit-on-error-v1')
                self.assertNotIn('PRIVATE',json.dumps(snapshot)); self.assertNotIn('could not access',json.dumps(snapshot))
            finally: relay.close(); server.close()

    def test_bounded_classifier_requires_actual_load_error_plus_exact_extension_command(self):
        classifier=runner.MissingLibraryDiagnostic()
        message=(b'pg_restore: error: could not execute query: ERROR:  could not access file "$libdir/hstore": No such file or directory\n'
                 b'Command was: CREATE EXTENSION IF NOT EXISTS hstore WITH SCHEMA public;\n\n')
        for byte in message: classifier.feed(bytes([byte]))
        value=classifier.finish()
        self.assertEqual(value,{'cause':'hstore_binary_load_missing','complete':True,'error_count':1})
        for data in [message.replace(b'hstore',b'other'),message.replace(b'CREATE EXTENSION',b'DROP EXTENSION'),
                     message+b'pg_restore: error: unrelated PRIVATE_ERROR\n',b'PRIVATE_CANARY'*5000,message[:-1]]:
            c=runner.MissingLibraryDiagnostic(); c.feed(data)
            projected=c.finish()
            if data==message[:-1]: continue  # Full command line still ended.
            self.assertEqual(projected['cause'],'unclassified')
            self.assertNotIn('PRIVATE',json.dumps(projected))


if __name__=='__main__': unittest.main()
