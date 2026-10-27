"""F19/F20/F22 offline regressions, never hosted acceptance evidence."""
import importlib
import os
from pathlib import Path
import subprocess
import unittest


class TraceTests(unittest.TestCase):
    def module(self):
        try:
            return importlib.import_module('hosted_storage_trace')
        except ImportError:
            self.fail('bounded syscall projection is missing')

    def test_real_kernel_enospc_is_projected_without_payload_or_raw_path(self):
        m = self.module()
        cp = subprocess.run(['strace','-qq','-f','-yy','-s','0','-e','trace=write,pwrite64,writev',
                             '-e','status=failed','python3','-c',
                             'import os; f=os.open("/dev/full",os.O_WRONLY); os.write(f,b"PRIVATE-CANARY")'],
                            stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        self.assertEqual(cp.returncode,1)
        lines=[line for line in cp.stderr.splitlines() if 'ENOSPC' in line and line.startswith('write(')]
        self.assertEqual(len(lines),1)
        row=m.project_write(lines[0],root_pid=os.getpid(),path_kind=lambda p:'unit-full' if p.startswith('/dev/full') else None)
        self.assertEqual(row['errno'],28)
        self.assertEqual(row['path_kind'],'unit-full')
        self.assertNotIn('PRIVATE',str(row)); self.assertNotIn('/dev/full',str(row))
        self.assertIsNone(m.project_write('write(3</tmp/else>, "secret", 2) = -1 EIO (I/O error)',root_pid=1,path_kind=lambda p:'temporary'))


    def test_multithread_unfinished_syscall_pairs_cannot_lose_or_rebind_enospc(self):
        m=self.module()
        self.assertTrue(hasattr(m,'WriteStream'),'multithread syscall pairing missing')
        stream=m.WriteStream(10,lambda p:'temp_pack' if p.startswith('/tmp/restic-temp-pack-') else None)
        self.assertIsNone(stream.feed('[pid 12] write(6</tmp/restic-temp-pack-a (deleted)>, ""..., 4096 <unfinished ...>'))
        row=stream.feed('[pid 12] <... write resumed>) = -1 ENOSPC (No space left on device)')
        self.assertEqual(row,{'pid':12,'syscall':'write','fd':6,'errno':28,'path_kind':'temp_pack'})
        with self.assertRaises(ValueError): stream.feed('[pid 13] <... write resumed>) = -1 ENOSPC (No space left on device)')

    def test_attach_and_detach_real_owned_process_retains_numeric_kernel_failure(self):
        import tempfile
        import time
        m = self.module()
        self.assertTrue(hasattr(m,'WriteTrace'),'owned trace lifecycle missing')
        with tempfile.TemporaryDirectory() as directory:
            gate=Path(directory)/'go'
            child=subprocess.Popen(['python3','-c',
                "import ctypes,os,time,pathlib; ctypes.CDLL(None).prctl(0x59616d61,-1,0,0,0); print('ready',flush=True); "
                "\nwhile not pathlib.Path("+repr(str(gate))+").exists(): time.sleep(.01)\n"
                "f=os.open('/dev/full',os.O_WRONLY)\ntry: os.write(f,b'PRIVATE')\nexcept OSError: pass\ntime.sleep(.1)"],
                stdout=subprocess.PIPE,text=True)
            try:
                self.assertEqual(child.stdout.readline().strip(),'ready')
                trace=m.WriteTrace([child.pid],lambda p:'unit-full' if p.startswith('/dev/full') else None)
                trace.start(); gate.touch(); self.assertEqual(child.wait(5),0); trace.finish()
                self.assertEqual(trace.receipt()['errors'],[])
                self.assertTrue(trace.receipt()['attached'])
                self.assertEqual(trace.receipt()['writes'][0]['errno'],28)
            finally:
                if child.poll() is None: child.kill(); child.wait()
                child.stdout.close()


F19='temp-pack-ENOSPC'
F20='restore-output-ENOSPC'
F22='restore-missing-extension-binary-prerequisites'
LOGICAL='fixture/compose/project/files/volume/data'


def synthetic(case=F19):
    # Synthetic offline schema only; never written to a hosted runtime directory.
    import hashlib
    a={'runID':'a'*32,'workerContainerID':'b'*64,'workerName':'bakabel-worker-'+'a'*32,
       'daemonID':'unit-daemon','workerStartAuthorized':True,'phase':'exec_started','status':'active',
       'sourceContainerID':'c'*64,'sourceStartedAt':'source-start','execID':'d'*64,'execKind':'dump',
       'targetID':hashlib.sha256(LOGICAL.encode()).hexdigest()}
    worker={'container_id':'b'*64,'image_id':'sha256:'+'2'*64,'run_id':a['runID'],
            'memory_bytes':536870912,'nanocpus':2000000000,'cpu.max':'200000 100000','memory.max':'536870912',
            'socket':{'source':'/unit/relay.sock','destination':'/run/bakabel/docker.sock','read_only':True}}
    obs={'container_id':'b'*64,'running':False,'pid':0,'exit_code':1,'started_at':'worker-start'}
    term={'daemon':'unit-daemon','container_id':'c'*64,'started_at':'source-start','exec_id':'d'*64,
          'exec_exit_code':1,'sessions':0,'processes':0}
    removal={'method':'DELETE','boundary':'worker-remove','container_id':'b'*64,'forwarded':True,'status':204,
             'remove_query':'','remove_query_valid':True,'remove_force':False,'remove_volumes':False,
             'owner_before_remove':a,'execution_owner':a,'worker_before_remove':obs,'terminal_before_remove':term}
    fs={'type':'tmpfs','capacity_bytes':67108864,'available_bytes':0,'device':55,'inode':1}
    trace={'root_pids':[123],'start_ticks':{'123':'42'},'attached':True,'quiescent':True,'errors':[],
           'writes':[{'pid':124,'syscall':'write','fd':5,'errno':28,'path_kind':'temp_pack',
                      'writer':{'root_pid':123,'chain':[{'pid':124,'tgid':123,'ppid':1,'start_ticks':'43'},
                                                       {'pid':123,'tgid':123,'ppid':1,'start_ticks':'42'}]}}],
           'worker_id':'b'*64,'worker_pid':123,'worker_started_at':'worker-start'}
    result={'runID':a['runID'],'status':'failed','targets':[{'targetID':LOGICAL,'status':'unknown','error':'backup failed'}]}
    return {'schema':1,'case':case,'status':'pass','exercised':True,'ordinary_image':True,'request_mutations':[],
        'backend':'local','platform':'compose','daemon':'unit-daemon','source_sha256':'1'*64,'image_id':'sha256:'+'2'*64,
        'source':{'container_id':'c'*64,'started_at':'source-start','restart_count':0},'source_unchanged':True,
        'workers':{'b'*64:worker},'relay':{'errors':[],'records':[
            {'boundary':'dump-start','method':'POST','forwarded':True,'status':101,'exec_id':a['execID'],'owner_checkpoint':a},removal]},
        'mapping':{'plan':{'ID':LOGICAL,'Kind':'postgres','Source':{'DaemonID':'unit-daemon','ContainerID':'c'*64,'StartedAt':'source-start'}}},
        'attempts':[{'owner':a,'result':result,'cli_exit':1,'worker_absent':True,'owner_released':True,
                     'last_success_unchanged':True,'terminal':term}],
        'storage':{'before':{**fs,'available_bytes':67108864},'full':fs,'filler_bytes':67108864,'direct_errno':28,
                   'direct_write':{'stage':'write','write_attempted':True,'attempt_bytes':1,'create_errno':0,'write_errno':28,'errno':28,'capacity_bytes':67108864,'available_bytes':0},
                   'trace':trace,'no_cache':True,'pack_size_mib':4,'worker_tmpfs':'rw,nosuid,nodev,size=67108864',
                   'repository_device':99,'pressure_retained_until_terminal':True,'dump_lock_wait_observed':True},
        'no_complete_snapshot':True,'repository_run_token':a['runID']+'-'+hashlib.sha256(LOGICAL.encode()).hexdigest(),'snapshot_inventory':[],
        'cleanup':{'containers_absent':{'b'*64:True,'c'*64:True},
        'volumes_absent':{'owned':True},'private_paths_absent':True,'source_removed_only_after_gate':True}}


class StorageVerifierTests(unittest.TestCase):
    def module(self):
        try: return importlib.import_module('verify_hosted_storage_prereqs')
        except ImportError: self.fail('independent storage/prerequisite verifier missing')

    def test_report_does_not_promote_subset_or_wrong_build(self):
        m=self.module()
        self.assertTrue(hasattr(m,'verify_report'),'additive aggregate verifier missing')
        report={'schema':1,'storage_acceptance_pass':True,'full_plan_acceptance_pass':False,
            'source_sha256':'1'*64,'image_id':'sha256:'+'2'*64,'daemon':'unit-daemon',
            'cases':[{'case':F19,'status':'pass'}]}
        with self.assertRaises(ValueError): m.verify_report(report,[synthetic()])

    def test_verifier_rejects_disguised_correlated_removal_or_source_rebinding(self):
        import copy
        m=self.module()
        row=synthetic(); extra=copy.deepcopy(row['relay']['records'][-1]); extra.update(method='GET',boundary='other')
        row['relay']['records'].append(extra)
        with self.assertRaises(ValueError): m.verify_case(row)
        for path,value in [(('mapping','plan','Source','ContainerID'),'9'*64),
            (('attempts',0,'owner','sourceContainerID'),'9'*64),
            (('storage','trace','writes',0,'errno'),True)]:
            row=synthetic(); item=row
            for k in path[:-1]: item=item[k]
            item[path[-1]]=value
            with self.subTest(path=path),self.assertRaises(ValueError): m.verify_case(row)

    def test_source_snapshot_and_restic_identity_are_required_not_only_booleans(self):
        import copy
        m=self.module()
        for key in ('snapshot_inventory','repository_run_token'):
            row=synthetic(); row.pop(key,None)
            with self.subTest(missing=key),self.assertRaises(ValueError): m.verify_case(row)

    def test_f19_accepts_only_actual_temp_syscall_enospc_and_terminal_before_release(self):
        import copy
        m=self.module(); m.verify_case(synthetic())
        mutations=[(('storage','trace','writes'),[]),(('storage','trace','attached'),False),
            (('storage','trace','errors'),['trace_reader']),(('storage','full','capacity_bytes'),0),
            (('storage','direct_errno'),0),(('storage','no_cache'),False),
            (('storage','pack_size_mib'),16),(('storage','pressure_retained_until_terminal'),False),
            (('no_complete_snapshot',),False),(('attempts',0,'cli_exit'),0),
            (('attempts',0,'terminal','sessions'),True),(('source_unchanged',),False),
            (('relay','records',1,'remove_query'),'force=true'),
            (('relay','records',1,'owner_before_remove','workerStartAuthorized'),False),
            (('storage','trace','writes',0,'path_kind'),'repository'),
            (('storage','trace','worker_id'),'e'*64),(('storage','trace','worker_pid'),True)]
        for path,value in mutations:
            row=copy.deepcopy(synthetic()); selected=row
            for key in path[:-1]: selected=selected[key]
            selected[path[-1]]=value
            with self.subTest(path=path),self.assertRaises(ValueError): m.verify_case(row)


    def test_f20_requires_bounded_output_syscall_partial_retention_and_frozen_job(self):
        import copy
        row=synthetic(F20); a=row['attempts'][0]['owner']; a['targetID']=''; a['phase']='intent'
        for k in ('sourceContainerID','sourceStartedAt','execID','execKind'): a.pop(k)
        row['mapping']['plan']['Kind']='volume'
        row['mapping']['snapshot']={'snapshotID':'f'*64,'source':LOGICAL,'type':'volume','status':'complete',
            'metadata':{'version':1,'kind':'volume','source':LOGICAL}}
        row['mapping']['job']={'runID':a['runID'],'targetID':LOGICAL,'snapshotID':'f'*64,'directory':'/unit/output'}
        row['attempts'][0]['result']['targets'][0]['snapshotID']='f'*64
        removed=row['relay']['records'][-1]; removed.pop('terminal_before_remove'); removed.pop('execution_owner')
        row['relay']['records']=[removed]; row['attempts'][0].pop('terminal')
        fs={'type':'tmpfs','capacity_bytes':8388608,'available_bytes':8388608,'device':88,'inode':2}
        trace=row['storage']['trace']; trace['writes'][0]['path_kind']='restore_output'
        row['storage']={'before':fs,'full':{**fs,'available_bytes':0},'trace':trace,'direct_errno':28,
            'direct_write':{'stage':'write','write_attempted':True,'attempt_bytes':1,'create_errno':0,'write_errno':28,'errno':28,'capacity_bytes':8388608,'available_bytes':0},
            'repository_device':99,'partial_retained':{'directory':'/unit/output','device':88,'inode':2,'files':1,'allocated_bytes':8388608},
            'source_file_unchanged':True,'output_unmounted_after_cleanup':True}
        m=self.module()
        try: m.verify_case(row)
        except (ValueError,NameError): self.fail('F20 output-specific identity/verification is missing')
        for path,value in [(('storage','partial_retained','files'),0),(('storage','partial_retained','device'),99),
            (('storage','output_unmounted_after_cleanup'),False),(('mapping','job','snapshotID'),'e'*64),
            (('mapping','snapshot','metadata','source'),'foreign'),(('storage','trace','writes'),[]),
            (('storage','direct_errno'),0),(('storage','source_file_unchanged'),False)]:
            changed=copy.deepcopy(row); item=changed
            for k in path[:-1]: item=item[k]
            item[path[-1]]=value
            with self.subTest(path=path),self.assertRaises(ValueError): m.verify_case(changed)


    def test_f22_missing_binary_is_not_missing_role_or_nonempty_extension_and_same_target_recovers(self):
        import copy
        row=synthetic(F22); row.pop('storage'); row.pop('no_complete_snapshot')
        row['mapping']['snapshot']={'snapshotID':'f'*64,'source':LOGICAL,'type':'postgres','status':'complete',
            'metadata':{'version':1,'kind':'postgres','source':LOGICAL}}
        a=row['attempts'][0]['owner']; a.update(execKind='restore',sourceContainerID='e'*64,sourceStartedAt='target-start',importRunID='restore_'+'f'*48)
        terminal=row['attempts'][0]['terminal']; terminal.update(container_id='e'*64,started_at='target-start')
        row['relay']['records'][0].update(boundary='restore-start')
        row['attempts'][0]['result']['targets'][0]['snapshotID']='f'*64
        second=copy.deepcopy(row['attempts'][0]); b=second['owner']; b.update(runID='1'*32,workerContainerID='2'*64,workerName='bakabel-worker-'+'1'*32,execID='3'*64,importRunID='restore_'+'4'*48)
        second.update(cli_exit=0); second['result'].update(runID=b['runID'],status='restored')
        second['result']['targets'][0].update(status='restored',error=''); second['terminal'].update(exec_id=b['execID'],exec_exit_code=0)
        row['attempts'].append(second)
        worker=copy.deepcopy(row['workers']['b'*64]); worker.update(container_id='2'*64,run_id='1'*32); row['workers']['2'*64]=worker
        removed=copy.deepcopy(row['relay']['records'][-1]); removed.update(container_id='2'*64,owner_before_remove=b,execution_owner=b,terminal_before_remove=second['terminal'])
        removed['worker_before_remove'].update(container_id='2'*64,exit_code=0)
        row['relay']['records'].extend([{'boundary':'restore-start','method':'POST','forwarded':True,'status':101,'exec_id':b['execID'],'owner_checkpoint':b},removed])
        row['cleanup']['containers_absent'].update({'2'*64:True,'e'*64:True})
        target={'container_id':'e'*64,'started_at':'target-start','restart_count':0}
        row['extension']={'name':'hstore','source_major':18,'target_major':18,'source_installed_version':'1.8',
            'target_versions':['1.8'],'library_sha256':'6'*64,'library_after_sha256':'6'*64,'control_present':True,
            'library_missing_exit':1,'library_present_exit':0,'roles_prepared_before_failure':True,
            'target_before':target,'target_after_failure':target,'target_after_prepare':target,'target_after_restore':target,
            'installed_before':0,'installed_after_failure':0,'payload_after_failure':False,
            'operator_action':'restore-owned-hidden-library','database_not_deleted':True,
            'source_data':'300000|45000150000|'+('8'*32),'target_data':'300000|45000150000|'+('8'*32),
            'table_owner':'fixture_owner','reader_select':True,'database_owner':'postgres','database_acl_matches':True,
            'extension_function':True,'role_oids_differ':True}
        from verify_hosted_storage_prereqs import restore_contract
        baseline,_=restore_contract()
        database={'cluster_id':'123456','database_oid':'16384','database':'fixture'}
        row['extension'].update({k:copy.deepcopy(baseline) for k in ('catalog_before','catalog_after_failure','catalog_before_retry')})
        row['extension'].update({k:dict(database) for k in ('database_before','database_after_failure','database_before_retry','database_after_restore')})
        diagnostic={'cause':'hstore_binary_load_missing','complete':True,'error_count':1}
        row['extension']['failure_cause']=diagnostic
        row['relay']['records'][0].update(container_id='e'*64,import_contract='pg_restore-fixture-exit-on-error-v1',import_diagnostic=diagnostic)
        m=self.module()
        try: m.verify_case(row)
        except (NameError,ValueError): self.fail('F22 binary-prerequisite verifier missing')
        for path,value in [(('extension','library_missing_exit'),0),(('extension','installed_before'),1),
            (('extension','roles_prepared_before_failure'),False),(('extension','target_after_prepare','started_at'),'replacement'),
            (('extension','database_not_deleted'),False),(('extension','library_after_sha256'),'9'*64),
            (('extension','source_data'),'foreign'),(('extension','extension_function'),False),
            (('attempts',0,'terminal','exec_exit_code'),0),(('attempts',1,'result','status'),'failed')]:
            changed=copy.deepcopy(row); item=changed
            for k in path[:-1]: item=item[k]
            item[path[-1]]=value
            with self.subTest(path=path),self.assertRaises(ValueError): m.verify_case(changed)


class RunnerTests(unittest.TestCase):
    def module(self):
        try: return importlib.import_module('run_hosted_storage_prereqs')
        except ImportError: self.fail('runtime-capable additive runner missing')

    def test_temporary_pressure_refuses_ordinary_host_filesystem_before_write(self):
        import tempfile
        m=self.module()
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError): m.fill_temporary(Path(directory),{'type':'tmpfs','capacity_bytes':67108864,'device':-1,'inode':1})
            self.assertEqual(list(Path(directory).iterdir()),[])

    def test_space_readback_uses_parent_descriptor_and_fill_accepts_pinned_fd(self):
        import tempfile
        m=self.module()
        fd=os.open('/dev/shm',os.O_RDONLY|os.O_DIRECTORY)
        try:
            direct=m.space(Path('/dev/shm'))
            self.assertEqual(m.space(Path(f'/proc/{os.getpid()}/fd/{fd}')),direct)
        finally: os.close(fd)
        with tempfile.TemporaryDirectory() as directory:
            fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY)
            try:
                try:
                    with self.assertRaises(ValueError): m.fill_temporary(fd,{'type':'tmpfs'})
                except TypeError: self.fail('pinned FD pressure entrypoint is missing')
            finally: os.close(fd)
            self.assertEqual(list(Path(directory).iterdir()),[])

    def test_real_unix_inventory_boundary_is_observed_before_byte_identical_forwarding(self):
        import socket
        import tempfile
        import threading
        from run_hosted_faults import FaultRelay
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); upstream=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
            upstream.bind(str(root/'up.sock')); upstream.listen(1); received=[]
            request=b'GET /v1.47/containers/json?all=true HTTP/1.1\r\nHost: docker\r\nConnection: close\r\n\r\n'
            def peer():
                conn,_=upstream.accept()
                with conn:
                    data=b''
                    while not data.endswith(b'\r\n\r\n'): data+=conn.recv(4096)
                    received.append(data); conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n[]')
            thread=threading.Thread(target=peer); thread.start()
            relay=FaultRelay(root/'relay.sock',root/'up.sock'); events=[]
            relay.observer=lambda phase,record: events.append((phase,record.get('inventory_all'),record['forwarded']))
            relay.start()
            try:
                with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as client:
                    client.settimeout(3);client.connect(str(root/'relay.sock'));client.sendall(request)
                    result=b''
                    while True:
                        chunk=client.recv(4096)
                        if not chunk: break
                        result+=chunk
                thread.join(3)
                self.assertEqual(received,[request]); self.assertTrue(result.endswith(b'[]'))
                self.assertEqual(events,[('request',True,False),('response',True,True)])
            finally: relay.close(); upstream.close()

    def test_output_case_has_real_mount_and_restore_entrypoint(self):
        m=self.module()
        self.assertTrue(hasattr(m.StorageProbe,'exercise_output'),'F20 runtime fixture missing')

    def test_actual_additive_runner_terminal_callback_precedes_real_unix_delete_forward(self):
        import copy
        import socket
        import tempfile
        import threading
        from run_hosted_faults import FaultRelay
        m=self.module(); row=synthetic(); active=row['attempts'][0]['owner']; cid=active['workerContainerID']
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); upstream=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
            upstream.bind(str(root/'up.sock')); upstream.listen(1); events=[]; wire=[]
            p=m.StorageProbe.__new__(m.StorageProbe)
            p.case=F22; p.tracking=True; p.operations={active['runID']:active}; p.removals={}; p.traces=[]
            p.result={}; p.image=row['image_id']; p.daemon=row['daemon']; p.sock=str(root/'relay.sock')
            p.owner=lambda: active
            worker={'Id':cid,'Name':'/'+active['workerName'],'Image':p.image,
                'Config':{'Cmd':['_workflow'],'Entrypoint':['/usr/local/bin/bakabel'],
                          'Labels':{'bakabel.worker':'1','bakabel.run':active['runID'],'bakabel.daemon':p.daemon}},
                'HostConfig':{'NanoCpus':2000000000,'Memory':536870912,'AutoRemove':False,'RestartPolicy':{'Name':'no'}},
                'Mounts':[{'Destination':'/run/bakabel/docker.sock','Type':'bind','Source':p.sock,'RW':False}],
                'State':{'Running':False,'Pid':0,'ExitCode':1,'StartedAt':'worker-start'}}
            class PeerEngine:
                def inspect(self,target):
                    if target != cid: raise AssertionError('foreign worker inspection')
                    events.append('worker-terminal-read'); return copy.deepcopy(worker)
            p.e=PeerEngine()
            def terminal(a):
                self.assertEqual(a,active); events.append('exec-terminal-read'); return row['attempts'][0]['terminal']
            p.terminal_proof=terminal
            def peer():
                conn,_=upstream.accept()
                with conn:
                    data=b''
                    while not data.endswith(b'\r\n\r\n'): data+=conn.recv(4096)
                    wire.append(data);events.append('delete-forwarded')
                    conn.sendall(b'HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
            thread=threading.Thread(target=peer); thread.start()
            relay=FaultRelay(root/'relay.sock',root/'up.sock'); relay.workers.add(cid); relay.observer=p.observe_transport; relay.start()
            request=('DELETE /v1.47/containers/'+cid+'?force=false&v=false HTTP/1.1\r\nHost: docker\r\nConnection: close\r\n\r\n').encode()
            try:
                with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as client:
                    client.settimeout(3);client.connect(str(root/'relay.sock'));client.sendall(request)
                    while client.recv(4096): pass
                thread.join(3)
                self.assertEqual(wire,[request])
                self.assertEqual(events,['worker-terminal-read','exec-terminal-read','delete-forwarded'])
                self.assertEqual(p.removals[active['runID']]['terminal_before_remove'],row['attempts'][0]['terminal'])
                self.assertEqual(relay.snapshot()['errors'],[])
            finally: relay.close();upstream.close()

    def test_extension_override_refuses_backup_source_before_any_exec(self):
        m=self.module()
        self.assertTrue(hasattr(m.StorageProbe,'extension_action'),'owned missing-library fixture missing')
        p=m.StorageProbe.__new__(m.StorageProbe); p.source='c'*64; p.containers={'c'*64:'source'}
        class ForbiddenEngine:
            def inspect(self,*args,**kwargs): raise AssertionError('source inspected for mutation')
            def exec(self,*args,**kwargs): raise AssertionError('source mutation attempted')
        p.e=ForbiddenEngine()
        with self.assertRaises(ValueError): p.extension_action(p.source,'hide',{})
        with self.assertRaises(ValueError): p.extension_action('e'*64,'install-arbitrary',{})

    def test_safe_failure_diagnostics_use_fixed_allowlists_and_null_for_unknown(self):
        m=self.module()
        self.assertTrue(hasattr(m,'safe_failure'),'additive diagnostics must be allowlisted')
        SecretError=type('PRIVATE_CANARY_EXCEPTION',(Exception,),{})
        try: raise SecretError('PRIVATE_CANARY_TEXT')
        except SecretError as exc: value=m.safe_failure(exc)
        self.assertIsNone(value['kind']); self.assertIsNone(value['errno'])
        self.assertNotIn('PRIVATE',str(value))
        self.assertTrue(all(frame['file'] is None and frame['function'] is None for frame in value['frames']))

    def test_cli_refuses_local_execution_before_opening_engine_socket(self):
        runner=Path(__file__).with_name('run_hosted_storage_prereqs.py')
        env={k:v for k,v in os.environ.items() if k not in ('GITHUB_ACTIONS','RUNNER_ENVIRONMENT')}
        cp=subprocess.run(['python3',str(runner),'--socket','/definitely-not-an-engine.sock','--runtime','/unused'],
                          capture_output=True,text=True,env=env)
        self.assertNotEqual(cp.returncode,0,'additive runner must have a fail-closed CLI')
        self.assertIn('GitHub-hosted',cp.stderr)
        self.assertNotIn('Traceback',cp.stderr)

    def test_shared_runner_uses_explicit_additive_verifier_without_weakening_old_default(self):
        import inspect
        from run_hosted_faults import run_case
        self.assertIn('case_verifier',inspect.signature(run_case).parameters,'shared lifecycle needs explicit additive verifier seam')

    def test_separate_additive_cases_leave_original_fourteen_unchanged(self):
        m=self.module()
        from verify_hosted_faults import CASES as old
        from verify_hosted_storage_prereqs import CASES as new
        legacy=('producer-failure-after-output','streaming-worker-SIGKILL','docker-stream-drop',
                'docker-stream-drop-status-unavailable-recovery','worker-create-response-loss','worker-start-response-loss',
                'dump-create-response-loss','dump-start-response-loss','restore-create-response-loss','restore-start-response-loss',
                'backup-vs-restore-and-retention','scheduler-restart-original-deadline',
                'dump-persisted-before-start-worker-SIGKILL','restore-active-import-worker-SIGKILL')
        self.assertEqual(old[:len(legacy)],legacy)
        self.assertEqual(new,(F19,F20,F22))
        self.assertTrue(set(old).isdisjoint(new))
        self.assertTrue(hasattr(m.StorageProbe,'exercise_temp'))


class HostedWiringTests(unittest.TestCase):
    def test_workflow_executes_additive_runner_and_independent_verifier(self):
        root=Path(__file__).resolve().parents[3]
        text=(root/'.github/workflows/acceptance.yaml').read_text()
        self.assertIn('run_hosted_storage_prereqs.py',text,'F19/F20/F22 not wired to real hosted workflow')
        step=next(s for s in text.split('      - name: ') if 'run_hosted_storage_prereqs.py' in s)
        self.assertIn("if: matrix.suite == 'faults'",step)
        self.assertIn('verify_hosted_storage_prereqs.py',step)
        self.assertNotIn('continue-on-error',step)
        self.assertIn('--expected-image-id "$image_id"',step)

    def test_real_exporter_only_copies_named_additive_receipts(self):
        import json
        import tempfile
        import textwrap
        root=Path(__file__).resolve().parents[3]
        text=(root/'.github/workflows/acceptance.yaml').read_text()
        block=text.split('      - name: Export only allowlisted evidence even on failure',1)[1].split('      - uses:',1)[0]
        script=textwrap.dedent(block.split('        run: |\n',1)[1])
        with tempfile.TemporaryDirectory() as directory:
            work=Path(directory); tools=work/'tools';tools.mkdir()
            sudo=tools/'sudo';sudo.write_text('#!/bin/sh\ncase "$1" in --preserve-env=*) shift;; esac\nif [ "$1" = chown ]; then exit 0; fi\nexec "$@"\n');sudo.chmod(0o700)
            storage=work/'bakabel-storage';storage.mkdir()
            (storage/'hosted-storage.json').write_text('{}')
            for case in (F19,F20,F22,'private','not-an-allowlisted-case'):
                target=storage/case;target.mkdir();(target/'receipt.json').write_text(json.dumps({'case':case}))
            (storage/'raw-trace.log').write_text('PRIVATE-TRACE-CANARY')
            cp=subprocess.run(['bash','-eu','-c',script],cwd=root,capture_output=True,text=True,
                env={**os.environ,'RUNNER_TEMP':str(work),'PATH':str(tools)+os.pathsep+os.environ['PATH']})
            self.assertEqual(cp.returncode,0,cp.stderr)
            actual={p.name for p in (work/'bakabel-public').iterdir()}
            self.assertEqual(actual,{'hosted-storage.json',*[('storage-'+case+'.json') for case in (F19,F20,F22)]})
            self.assertNotIn('PRIVATE-TRACE-CANARY',''.join(p.read_text() for p in (work/'bakabel-public').iterdir()))


if __name__ == '__main__': unittest.main()
