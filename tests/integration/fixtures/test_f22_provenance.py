"""Offline F22 contracts, not hosted receipts or Engine responses."""
import copy
import importlib
import unittest

TOKEN='restore_'+'a'*48
CMD=['/usr/local/bin/pg_restore','--no-password','--exit-on-error','--dbname',"host='/var/run/postgresql' port='5432' user='postgres' dbname='fixture'"]
ENV=['PGAPPNAME='+TOKEN,'BAKABEL_RUN_ID='+TOKEN,'PGHOSTADDR=','PGPASSWORD=','PGPASSFILE=/dev/null','PGSERVICEFILE=/dev/null','PGOPTIONS=','PGCONNECT_TIMEOUT=10']

def spec():
    return dict(User='0',Cmd=list(CMD),Env=list(ENV),AttachStdin=True,AttachStdout=True,AttachStderr=True,Tty=False)

class CreateTests(unittest.TestCase):
    def test_exact_create_rejects_every_nonproduction_override(self):
        from run_hosted_storage_prereqs import StorageProbe
        self.assertTrue(hasattr(StorageProbe,'validate_restore_create'),'real transient create validator missing')
        StorageProbe.validate_restore_create(spec(),TOKEN)
        mutations=[('User','postgres'),('Tty',True),('AttachStdin',False),('AttachStdout',1),('AttachStderr',False),
                   ('Cmd',['sh','-c',' '.join(CMD)]),('Cmd',CMD+['--verbose']),('Cmd',[CMD[0].replace('/usr/local/bin','/tmp')]+CMD[1:]),
                   ('Env',ENV+['PGSERVICE=else']),('Env',ENV+['PGPASSWORD=']),('Env',ENV+['LC_ALL=C']),
                   ('Env',ENV+['LD_PRELOAD=/tmp/PRIVATE']),('Env',[v.replace(TOKEN,'restore_'+'b'*48) for v in ENV]),
                   ('Privileged',True),('WorkingDir','/tmp'),('Detach',True)]
        for key,value in mutations:
            s=spec();s[key]=value
            with self.subTest(key=key,value=value),self.assertRaises(ValueError):StorageProbe.validate_restore_create(s,TOKEN)
        for key in spec():
            s=spec();s.pop(key)
            with self.subTest(missing=key),self.assertRaises(ValueError):StorageProbe.validate_restore_create(s,TOKEN)
        with self.assertRaises(ValueError):StorageProbe.validate_restore_create(spec(),'not-import-token')

# Pinned public upstream Config.Env, not private target state.
IMAGE_ENV=['PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin','GOSU_VERSION=1.19',
           'LANG=en_US.utf8','PG_MAJOR=18','PG_VERSION=18.6',
           'PG_SHA256=555610c24d53e4316da5b7d3fc25c279d96856d5e0e23ee308c328c5fa881d9f',
           'DOCKER_PG_LLVM_DEPS=llvm21-dev \t\tclang21','PGDATA=/var/lib/postgresql/18/docker']
PIN='sha256:83148c0bc09eac4d598b70a61e1404d0212b76c95c504bfd6c81a4c59ec91792'
FIXTURE_ENV=['POSTGRES_HOST_AUTH_METHOD=trust','POSTGRES_DB=fixture','POSTGRES_USER=postgres']
BASE=[{'Path':p,'Kind':k} for p,k in [('/run',0),('/run/postgresql',0),('/run/postgresql/.s.PGSQL.5432',1),('/run/postgresql/.s.PGSQL.5432.lock',1)]]
HIDDEN=BASE+[{'Path':p,'Kind':k} for p,k in [('/usr',0),('/usr/local',0),('/usr/local/lib',0),('/usr/local/lib/postgresql',0),('/usr/local/lib/postgresql/hstore.so',2),('/usr/local/lib/postgresql/hstore.so.bakabel-f22-owned',1)]]
def target_config():
    c={'Env':IMAGE_ENV+FIXTURE_ENV,'Entrypoint':['docker-entrypoint.sh'],'Cmd':['postgres'],'User':'','WorkingDir':'/','Tty':False}
    obj={'Image':PIN,'Config':c,'Mounts':[{'Type':'volume','Name':'owned-data','Destination':'/var/lib/postgresql','RW':True,'Driver':'local'}],
         'HostConfig':{'Privileged':False,'Binds':None,'Tmpfs':{},'Devices':[],'VolumesFrom':None}}
    image={'Id':PIN,'Config':{'Env':IMAGE_ENV,'Entrypoint':['docker-entrypoint.sh'],'Cmd':['postgres'],'WorkingDir':'/'}}
    return obj,image

class TargetTests(unittest.TestCase):
    def test_full_pinned_inheritance_mounts_and_layer_not_entrypoint_spelling(self):
        from run_hosted_storage_prereqs import StorageProbe
        self.assertTrue(hasattr(StorageProbe,'validate_restore_target'),'effective target provenance missing')
        obj,image=target_config()
        StorageProbe.validate_restore_target(obj,image,'owned-data',HIDDEN,True)
        StorageProbe.validate_restore_target(obj,image,'owned-data',BASE,False)
        for path,value in [(('Image',),'sha256:'+'9'*64),(('Config','Env'),IMAGE_ENV+FIXTURE_ENV+['PGSERVICE=x']),
            (('Config','Env'),IMAGE_ENV+FIXTURE_ENV+['LANG=en_US.utf8']),
            (('Config','Env'),IMAGE_ENV+FIXTURE_ENV+['LD_PRELOAD=/tmp/PRIVATE']),
            (('Config','Entrypoint'),['sh','-c']),(('Config','User'),'postgres'),
            (('Mounts',),obj['Mounts']+[{'Type':'bind','Destination':'/usr/local/bin','Source':'/tmp/PRIVATE'}]),
            (('Mounts',0,'Name'),'foreign-data'),(('Mounts',0,'RW'),False),(('HostConfig','Privileged'),True)]:
            changed=copy.deepcopy(obj);item=changed
            for key in path[:-1]:item=item[key]
            item[path[-1]]=value
            with self.subTest(path=path),self.assertRaises(ValueError):StorageProbe.validate_restore_target(changed,image,'owned-data',HIDDEN,True)
        for changes in (HIDDEN+[{'Path':'/usr/local/bin/pg_restore','Kind':0}],HIDDEN+[HIDDEN[-1]],BASE,[],
                        [dict(x,Kind=True) if i==0 else x for i,x in enumerate(HIDDEN)]):
            with self.subTest(changes=changes),self.assertRaises(ValueError):StorageProbe.validate_restore_target(obj,image,'owned-data',changes,True)
        for changes in (BASE+[{'Path':p,'Kind':0} for p in ('/usr','/usr/local','/usr/local/lib','/usr/local/lib/postgresql','/usr/local/lib/postgresql/hstore.so')],):
            with self.assertRaises(ValueError):StorageProbe.validate_restore_target(obj,image,'owned-data',changes,False)
        image['Config']['Env']=IMAGE_ENV+['LC_ALL=C']
        with self.assertRaises(ValueError):StorageProbe.validate_restore_target(obj,image,'owned-data',HIDDEN,True)

    def test_owned_volume_options_are_present_null_or_exact_empty_object(self):
        from types import SimpleNamespace
        from run_hosted_storage_prereqs import StorageProbe,PG
        obj,image=target_config(); cid='c'*64
        identity={'container_id':cid,'started_at':'pg-start','restart_count':0}
        obj.update(Id=cid,Name='/owned-target',State={'Running':True,'StartedAt':'pg-start'},RestartCount=0)
        obj['Config']['Labels']={'probe.bakabel.owner':'owned'}
        volume={'Name':'owned-data','Driver':'local','Labels':{'probe.bakabel.owner':'owned'},'Options':None}
        probe=StorageProbe.__new__(StorageProbe)
        probe.extension_target=cid; probe.extension_volume='owned-data'; probe.extension_hidden=False
        probe.source='other-source'; probe.prefix='owned'; probe.daemon='unit-daemon'
        probe.containers={cid:'owned-target'}; probe.roles={cid:'restore-pg'}; probe.volumes=['owned-data']
        probe.result={'images':{PG:PIN},'extension':{'target_before':identity}}
        def call(method,path):
            self.assertEqual(method,'GET')
            return copy.deepcopy({'/volumes/owned-data':volume,'/images/'+PIN+'/json':image,
                '/containers/'+cid+'/changes':BASE,'/info':{'ID':probe.daemon}}[path])
        probe.e=SimpleNamespace(inspect=lambda target:copy.deepcopy(obj),call=call)
        for options in (None,{}):
            volume['Options']=options
            self.assertEqual(probe.restore_target_provenance(),identity)
        missing=object()
        for options in (missing,[],False,0,'',{'type':'nfs'}):
            if options is missing: volume.pop('Options',None)
            else: volume['Options']=options
            with self.subTest(options='missing' if options is missing else options),self.assertRaises(ValueError):
                probe.restore_target_provenance()

class RelayBindingTests(unittest.TestCase):
    def test_optin_transient_hook_binds_real_response_and_unique_start_without_raw_fields(self):
        import tempfile,json
        from pathlib import Path
        from run_hosted_faults import FaultRelay
        with tempfile.TemporaryDirectory() as directory:
            relay=FaultRelay(Path(directory)/'r',Path(directory)/'unused')
            try:
                self.assertTrue(hasattr(relay,'validate_restore_request'),'pre-forward private callback missing')
                events=[]
                def validate(phase,record,value,binding):
                    events.append(phase)
                    if phase=='create':
                        from run_hosted_storage_prereqs import StorageProbe
                        StorageProbe.validate_restore_create(value,TOKEN)
                        return {'schema':1,'import_run_id':TOKEN,'run_id':'b'*32}
                    self.assertEqual(binding['exec_id'],'e'*64)
                    if value != {'Detach':False,'Tty':False}:raise ValueError('bad start')
                    return dict(binding,started=True)
                relay.restore_validator=validate
                create={'boundary':'restore-create','container_id':'c'*64}
                relay.validate_restore_request(create,json.dumps(spec()).encode())
                self.assertNotIn('restore_create',create) # no ID before real response
                relay.bind_restore_response(create,'e'*64)
                self.assertEqual(create['restore_create']['exec_id'],'e'*64)
                start={'boundary':'restore-start','container_id':'c'*64,'exec_id':'e'*64}
                relay.validate_restore_request(start,b'{"Detach":false,"Tty":false}')
                self.assertTrue(start['restore_start']['started'])
                with self.assertRaises(ValueError):relay.validate_restore_request(dict(start),b'{"Detach":false,"Tty":false}')
                with self.assertRaises(ValueError):relay.bind_restore_response(dict(create),'e'*64)
                with self.assertRaises(ValueError):relay.validate_restore_request(dict(create),json.dumps(spec()).encode())
                for body in (b'{"Detach":false,"Detach":true,"Tty":false}', b'{"Detach":false,"Tty":false,"PRIVATE":1}'):
                    # Fresh ID so replay check cannot hide body rejection.
                    relay.restore_bindings['f'*64]=dict(create['restore_create'],exec_id='f'*64)
                    with self.assertRaises((ValueError,AssertionError)):relay.validate_restore_request(dict(start,exec_id='f'*64),body)
                self.assertNotIn('Env',str(relay.snapshot()));self.assertNotIn('PRIVATE',str(relay.snapshot()))
                self.assertEqual(events[:2],['create','start'])
            finally:relay.close()

class CheckpointTests(unittest.TestCase):
    def test_create_owner_and_frozen_job_are_bound_before_start_token_persistence(self):
        import hashlib
        from run_hosted_storage_prereqs import StorageProbe
        self.assertTrue(hasattr(StorageProbe,'validate_restore_checkpoint'),'persisted create/job binding missing')
        target={'container_id':'c'*64,'started_at':'pg-start','restart_count':0}
        a={'runID':'b'*32,'daemonID':'unit-daemon','workerContainerID':'d'*64,'workerName':'bakabel-worker-'+'b'*32,
           'workerStartAuthorized':True,'phase':'creating_exec','status':'active','execKind':'restore',
           'sourceContainerID':'c'*64,'sourceStartedAt':'pg-start','targetID':hashlib.sha256(b'logical').hexdigest()}
        job={'runID':a['runID'],'targets':[{'ID':'logical','Kind':'postgres','Source':{'DaemonID':'unit-daemon','ContainerID':'c'*64,'StartedAt':'pg-start'},'Database':'fixture'}],
             'restore':{'snapshotID':'e'*64,'postgresContainer':'c'*64,'database':'fixture','user':'postgres'}}
        def check(owner,j=job,phase='create'):
            StorageProbe.validate_restore_checkpoint(owner,j,phase,TOKEN,'logical','e'*64,target,'unit-daemon')
        check(a)
        start=dict(a,phase='exec_started',execID='f'*64,importRunID=TOKEN);check(start,phase='start')
        for key,value in [('runID','9'*32),('daemonID','foreign'),('workerStartAuthorized',1),('workerContainerID','bad'),
            ('sourceContainerID','9'*64),('sourceStartedAt','restart'),('targetID','9'*64),('phase','intent'),('execKind','dump'),
            ('execID','f'*64),('importRunID',TOKEN)]:
            with self.subTest(key=key),self.assertRaises(ValueError):check(dict(a,**{key:value}))
        for key,value in [('runID','9'*32),('restore',dict(job['restore'],snapshotID='9'*64)),
                          ('targets',[dict(job['targets'][0],ID='foreign')])]:
            with self.subTest(job=key),self.assertRaises(ValueError):check(a,dict(job,**{key:value}))
        with self.assertRaises(ValueError):check(dict(start,importRunID='restore_'+'9'*48),phase='start')

class ProducerTests(unittest.TestCase):
    def test_independent_exec_inspect_must_agree_with_real_create_before_start(self):
        from run_hosted_storage_prereqs import StorageProbe
        self.assertTrue(hasattr(StorageProbe,'validate_restore_exec'),'independent exec-inspect gate missing')
        for name in ('restore_validator','restore_target_provenance','start_extension_target','finish_native_capture'):
            self.assertTrue(callable(getattr(StorageProbe,name,None)),name+' producer wiring missing')
        execution={'ID':'e'*64,'ContainerID':'c'*64,'OpenStdin':True,'OpenStdout':True,'OpenStderr':True,
            'Running':False,'Pid':0,'ExitCode':None,'ProcessConfig':{'entrypoint':CMD[0],'arguments':CMD[1:],
            'tty':False,'privileged':False,'user':'0'}}
        StorageProbe.validate_restore_exec(execution,'e'*64,'c'*64)
        for key,value in [('ID','f'*64),('ContainerID','f'*64),('OpenStdin',False),('Running',True),('Pid',1),('ExitCode',0),
                          ('ProcessConfig',dict(execution['ProcessConfig'],privileged=True)),
                          ('ProcessConfig',dict(execution['ProcessConfig'],arguments=CMD[1:]+['--verbose']))]:
            with self.subTest(key=key),self.assertRaises(ValueError):StorageProbe.validate_restore_exec(dict(execution,**{key:value}),'e'*64,'c'*64)

def native_receipt():
    """Synthetic schema combined with a real owned AF_UNIX reset control.

    This is NOT an Engine observation or a hosted receipt.
    """
    from test_hosted_storage_cycle1 import extension_receipt
    from test_f22_native_lifecycle import NativeFramingTests,NATIVE
    row=copy.deepcopy(extension_receipt())
    capture=NativeFramingTests().capture_reset(NativeFramingTests.frame(b'WARNING: password file "/dev/null" is not a plain file\n'+NATIVE))
    records=row['relay']['records']
    for attempt in row['attempts']:
        a=attempt['owner']; start=next(r for r in records if r.get('boundary')=='restore-start' and r.get('exec_id')==a['execID'])
        start['container_id']=a['sourceContainerID']
        binding={'schema':1,'contract':'f22-native-provenance-v1','run_id':a['runID'],'import_run_id':a['importRunID'],
            'daemon':row['daemon'],'worker_id':a['workerContainerID'],'worker_image':row['image_id'],
            'worker_started_at':next(r for r in records if r.get('boundary')=='worker-remove' and r['container_id']==a['workerContainerID'])['worker_before_remove']['started_at'],
            'target':row['extension']['target_before'],'target_image':PIN,'logical_target':row['mapping']['plan']['ID'],
            'snapshot_id':row['mapping']['snapshot']['snapshotID'],'profile':'pg18.6-fixture-pgEnv-v1',
            'create_exact':True,'effective_environment':True,'mounts_owned':True,'native_layer':True,'exec_id':a['execID']}
        start['restore_start']=dict(binding,inspect_agrees=True)
        start['native_terminal']={'schema':1,'exec_id':a['execID'],'import_run_id':a['importRunID'],
            'capture_quiescent':True,'target_after':row['extension']['target_before'],'native_layer_after':True,
            'all_client_sessions':0,'all_import_processes':0,'terminal':attempt['terminal']}
        owner=dict(a,phase='creating_exec');owner.pop('execID',None);owner.pop('importRunID',None)
        records.insert(records.index(start),{'boundary':'restore-create','method':'POST','container_id':a['sourceContainerID'],
            'exec_id':a['execID'],'forwarded':True,'status':201,'owner_checkpoint':owner,'restore_create':binding})
    first=next(r for r in records if r.get('boundary')=='restore-start')
    first.update(capture)
    first['native_fatal_witness']={'schema':1,'exec_id':row['attempts'][0]['owner']['execID'],
        'import_run_id':row['attempts'][0]['owner']['importRunID'],'stderr_complete':False,'total_error_count':None}
    row['extension']['failure_cause']=first['import_diagnostic']
    return row

class ConsumerTests(unittest.TestCase):
    def test_real_reset_with_full_producer_chain_only_admits_first_failed_attempt(self):
        from verify_hosted_storage_prereqs import verify_case
        row=native_receipt()
        try: verify_case(row)
        except ValueError as exc: self.fail('approved native-fatal route missing: '+str(exc))
        first=next(r for r in row['relay']['records'] if r.get('boundary')=='restore-start')
        self.assertEqual(first['capture']['state'],'aborted')
        self.assertIs(first['import_diagnostic']['complete'],False)
        self.assertIsNone(first['native_fatal_witness']['total_error_count'])

    def test_complete_route_cannot_mask_observed_reset_or_incompleteness(self):
        from verify_hosted_storage_prereqs import verify_case
        from test_hosted_storage_cycle1 import extension_receipt
        verify_case(extension_receipt()) # Preserve the original complete-EOF receipt.
        for section,value in [('capture',{'state':'aborted','stop_reason':'recv_back_reset'}),
                ('import_observation',{'transport_complete':False}),
                ('native_fatal_observation',{'reset_candidate':True})]:
            row=copy.deepcopy(extension_receipt())
            start=next(r for r in row['relay']['records'] if r.get('boundary')=='restore-start')
            start[section]=value
            with self.subTest(section=section),self.assertRaises(ValueError):verify_case(row)
        row=native_receipt()
        start=next(r for r in row['relay']['records'] if r.get('boundary')=='restore-start')
        start.pop('native_fatal_witness')
        start['import_diagnostic']={'cause':'hstore_binary_load_missing','complete':True,'error_count':1}
        row['extension']['failure_cause']=copy.deepcopy(start['import_diagnostic'])
        with self.assertRaises(ValueError):verify_case(row)

class RunnerGuardTests(unittest.TestCase):
    def test_runner_uses_full_first_failure_conjunction_before_any_library_action(self):
        from run_hosted_storage_prereqs import StorageProbe
        self.assertTrue(hasattr(StorageProbe,'require_extension_failure'),'runner native acceptance guard missing')
        row=native_receipt(); p=StorageProbe.__new__(StorageProbe); p.result=row
        class Relay:
            def snapshot(self):return row['relay']
        p.relay=Relay(); p.verify_source_online=lambda:None
        start=next(r for r in row['relay']['records'] if r.get('boundary')=='restore-start')
        p.require_extension_failure(row['attempts'][0],start)
        row['case']='other-fault'
        with self.assertRaises(ValueError):p.require_extension_failure(row['attempts'][0],start)
        row['case']='restore-missing-extension-binary-prerequisites'
        for section,key,value in [('native_terminal','capture_quiescent',False),('restore_start','effective_environment',False),
                                  ('capture','stop_reason','drain_timeout'),('native_fatal_witness','total_error_count',1)]:
            original=start[section][key];start[section][key]=value
            with self.subTest(section=section,key=key),self.assertRaises(ValueError):p.require_extension_failure(row['attempts'][0],start)
            start[section][key]=original

class AdversaryTests(unittest.TestCase):
    def test_every_provenance_and_retirement_leaf_is_mandatory_and_typed(self):
        from verify_hosted_storage_prereqs import verify_case,verify_f22_first_failure
        original=native_receipt()
        def leaves(value,path=()):
            if isinstance(value,dict):
                for k,v in value.items():yield from leaves(v,path+(k,))
            else:yield path,value
        paths=[]
        for i,record in enumerate(original['relay']['records']):
            for key in ('restore_create','restore_start','native_terminal','native_fatal_witness','native_fatal_observation','capture','import_observation'):
                if key in record:
                    paths.extend((('relay','records',i,key)+p,v) for p,v in leaves(record[key]))
        for path,value in paths:
            changed=copy.deepcopy(original);item=changed
            for key in path[:-1]:item=item[key]
            item[path[-1]]=(not value if type(value) is bool else value+1 if type(value) is int else 1 if value is None else 'FOREIGN')
            with self.subTest(path=path),self.assertRaises(ValueError):verify_case(changed)
        for key,value in [('exec_exit_code',True),('exec_exit_code',0),('exec_exit_code',2),('exec_exit_code',124),
                          ('exec_exit_code',137),('exec_exit_code',143),('sessions',1),('processes',1)]:
            row=copy.deepcopy(original);row['attempts'][0]['terminal'][key]=value
            start=next(r for r in row['relay']['records'] if r.get('boundary')=='restore-start')
            with self.subTest(terminal=key,value=value),self.assertRaises(ValueError):verify_case(row)
            with self.assertRaises(ValueError):verify_f22_first_failure(row,start,row['attempts'][0])
        for key,value in [('catalog_after_failure',{'objects':['dirty']}),('database_after_failure',{'database_oid':'999'}),
            ('installed_after_failure',False),('installed_before',1),('control_present',False),('library_missing_exit',0),
            ('roles_prepared_before_failure',False),('payload_after_failure',True)]:
            row=copy.deepcopy(original);row['extension'][key]=value
            start=next(r for r in row['relay']['records'] if r.get('boundary')=='restore-start')
            with self.subTest(extension=key),self.assertRaises(ValueError):verify_f22_first_failure(row,start,row['attempts'][0])

    def test_replay_wrong_profile_and_retry_shortcuts_never_admit(self):
        from verify_hosted_storage_prereqs import verify_case
        original=native_receipt()
        for mode in ('duplicate-create','duplicate-start','reorder-create','no-create','wrong-profile','native-on-retry','retry-failed','retry-new-db','retry-token-reuse','data','acl','cleanup','create-fault','retry-fault'):
            row=copy.deepcopy(original);records=row['relay']['records'];first=next(r for r in records if r.get('boundary')=='restore-start');second=next(r for r in records if r.get('boundary')=='restore-start' and r is not first)
            if mode=='duplicate-create':records.append(copy.deepcopy(records[0]))
            elif mode=='duplicate-start':records.append(copy.deepcopy(first))
            elif mode=='reorder-create':records.insert(2,records.pop(0))
            elif mode=='no-create':records.pop(0)
            elif mode=='wrong-profile':first['native_fatal_observation']['template']='pg18-hstore-374-v1'
            elif mode=='native-on-retry':second['native_fatal_witness']=copy.deepcopy(first['native_fatal_witness'])
            elif mode=='retry-failed':row['attempts'][1]['result']['status']='failed'
            elif mode=='retry-new-db':row['extension']['database_before_retry']['database_oid']='999'
            elif mode=='retry-token-reuse':row['attempts'][1]['owner']['importRunID']=row['attempts'][0]['owner']['importRunID']
            elif mode=='data':row['extension']['target_data']='changed'
            elif mode=='acl':row['extension']['reader_select']=False
            elif mode=='create-fault':records[0]['fault']='response-loss'
            elif mode=='retry-fault':second['fault']='injected'
            elif mode=='cleanup':row['cleanup']['containers_absent'][row['extension']['target_before']['container_id']]=False
            with self.subTest(mode=mode),self.assertRaises(ValueError):verify_case(row)

if __name__=='__main__':unittest.main()
