"""F15 offline contracts. Synthetic observations are NOT hosted/runtime evidence."""
import copy
import hashlib
import importlib
import json
import unittest
from unittest.mock import Mock


CASE = 'restore-active-import-worker-SIGKILL'
LOGICAL_TARGET = 'fixture-installation/compose/fixture-project/pg/postgres/fixture'


def planned_source():
    return {'ID':LOGICAL_TARGET,'Kind':'postgres',
            'Source':{'DaemonID':'unit-daemon','ContainerID':'9'*64,'StartedAt':'source-start'}}


def trusted_snapshot():
    return {'snapshotID':'7'*64,'source':LOGICAL_TARGET,'type':'postgres','status':'complete',
            'metadata':{'version':1,'kind':'postgres','source':LOGICAL_TARGET}}


def owner():
    return {'runID': 'a'*32, 'daemonID': 'unit-daemon', 'workerContainerID': 'b'*64,
            'workerName': 'bakabel-worker-'+'a'*32, 'workerStartAuthorized': True,
            'targetID': hashlib.sha256(LOGICAL_TARGET.encode('utf-8')).hexdigest(), 'sourceContainerID': 'd'*64, 'sourceStartedAt': 'target-start',
            'execID': 'e'*64, 'execKind': 'restore', 'importRunID': 'restore_'+'f'*48,
            'phase': 'exec_started', 'status': 'active'}


class VerifierTests(unittest.TestCase):
    def receipt(self):
        # Explicitly synthetic offline object, never saved as hosted evidence.
        a = owner(); cid = a['workerContainerID']; eid = a['execID']; target = a['sourceContainerID']
        terminal = {'daemon':'unit-daemon','container_id':target,'started_at':'target-start','exec_id':eid,
                    'exec_exit_code':143,'sessions':0,'processes':0,'import_run_id':a['importRunID']}
        observation = {'owner':a,'exec_pid':44,'processes':1,'target':{'container_id':target,'started_at':'target-start','restart_count':0},
            'session':{'pid':55,'backend_start':'backend-start','application_name':a['importRunID'],'datname':'fixture',
                'usename':'postgres','state':'active','wait_event':'PgSleep','copy_active':True}}
        create_owner = {k:v for k,v in a.items() if k not in ('execID','importRunID')}; create_owner['phase'] = 'creating_exec'
        records = [{'method':'POST','boundary':'restore-create','container_id':target,'exec_id':eid,'forwarded':True,
                    'status':201,'owner_checkpoint':create_owner},
                   {'method':'POST','boundary':'restore-start','container_id':target,'exec_id':eid,'forwarded':True,
                    'status':101,'owner_checkpoint':a},
                   {'method':'DELETE','boundary':'worker-remove','container_id':cid,'forwarded':True,'status':204,
                    'remove_query':'','remove_query_valid':True,'remove_force':False,'remove_volumes':False,
                    'owner_before_remove':a,'terminal_before_remove':terminal,
                    'worker_before_remove':{'container_id':cid,'running':False,'pid':0,'exit_code':137}}]
        return {'schema':1,'case':CASE,'status':'pass','exercised':True,'ordinary_image':True,'request_mutations':[],
            'backend':'local','platform':'compose','source_unchanged':True,'daemon':'unit-daemon',
            'source_sha256':'1'*64,'image_id':'sha256:'+'2'*64,'source':{'container_id':'9'*64,'started_at':'source-start','restart_count':0},
            'workers':{cid:{'container_id':cid,'run_id':a['runID'],'image_id':'sha256:'+'2'*64,
                'memory_bytes':536870912,'nanocpus':2000000000,'cpu.max':'200000 100000','memory.max':'536870912',
                'socket':{'source':'/unit/relay.sock','destination':'/run/bakabel/docker.sock','read_only':True}}},
            'relay':{'records':records,'errors':[],'workers':[cid],
                     'execs':{eid:{'kind':'restore','container_id':target,'stdin_bytes':4096,'stdout_bytes':0}}},
            'injection':{'active_import':observation,'worker_before_kill':{'container_id':cid,'running':True,'pid':22},
                         'snapshot_id':'7'*64,'controller_id':'8'*64,
                         'target_mapping':{'plan':planned_source(),'snapshot':trusted_snapshot()}},
            'proof':{'outcome':'failed','owner_released':True,'worker_absent':True,'cli_exit':1,'last_success_unchanged':True,
                'terminal':terminal,'partial_target':{**observation['target'],'payload_exists':True,'payload_rows':0},
                'restore_result':{'runID':a['runID'],'status':'failed','targets':[{'targetID':LOGICAL_TARGET,'snapshotID':'7'*64,'status':'unknown','error':'restore failed'}]},
                'events':['active-copy-observed','prekill-rechecked','worker-kill-requested','import-terminal-before-worker-remove',
                          'public-restore-failed','partial-target-retained'],
                'recovery_boundary':'original public restore CLI controller, independent of killed worker'},
            'cleanup':{'containers_absent':{cid:True,target:True,'9'*64:True},'volumes_absent':{'owned':True},'private_paths_absent':True}}

    def test_accepts_only_exact_active_import_terminal_order_and_failed_public_result(self):
        m = importlib.import_module('verify_hosted_faults')
        self.assertTrue(hasattr(m,'verify_import_kill'),'F15 needs import-specific independent verification')
        m.verify_case(json.loads(json.dumps(self.receipt())))

    def test_json_roundtrip_rejects_durable_digest_as_public_logical_target(self):
        row = self.roundtrip(self.receipt())
        row['proof']['restore_result']['targets'][0]['targetID'] = owner()['targetID']
        with self.assertRaises(ValueError): importlib.import_module('verify_hosted_faults').verify_case(row)

    def test_json_roundtrip_rejects_foreign_logical_other_hash_and_coherent_rebinding(self):
        m = importlib.import_module('verify_hosted_faults')
        foreign = LOGICAL_TARGET.replace('fixture-project','foreign-project')
        digest = hashlib.sha256(foreign.encode('utf-8')).hexdigest()
        for public,durable in ((foreign,None),(digest,None),(LOGICAL_TARGET,digest),(foreign,digest),(digest,digest)):
            row = self.roundtrip(self.receipt())
            if durable:
                for a in (row['injection']['active_import']['owner'],
                          row['relay']['records'][0]['owner_checkpoint'],
                          row['relay']['records'][1]['owner_checkpoint'],
                          row['relay']['records'][2]['owner_before_remove']): a['targetID'] = durable
            row['proof']['restore_result']['targets'][0]['targetID'] = public
            with self.subTest(public=public,durable=durable), self.assertRaises(ValueError): m.verify_case(row)

    def test_json_roundtrip_requires_grounded_plan_and_exact_snapshot_not_a_mapping_claim(self):
        edits = [(('plan','ID'),'foreign'),(('plan','Kind'),'volume'),
            (('plan','Source','DaemonID'),'foreign'),(('plan','Source','ContainerID'),'0'*64),
            (('plan','Source','StartedAt'),'replacement'),(('snapshot','snapshotID'),'0'*64),
            (('snapshot','source'),'foreign'),(('snapshot','status'),'unknown'),(('snapshot','type'),'volume'),
            (('snapshot','metadata','source'),'foreign'),(('snapshot','metadata','version'),True),
            (('snapshot','metadata','kind'),'volume')]
        m = importlib.import_module('verify_hosted_faults')
        for path,value in edits:
            row = self.roundtrip(self.receipt()); selected = row['injection']['target_mapping']
            for key in path[:-1]: selected = selected[key]
            selected[path[-1]] = value
            with self.subTest(path=path), self.assertRaises(ValueError): m.verify_case(row)
        for field in ('plan','snapshot'):
            row = self.roundtrip(self.receipt()); del row['injection']['target_mapping'][field]
            with self.subTest(missing=field), self.assertRaises(ValueError): m.verify_case(row)
        row = self.roundtrip(self.receipt()); del row['injection']['target_mapping']
        with self.assertRaises(ValueError): m.verify_case(row)

    def test_rejects_missing_proofs_reader_only_wrong_token_early_release_and_false_success(self):
        m = importlib.import_module('verify_hosted_faults')
        edits = [
            (('proof','terminal','import_run_id'),owner()['runID']),
            (('injection','active_import','owner','importRunID'),owner()['runID']),
            (('injection','active_import','owner','sourceContainerID'),'9'*64),
            (('injection','active_import','owner','execKind'),'dump'),
            (('injection','active_import','session','wait_event'),'ClientRead'),
            (('injection','active_import','session','copy_active'),False),
            (('injection','active_import','session','application_name'),owner()['runID']),
            (('injection','active_import','processes'),0),
            (('injection','worker_before_kill','container_id'),'0'*64),
            (('proof','partial_target','payload_exists'),False),
            (('proof','partial_target','payload_rows'),300000),
            (('proof','terminal','exec_id'),'0'*64),
            (('proof','terminal','exec_exit_code'),0),
            (('proof','terminal','sessions'),False),
            (('proof','terminal','processes'),1),
            (('proof','restore_result','status'),'restored'),
            (('proof','restore_result','targets',0,'status'),'restored'),
            (('proof','cli_exit'),0),
            (('proof','owner_released'),False),
            (('proof','events'),['public-restore-failed']),
            (('relay','records',2,'owner_before_remove'),{}),
            (('relay','records',2,'worker_before_remove','exit_code'),0),
            (('relay','records',2,'terminal_before_remove','exec_exit_code'),None),
            (('relay','records',1,'forwarded'),False),
        ]
        for path,value in edits:
            row = copy.deepcopy(self.receipt()); selected = row
            for key in path[:-1]: selected = selected[key]
            selected[path[-1]] = value
            with self.subTest(path=path), self.assertRaises(ValueError): m.verify_case(row)
        for section in ('injection','relay','proof'):
            row = self.receipt(); del row[section]
            with self.subTest(missing=section), self.assertRaises(ValueError): m.verify_case(row)


    def roundtrip(self, row):
        # The actual receipt boundary destroys Python alias identity.
        return json.loads(json.dumps(row))

    def test_json_roundtrip_rejects_rebound_exec_without_actual_relay_execution(self):
        row = self.roundtrip(self.receipt()); new = '0'*64
        row['injection']['active_import']['owner']['execID'] = new
        row['proof']['terminal']['exec_id'] = new
        for record in row['relay']['records']:
            if 'exec_id' in record: record['exec_id'] = new
            if 'owner_checkpoint' in record and record['owner_checkpoint'].get('execID'):
                record['owner_checkpoint']['execID'] = new
            if 'owner_before_remove' in record: record['owner_before_remove']['execID'] = new
            if 'terminal_before_remove' in record: record['terminal_before_remove']['exec_id'] = new
        with self.assertRaises(ValueError): importlib.import_module('verify_hosted_faults').verify_case(row)

    def test_json_roundtrip_binds_actual_exec_kind_source_and_public_target(self):
        m = importlib.import_module('verify_hosted_faults')
        mutations = [('kind','dump'),('container_id','0'*64)]
        for key,value in mutations:
            row = self.roundtrip(self.receipt()); row['relay']['execs']['e'*64][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): m.verify_case(row)
        for value in (None,'0'*64):
            row = self.roundtrip(self.receipt())
            if value is None: del row['proof']['restore_result']['targets'][0]['targetID']
            else: row['proof']['restore_result']['targets'][0]['targetID'] = value
            with self.subTest(target=value), self.assertRaises(ValueError): m.verify_case(row)

    def test_json_roundtrip_rejects_all_correlated_exec_contradictions_not_just_labels(self):
        m = importlib.import_module('verify_hosted_faults')
        for label in ('restore-start','dump-start','other','worker-start','restore-create'):
            for field,value in (('exec_id','0'*64),('container_id','0'*64),('method','GET')):
                row = self.roundtrip(self.receipt()); record = copy.deepcopy(row['relay']['records'][1])
                record.update(boundary=label); record[field] = value
                row['relay']['records'].insert(2,record)
                with self.subTest(label=label,field=field), self.assertRaises(ValueError): m.verify_case(row)
        for mutation in ({'exec_id':'0'*64},{'container_id':'0'*64},{'method':'POST'},
                         {'boundary':'restore-create'},{'status':101},{'forwarded':False}):
            row = self.roundtrip(self.receipt())
            inspect = {'method':'GET','boundary':'other','exec_id':'e'*64,'forwarded':True,'status':200,
                       'owner_checkpoint':copy.deepcopy(row['injection']['active_import']['owner'])}
            inspect.update(mutation); row['relay']['records'].insert(2,inspect)
            with self.subTest(inspect=mutation), self.assertRaises(ValueError): m.verify_case(row)

    def test_json_roundtrip_requires_typed_verified_nonforce_removal_query(self):
        m = importlib.import_module('verify_hosted_faults')
        for mutation in ({'remove_force':True},{'remove_force':0},{'remove_force':None},
                         {'remove_query_valid':False},{'remove_query_valid':1},{'remove_volumes':0},
                         {'remove_query':'force=true&v=true'},{'remove_query':'force=false&force=true'},
                         {'remove_query':'force=false&force=false'},{'remove_query':'v=true&v=false'},
                         {'remove_query':'force=FALSE'},{'remove_query':'force=%66alse'},
                         {'remove_query':'force'},{'remove_query':'force=false;v=true'},
                         {'remove_query':'unknown=false'}):
            row = self.roundtrip(self.receipt()); row['relay']['records'][2].update(mutation)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): m.verify_case(row)
        row = self.roundtrip(self.receipt()); del row['relay']['records'][2]['remove_query']
        with self.assertRaises(ValueError): m.verify_case(row)

    def test_json_roundtrip_rejects_shadow_correlated_deletes_despite_relabeling(self):
        m = importlib.import_module('verify_hosted_faults')
        for label in ('other','worker-start','restore-create'):
            for cid in ('b'*64,'0'*64):
                row = self.roundtrip(self.receipt()); record = copy.deepcopy(row['relay']['records'][2])
                record.update(boundary=label,container_id=cid,remove_query='force=true&v=true',
                              remove_force=True,remove_volumes=True)
                row['relay']['records'].append(record)
                with self.subTest(label=label,cid=cid), self.assertRaises(ValueError): m.verify_case(row)

    def test_json_roundtrip_allows_real_inspect_nonexec_worker_and_unrelated_baseline(self):
        row = self.roundtrip(self.receipt()); a = row['injection']['active_import']['owner']
        row['relay']['records'].insert(2,{'method':'GET','boundary':'other','exec_id':a['execID'],
                                        'forwarded':True,'status':200})
        row['relay']['records'].insert(0,{'method':'POST','boundary':'worker-start','container_id':a['workerContainerID'],
                                        'owner_checkpoint':copy.deepcopy(a),'forwarded':True,'status':204})
        row['relay']['records'].insert(0,{'method':'POST','boundary':'dump-start','exec_id':'1'*64,'container_id':'9'*64,
                                        'owner_checkpoint':{'runID':'2'*32},'forwarded':True,'status':101})
        importlib.import_module('verify_hosted_faults').verify_case(row)

    def test_json_roundtrip_removal_evidence_outranks_every_method_and_boundary_label(self):
        m = importlib.import_module('verify_hosted_faults')
        methods = ('GET','POST','PUT','PATCH','HEAD','OPTIONS','CONNECT','TRACE','DELETE',
                   'delete','get',' Delete ','',None,0,False,[],{})
        boundaries = ('other','worker-start','worker-create','worker-remove','restore-create','restore-start',
                      'dump-create','dump-start','WORKER-REMOVE','worker_remove','',None,0,False,[],{})
        for method in methods:
            for boundary in boundaries:
                for forced in (False,True):
                    row = self.roundtrip(self.receipt())
                    shadow = copy.deepcopy(row['relay']['records'][2])
                    shadow.update(method=method,boundary=boundary,remove_force=forced,
                                  remove_query='force=true&v=true' if forced else '',remove_volumes=forced)
                    row['relay']['records'].insert(2,shadow)
                    with self.subTest(method=method,boundary=boundary,forced=forced), self.assertRaises(ValueError):
                        m.verify_case(self.roundtrip(row))

    def test_json_roundtrip_each_removal_specific_field_independently_identifies_removal(self):
        m = importlib.import_module('verify_hosted_faults')
        original = self.receipt()['relay']['records'][2]
        fields = {k:v for k,v in original.items() if k.startswith('remove_') or k.endswith('_before_remove')}
        fields['remove_future_option'] = None
        for key,value in fields.items():
            for method,boundary in (('GET','other'),('POST','worker-start'),('delete','restore-create')):
                row = self.roundtrip(self.receipt())
                shadow = {'method':method,'boundary':boundary,'container_id':'b'*64,
                          'forwarded':True,'status':200,key:copy.deepcopy(value)}
                row['relay']['records'].insert(2,shadow)
                with self.subTest(field=key,method=method,boundary=boundary), self.assertRaises(ValueError):
                    m.verify_case(self.roundtrip(row))

    def test_json_roundtrip_removal_correlation_closes_every_identity_route_independently(self):
        m = importlib.import_module('verify_hosted_faults'); a = owner()
        routes = [(('container_id',),a['workerContainerID']), (('container_id',),a['sourceContainerID']),
                  (('exec_id',),a['execID'])]
        for section in ('owner_checkpoint','owner_before_remove'):
            for key in ('runID','workerContainerID','workerName','sourceContainerID','targetID','execID','importRunID'):
                routes.append(((section,key),a[key]))
        routes += [(('terminal_before_remove',key),value) for key,value in (
            ('exec_id',a['execID']),('container_id',a['sourceContainerID']),
            ('import_run_id',a['importRunID']),('run_id',a['runID']))]
        routes += [(('worker_before_remove',key),value) for key,value in (
            ('container_id',a['workerContainerID']),('run_id',a['runID']))]
        for path,value in routes:
            for method,boundary in (('GET','other'),('POST','worker-start'),('delete','restore-create'),
                                    ('DELETE','worker-remove'),('PATCH','unrecognized')):
                row = self.roundtrip(self.receipt())
                # All other identities and annotations are absent/foreign. Safe
                # options still cannot make a second correlated removal unique.
                shadow = {'method':method,'boundary':boundary,'container_id':'0'*64,'forwarded':True,'status':204,
                          'remove_query':'','remove_query_valid':True,'remove_force':False,'remove_volumes':False}
                selected = shadow
                for key in path[:-1]: selected = selected.setdefault(key,{})
                selected[path[-1]] = value
                row['relay']['records'].insert(2,shadow)
                with self.subTest(route=path,method=method,boundary=boundary), self.assertRaises(ValueError):
                    m.verify_case(self.roundtrip(row))

    def test_json_roundtrip_sole_removal_requires_canonical_delete_worker_remove(self):
        m = importlib.import_module('verify_hosted_faults')
        for method,boundary in (('GET','worker-remove'),('POST','worker-remove'),('delete','worker-remove'),
                                ('DELETE','other'),('DELETE','worker-start'),('DELETE','restore-create')):
            row = self.roundtrip(self.receipt()); row['relay']['records'][2].update(method=method,boundary=boundary)
            with self.subTest(method=method,boundary=boundary), self.assertRaises(ValueError): m.verify_case(row)

    def test_json_roundtrip_duplicate_removal_is_rejected_even_when_all_annotations_agree(self):
        row = self.roundtrip(self.receipt())
        row['relay']['records'].append(copy.deepcopy(row['relay']['records'][2]))
        with self.assertRaises(ValueError): importlib.import_module('verify_hosted_faults').verify_case(self.roundtrip(row))

    def test_json_roundtrip_real_worker_target_and_exec_get_inspections_are_not_removals(self):
        row = self.roundtrip(self.receipt()); a = row['injection']['active_import']['owner']
        inspections = [
            {'container_id':a['workerContainerID']},
            {'container_id':a['workerContainerID'],'owner_checkpoint':copy.deepcopy(a)},
            {'container_id':a['sourceContainerID'],'owner_checkpoint':copy.deepcopy(a)},
            {'container_id':a['sourceContainerID'],'exec_id':a['execID'],'owner_checkpoint':copy.deepcopy(a)},
        ]
        for identity in inspections:
            row['relay']['records'].insert(2,{'method':'GET','boundary':'other','forwarded':True,'status':200,**identity})
        importlib.import_module('verify_hosted_faults').verify_case(self.roundtrip(row))

    def test_json_roundtrip_unrelated_removal_records_remain_unrelated(self):
        row = self.roundtrip(self.receipt())
        for method,boundary in (('DELETE','worker-remove'),('GET','other'),('POST','worker-start')):
            row['relay']['records'].insert(0,{
                'method':method,'boundary':boundary,'container_id':'0'*64,'exec_id':'1'*64,
                'owner_checkpoint':{'runID':'2'*32,'workerContainerID':'0'*64,'execID':'1'*64},
                'owner_before_remove':{'runID':'2'*32,'workerContainerID':'0'*64,'execID':'1'*64},
                'terminal_before_remove':{'container_id':'3'*64,'exec_id':'1'*64,'import_run_id':'restore_'+'4'*48},
                'worker_before_remove':{'container_id':'0'*64},'forwarded':True,'status':204,
                'remove_query':'force=true&v=true','remove_query_valid':True,'remove_force':True,'remove_volumes':True})
        importlib.import_module('verify_hosted_faults').verify_case(self.roundtrip(row))

    def test_json_roundtrip_nonforce_query_free_and_explicit_options_remain_valid(self):
        m = importlib.import_module('verify_hosted_faults')
        for query,volumes in (('',False),('force=false',False),('v=true',True),('force=false&v=true',True),('v=false&force=false',False)):
            row = self.roundtrip(self.receipt())
            row['relay']['records'][2].update(remove_query=query,remove_volumes=volumes)
            with self.subTest(query=query): m.verify_case(row)


class RunnerTests(unittest.TestCase):
    def probe(self):
        m = importlib.import_module('run_hosted_faults')
        self.assertIn('exercise_import_kill',m.FaultProbe.__dict__,'need public restore orchestration, not API-only cancellation')
        p = m.FaultProbe.__new__(m.FaultProbe); p.case = CASE; p.daemon = 'unit-daemon'; p.source = '9'*64
        p.result = {}; p.target = LOGICAL_TARGET; p.f15_plan = planned_source()
        p.source_before = {'container_id':p.source,'started_at':'source-start','restart_count':0}
        p.call_cli = Mock(return_value=[trusted_snapshot()])
        self.current = owner(); self.worker = {'Id':'b'*64,'State':{'Running':True,'Pid':22,'ExitCode':0}}
        self.observed = {'owner':owner(),'session':{'pid':55,'backend_start':'backend-start','application_name':owner()['importRunID'],
            'datname':'fixture','usename':'postgres','state':'active','wait_event':'PgSleep','copy_active':True},
            'exec_pid':44,'processes':1,'target':{'container_id':'d'*64,'started_at':'target-start','restart_count':0}}
        p.owner = Mock(side_effect=lambda: self.current); p.e = Mock()
        def call(method,path,**kwargs):
            self.assertEqual((method,path),('POST','/containers/'+'b'*64+'/kill?signal=KILL'))
            self.worker['State'] = {'Running':False,'Pid':0,'ExitCode':137}
        p.e.call.side_effect = call
        p.e.inspect.side_effect = lambda cid,**kwargs: copy.deepcopy(self.worker) if cid == 'b'*64 else {
            'Id':'d'*64,'State':{'Running':True,'StartedAt':'target-start'},'RestartCount':0}
        p.capture_owned_worker = Mock(); p.worker_identity_proof = Mock()
        p.active_import = Mock(side_effect=lambda *args: copy.deepcopy(self.observed))
        p.wait = Mock(side_effect=lambda fn,*args: fn()); p.success_snapshot = Mock(return_value='7'*64)
        p.baseline_success = 'baseline'; p.startpg = Mock(return_value='d'*64); p.controller = Mock(return_value='8'*64)
        p.sql = Mock(side_effect=lambda cid,query: '0' if query == 'SELECT count(*) FROM public.payload' else 't')
        p.terminal_proof = Mock(return_value={'daemon':'unit-daemon','container_id':'d'*64,'started_at':'target-start',
            'exec_id':'e'*64,'exec_exit_code':143,'sessions':0,'processes':0})
        self.records = []
        p.relay = Mock(); p.relay.snapshot.side_effect = lambda: {'records':self.records,'workers':['b'*64]}
        self.rows = [{'runID':'a'*32,'status':'failed','targets':[{'targetID':LOGICAL_TARGET,'snapshotID':'7'*64,'status':'unknown','error':'restore failed'}]}]
        def finish(*args,**kwargs):
            record = {'method':'DELETE','boundary':'worker-remove','container_id':'b'*64,'forwarded':False,
                      'remove_query':'','remove_query_valid':True,'remove_force':False,'remove_volumes':False}
            p.observe_transport('request',record); record.update(forwarded=True,status=204); self.records.append(record)
            self.current = None; p.e.inspect.side_effect = lambda cid,**kw: None if cid == 'b'*64 else {
                'Id':'d'*64,'State':{'Running':True,'StartedAt':'target-start'},'RestartCount':0}
            return self.rows
        p.finish = Mock(side_effect=finish)
        p.last = Mock(return_value={'runID':'a'*32,'status':'failed','operation':'restore','lastBackupSuccessAt':'baseline'})
        return p

    def test_public_restore_kills_only_freshly_checked_worker_and_keeps_partial_destination(self):
        p = self.probe(); p.exercise_import_kill()
        p.controller.assert_called_once_with('restore','--snapshot','7'*64,'--postgres-container','d'*64,'--database','fixture','--user','postgres')
        self.assertEqual(p.active_import.call_count,2)
        p.e.call.assert_called_once_with('POST','/containers/'+'b'*64+'/kill?signal=KILL')
        p.finish.assert_called_once_with('8'*64,expect=1,timeout=85)
        self.assertEqual(p.result['proof']['events'],['active-copy-observed','prekill-rechecked','worker-kill-requested',
            'import-terminal-before-worker-remove','public-restore-failed','partial-target-retained'])
        self.assertEqual(p.result['proof']['restore_result'],self.rows[0])
        self.assertEqual(p.result['proof']['partial_target']['payload_rows'],0)
        self.assertEqual(p.result['proof']['recovery_boundary'],'original public restore CLI controller, independent of killed worker')
        p.call_cli.assert_called_once_with('snapshots')
        self.assertEqual(p.result['injection']['target_mapping'],{'plan':planned_source(),'snapshot':trusted_snapshot()})
        row = VerifierTests().receipt(); row.update(injection=p.result['injection'],proof=p.result['proof'])
        importlib.import_module('verify_hosted_faults').verify_case(json.loads(json.dumps(row)))
        p.relay.arm.assert_not_called()

    def test_import_or_owner_drift_prevents_worker_signal(self):
        for kind in ('no-active-import','changed-owner','worker-stopped'):
            p = self.probe()
            if kind == 'no-active-import': p.active_import.side_effect = [copy.deepcopy(self.observed),None]
            if kind == 'changed-owner': self.current['importRunID'] = 'restore_'+'0'*48
            if kind == 'worker-stopped': self.worker['State']['Running'] = False
            with self.subTest(kind=kind), self.assertRaises(ValueError): p.exercise_import_kill()
            p.e.call.assert_not_called()

    def test_false_restored_cli_result_is_rejected(self):
        p = self.probe(); self.rows[0]['targets'][0]['status'] = 'restored'
        with self.assertRaises(ValueError): p.exercise_import_kill()

    def test_public_restore_rejects_digest_instead_of_logical_target(self):
        p = self.probe(); self.rows[0]['targets'][0]['targetID'] = owner()['targetID']
        with self.assertRaises(ValueError): p.exercise_import_kill()

    def test_public_restore_rejects_foreign_logical_other_hash_and_coherent_rebinding(self):
        foreign = LOGICAL_TARGET.replace('fixture-project','foreign-project')
        digest = hashlib.sha256(foreign.encode('utf-8')).hexdigest()
        for public,durable in ((foreign,None),(digest,None),(LOGICAL_TARGET,digest),(foreign,digest),(digest,digest)):
            p = self.probe(); self.rows[0]['targets'][0]['targetID'] = public
            if durable:
                self.current['targetID'] = durable; self.observed['owner']['targetID'] = durable
            with self.subTest(public=public,durable=durable), self.assertRaises(ValueError): p.exercise_import_kill()
            if durable: p.e.call.assert_not_called()

    def test_public_restore_rejects_untyped_snapshot_list_and_boolean_metadata_version(self):
        for value in (None,{'snapshotID':'7'*64},[{**trusted_snapshot(),'metadata':{
                **trusted_snapshot()['metadata'],'version':True}}]):
            p = self.probe(); p.call_cli.return_value = value
            with self.subTest(value=value), self.assertRaises(ValueError): p.exercise_import_kill()
            p.controller.assert_not_called(); p.e.call.assert_not_called()

    def test_public_restore_requires_exact_snapshot_source_and_original_plan_before_launch(self):
        for kind in ('missing','duplicate','wrong-snapshot','foreign-source','foreign-metadata','partial','plan-id','plan-source'):
            p = self.probe(); snapshots = p.call_cli.return_value
            if kind == 'missing': snapshots.clear()
            if kind == 'duplicate': snapshots.append(copy.deepcopy(snapshots[0]))
            if kind == 'wrong-snapshot': snapshots[0]['snapshotID'] = '0'*64
            if kind == 'foreign-source': snapshots[0]['source'] = 'foreign'
            if kind == 'foreign-metadata': snapshots[0]['metadata']['source'] = 'foreign'
            if kind == 'partial': snapshots[0]['status'] = 'partial'
            if kind == 'plan-id': p.f15_plan['ID'] = 'foreign'
            if kind == 'plan-source': p.f15_plan['Source']['ContainerID'] = '0'*64
            with self.subTest(kind=kind), self.assertRaises(ValueError): p.exercise_import_kill()
            p.controller.assert_not_called(); p.e.call.assert_not_called()

    def test_prepare_preserves_actual_public_plan_source_for_f15_only(self):
        m = importlib.import_module('run_hosted_faults')
        for case in (CASE,'streaming-worker-SIGKILL'):
            p = m.FaultProbe.__new__(m.FaultProbe); p.case = case; p.daemon = 'unit-daemon'; p.result = {}
            p.config = Mock(); p.restic = Mock(); p.startpg = Mock(return_value='9'*64); p.sql = Mock()
            p.e = Mock(); p.e.inspect.return_value = {'State':{'StartedAt':'source-start'},'RestartCount':0}
            plan = planned_source(); p.call_cli = Mock(return_value={'targets':[plan]})
            p.prepare(); p.call_cli.assert_called_once_with('plan')
            if case == CASE:
                self.assertEqual(p.f15_plan,planned_source()); plan['Source']['ContainerID'] = '0'*64
                self.assertEqual(p.f15_plan,planned_source())
            else: self.assertFalse(hasattr(p,'f15_plan'))

    def test_actual_active_import_orchestration_never_kills_without_strict_true_authorization(self):
        m = importlib.import_module('run_hosted_faults')
        for value in ('missing',False,1):
            with self.subTest(value=value):
                p = self.probe()
                if value == 'missing': del self.current['workerStartAuthorized']
                else: self.current['workerStartAuthorized'] = value
                p.active_import = m.FaultProbe.active_import.__get__(p)
                p.process_count = Mock(return_value=1)
                original_call = p.e.call.side_effect
                execution = {'ID':'e'*64,'ContainerID':'d'*64,'Running':True,'Pid':44,
                    'ProcessConfig':{'entrypoint':'/usr/local/bin/pg_restore','arguments':[
                        '--no-password','--exit-on-error','--dbname',
                        "host='/var/run/postgresql' port='5432' user='postgres' dbname='fixture'"]}}
                def call(method,path,**kwargs):
                    if method == 'GET': return {'ID':'unit-daemon'} if path == '/info' else execution
                    return original_call(method,path,**kwargs)
                p.e.call.side_effect = call
                original_sql = p.sql.side_effect
                p.sql.side_effect = lambda cid,q: json.dumps([self.observed['session']]) if 'FROM pg_stat_activity' in q else original_sql(cid,q)
                rejected = False
                try: p.exercise_import_kill()
                except ValueError: rejected = True
                kills = [c for c in p.e.call.call_args_list if c.args[0] == 'POST']
                self.assertEqual(kills,[], 'strict authorization failure reached actual orchestration KILL')
                self.assertTrue(rejected)

    def test_authorization_drift_during_worker_readback_is_rechecked_at_final_kill_gate(self):
        for value in ('missing',False,1):
            with self.subTest(value=value):
                p = self.probe()
                def drift(*args):
                    if value == 'missing': self.current.pop('workerStartAuthorized',None)
                    else: self.current['workerStartAuthorized'] = value
                p.worker_identity_proof.side_effect = drift
                rejected = False
                try: p.exercise_import_kill()
                except ValueError: rejected = True
                p.e.call.assert_not_called(); self.assertTrue(rejected)

    def test_final_kill_gate_rejects_every_durable_identity_drift_after_worker_readback(self):
        edits = [('runID','0'*32),('workerContainerID','0'*64),('workerName','other-worker'),
                 ('daemonID','other-daemon'),('sourceContainerID','0'*64),('sourceStartedAt','replacement'),
                 ('targetID','0'*64),('execID','0'*64),('execKind','dump'),('importRunID','restore_'+'0'*48),
                 ('phase','quarantine'),('status','blocked')]
        for key,value in edits:
            with self.subTest(key=key):
                p = self.probe()
                p.worker_identity_proof.side_effect = lambda *args: self.current.update({key:value})
                with self.assertRaises(ValueError): p.exercise_import_kill()
                p.e.call.assert_not_called()

    def test_public_restore_result_must_match_exact_durable_target(self):
        p = self.probe(); self.rows[0]['targets'][0]['targetID'] = '0'*64
        with self.assertRaises(ValueError): p.exercise_import_kill()

    def test_f15_is_named_and_dispatch_does_not_relabel_old_thirteen_cases(self):
        m = importlib.import_module('run_hosted_faults'); v = importlib.import_module('verify_hosted_faults')
        self.assertIn(CASE,v.CASES,'F15 needs a separately named hosted case')
        self.assertEqual(len(v.CASES),14)
        p = m.FaultProbe.__new__(m.FaultProbe); p.case = CASE; p.result = {}
        p.prepare = Mock(); p.exercise_import_kill = Mock(); p.verify_source_online = Mock()
        p.run(); p.exercise_import_kill.assert_called_once_with(); self.assertTrue(p.result['exercised'])


class RemovalBoundaryTests(unittest.TestCase):
    def test_exact_worker_delete_is_observed_before_byte_preserving_forward(self):
        import socket
        import tempfile
        import threading
        from pathlib import Path
        m = importlib.import_module('run_hosted_faults')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); server = socket.socket(socket.AF_UNIX)
            server.bind(str(root/'back')); server.listen(); server.settimeout(3)
            relay = m.FaultRelay(root/'front', root/'back'); relay.workers.add('b'*64)
            seen = []; events = []; response = b'HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n'
            def peer():
                with server.accept()[0] as conn:
                    seen.append(m.read_headers(conn)[1]); events.append('forwarded'); conn.sendall(response)
            def observer(phase, record):
                if phase == 'request':
                    self.assertEqual(record['boundary'], 'worker-remove')
                    self.assertEqual(record['container_id'], 'b'*64)
                    self.assertIs(record['forwarded'], False); events.append('terminal-readback')
            relay.observer = observer; relay.start(); thread = threading.Thread(target=peer, daemon=True); thread.start()
            request = b'DELETE /v1.47/containers/'+b'b'*64+b' HTTP/1.1\r\nHost: local\r\nConnection: close\r\n\r\n'
            try:
                with socket.socket(socket.AF_UNIX) as client:
                    client.settimeout(3); client.connect(str(root/'front')); client.sendall(request)
                    received = b''
                    while True:
                        chunk = client.recv(1024)
                        if not chunk: break
                        received += chunk
                thread.join(3)
                self.assertEqual(received, response)
                self.assertEqual(seen, ['DELETE /v1.47/containers/'+'b'*64+' HTTP/1.1'])
                self.assertEqual(events, ['terminal-readback','forwarded'])
                self.assertEqual(relay.snapshot()['errors'], [])
            finally: relay.close(); server.close()

    def unix_removal(self, query, case=CASE, active=True):
        import socket
        import tempfile
        import threading
        from pathlib import Path
        m = importlib.import_module('run_hosted_faults')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); server = socket.socket(socket.AF_UNIX)
            server.bind(str(root/'back')); server.listen(); server.settimeout(.25)
            relay = m.FaultRelay(root/'front',root/'back'); relay.workers.add('b'*64)
            p = m.FaultProbe.__new__(m.FaultProbe); p.case = case; p.f15_active = owner()
            if not active: del p.f15_active
            p.owner = Mock(return_value=owner()); p.f15_events = []; p.e = Mock()
            p.e.inspect.return_value = {'State':{'Running':False,'Pid':0,'ExitCode':137}}
            p.worker_identity_proof = Mock()
            events = []; seen = []
            def terminal(*args):
                events.append('terminal-readback'); return {'exec_exit_code':143,'sessions':0,'processes':0}
            p.terminal_proof = Mock(side_effect=terminal)
            relay.observer = p.observe_transport
            request = ('DELETE /v1.55/containers/'+'b'*64+query+' HTTP/1.1\r\nHost: local\r\nConnection: close\r\n\r\n').encode()
            response = b'HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n'
            def peer():
                try: conn = server.accept()[0]
                except socket.timeout: return
                with conn:
                    seen.append(m.read_headers(conn)[0]); events.append('forwarded'); conn.sendall(response)
            thread = threading.Thread(target=peer,daemon=True); relay.start(); thread.start()
            try:
                with socket.socket(socket.AF_UNIX) as client:
                    client.settimeout(3); client.connect(str(root/'front')); client.sendall(request)
                    received = b''
                    while True:
                        data = client.recv(1024)
                        if not data: break
                        received += data
                thread.join(3); self.assertFalse(thread.is_alive())
                return p,relay.snapshot(),seen,events,received,request,response
            finally: relay.close(); server.close()

    def test_real_unix_f15_rejects_forced_malformed_and_duplicate_queries_before_forward_or_terminal(self):
        queries = ('?force=true&v=true','?force=true','?force=1','?force=FALSE','?force',
                   '?force=false&force=true','?force=true&force=false','?force=false&force=false',
                   '?v=true&v=false','?v=true&v=true','?force=%66alse','?%66orce=false',
                   '?force=false;v=true','?force=false&','?unknown=false')
        for query in queries:
            with self.subTest(query=query):
                p,receipt,seen,events,received,request,response = self.unix_removal(query)
                self.assertEqual(seen,[], 'unsafe removal reached actual Unix peer')
                self.assertEqual(received,b''); self.assertEqual(events,[])
                p.terminal_proof.assert_not_called(); p.e.inspect.assert_not_called()
                self.assertIs(receipt['records'][0]['forwarded'],False)
                self.assertEqual(receipt['errors'],['ValueError'])

    def test_real_unix_nonforce_queries_preserved_and_terminal_before_forward(self):
        for query,volumes in (('',False),('?force=false',False),('?v=true',True),('?force=false&v=true',True)):
            with self.subTest(query=query):
                p,receipt,seen,events,received,request,response = self.unix_removal(query)
                self.assertEqual(seen,[request]); self.assertEqual(received,response)
                self.assertEqual(events,['terminal-readback','forwarded']); self.assertEqual(receipt['errors'],[])
                record = receipt['records'][0]
                self.assertEqual(record['remove_query'],query.removeprefix('?'))
                self.assertIs(record['remove_query_valid'],True); self.assertIs(record['remove_force'],False)
                self.assertIs(record['remove_volumes'],volumes)

    def test_real_unix_f15_query_gate_also_precedes_active_import_annotation(self):
        for query in ('?force=true&v=true','?force=false&force=true'):
            with self.subTest(query=query):
                p,receipt,seen,events,received,request,response = self.unix_removal(query,active=False)
                self.assertEqual(seen,[]); self.assertEqual(events,[]); self.assertEqual(received,b'')
                p.terminal_proof.assert_not_called(); self.assertEqual(receipt['errors'],['ValueError'])
        p,receipt,seen,events,received,request,response = self.unix_removal('',active=False)
        self.assertEqual(seen,[request]); self.assertEqual(received,response)
        self.assertEqual(events,['forwarded']); self.assertEqual(receipt['errors'],[])

    def test_real_unix_other_cases_removal_observation_does_not_change_requests(self):
        for query in ('?force=true&v=true','?force=false&force=true'):
            with self.subTest(query=query):
                p,receipt,seen,events,received,request,response = self.unix_removal(query,'streaming-worker-SIGKILL')
                self.assertEqual(seen,[request]); self.assertEqual(received,response)
                self.assertEqual(events,['forwarded']); self.assertEqual(receipt['errors'],[])
                p.terminal_proof.assert_not_called()

    def test_f15_terminal_readback_precedes_owned_removal_and_rejects_lost_owner(self):
        m = importlib.import_module('run_hosted_faults'); p = m.FaultProbe.__new__(m.FaultProbe)
        p.case = CASE; p.f15_active = owner(); p.owner = Mock(return_value=owner())
        p.f15_events = ['active-copy-observed','prekill-rechecked','worker-kill-requested']
        p.e = Mock(); p.e.inspect.return_value = {'State': {'Running': False, 'Pid': 0, 'ExitCode': 137}}
        p.worker_identity_proof = Mock()
        p.terminal_proof = Mock(return_value={'exec_exit_code': 143, 'sessions': 0, 'processes': 0})
        record = {'method':'DELETE','boundary':'worker-remove','container_id':'b'*64,'forwarded':False,
                      'remove_query':'','remove_query_valid':True,'remove_force':False,'remove_volumes':False}
        p.observe_transport('request', record)
        self.assertIn('terminal_before_remove', record, 'post-release inspection does not establish ordering')
        self.assertEqual(record['terminal_before_remove']['import_run_id'], owner()['importRunID'])
        self.assertEqual(record['owner_before_remove'], owner())
        self.assertEqual(p.f15_events[-1], 'import-terminal-before-worker-remove')
        p.owner.return_value = None
        with self.assertRaises(ValueError): p.observe_transport('request', copy.deepcopy(record))


class ActiveImportTests(unittest.TestCase):
    def probe(self):
        m = importlib.import_module('run_hosted_faults')
        self.assertIn('active_import', m.FaultProbe.__dict__, 'F15 must observe import, not reader stdout')
        p = m.FaultProbe.__new__(m.FaultProbe)
        p.daemon = 'unit-daemon'; p.source = '9'*64; p.owner = Mock(return_value=owner())
        p.e = Mock()
        self.execution = {'ID': 'e'*64, 'ContainerID': 'd'*64, 'Running': True, 'Pid': 44,
            'ProcessConfig': {'entrypoint': '/usr/local/bin/pg_restore', 'arguments': [
                '--no-password', '--exit-on-error', '--dbname',
                "host='/var/run/postgresql' port='5432' user='postgres' dbname='fixture'"]}}
        self.target = {'Id': 'd'*64, 'State': {'Running': True, 'StartedAt': 'target-start'}, 'RestartCount': 0}
        self.session = {'pid': 55, 'backend_start': 'backend-start', 'application_name': owner()['importRunID'],
                        'datname': 'fixture', 'usename': 'postgres', 'state': 'active',
                        'wait_event': 'PgSleep', 'copy_active': True}
        p.e.inspect.side_effect = lambda cid: self.target if cid == 'd'*64 else {'State': {'Running': True}}
        p.e.call.side_effect = lambda method, path: {'ID': 'unit-daemon'} if path == '/info' else self.execution
        p.sql = Mock(side_effect=lambda *args: __import__('json').dumps([self.session]))
        p.process_count = Mock(return_value=1)
        return p

    def test_active_import_requires_exact_independent_token_copy_sleep_exec_and_process(self):
        p = self.probe()
        got = p.active_import('d'*64, '8'*64)
        self.assertEqual(got['owner'], owner()); self.assertEqual(got['session'], self.session)
        self.assertEqual(got['target'], {'container_id': 'd'*64, 'started_at': 'target-start', 'restart_count': 0})
        p.process_count.assert_called_once_with('d'*64, owner()['importRunID'], 'pg_restore')
        self.assertIn("application_name='"+owner()['importRunID']+"'", p.sql.call_args.args[1])
        self.assertNotIn("application_name='"+owner()['runID']+"'", p.sql.call_args.args[1])

    def test_active_import_requires_worker_authorized_is_true_not_truthy(self):
        p = self.probe()
        for value in ('missing',False,1):
            active = owner()
            if value == 'missing': del active['workerStartAuthorized']
            else: active['workerStartAuthorized'] = value
            p.owner.return_value = active
            with self.subTest(value=value), self.assertRaises(ValueError): p.active_import('d'*64,'8'*64)
        self.assertFalse(any(c.args[0] == 'POST' for c in p.e.call.call_args_list))

    def test_reader_only_or_wrong_token_is_never_active_import(self):
        p = self.probe()
        for key, value in [('wait_event', 'ClientRead'), ('state', 'idle'), ('copy_active', False),
                           ('application_name', owner()['runID']), ('datname', 'postgres'), ('usename', 'other')]:
            before = copy.deepcopy(self.session); self.session[key] = value
            with self.subTest(key=key): self.assertIsNone(p.active_import('d'*64, '8'*64))
            self.session = before
        self.execution['Running'] = False
        self.assertIsNone(p.active_import('d'*64, '8'*64))

    def test_identity_drift_fails_closed_before_any_signal(self):
        p = self.probe()
        for key, value in [('importRunID', owner()['runID']), ('sourceContainerID', p.source),
                           ('execKind', 'dump'), ('daemonID', 'different')]:
            bad = owner(); bad[key] = value; p.owner.return_value = bad
            with self.subTest(key=key), self.assertRaises(ValueError): p.active_import('d'*64, '8'*64)
        p.owner.return_value = owner(); self.target['State']['StartedAt'] = 'replacement'
        with self.assertRaises(ValueError): p.active_import('d'*64, '8'*64)
        self.assertFalse(any(c.args[0] == 'POST' for c in p.e.call.call_args_list))
