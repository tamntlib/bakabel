"""Additive F14 hosted fixture. Uses only ordinary public restore CLI.

The host tracer is armed before forwarding the unchanged real restore-start.
A tiny archive can finish reading before this gate: retain the existing 300000
row corpus, and fail closed if a unique backpressured reader is unavailable.
"""
import copy
import hashlib
import json
import re
import select
import subprocess
import sys
import time
from pathlib import Path
from hosted_f14_reader import find_reader, check_binding
from verify_hosted_f14 import CASE, demand

DATA_SQL = "SELECT json_build_object('rows',count(*),'min',min(g),'max',max(g),'sum',sum(g),'digest',md5(string_agg(md5(g::text||':'||data),'' ORDER BY g)))::text FROM public.payload"


class F14Mixin:
    def run(self):
        if self.case != CASE: return super().run()
        self.prepare()
        self.exercise_reader_failure()
        self.verify_source_online()
        self.result['exercised'] = True

    def start_reader_tracer(self, active):
        attempt = self.f14_attempt
        demand(active.get('workerStartAuthorized') is True and self.owner() == active,
               'strict current import authorization missing')
        demand(active.get('sourceContainerID') == attempt['target']['container_id'] and
               active.get('sourceStartedAt') == attempt['target']['started_at'], 'exact import target changed')
        cid = active['workerContainerID']; self.capture_owned_worker(cid)
        obj = self.e.inspect(cid); self.worker_identity_proof(obj,active)
        demand(obj['State'].get('Running') is True,'exact worker not live')
        worker_pid = obj['State']['Pid']
        # Reader goroutine and relay request can race. Retry only this read-only
        # discovery, under one 1s observation bound; never resize the corpus.
        end=time.monotonic()+1
        while True:
            try:
                process = find_reader(worker_pid,self.f14_snapshot,self.f14_dump_path); break
            except ValueError:
                if time.monotonic() >= end: raise TimeoutError('ordinary reader discovery unavailable') from None
                time.sleep(.01)
        binding = {'owner':copy.deepcopy(active),'reader':process,'worker_pid':worker_pid,
                   'snapshot_id':self.f14_snapshot,'dump_path':self.f14_dump_path,'mode':attempt['mode'],'image_id':self.image}
        check_binding(binding,self.owner(),process)
        path=self.root/'private'/('f14-'+attempt['mode']+'.json')
        path.write_text(json.dumps(binding)); path.chmod(0o600)
        child=subprocess.Popen([sys.executable,str(Path(__file__).with_name('hosted_f14_reader.py')),
            '--binding',str(path),'--owner',str(self.root/'state/owner.json'),'--socket',str(self.args.socket)],
            stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True)
        self.f14_tracer=child
        ready,_,_=select.select([child.stdout],[],[],5)
        demand(bool(ready),'host reader tracer did not arm')
        line=child.stdout.readline(4096)
        demand(json.loads(line) == {'state':'armed'},'host reader tracer refused attachment')
        attempt.update(owner=copy.deepcopy(active),worker_pid=worker_pid)

    def finish_reader_tracer(self):
        child=self.f14_tracer
        # Worker termination means reader Wait completed; helper must promptly
        # supply its actual ptrace wait status, not inferred CLI failure.
        output,_=child.communicate(timeout=3)
        demand(child.returncode == 0 and len(output) <= 4096,'host reader tracer failed')
        rows=[json.loads(x) for x in output.splitlines()]
        demand(len(rows) == 1 and rows[0].get('state') == 'terminal','host reader terminal proof missing')
        self.f14_tracer=None
        return rows[0]['reader']

    def observe_transport(self,phase,record):
        super().observe_transport(phase,record)
        attempt=getattr(self,'f14_attempt',None)
        if not attempt or phase != 'request': return
        if record['boundary'] == 'restore-start':
            demand('owner' not in attempt,'duplicate import start')
            self.start_reader_tracer(record['owner_checkpoint'])
        elif record['boundary'] == 'worker-remove' and 'owner' in attempt and record.get('container_id') == attempt['owner']['workerContainerID']:
            from verify_hosted_faults import verify_nonforce_remove
            verify_nonforce_remove(record)
            demand(record.get('forwarded') is False and 'terminal' not in attempt,'duplicate or late removal observation')
            active=attempt['owner']; current=self.owner(); cid=active['workerContainerID']
            demand(current and all(current.get(k) == active[k] for k in ('runID','daemonID','workerContainerID','workerName')) and
                   current.get('workerStartAuthorized') is True and current.get('phase') == 'intent' and current.get('status') == 'active' and
                   all(not current.get(k) for k in ('sourceContainerID','execID','importRunID')),
                   'ordinary reader terminal ownership lost before removal')
            reader=self.finish_reader_tracer()
            terminal={**self.terminal_proof(active),'import_run_id':active['importRunID']}
            demand(type(terminal.get('exec_exit_code')) is int and terminal['exec_exit_code'] == 0,
                   'reader fault did not leave otherwise-valid importer zero')
            obj=self.e.inspect(cid); self.worker_identity_proof(obj,active)
            state=obj['State']; expected=1 if attempt['mode'] == 'fault' else 0
            demand(state.get('Running') is False and type(state.get('Pid')) is int and state['Pid'] == 0 and
                   type(state.get('ExitCode')) is int and state['ExitCode'] == expected and self.owner() == current,
                   'ordinary worker falsely succeeded or terminal ownership drifted')
            record.update(owner_before_remove=current,terminal_before_remove=terminal,reader_before_remove=reader,
                          worker_before_remove=self.worker_observation(cid,obj,time.monotonic()))
            attempt.update(reader=reader,terminal=terminal)

    def exercise_reader_failure(self):
        # Independently freeze the public logical ID; never substitute the
        # durable owner target SHA-256 for this public ID.
        plan=self.call_cli('plan'); demand(isinstance(plan,dict) and len(plan.get('targets',[])) == 1,'one planned source required')
        planned=plan['targets'][0]
        demand(planned.get('ID') == self.target and planned.get('Kind') == 'postgres' and planned.get('Source',{}).get('ContainerID') == self.source,
               'frozen planned source changed')
        frozen={'ID':planned['ID'],'Kind':planned['Kind'],'Source':{k:planned['Source'][k] for k in ('DaemonID','ContainerID','StartedAt')}}
        snapshot=self.success_snapshot(); self.f14_snapshot=snapshot
        exact=[x for x in self.call_cli('snapshots') if x.get('snapshotID') == snapshot]
        demand(len(exact) == 1,'exact trusted snapshot missing')
        snap=exact[0]
        mapping={'plan':frozen,'snapshot':{k:snap[k] for k in ('snapshotID','status','type','source')}}
        mapping['snapshot']['metadata']={k:snap['metadata'][k] for k in ('version','kind','source','paths')}
        expected_path='/bakabel/postgres/'+hashlib.sha256(frozen['ID'].encode()).hexdigest()+'/database.dump'
        demand(re.fullmatch('[a-f0-9]{64}',snapshot) and snap.get('source') == frozen['ID'] and
               snap.get('status') == 'complete' and snap.get('type') == 'postgres' and
               type(snap['metadata'].get('version')) is int and snap['metadata']['version'] == 1 and
               snap['metadata'].get('kind') == 'postgres' and snap['metadata'].get('source') == frozen['ID'] and
               snap['metadata'].get('paths') == [expected_path],
               'trusted public snapshot identity/path mismatch')
        self.f14_dump_path=mapping['snapshot']['metadata']['paths'][0]
        source_data=json.loads(self.sql(self.source,DATA_SQL)); attempts=[]
        self.result['proof']={'target_mapping':mapping,'source_data':source_data,'attempts':attempts}
        for mode in ('control','fault'):
            target=self.startpg('restore-'+mode,False); obj=self.e.inspect(target)
            attempt={'mode':mode,'target':{'container_id':target,'started_at':obj['State']['StartedAt'],'restart_count':obj['RestartCount']}}
            self.f14_attempt=attempt
            controller=self.controller('restore','--snapshot',snapshot,'--postgres-container',target,'--database','fixture','--user','postgres')
            attempt['controller_id']=controller
            rows=self.finish(controller,expect=1 if mode == 'fault' else 0,timeout=85)
            demand('terminal' in attempt and len(rows) == 1,'ordinary CLI lacks retained reader/import terminal observations')
            active=attempt['owner']; last=self.last()
            result=rows[0]; targets=result.get('targets',[])
            demand(result.get('runID') == active['runID'] and result.get('status') == ('failed' if mode == 'fault' else 'restored') and
                   len(targets) == 1 and targets[0].get('targetID') == self.target and targets[0].get('snapshotID') == snapshot and
                   targets[0].get('status') == ('unknown' if mode == 'fault' else 'restored') and
                   (targets[0].get('error') == 'restore failed' if mode == 'fault' else not targets[0].get('error')),
                   'public CLI reader failure masked by importer or lost exact snapshot/logical source')
            demand(last.get('runID') == active['runID'] and last.get('operation') == 'restore' and
                   last.get('status') == ('failed' if mode == 'fault' else 'success') and
                   last.get('lastBackupSuccessAt') == self.baseline_success,'restore changed last backup success/result')
            demand(self.owner() is None and self.e.inspect(active['workerContainerID'],missing=True) is None,'terminal ownership not released')
            after=self.e.inspect(target)
            demand(after['State']['Running'] is True and {'container_id':after['Id'],'started_at':after['State']['StartedAt'],'restart_count':after['RestartCount']} == attempt['target'],
                   'restore destination not retained unchanged')
            data=json.loads(self.sql(target,DATA_SQL))
            demand(data == source_data,'otherwise-valid importer lost expected payload')
            attempt.update(result=rows[0],data=data,cli_exit=1 if mode == 'fault' else 0,
                           owner_released=True,worker_absent=True,last_success_unchanged=True)
            attempts.append(attempt)
            self.f14_attempt=None
        demand(json.loads(self.sql(self.source,DATA_SQL)) == source_data,'source data changed')

    def cleanup(self):
        # Stop only our host observer. Its bounded finally detaches owned
        # tracees; inherited identity-gated fixture cleanup handles containers.
        child=getattr(self,'f14_tracer',None)
        if child is not None:
            try: child.communicate(timeout=22)
            except subprocess.TimeoutExpired:
                # Do not terminate a tracer and strand unknown stopped tasks.
                raise ValueError('host tracer not quiescent; preserve exact recovery paths') from None
            self.f14_tracer=None
        return super().cleanup()
