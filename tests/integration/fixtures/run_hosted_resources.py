#!/usr/bin/env python3
"""Replay actual lifecycle/resources and OOM/ENOSPC on an exclusive hosted VM."""
import argparse
import copy
import json
import os
import re
import stat
from pathlib import Path
import subprocess
import sys
import time
from urllib.parse import quote

from run_compose_pg_acceptance import fingerprint
from run_hosted_acceptance import require_hosted_daemon,run_platform
from run_resource_failures import FailureProbe
from run_resource_probe import Engine,PG,Probe,kv_numbers,sha,utc
from summarize_resource_probe import summarize
from hosted_evidence import public_receipt

CASES=('scheduler','oom-active','enospc','oom')


def case_settings(case):
    if case not in CASES:raise ValueError('unsupported resource case')
    return {'mode':case,'memory_mib':16 if case=='oom-active' else 32}


def numeric_fields(value,keys):
    result={}
    for key in keys:
        if key not in value:continue
        item=value[key]
        if item is not None and not isinstance(item,(int,float,bool)):
            raise ValueError('non-numeric resource counter')
        result[key]=item
    return result


def public_measurements(summary):
    result={}
    result['idle']=numeric_fields(summary.get('idle',{}),('seconds_between_samples','cgroup_cpu_seconds_delta','one_core_percent','RSS_first_bytes','RSS_last_bytes','PSS_first_bytes','PSS_last_bytes'))
    result['image']=numeric_fields(summary.get('image',{}),('actual_save_tar_bytes','oci_compressed_layer_bytes','actual_merged_export_tar_bytes','actual_export_extracted_regular_file_allocated_bytes','merged_export_regular_file_payload_bytes','merged_export_regular_files'))
    metrics=('sample_count','process_RSS_sum_peak_bytes','process_rollup_RSS_sum_peak_bytes','process_PSS_sum_peak_bytes','cgroup_memory_peak_bytes','sampled_cgroup_memory_current_peak_bytes','cpu_usage_seconds_observed_delta','cpu_throttled_seconds_observed_delta','io_stat_available','tmp_cache_file_bytes_peak_sampled','log_bytes_peak_sampled','state_bytes_peak_sampled','process_rollup_missing_observations','footprint_unlinked_observations')
    roles={'source-pg','source-files','restore-pg','worker','scheduler','controller','fixture-s3-backend','operator-readback','operator-restic','image-audit','health-monitor'}
    result['containers']=[]
    for row in summary.get('containers',[]):
        if row['role'] not in roles:raise ValueError('unexpected resource role')
        result['containers'].append({'role':row['role'],'container':row['container'],**numeric_fields(row,metrics)})
    pg=('wal_bytes','wal_records','blks_read','blks_hit','temp_bytes','tup_inserted','tup_returned','cgroup_cpu_seconds_delta','window_seconds','database_bytes_before','database_bytes_after')
    for name in ('source_pg_first_dump_window','target_pg_restore_window'):
        if name in summary:result[name]=numeric_fields(summary[name],pg)
    return result


def scheduler_completion_fields(value):
    """Only the completion status and ordinal target diagnostics, never IDs/text."""
    targets=value.get('targets')
    if not isinstance(targets,list) or len(targets)>128 or any(not isinstance(t,dict) for t in targets):return None
    def enum(item,allowed):return item if isinstance(item,str) and item in allowed else None
    rows=[]
    for index,target in enumerate(targets):
        code=target.get('resticExitCode')
        rows.append({'ordinal':index,'status':enum(target.get('status'),('complete','restored','unknown','partial')),
            'failureCode':enum(target.get('failureCode'),('file_preflight','list_before','backup','list_after','source_verification','tag','final_readback','metadata_readback')),
            'resticExitCode':code if type(code) is int and 0<=code<=255 else None,
            'resticReason':enum(target.get('resticReason'),('enospc','permission','backend','unknown'))})
    return {'status':enum(value.get('status'),('complete','restored','failed')),'targets':rows}


def public_scheduler_diagnostics(raw):
    """Re-project even our private diagnostic receipt; never copy free text."""
    value=raw.get('scheduler_diagnostics',{})
    out={'workers':[],'durable':[],'events':{'status':'unavailable','items':[]},'controller_completions':{'status':'unavailable','items':[]}}
    if not isinstance(value,dict):return out
    def identifier(item,length):return isinstance(item,str) and re.fullmatch(r'[0-9a-f]{'+str(length)+'}',item)
    def enum(item,allowed):return item if item in allowed else None
    def code(item):return item if type(item) is int and 0<=item<=255 else None
    rows=value.get('workers',[])
    for row in rows[:130] if isinstance(rows,list) else []:
        if (not isinstance(row,dict) or not identifier(row.get('container'),64) or not identifier(row.get('run_id'),32) or
            row.get('state_directory') not in ('state','fresh-state')):continue
        out['workers'].append({'container':row['container'],'run_id':row['run_id'],'state_directory':row['state_directory'],
            'inspect_status':enum(row.get('inspect_status'),('observed','missing','unavailable')),
            'state':enum(row.get('state'),('created','running','paused','restarting','removing','exited','dead')),
            'running':row.get('running') if type(row.get('running')) is bool else None,
            'exit_code':code(row.get('exit_code')),'oom_killed':row.get('oom_killed') if type(row.get('oom_killed')) is bool else None})
    owned={(r['state_directory'],r['run_id']) for r in out['workers']}
    statuses={'owner':('active','blocked'),'last_result':('success','failed','canceled','unknown'),'workflow_output':('complete','restored','failed')}
    rows=value.get('durable',[])
    for row in rows[:6] if isinstance(rows,list) else []:
        if (not isinstance(row,dict) or not identifier(row.get('run_id'),32) or
            row.get('state_directory') not in ('state','fresh-state') or not isinstance(row.get('record'),str) or
            row['record'] not in statuses or (row['state_directory'],row['run_id']) not in owned):continue
        out['durable'].append({'state_directory':row['state_directory'],'record':row['record'],'run_id':row['run_id'],
            'status':enum(row.get('status'),statuses[row['record']]),
            'phase':enum(row.get('phase'),('intent','creating_exec','exec_created','exec_started','quarantine')) if row['record']=='owner' else None})
    completions=value.get('controller_completions',{})
    if isinstance(completions,dict) and completions.get('status')=='observed':
        rows=completions.get('items',[])
        for row in rows if isinstance(rows,list) and len(rows)<=256 else []:
            if (not isinstance(row,dict) or not identifier(row.get('run_id'),32) or
                row.get('state_directory') not in ('state','fresh-state') or
                (row['state_directory'],row['run_id']) not in owned):continue
            fields=scheduler_completion_fields(row)
            if fields is not None:
                out['controller_completions']['items'].append({'state_directory':row['state_directory'],'run_id':row['run_id'],
                    **fields,'controller_failed':row.get('controller_failed') if type(row.get('controller_failed')) is bool else None})
        if out['controller_completions']['items']:out['controller_completions']['status']='observed'
    events=value.get('events',{})
    if not isinstance(events,dict) or events.get('status')!='observed':return out
    out['events']['status']='observed'
    rows=events.get('items',[]);containers={r['container'] for r in out['workers']}
    for row in rows[:256] if isinstance(rows,list) else []:
        if (not isinstance(row,dict) or not identifier(row.get('container'),64) or row['container'] not in containers or
            row.get('event') not in ('oom','die') or type(row.get('time_ns')) is not int or not 0<row['time_ns']<2**63):continue
        out['events']['items'].append({'container':row['container'],'event':row['event'],'time_ns':row['time_ns'],
                                      'exit_code':code(row.get('exit_code')) if row['event']=='die' else None})
    return out


def public_failure_diagnostics(raw):
    """Small typed fault/readback receipt; no paths, errors, logs or Env."""
    value=raw.get('failure_diagnostics',{})
    if not isinstance(value,dict):value={}
    out={}
    for key in ('warning_count','requested_memory_bytes','requested_swap_total_bytes','host_memory_bytes','host_swap_total_bytes',
                'effective_memory_bytes','effective_swap_bytes','terminal_pid','terminal_exit_code','terminal_oom_kill'):
        item=value.get(key);maximum=255 if key=='terminal_exit_code' else 2**63-1
        out[key]=item if type(item) is int and 0<=item<=maximum else None
    for key in ('source_unlocked','terminal_oom_killed'):
        item=value.get(key);out[key]=item if type(item) is bool else None
    status=value.get('update_http_status')
    out['update_http_status']=status if type(status) is int and 100<=status<=599 else None
    for key,allowed in (('failure_code',('memory_update','effective_limits','worker_terminal','recovery','oom_proof','final_readback')),
                        ('update_status',('accepted','rejected','unavailable')),('terminal_counter_status',('observed','unavailable'))):
        item=value.get(key);out[key]=item if isinstance(item,str) and item in allowed else None
    fields=scheduler_completion_fields({'targets':value.get('targets',[])})
    out['targets']=[] if fields is None else [{k:row[k] for k in ('failureCode','resticExitCode','resticReason')} for row in fields['targets']]
    return out


def verify_early_oom(raw,image):
    assert raw['mode']=='oom' and raw['early_oom_phase']=='intent-before-source-exec'
    proof=raw['failure_terminal_proof'];last=proof['last_result']
    assert proof['status']=='failed' and not proof['complete'] and proof['owner_released']
    assert proof['worker_terminal'] and proof['source_never_started'] and proof['session_count']==0
    assert last['status']=='failed' and raw['snapshots_after_failure']==[]
    worker=raw['worker_last_inspect']
    assert worker['Image']==image and worker['State']['OOMKilled']
    assert worker['HostConfig']['Memory']==33554432 and worker['HostConfig']['NanoCpus']==2000000000
    owners=[row['owner'] for row in raw['owner_history']]
    assert owners and all(o['phase']=='intent' and not o.get('execID') and not o.get('sourceContainerID') and o['runID']==last['runID'] and o['workerContainerID']==worker['Id'] for o in owners)
    rows=raw['failure_cgroup_samples']
    assert rows and all(r['cpu.max']=='200000 100000' and r['memory.max']=='33554432' for r in rows)
    assert max(kv_numbers(row['memory.events']).get('oom_kill',0) for row in rows)>0
    assert not any('pg_dump' in str(e.get('action','')) or 'pg_dump' in str(e.get('execCommand','')) for e in raw['source_exec_events'])
    assert raw['source_after']['identity_unchanged'] and raw['source_after']['read_write_ok']
    return {'verified':True,'before_source_only':True,'configured_memory_bytes':33554432,'active_export_support_claimed':False}


class BoundEvidence:
    def __init__(self,args):
        super().__init__(args,inventory_images=(args.image,PG))
        if self.image!=args.expected_image_id or fingerprint(args.source)!=args.expected_source_sha256:
            raise ValueError('resource candidate differs from build binding')
        self.result.update(platform=args.platform,source_sha256=args.expected_source_sha256,image_id=self.image,direct_engine=True,cpu_fields_omitted=[])

    def save(self):
        if any(value in json.dumps(self.result) for value in self.values):
            raise ValueError('credential found in resource evidence')
        super().save()


class HostedResourceProbe(BoundEvidence,Probe):
    def __init__(self,args):
        self._events_since_ns=time.time_ns()
        super().__init__(args)

    def diagnostic_json(self,relative):
        """Fixed owned paths only; bounded regular files, no symlink traversal."""
        directory=None
        try:
            directory=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            parts=relative.split('/')
            for part in parts[:-1]:
                child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=directory)
                os.close(directory);directory=child
            fd=os.open(parts[-1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory)
            with os.fdopen(fd,'rb') as stream:
                if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):return {}
                data=stream.read(256*1024+1)
            if len(data)>256*1024:return {}
            value=json.loads(data)
            return value if isinstance(value,dict) else {}
        except (OSError,ValueError):return {}
        finally:
            if directory is not None:os.close(directory)

    def collect_scheduler_completions(self,verified,diagnostics):
        """Retained stdout is controller evidence, not a worker-published receipt."""
        completion=diagnostics['controller_completions']
        containers=dict(getattr(self,'containers',{}))
        if not verified or len(containers)>128:return
        for cid,name in containers.items():
            if (not isinstance(cid,str) or not re.fullmatch(r'[0-9a-f]{64}',cid) or not isinstance(name,str) or
                getattr(self,'roles',{}).get(cid)!='scheduler'):continue
            try:
                obj=self.e.inspect(cid,missing=True)
                if not isinstance(obj,dict):continue
                config=obj.get('Config',{});labels=config.get('Labels') or {}
                if (obj.get('Id')!=cid or obj.get('Name')!='/'+name or obj.get('Image')!=self.image or
                    labels.get('probe.bakabel.owner')!=self.prefix or labels.get('bakabel.installation')!=self.prefix or
                    labels.get('bakabel.role')!='scheduler' or config.get('Cmd')!=['--config','/config.yaml','serve'] or
                    config.get('Entrypoint')!=['/usr/local/bin/bakabel'] or config.get('Tty',False) is not False):continue
                states=[state for state in ('state','fresh-state') if any(
                    m.get('Type')=='bind' and m.get('Destination')=='/state' and m.get('Source')==str(self.root/state)
                    for m in obj.get('Mounts',[]))]
                if len(states)!=1 or not any(r['state']==states[0] for r in verified.values()):continue
                raw=self.e.call('GET','/containers/'+cid+'/logs?stdout=true&stderr=false&follow=false&timestamps=false&tail=256',raw=True)
                if not isinstance(raw,bytes) or len(raw)>256*1024:continue
                text=b''
                while raw:
                    if len(raw)<8 or raw[0] not in (1,2) or raw[1:4]!=b'\0\0\0':raise ValueError('invalid log frame')
                    stream=raw[0];size=int.from_bytes(raw[4:8],'big')
                    if size>len(raw)-8:raise ValueError('truncated log frame')
                    if stream==1:text+=raw[8:8+size]
                    raw=raw[8+size:]
                lines=text.decode().splitlines()
                if len(lines)>256:continue
                for line in lines:
                    try:event=json.loads(line)
                    except ValueError:continue
                    if not isinstance(event,dict) or event.get('event')!='run_finished':continue
                    value=event.get('result')
                    if not isinstance(value,dict):continue
                    run=value.get('runID')
                    if not any(r['runID']==run and r['state']==states[0] for r in verified.values()):continue
                    fields=scheduler_completion_fields(value)
                    if fields is None:continue
                    failed=event.get('failed',False)  # Serve omits false; absence is not a missing receipt.
                    row={'state_directory':states[0],'run_id':run,**fields,'controller_failed':failed if type(failed) is bool else None}
                    if len(completion['items'])<256 and row not in completion['items']:completion['items'].append(row)
            except Exception:continue
        if completion['items']:completion['status']='observed'

    def collect_scheduler_diagnostics(self):
        """Best effort only; never replace the lifecycle or sampler's errors."""
        from run_resource_probe import worker_owned
        diagnostics={'workers':[],'durable':[],'events':{'status':'unavailable','items':[]},'controller_completions':{'status':'unavailable','items':[]}}
        self.result['scheduler_diagnostics']=diagnostics
        if len(self.worker_records)>128:return
        if self.e.call('GET','/info')['ID']!=self.daemon:return
        records=dict(self.worker_records);owners={};verified={}
        for state in ('state','fresh-state'):
            owner=self.diagnostic_json(state+'/owner.json');owners[state]=owner
            cid=owner.get('workerContainerID');run=owner.get('runID')
            if (not isinstance(cid,str) or not re.fullmatch(r'[0-9a-f]{64}',cid) or
                not isinstance(run,str) or not re.fullmatch(r'[0-9a-f]{32}',run) or
                not isinstance(owner.get('workerName'),str) or owner.get('daemonID')!=self.daemon or cid in records):continue
            try:
                obj=self.e.inspect(cid,missing=True)
                if obj and worker_owned(obj,owner,self.image,self.daemon):records[cid]={**obj,'runID':run,'state':state}
            except Exception:pass
        for cid,record in list(records.items()):
            if (not isinstance(cid,str) or not re.fullmatch(r'[0-9a-f]{64}',cid) or
                not isinstance(record.get('runID'),str) or not re.fullmatch(r'[0-9a-f]{32}',record['runID']) or
                not isinstance(record.get('Name'),str) or not record['Name'].startswith('/') or
                record.get('state') not in ('state','fresh-state')):continue
            owner={'workerContainerID':cid,'workerName':record['Name'].lstrip('/'),
                   'runID':record['runID'],'daemonID':self.daemon}
            if not worker_owned(record,owner,self.image,self.daemon):continue
            verified[cid]=record
            row={'container':cid,'run_id':record['runID'],'state_directory':record['state'],
                 'inspect_status':'unavailable','state':None,'running':None,'exit_code':None,'oom_killed':None}
            diagnostics['workers'].append(row)
            try:
                obj=self.e.inspect(cid,missing=True)
                if obj is None:row['inspect_status']='missing'
                elif worker_owned(obj,owner,self.image,self.daemon):
                    state=obj.get('State',{})
                    row.update(inspect_status='observed',
                               state=state.get('Status') if state.get('Status') in ('created','running','paused','restarting','removing','exited','dead') else None,
                               running=state.get('Running') if type(state.get('Running')) is bool else None,
                               exit_code=state.get('ExitCode') if type(state.get('ExitCode')) is int and 0<=state['ExitCode']<=255 else None,
                               oom_killed=state.get('OOMKilled') if type(state.get('OOMKilled')) is bool else None)
            except Exception:pass  # Unavailable is not zero/false or a terminal proof.
        phases=('intent','creating_exec','exec_created','exec_started','quarantine')
        for state,owner in owners.items():
            for kind,path,statuses in (('owner','owner.json',('active','blocked')),
                                       ('last_result','last-result.json',('success','failed','canceled','unknown')),
                                       ('workflow_output','workflow/output/result.json',('complete','restored','failed'))):
                value=owner if kind=='owner' else self.diagnostic_json(state+'/'+path)
                if not any(r['state']==state and r['runID']==value.get('runID') and
                           (kind!='owner' or worker_owned(r,owner,self.image,self.daemon)) for r in verified.values()):continue
                diagnostics['durable'].append({'state_directory':state,'record':kind,'run_id':value['runID'],
                    'status':value.get('status') if value.get('status') in statuses else None,
                    'phase':value.get('phase') if kind=='owner' and value.get('phase') in phases else None})
        self.collect_scheduler_completions(verified,diagnostics)
        # Engine history is bounded/cache-limited; no event is not proof of no OOM.
        start=getattr(self,'_events_since_ns',None);end=time.time_ns()
        if not verified or type(start) is not int or not 0<start<end:return
        def seconds(ns):return '%d.%09d'%divmod(ns,1000000000)
        filters={'type':['container'],'container':sorted(verified),'event':['oom','die']}
        raw=self.e.call('GET','/events?since='+seconds(start)+'&until='+seconds(end)+
                        '&filters='+quote(json.dumps(filters),safe=''),raw=True)
        if not isinstance(raw,bytes) or len(raw)>256*1024:return
        lines=raw.splitlines()
        if len(lines)>256:return
        items=[]
        for line in lines:
            event=json.loads(line);actor=event.get('Actor',{})
            cid=actor.get('ID');at=event.get('timeNano');action=event.get('Action')
            if (event.get('Type')!='container' or cid not in verified or action not in ('oom','die') or
                type(at) is not int or not start<=at<=end):continue
            code=actor.get('Attributes',{}).get('exitCode')
            code=int(code) if action=='die' and isinstance(code,str) and re.fullmatch(r'[0-9]{1,3}',code) and int(code)<=255 else None
            items.append({'container':cid,'event':action,'time_ns':at,'exit_code':code})
        diagnostics['events'].update(status='observed',items=items)

    def cleanup(self):
        try:self.collect_scheduler_diagnostics()
        except Exception:pass  # Only this diagnostic read is best effort.
        super().cleanup()


class HostedFailureProbe(BoundEvidence,FailureProbe):
    pass


def verify_cleanup(raw,args,engine):
    assert not raw.get('error') and not raw.get('cleanup_error')
    assert not raw.get('sampler_errors') and not raw.get('fast_observer_errors')
    info=engine.call('GET','/info')
    assert info['ID']==raw['daemon'] and info['Swarm']['LocalNodeState']=='inactive'
    assert engine.call('GET','/images/'+args.image+'/json')['Id']==args.expected_image_id
    assert raw['image_id']==args.expected_image_id and raw['source_sha256']==fingerprint(args.source)==args.expected_source_sha256
    assert raw['workers'] or args.mode=='oom'
    for worker in raw['workers'].values():assert worker['Image']==args.expected_image_id
    cleanup=raw['cleanup']
    for cid,absent in cleanup['containers_absent'].items():assert absent and engine.inspect(cid,missing=True) is None
    for name,absent in cleanup['volumes_absent'].items():assert absent and engine.call('GET','/volumes/'+name,missing=True) is None
    assert cleanup['private_paths_absent'] and all(not (args.runtime/name).exists() for name in ('private','state','fresh-state','backend','bin'))
    assert engine.call('GET','/containers/json?all=true')==[]


def run_case(args,case,engine):
    args=copy.copy(args);args.runtime=args.runtime/case;args.platform='resources-'+case
    for key,value in case_settings(case).items():setattr(args,key,value)
    row=run_platform(args,probe_class=HostedResourceProbe if case=='scheduler' else HostedFailureProbe)
    directory=args.runtime;raw=json.loads((directory/'receipt.json').read_text())
    public=public_receipt(raw);public['case']=case;public['verified']=False
    public['raw_receipt_sha256']=sha(directory/'receipt.json')
    if case!='scheduler':
        public['failure_diagnostics']=public_failure_diagnostics(raw)
        terminal=raw.get('worker_terminal_before_recovery',raw.get('worker_last_inspect',{}))
        state=terminal.get('State',{});config=terminal.get('HostConfig',{})
        samples=raw.get('failure_cgroup_samples',[])
        counts=[kv_numbers(s.get('memory.events',''))['oom_kill'] for s in samples if 'oom_kill' in kv_numbers(s.get('memory.events',''))]
        public['failure_observations']={'worker_exit_code':state.get('ExitCode') if type(state.get('ExitCode')) is int else None,'worker_oom_killed':state.get('OOMKilled') if type(state.get('OOMKilled')) is bool else None,'worker_memory_bytes':config.get('Memory') if type(config.get('Memory')) is int else None,'cgroup_samples':len(samples),'sampled_oom_kill_max':max(counts,default=None),'sampled_memory_max_bytes':sorted({int(s['memory.max']) for s in samples if str(s.get('memory.max','')).isdigit()})}
    if row['failed']:
        public['failed']=True
        if case=='scheduler':public['scheduler_diagnostics']=public_scheduler_diagnostics(raw)
        (directory/'public.json').write_text(json.dumps(public,indent=2)+'\n')
        return public
    try:
        verify_cleanup(raw,args,engine)
        if case=='scheduler':
            summary=summarize(directory)
            (directory/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
            public['measurements']=public_measurements(summary)
            verifier='verify_resource_probe.py'
        elif case=='oom':
            public['configured_oom']=verify_early_oom(raw,args.expected_image_id)
            verifier=None
        else:verifier='verify_resource_failures.py'
        if verifier:
            command=[sys.executable,str(Path(__file__).parent/verifier),'--runtime',str(directory),'--source',str(args.source),'--output',str(directory/'verified.json'),'--expected-source-sha256',args.expected_source_sha256,'--expected-image-id',args.expected_image_id]
            result=subprocess.run(command,text=True,capture_output=True)
            (directory/'verification.log').write_text(result.stdout+result.stderr)
            if result.returncode:raise ValueError('independent resource verifier failed')
            public['verifier_sha256']=sha(directory/'verified.json')
        if case!='scheduler':
            proof=raw['failure_terminal_proof']
            public['failure_safety']={k:proof[k] for k in ('status','complete','owner_released','worker_terminal','source_never_started','exec_terminal','session_count','worker_removed') if k in proof}
            public['effective_memory_max_values']=sorted({r.get('memory.max') for r in raw['failure_cgroup_samples'] if r.get('memory.max')})
            public['observed_oom_kill_max']=max((kv_numbers(r.get('memory.events','')).get('oom_kill',0) for r in raw['failure_cgroup_samples']),default=0)
            public['actual_enospc_observations']=sum(row['errno']==28 for row in raw['repository_space_samples'])
        public['verified']=True
    except Exception as error:
        from run_hosted_acceptance import failure_location
        public['failed']=True;public['failure']=failure_location(error)
        if case=='scheduler':public['scheduler_diagnostics']=public_scheduler_diagnostics(raw)
    (directory/'public.json').write_text(json.dumps(public,indent=2)+'\n')
    return public


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('socket','source','runtime','minio-binary'):parser.add_argument('--'+name,type=Path,required=True)
    for name in ('image','expected-source-sha256','expected-image-id'):parser.add_argument('--'+name,required=True)
    parser.add_argument('--exclusive-hosted-daemon',action='store_true')
    parser.add_argument('--case',choices=(*CASES,'all'),default='all')
    args=parser.parse_args(argv)
    if os.environ.get('GITHUB_ACTIONS')!='true' or os.environ.get('RUNNER_ENVIRONMENT')!='github-hosted' or os.geteuid()!=0 or not args.exclusive_hosted_daemon:
        parser.error('requires explicit exclusive GitHub-hosted VM and root; local/shared use refused')
    engine=Engine(args.socket)
    info=engine.call('GET','/info')
    require_hosted_daemon(os.environ,os.geteuid(),args.exclusive_hosted_daemon,info,engine.call('GET','/containers/json?all=true'))
    temporary=Path(os.environ['RUNNER_TEMP']).resolve();args.runtime=args.runtime.resolve()
    if args.runtime==temporary or not args.runtime.is_relative_to(temporary) or args.runtime.exists():parser.error('runtime must be a fresh child of RUNNER_TEMP')
    if fingerprint(args.source)!=args.expected_source_sha256 or engine.call('GET','/images/'+args.image+'/json')['Id']!=args.expected_image_id:parser.error('candidate build binding differs')
    os.sched_setaffinity(0,{0,1});args.runtime.mkdir(mode=0o700)
    selected=CASES if args.case=='all' else (args.case,)
    results=[]
    for case in selected:
        result=run_case(args,case,engine);results.append(result)
        report={'finished_at':utc(),'source_sha256':args.expected_source_sha256,'image_id':args.expected_image_id,'daemon':info['ID'],'cases':results,'resources_pass':selected==CASES and len(results)==len(CASES) and all(r['verified'] and not r['failed'] for r in results),'full_plan_acceptance_pass':False}
        (args.runtime/'resources-public.json').write_text(json.dumps(report,indent=2)+'\n')
        print(json.dumps({'case':case,'verified':result['verified'],'failed':result['failed']}),flush=True)
        if result['failed'] or not result['verified']:return 1
    return 0 if len(results)==len(selected) and all(r['verified'] and not r['failed'] for r in results) else 1


if __name__=='__main__':raise SystemExit(main())
