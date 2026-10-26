#!/usr/bin/env python3
"""Replay actual lifecycle/resources and OOM/ENOSPC on an exclusive hosted VM."""
import argparse
import copy
import json
import os
from pathlib import Path
import subprocess
import sys

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
    metrics=('sample_count','process_RSS_sum_peak_bytes','process_rollup_RSS_sum_peak_bytes','process_PSS_sum_peak_bytes','cgroup_memory_peak_bytes','sampled_cgroup_memory_current_peak_bytes','cpu_usage_seconds_observed_delta','cpu_throttled_seconds_observed_delta','io_stat_available','tmp_cache_file_bytes_peak_sampled','log_bytes_peak_sampled','state_bytes_peak_sampled','process_rollup_missing_observations')
    roles={'source-pg','source-files','restore-pg','worker','scheduler','controller','fixture-s3-backend','operator-readback','operator-restic','image-audit','health-monitor'}
    result['containers']=[]
    for row in summary.get('containers',[]):
        if row['role'] not in roles:raise ValueError('unexpected resource role')
        result['containers'].append({'role':row['role'],'container':row['container'],**numeric_fields(row,metrics)})
    pg=('wal_bytes','wal_records','blks_read','blks_hit','temp_bytes','tup_inserted','tup_returned','cgroup_cpu_seconds_delta','window_seconds','database_bytes_before','database_bytes_after')
    for name in ('source_pg_first_dump_window','target_pg_restore_window'):
        if name in summary:result[name]=numeric_fields(summary[name],pg)
    return result


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
    pass


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
    if row['failed']:
        public['failed']=True
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
