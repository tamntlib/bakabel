#!/usr/bin/env python3
"""Independent exact readback for real mid-run OOM / bounded-repository ENOSPC."""
import argparse, datetime, hashlib, json, os
from pathlib import Path
from run_resource_probe import Engine, sha, kv_numbers
from run_resource_failures import assert_failure_proof, is_write_enospc

def epoch(value):return datetime.datetime.fromisoformat(value.replace('Z','+00:00')).timestamp()

def assert_bounded_recovery(job, worker_finished, result_finished):
    deadline=epoch(job['createdAt'])+job['config']['Timeout']/1e9
    assert epoch(worker_finished)<=deadline+20
    assert epoch(result_finished)<=deadline+20
    assert epoch(result_finished)-epoch(worker_finished)<=20
    return {'original_deadline_epoch':deadline,'worker_seconds_after_deadline':epoch(worker_finished)-deadline,'release_seconds_after_deadline':epoch(result_finished)-deadline,'release_seconds_after_worker_terminal':epoch(result_finished)-epoch(worker_finished)}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ['runtime','source','output']:p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--expected-source-sha256',required=True);p.add_argument('--expected-image-id',required=True)
    a=p.parse_args();os.sched_setaffinity(0,{0,1})
    r=json.loads((a.runtime/'receipt.json').read_text());metrics=json.loads((a.runtime/'metrics.json').read_text())
    assert not r.get('error'),r.get('error')
    assert r['mode'] in ['oom-active','enospc'] and len(r['gates'])==1
    assert not r.get('fast_observer_errors') and not r.get('sampler_errors')
    assert sha(a.runtime/'executed_failure_probe.py')==r['failure_probe_sha256']
    assert sha(a.source/'tests/integration/fixtures/run_resource_probe.py')==r['fingerprint']['probe_sha256']
    for path,value in r['fingerprint']['source_files'].items():assert sha(a.source/path)==value
    core=hashlib.sha256()
    files=sorted((f for f in a.source.rglob('*') if f.is_file() and (f.suffix=='.go' or f.name in ['go.mod','go.sum','Dockerfile'])),key=lambda f:str(f.relative_to(a.source)))
    for f in files:core.update(str(f.relative_to(a.source)).encode()+b'\0'+bytes.fromhex(sha(f)))
    assert core.hexdigest()==a.expected_source_sha256
    image=next(iter(r['images'].values()))['id'];assert image==a.expected_image_id
    e=Engine(r['socket']);info=e.call('GET','/info');assert info['ID']==r['daemon'] and info['Swarm']['LocalNodeState']=='inactive'
    assert e.call('GET','/images/'+image+'/json')['Id']==image
    assert all(w['Image']==image for w in r['workers'].values())
    proof=r['failure_terminal_proof'];assert_failure_proof(proof)
    assert proof['worker_removed'] and proof['owner_released'] and not proof['exec']['Running']
    assert r['snapshots_after_failure']==[] and r['source_after']['identity_unchanged'] and r['source_after']['read_write_ok']
    timing=assert_bounded_recovery(r['frozen_job_before_failure'],r['worker_terminal_before_recovery']['State']['FinishedAt'],proof['last_result']['finishedAt'])
    assert r['bounded_repository']['keeper_mount']['Source']==r['bounded_repository']['volume_inspect']['Mountpoint']
    worker=r['active_before_failure']['workerContainerID'];assert worker in r['workers']
    assert r['active_before_failure']['phase']=='exec_started'
    assert r['workers'][worker]['HostConfig']['Memory']==536870912
    assert r['workers'][worker]['HostConfig']['NanoCpus']==2000000000
    assert r['workers'][worker]['HostConfig']['CpusetCpus']==''
    rows=r['failure_cgroup_samples'];assert rows and all(x.get('cpu.max')=='200000 100000' for x in rows)
    env=r['restic_effective_env'];assert env and all(x['GOMAXPROCS']==['GOMAXPROCS=2'] for x in env)
    if r['mode']=='oom-active':
        assert r['injected_memory_update']['exact_worker']==worker
        limit=r['injected_memory_update']['request']['Memory']
        assert r['updated_worker_hostconfig']['Memory']==limit
        assert {str(limit),'536870912'}<={x.get('memory.max') for x in rows}
        assert max(kv_numbers(x.get('memory.events','')).get('oom_kill',0) for x in rows)>0
        assert r['worker_terminal_before_recovery']['State']['OOMKilled']
    else:
        assert all(x.get('memory.max')=='536870912' for x in rows)
        proofspace=r['enospc_proof'];assert proofspace['worker_repository_source']==proofspace['repository_mountpoint']
        assert r['bounded_repository']['requested_bytes']==8388608
        direct=r['enospc_direct_write_before_release'];assert is_write_enospc(direct) and direct['capacity_bytes']==8388608 and direct['available_bytes']==0
        end=epoch(r['worker_terminal_before_recovery']['State']['FinishedAt'])
        relevant=[x for x in r['repository_space_samples'] if is_write_enospc(x) and epoch(direct['at'])<=epoch(x['at'])<=end]
        assert relevant and all(x['capacity_bytes']==8388608 and x['available_bytes']==0 for x in relevant)
        assert is_write_enospc(r['repository_full_after_exact_terminal_proof'])
    for cid,value in r['cleanup']['containers_absent'].items():assert value and e.inspect(cid,missing=True) is None
    for vol,value in r['cleanup']['volumes_absent'].items():assert value and e.call('GET','/volumes/'+vol,missing=True) is None
    assert r['cleanup']['private_paths_absent'] and all(not (a.runtime/d).exists() for d in ['private','state','fresh-state','backend','bin'])
    out={'mode':r['mode'],'verified_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'gates':r['gates'],'source_sha256':core.hexdigest(),'image':image,'failure_proof':proof,'timing':timing,'effective_memory_max_values':sorted({x.get('memory.max') for x in rows}),'restic_effective_GOMAXPROCS':sorted({v for x in env for v in x['GOMAXPROCS']}),'exact_cleanup_readback':True,'files':{n:sha(a.runtime/n) for n in ['receipt.json','metrics.json','executed_failure_probe.py']},'limits':'Physical block I/O unavailable; sampled peaks not universal RAM bounds. Mid-run OOM is explicitly an injected Engine update during source lock-wait; short process birth-to-pin affinity gaps remain.'}
    a.output.write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(out,indent=2))

# This vocabulary is diagnostic only. The original verifier above remains the
# sole acceptance authority; never evaluate it twice to obtain a failure reason.
DIAGNOSTIC_MARKER='BAKABEL_RESOURCE_VERIFIER_V1 '
DIAGNOSTIC_PROGRAMS=('run_resource_failures.py','run_resource_probe.py','verify_resource_failures.py')
DIAGNOSTIC_FUNCTIONS={'verify_resource_failures.py':{'main':(17,69),'epoch':(8,8),'assert_bounded_recovery':(10,15)},
                      'run_resource_failures.py':{'assert_failure_proof':(199,204),'is_write_enospc':(99,104)}}
DIAGNOSTIC_ERRORS=('AssertionError','OSError','FileNotFoundError','PermissionError','TimeoutError',
                   'RuntimeError','ValueError','KeyError','TypeError','IndexError','StopIteration',
                   'JSONDecodeError','UnicodeDecodeError')


def diagnostic_program_sha256():
    digest=hashlib.sha256()
    for name in DIAGNOSTIC_PROGRAMS:
        digest.update(name.encode()+b'\0'+bytes.fromhex(sha(Path(__file__).parent/name)))
    return digest.hexdigest()


def diagnostic_descriptor(error,runtime):
    frame=None;tb=error.__traceback__;count=0
    while tb is not None and count<64:
        code=tb.tb_frame.f_code;count+=1
        for name,functions in DIAGNOSTIC_FUNCTIONS.items():
            bounds=functions.get(code.co_name)
            if code.co_filename==str(Path(__file__).parent/name) and bounds and bounds[0]<=tb.tb_lineno<=bounds[1]:
                frame={'file':name,'function':code.co_name,'line':tb.tb_lineno}
        tb=tb.tb_next
    if tb is not None:frame=None
    kind=type(error).__name__
    return {'schema_version':1,'error_class':kind if kind in DIAGNOSTIC_ERRORS else None,'frame':frame,
            'program_sha256':diagnostic_program_sha256(),'raw_receipt_sha256':sha(runtime/'receipt.json')}


def cli():
    try:main()
    except Exception as error:
        try:
            import sys
            # Only the parent's fixed CLI shape is needed for the private binding.
            runtime=Path(sys.argv[sys.argv.index('--runtime')+1])
            print(DIAGNOSTIC_MARKER+json.dumps(diagnostic_descriptor(error,runtime),separators=(',',':')),file=sys.stderr)
        except Exception:pass  # A diagnostic must not replace the original error.
        raise


if __name__=='__main__':cli()
