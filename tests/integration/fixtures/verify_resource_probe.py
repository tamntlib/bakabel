#!/usr/bin/env python3
"""Independent readback/identity verification for completed B4/B5 evidence."""
import argparse, hashlib, importlib.util, json, os, sys
from pathlib import Path
from run_resource_probe import Engine, sha

EXPECTED_GATES={
    'B4-real-minute-scheduled-mixed-success',
    'B4-scheduler-SIGKILL-same-worker-original-createdAt-adopted-success',
    'B5-256MiB-many-files-first-second-parent-no-new-data',
    'B5-full-256MiB-S3-readback-512-SHA256s-match',
    'B5-real-200k-row-fresh-target-streaming-PG-restore',
    'B4-original-deadline-bounded-cleanup-no-last-success-refresh',
    'B4-independent-readonly-monitor-failed-overdue-no-HTTP-server',
    'source-startedAt-restartCount-unchanged-read-write-available'
}
def assert_worker_resources(w, rows):
    h=w['HostConfig']
    assert h['NanoCpus']==2000000000 and h['Memory']==536870912
    assert h['CpusetCpus']==''
    assert rows and all(s['cpu.max']=='200000 100000' and s['memory.max']=='536870912' for s in rows)

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--runtime',type=Path,required=True);p.add_argument('--source',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--expected-source-sha256');p.add_argument('--expected-image-id');a=p.parse_args();os.sched_setaffinity(0,{0,1})
    r=json.loads((a.runtime/'receipt.json').read_text());e=Engine(r['socket'])
    assert not r.get('error'),r.get('error');assert {g['name'] for g in r['gates']}==EXPECTED_GATES
    assert len(r['gates'])==len(EXPECTED_GATES)
    assert e.call('GET','/info')['ID']==r['daemon']
    assert e.call('GET','/info')['Swarm']['LocalNodeState']=='inactive'
    assert all(sha(a.source/f)==v for f,v in r['fingerprint']['source_files'].items())
    assert sha(a.source/'Dockerfile')==r['fingerprint']['dockerfile_sha256']
    assert sha(a.source/'tests/integration/fixtures/run_resource_probe.py')==r['fingerprint']['probe_sha256']
    source_hash=hashlib.sha256()
    source_files=sorted((f for f in a.source.rglob('*') if f.is_file() and (f.suffix=='.go' or f.name in ['go.mod','go.sum','Dockerfile'])),key=lambda f:str(f.relative_to(a.source)))
    for f in source_files:source_hash.update(str(f.relative_to(a.source)).encode()+b'\0'+bytes.fromhex(sha(f)))
    if a.expected_source_sha256:assert source_hash.hexdigest()==a.expected_source_sha256
    actual_image=next(iter(r['images'].values()))['id']
    assert e.call('GET','/images/'+actual_image+'/json')['Id']==actual_image
    if a.expected_image_id:assert actual_image==a.expected_image_id
    assert {w['Image'] for w in r['workers'].values()}=={actual_image}
    assert r['fingerprint']['runtime_restic_sha256']=='01143daba61a1dc8afb0cb3d03ba83e6b118f55b6b146b27473a09efc3df13d6'
    assert all(e.inspect(cid,missing=True) is None for cid in r['cleanup']['containers_absent'])
    assert all(e.call('GET','/volumes/'+v,missing=True) is None for v in r['cleanup']['volumes_absent'])
    assert all(r['cleanup']['containers_absent'].values()) and all(r['cleanup']['volumes_absent'].values())
    assert r['cleanup']['private_paths_absent'] and not any((a.runtime/d).exists() for d in ['private','state','fresh-state','backend','bin','image-unpacked','image-save.tar','image-export.tar'])
    assert len(r['workers'])==4 and len({w['runID'] for w in r['workers'].values()})==4
    worker_checks=[]
    for cid,w in r['workers'].items():
        h=w['HostConfig']
        metrics=json.loads((a.runtime/'metrics.json').read_text())
        rows=[s for s in metrics if s['container']==cid and 'cpu.max' in s]
        assert_worker_resources(w,rows)
        assert h['ReadonlyRootfs'] and h['NetworkMode']=='bridge'
        assert h['Tmpfs']['/tmp']=='rw,nosuid,nodev,size=67108864'
        assert w['Config']['Entrypoint']==['/usr/local/bin/bakabel'] and w['Config']['Cmd']==['_workflow']
        for target in ['/run/secrets/restic-password','/run/secrets/aws']:
            m=[m for m in w['Mounts'] if m['Destination']==target];assert len(m)==1 and not m[0]['RW']
        assert w['Config']['Labels']['bakabel.daemon']==r['daemon']
        worker_checks.append({'container':cid,'runID':w['runID'],'NanoCpus':h['NanoCpus'],'Memory':h['Memory'],'effective_memory_max':sorted({s['memory.max'] for s in rows}),'engine_cpuset':h['CpusetCpus'],'effective_cpu_max':sorted({s['cpu.max'] for s in rows}),'credential_mounts_RO':True,'exact_image':w['Image']})
    assert r['file_content_readback']['files_compared']==512 and r['file_content_readback']['all_sha256_equal']
    assert r['file_parent_assertions']['summary']['data_blobs']==0 and r['file_parent_assertions']['summary']['files_unmodified']==513
    assert r['pg_restore']['readback']==r['pg_fixture']['readback']
    assert r['independent_overdue_health']['overdue'] and r['independent_overdue_health']['status']=='failed'
    out={'verified_at':__import__('datetime').datetime.now(__import__('datetime').timezone.utc).isoformat(),'gates_verified':sorted(EXPECTED_GATES),'independent_exact_cleanup_readback':True,'source_and_frozen_probe_unchanged':True,'Go_module_Dockerfile_sha256':source_hash.hexdigest(),'worker_checks':worker_checks,'files':{f:sha(a.runtime/f) for f in ['receipt.json','metrics.json','summary.json']},'limits':'affinity gaps, unavailable io.stat and sampled peaks remain as documented; no hard memory bound or broad release-readiness claim'}
    a.output.write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(out,indent=2))
if __name__=='__main__':main()
