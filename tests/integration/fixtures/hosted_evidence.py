#!/usr/bin/env python3
"""Project raw fixture receipts to a small explicit artifact allowlist."""
import argparse
import hashlib
import json
from pathlib import Path


def public_receipt(raw):
    fields=('platform','source_sha256','image_id','daemon','started_at','finished_at','runtime_matrix_pass','full_plan_acceptance_pass','direct_engine','cpu_fields_omitted','cells','file_restore_exercised','swarm_exercised')
    out={k:raw[k] for k in fields if k in raw}
    out['failed']=bool(raw.get('error') or raw.get('cleanup_error'))
    out['gates']=[g['name'] for g in raw.get('gates',[])]
    cleanup=raw.get('cleanup',{})
    out['cleanup']={k:cleanup[k] for k in ('containers_absent','volumes_absent','private_paths_absent') if k in cleanup}
    out['workers']={cid:{'image_id':w.get('Image'),'command':w.get('Config',{}).get('Cmd'),'memory_bytes':w.get('HostConfig',{}).get('Memory'),'nanocpus':w.get('HostConfig',{}).get('NanoCpus')} for cid,w in raw.get('workers',{}).items()}
    return out


def collect(runtime,output):
    output.mkdir(mode=0o700,parents=True,exist_ok=False)
    for platform in ('compose','swarm'):
        path=runtime/platform/'receipt.json'
        if path.exists():
            receipt=public_receipt(json.loads(path.read_text()))
            receipt['raw_receipt_sha256']=hashlib.sha256(path.read_bytes()).hexdigest()
            (output/(platform+'.json')).write_text(json.dumps(receipt,indent=2)+'\n')
    # These are constructed without raw CLI output/environment by the runner
    # and verifier; their explicit schema is selected instead of glob copying.
    for name,fields in {
        'hosted-result.json':('finished_at','daemon','source_sha256','image_id','runtime_matrix_pass','full_plan_acceptance_pass'),
        'verified.json':('source_sha256','image_id','daemon','runtime_matrix_pass','full_plan_acceptance_pass','platforms'),
        'candidate.json':('commit','source_sha256','image_id','daemon','minio_source_sha256','minio_binary_sha256','docker_version'),
    }.items():
        path=runtime/name
        if path.exists():
            raw=json.loads(path.read_text())
            (output/name).write_text(json.dumps({k:raw[k] for k in fields if k in raw},indent=2)+'\n')


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--runtime',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    args=p.parse_args();collect(args.runtime,args.output)

if __name__=='__main__':main()
