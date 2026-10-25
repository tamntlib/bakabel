#!/usr/bin/env python3
"""Exact readback after hosted core-matrix cleanup, not a release approval."""
import argparse
import hashlib
import json
from pathlib import Path
from urllib.parse import quote
from run_compose_pg_acceptance import fingerprint
from run_hosted_acceptance import verify_matrix
from run_resource_probe import Engine


def verify_final(final,binding):
    rows=final.get('platforms',[])
    if (final.get('runtime_matrix_pass') is not True or
        any(final.get(k)!=binding[k] for k in ('source_sha256','image_id','daemon')) or
        len(rows)!=2 or {r['platform'] for r in rows}!={'compose','swarm'} or
        any(r.get('failed') is not False for r in rows)):
        raise ValueError('both bound platforms must finish successfully')


def verify_platform(result,platform):
    if result.get('platform')!=platform or result.get('swarm_exercised') is not (platform=='swarm'):
        raise ValueError('receipt belongs to a different platform')
    verify_matrix(result)


def verify(runtime,source,candidate,socket):
    binding=json.loads(candidate.read_text())
    if fingerprint(source)!=binding['source_sha256']:
        raise ValueError('source drift after build')
    engine=Engine(socket);info=engine.call('GET','/info')
    if info['ID']!=binding['daemon'] or info['Swarm']['LocalNodeState']!='inactive':
        raise ValueError('wrong daemon or residual Swarm')
    if engine.call('GET','/images/'+quote(binding['image_id'],safe='')+'/json')['Id']!=binding['image_id']:
        raise ValueError('bound image absent or changed')
    final=json.loads((runtime/'hosted-result.json').read_text())
    verify_final(final,binding)
    report={'source_sha256':binding['source_sha256'],'image_id':binding['image_id'],'daemon':info['ID'],'platforms':{},'full_plan_acceptance_pass':False}
    for platform in ('compose','swarm'):
        directory=runtime/platform;path=directory/'receipt.json';result=json.loads(path.read_text())
        verify_platform(result,platform)
        if result.get('cleanup_error') or not result.get('runtime_matrix_pass') or not result.get('direct_engine') or result.get('cpu_fields_omitted')!=[]:
            raise ValueError('failed cleanup/matrix or modified resource requests')
        if result['source_sha256']!=binding['source_sha256'] or result['image_id']!=binding['image_id'] or result['daemon']!=info['ID']:
            raise ValueError('receipt binding differs from image build/daemon')

        if result['swarm_before']!='inactive' or result['swarm_after']!='inactive':
            raise ValueError('Swarm not restored to its initial state')
        for cid,absent in result['cleanup']['containers_absent'].items():
            if not absent or engine.inspect(cid,missing=True) is not None:raise ValueError('owned container remains')
        for volume,absent in result['cleanup']['volumes_absent'].items():
            if not absent or engine.call('GET','/volumes/'+quote(volume,safe=''),missing=True) is not None:raise ValueError('owned volume remains')
        if not result['cleanup']['private_paths_absent'] or any((directory/d).exists() for d in ('private','state','fresh-state','backend','bin','destinations')):
            raise ValueError('fixture data/credential residue')
        for worker in result['workers'].values():
            if worker['Image']!=binding['image_id'] or worker['Config']['Cmd']!=['_workflow'] or worker['HostConfig']['Memory']!=536870912 or worker['HostConfig']['NanoCpus']!=2000000000:
                raise ValueError('unexpected ordinary worker/image/resource settings')
        metrics=json.loads((directory/'metrics.json').read_text())
        if not any(row['role']=='worker' and row.get('memory.max')=='536870912' and row.get('cpu.max')=='200000 100000' for row in metrics):
            raise ValueError('no observed kernel worker resource limits')
        if result.get('sampler_errors'):raise ValueError('sampler had unclassified errors')
        report['platforms'][platform]={'gates':[g['name'] for g in result['gates']],'cells':result['cells'],'exact_container_absence_count':len(result['cleanup']['containers_absent']),'exact_volume_absence_count':len(result['cleanup']['volumes_absent']),'receipt_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'metrics_sha256':hashlib.sha256((directory/'metrics.json').read_bytes()).hexdigest()}
    if engine.call('GET','/containers/json?all=true'):
        raise ValueError('exclusive hosted daemon unexpectedly still contains containers')
    report['runtime_matrix_pass']=True
    return report


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for key in ('runtime','source','candidate','socket','output'):p.add_argument('--'+key,type=Path,required=True)
    args=p.parse_args();report=verify(args.runtime,args.source,args.candidate,args.socket)
    args.output.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))

if __name__=='__main__':main()
