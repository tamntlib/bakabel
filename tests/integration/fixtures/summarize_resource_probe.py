#!/usr/bin/env python3
"""Summarize REAL run_resource_probe evidence without filling missing counters."""
import argparse, collections, datetime, json, os
from pathlib import Path

def kv(text):
    out={}
    for line in text.splitlines():
        f=line.split()
        if len(f)==2:
            try:out[f[0]]=int(f[1])
            except ValueError:pass
    return out

def summarize(root):
    receipt=json.loads((root/'receipt.json').read_text());samples=json.loads((root/'metrics.json').read_text())
    groups=collections.defaultdict(list)
    for s in samples:groups[(s['role'],s['container'])].append(s)
    out={'run':str(root),'gates':receipt['gates'],'sampler_errors':receipt.get('sampler_errors',[]),'sample_count':len(samples),'image':receipt['image_measurement'],'containers':[]}
    for (role,cid),ss in groups.items():
        processes=[p for s in ss for p in s['processes'] if not p.get('exited_during_sample')]
        def peaks(key):return max((sum(p.get('memory',{}).get(key,0) for p in s['processes']) for s in ss),default=0)
        stats=[s['docker_stats'] for s in ss if 'docker_stats' in s]
        tmp=[s['tmp_cache_footprint'] for s in ss if 'tmp_cache_footprint' in s]
        cg=[s for s in ss if 'cpu.stat' in s]
        def numeric_peak(key):return max((int(s[key]) for s in ss if str(s.get(key,'')).isdigit()),default=None)
        row={
            'role':role,'container':cid,'sample_count':len(ss),'from':ss[0]['at'],'through':ss[-1]['at'],
            'process_comms':sorted({p.get('comm','?') for p in processes}),
            'process_RSS_sum_peak_bytes':max(sum(p.get('rss_bytes',0) for p in s['processes']) for s in ss),
            'process_rollup_RSS_sum_peak_bytes':peaks('Rss'),'process_PSS_sum_peak_bytes':peaks('Pss'),
            'cgroup_memory_peak_bytes':numeric_peak('memory.peak'),
            'sampled_cgroup_memory_current_peak_bytes':numeric_peak('memory.current'),
            'cgroup_cpu_max':sorted({s['cpu.max'] for s in ss if 'cpu.max' in s}),
            'cgroup_memory_max':sorted({s['memory.max'] for s in ss if 'memory.max' in s}),
            'affinities_after_pin':sorted({a for p in processes for a in p.get('affinities',[])}),
            'cpu_usage_seconds_observed_delta':(kv(cg[-1]['cpu.stat']).get('usage_usec',0)-kv(cg[0]['cpu.stat']).get('usage_usec',0))/1e6 if cg else None,
            'cpu_throttled_seconds_observed_delta':(kv(cg[-1]['cpu.stat']).get('throttled_usec',0)-kv(cg[0]['cpu.stat']).get('throttled_usec',0))/1e6 if cg else None,
            'io_stat_available':any(s.get('io.stat') not in [None,'FileNotFoundError','PermissionError'] for s in ss),
            'docker_stats_samples':len(stats),'tmp_cache_file_bytes_peak_sampled':max((t['bytes'] for t in tmp),default=None),
            'log_bytes_peak_sampled':max((s.get('log_bytes') or 0 for s in ss),default=0),
            'state_bytes_peak_sampled':max((s.get('state_footprint',{}).get('bytes',0) for s in ss),default=0),
            'footprint_unlinked_observations':sum(s.get('state_footprint',{}).get('unlinked_during_sample',0)+s.get('tmp_cache_footprint',{}).get('unlinked_during_sample',0) for s in ss),
            'process_rollup_missing_observations':sum('memory' not in p for p in processes),
            'notes':'process peaks are sampled; cgroup memory.peak is kernel high-water through last live sample, not measured hard bound; exit-race missing counters remain null'
        }
        if stats:
            row['docker_stats_memory_usage_peak_bytes']=max(s['memory_stats'].get('usage',0) for s in stats)
            row['docker_stats_pids_peak']=max(s.get('pids_stats',{}).get('current',0) for s in stats)
            row['docker_stats_blkio_samples']=[s.get('blkio_stats') for s in stats[:1]]
        out['containers'].append(row)
    idle=receipt.get('idle_interval')
    if idle:
        first,last=idle['first'],idle['last'];used=(kv(last['cpu.stat'])['usage_usec']-kv(first['cpu.stat'])['usage_usec'])/1e6;duration=last['monotonic']-first['monotonic']
        out['idle']={'seconds_between_samples':duration,'cgroup_cpu_seconds_delta':used,'one_core_percent':100*used/duration,'RSS_first_bytes':sum(p.get('memory',{}).get('Rss',0) for p in first['processes']),'RSS_last_bytes':sum(p.get('memory',{}).get('Rss',0) for p in last['processes']),'PSS_first_bytes':sum(p.get('memory',{}).get('Pss',0) for p in first['processes']),'PSS_last_bytes':sum(p.get('memory',{}).get('Pss',0) for p in last['processes'])}
    def pgdelta(a,b):
        sql1,sql2=json.loads(a['sql']),json.loads(b['sql'])
        d={k:sql2[k]-sql1[k] for k in ['wal_bytes','wal_records','blks_read','blks_hit','temp_bytes','tup_inserted','tup_returned']}
        d['cgroup_cpu_seconds_delta']=(kv(b['metrics']['cpu.stat'])['usage_usec']-kv(a['metrics']['cpu.stat'])['usage_usec'])/1e6
        d['window_seconds']=(datetime.datetime.fromisoformat(b['at'])-datetime.datetime.fromisoformat(a['at'])).total_seconds()
        d['database_bytes_before']=sql1['database_bytes'];d['database_bytes_after']=sql2['database_bytes']
        def io_index(rows):return {tuple(r.get(k) for k in ['backend_type','object','context']):r for r in rows}
        ix1,ix2=io_index(a.get('pg_stat_io',[])),io_index(b.get('pg_stat_io',[]));iod=[]
        for key,r2 in ix2.items():
            r1=ix1.get(key,{})
            numeric={k:r2[k]-r1.get(k,0) for k in ['reads','read_bytes','writes','write_bytes','extends','extend_bytes','hits','evictions','fsyncs'] if isinstance(r2.get(k),(int,float))}
            iod.append({'backend_type':key[0],'object':key[1],'context':key[2],'delta':numeric})
        d['pg_stat_io_deltas']=iod;d['note']='PG counters are engine logical I/O, not unavailable kernel block-device attribution; window includes small control/readback queries and idle time, not isolated pg_dump CPU alone'
        return d
    pg=receipt.get('pg_fixture',{})
    if 'after_first_dump' in pg:out['source_pg_first_dump_window']=pgdelta(pg['before'],pg['after_first_dump'])
    restore=receipt.get('pg_restore')
    if restore:out['target_pg_restore_window']=pgdelta(restore['before'],restore['after'])
    out['checkpoints']=receipt['checkpoints'];out['cleanup']=receipt['cleanup'];out['error']=receipt.get('error')
    return out

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--runtime',type=Path,required=True);p.add_argument('--output',type=Path);a=p.parse_args()
    out=summarize(a.runtime);text=json.dumps(out,indent=2)
    if a.output:a.output.write_text(text+'\n')
    else:print(text)
if __name__=='__main__':main()
