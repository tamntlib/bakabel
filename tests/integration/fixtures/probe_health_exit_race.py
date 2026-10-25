#!/usr/bin/env python3
"""Tight REAL exit-race regression: short-lived, socketless RO CLI health only.
No source/container/database fixture is created. Every expected health exit is 1
because this fresh private state has never completed a backup.
"""
import argparse, os, traceback
from pathlib import Path
from run_resource_probe import Probe

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source',type=Path,required=True);p.add_argument('--runtime',type=Path,required=True)
    p.add_argument('--minio-binary',type=Path,required=True,help='fingerprint only; never launched here')
    p.add_argument('--image',default='bakabel-development:runtime');p.add_argument('--socket',type=Path)
    p.add_argument('--iterations',type=int,default=20);a=p.parse_args();assert 1<=a.iterations<=100
    os.sched_setaffinity(0,{0,1});probe=Probe(a);code=1
    try:
        probe.repository='s3:http://127.0.0.1:9/not-contacted/repository';probe.config()
        for _ in range(a.iterations):
            health=probe.health(expect=1);assert health['status']=='never' and health['overdue']
        probe.gate('short-lived-health-container-exit-race',iterations=a.iterations,all_expected_exit=1)
        code=0
    except Exception:
        probe.result['error']=traceback.format_exc();print(probe.result['error'])
    finally:probe.cleanup()
    return code
if __name__=='__main__':raise SystemExit(main())
