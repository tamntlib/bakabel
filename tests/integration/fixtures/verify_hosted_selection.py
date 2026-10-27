#!/usr/bin/env python3
"""Independent F16–F22 single-case evidence; never a full-suite/release verdict."""
import argparse
import json
from pathlib import Path
import re
from run_compose_pg_acceptance import fingerprint
from verify_hosted_faults import demand, verify_case as verify_fault
from verify_hosted_native_faults import NATIVE_CASES
from verify_hosted_storage_prereqs import CASES as STORAGE_CASES, verify_case as verify_storage


def verify_selection(report, rows, candidate, suite, case, source):
    demand(suite in ('native','storage'), 'not a remaining gate suite')
    cases, verify = {'native': (NATIVE_CASES, verify_fault),
                     'storage': (STORAGE_CASES, verify_storage)}[suite]
    demand(case in cases, 'case outside remaining gates')
    demand(candidate.get('scope') == 'remaining-faults' and candidate.get('suite') == suite and
           candidate.get('case') == case and re.fullmatch('[a-f0-9]{40}', candidate.get('commit','')),
           'candidate selection binding missing')
    aggregate = 'fault_acceptance_pass' if suite == 'native' else 'storage_acceptance_pass'
    demand(report.get('schema') == 1 and report.get(aggregate) is False and
           report.get('full_plan_acceptance_pass') is False, 'subset cannot claim aggregate acceptance')
    demand('cleanup_failure' not in report and 'verification_failure' not in report, 'selected report failed')
    demand(len(rows) == 1 and rows[0].get('case') == case and
           report.get('cases') == [{'case':case,'status':'pass'}], 'selection manifest mismatch')
    demand(candidate.get('source_sha256') == fingerprint(source), 'checked-out source binding drift')
    for row in rows:
        for key in ('source_sha256','image_id','daemon'):
            demand(key in candidate and row.get(key) == report.get(key) == candidate[key], 'selection build/daemon binding drift')
        demand('cleanup_failure' not in row and 'verification_failure' not in row,
               'selected case cleanup or verification failed')
        verify(row)
    return {'scope':'remaining-faults', 'suite':suite, 'case':case,
            'selected_case_pass':True, 'full_plan_acceptance_pass':False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--suite', choices=('native','storage'), required=True)
    parser.add_argument('--case', choices=(*NATIVE_CASES,*STORAGE_CASES), required=True)
    for name in ('runtime','candidate','source','output'):
        parser.add_argument('--'+name, type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        filename = 'hosted-faults.json' if args.suite == 'native' else 'hosted-storage.json'
        report = json.loads((args.runtime/filename).read_text())
        row = json.loads((args.runtime/args.case/'receipt.json').read_text())
        candidate = json.loads(args.candidate.read_text())
        result = verify_selection(report, [row], candidate, args.suite, args.case, args.source)
    except (ValueError, OSError, TypeError, KeyError, AttributeError):
        parser.error('selected gate evidence missing, invalid, or inconsistent')
    args.output.write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result))
    return 0


if __name__ == '__main__': raise SystemExit(main())
