#!/usr/bin/env python3
"""Validated dispatch matrix and independent F14/F16–F22 scoped evidence, never release acceptance."""
import argparse
import json
from pathlib import Path
import re
import sys
from run_compose_pg_acceptance import fingerprint
from verify_hosted_faults import demand, verify_case as verify_fault
from verify_hosted_native_faults import NATIVE_CASES
from verify_hosted_storage_prereqs import CASES as STORAGE_CASES, verify_case as verify_storage


F14 = 'restore-reader-failure-importer-zero'
SCOPED_CASES = {'reader': (F14,), 'native': NATIVE_CASES, 'storage': STORAGE_CASES}


def plan(scope, case):
    """Validate dispatch inputs before provisioning any acceptance VM."""
    if scope == 'single-fault':
        for suite, cases in SCOPED_CASES.items():
            if case in cases:
                return [{'suite':suite, 'case':case}]
        raise ValueError('single-fault requires a named case')
    demand(case == 'all', 'named case requires single-fault scope')
    if scope == 'all':
        return [{'suite':suite, 'case':'all'} for suite in ('core-resources','capacity','faults')]
    demand(scope == 'remaining-faults', 'unknown acceptance scope')
    # Preserve the existing F16–F22 VM order, including interleaved storage gates.
    cases = (*NATIVE_CASES[:3], *STORAGE_CASES[:2], NATIVE_CASES[3], STORAGE_CASES[2])
    return [{'suite':'native' if case in NATIVE_CASES else 'storage', 'case':case} for case in cases]


def verify_selection(report, rows, candidate, suite, case, source):
    demand(suite in SCOPED_CASES and case in SCOPED_CASES[suite], 'case outside selected suite')
    scope = candidate.get('scope')
    demand(scope in ('remaining-faults','single-fault') and
           {'suite':suite,'case':case} in plan(scope, 'all' if scope == 'remaining-faults' else case),
           'case outside selected scope')
    verify = verify_storage if suite == 'storage' else verify_fault
    demand(candidate.get('suite') == suite and
           candidate.get('case') == case and re.fullmatch('[a-f0-9]{40}', candidate.get('commit','')),
           'candidate selection binding missing')
    aggregate = 'storage_acceptance_pass' if suite == 'storage' else 'fault_acceptance_pass'
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
    return {'scope':scope, 'suite':suite, 'case':case,
            'selected_case_pass':True, 'full_plan_acceptance_pass':False}


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if '--plan' in argv:
        parser = argparse.ArgumentParser(description='Validate manual dispatch before builds')
        parser.add_argument('--plan', action='store_true', required=True)
        parser.add_argument('--scope', required=True)
        parser.add_argument('--case', required=True, action='append')
        args = parser.parse_args(argv)
        try:
            demand(len(args.case) == 1, 'exactly one case required')
            matrix = plan(args.scope, args.case[0])
        except (ValueError, TypeError):
            parser.error('invalid scope/case combination')
        print(json.dumps(matrix, separators=(',',':')))
        return 0
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--suite', choices=tuple(SCOPED_CASES), required=True)
    parser.add_argument('--case', choices=(F14,*NATIVE_CASES,*STORAGE_CASES), required=True, action='append')
    for name in ('runtime','candidate','source','output'):
        parser.add_argument('--'+name, type=Path, required=True)
    args = parser.parse_args(argv)
    if len(args.case) != 1: parser.error('exactly one case required')
    args.case = args.case[0]
    try:
        filename = 'hosted-storage.json' if args.suite == 'storage' else 'hosted-faults.json'
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
