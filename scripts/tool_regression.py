#!/usr/bin/env python3
"""Six persistent fixture-spec/real-tool regressions. No live LLM or installation."""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from spec_agent.artifacts import ArtifactStore, write_json_atomic
from spec_agent.config import load_config
from spec_agent.controller import run
from spec_agent.preflight import doctor
from spec_agent.verification.audit import audit_run

CASES = [
    ('sum', 'array_sum/program.c', 'array_sum/requirements.md', 'array_sum/llm_fixture.json', 'FEASIBLE', 'HOLDS', ['HOLDS']),
    ('sum-buggy', 'array_sum/buggy.c', 'array_sum/requirements.md', 'array_sum/llm_fixture.json', 'FEASIBLE', 'VIOLATED', ['VIOLATED']),
    ('clamp', 'clamp/program.c', 'clamp/requirements.md', 'clamp/llm_fixture.json', 'FEASIBLE', 'HOLDS', ['HOLDS', 'HOLDS']),
    ('buggy', 'clamp/buggy.c', 'clamp/requirements.md', 'clamp/llm_fixture.json', 'FEASIBLE', 'VIOLATED', ['HOLDS', 'VIOLATED']),
    ('infeasible', 'clamp/program.c', 'clamp/infeasible_requirements.md', 'clamp/infeasible_fixture.json', 'INFEASIBLE', 'VACUOUS', ['HOLDS', 'HOLDS']),
    ('array', 'array_bug/program.c', 'array_bug/requirements.md', None, None, None, None),
]


def inspect_result(case, result, audit):
    name, _, _, fixture, expected_p, expected_verdict, expected_clauses = case
    passed = result.get('status') == 'COMPLETED' and audit.get('status') == 'PASSED'
    item = {'case': name, 'mode': result.get('mode'), 'audit': audit.get('status'),
            'logging': result.get('logging', {}).get('status')}
    if fixture:
        passed &= result.get('mode') == 'FIXTURE_LLM_REAL_TOOLS'
        contracts = result.get('contracts', [])
        if len(contracts) != 1:
            passed = False
        else:
            c = contracts[0]
            item.update(P=c['precondition']['status'], contract=c['verification']['verdict'],
                        clauses=[q['verdict'] for q in c['properties']])
            passed &= (item['P'], item['contract'], item['clauses']) == (expected_p, expected_verdict, expected_clauses)
    else:
        passed &= result.get('mode') == 'REAL'
        props = result.get('static_properties', [])
        item['properties'] = [(p['cbmc_property_id'], p['verdict']) for p in props]
        passed &= any('bound' in p.get('category', '').lower() and p['verdict'] == 'VIOLATED' for p in props)
    item['status'] = 'PASSED' if passed else 'FAILED'
    return item


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--env', default=str(ROOT / '.env'))
    parser.add_argument('--output', default=str(ROOT / 'runs/tool-regression'))
    args = parser.parse_args(argv)
    store = ArtifactStore(args.output)
    report = {'scope': 'Fixture specs + real tools; NOT LIVE LLM ACCEPTANCE',
              'status': 'FAILED', 'live_llm': 'NOT_RUN', 'cases': [], 'evaluation': {'status': 'NOT_RUN'}}
    try:
        config = load_config(Path(args.env))
        caps = doctor(config, store.root / 'preflight', probe_tools=True)
        if not caps['ready'] or caps['semantic_probe']['status'] != 'PASSED':
            report['status'] = 'BLOCKED'
            report['issues'] = caps['issues']
        else:
            report['status'] = 'PASSED'
            for case in CASES:
                name, source, req, fixture, *_ = case
                root, result = run([ROOT / 'examples' / source], ROOT / 'examples' / req, config,
                                   output=store.root / name, branch='hoare' if fixture else 'static',
                                   fixture=ROOT / 'examples' / fixture if fixture else None,
                                   require_unguarded_posts=bool(fixture))
                audit = audit_run(root, require_real=False)
                write_json_atomic(root / 'audit.json', audit)
                item = inspect_result(case, result, audit)
                item['result'] = str(root / 'result.json')
                report['cases'].append(item)
                print(json.dumps(item, indent=2), flush=True)
                if item['status'] != 'PASSED':
                    report['status'] = 'FAILED'
                    break
    except Exception as exc:
        report['status'] = 'FAILED'
        report['error'] = {'code': getattr(exc, 'code', 'REGRESSION_ERROR'), 'type': type(exc).__name__}
    write_json_atomic(store.root / 'summary.json', report)
    print('Summary:', store.root / 'summary.json')
    return 0 if report['status'] == 'PASSED' else 2


if __name__ == '__main__':
    raise SystemExit(main())
