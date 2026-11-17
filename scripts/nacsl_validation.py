"""Bounded N-to-ACSL acceptance with independent reference comparisons."""
import argparse
import platform
import sys
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from spec_agent.artifacts import ArtifactStore, sha256_file
from spec_agent.config import load_config
from spec_agent.ir_ab.semantics import digest, expand
from spec_agent.nacsl.audit import audit
from spec_agent.nacsl.controller import code_identity, default_limits, run
from spec_agent.nacsl.gateway import Ledger
from spec_agent.t3t4.checks import Checks, compare, reference, status
from spec_agent.t3t4.cli import DEFAULT_LIBRARY
from spec_agent.t3t4.controller import files
from spec_agent.t3t4.input import freeze, read_json

CASES = ('access_decision', 'device_transition', 'dispatch_priority', 'ambiguous_route',
         'contradictory_rate', 'unsupported_growth')
COMPLEX_CASES = ('sensor_envelope', 'audit_disposition')
EXAMPLES = ROOT / 'examples/nacsl'


def offline_shadow(fixture):
    """An explicit fixture for the third model role, with different organization."""
    nodes = [
        {'id': 'Node' + s['id'], 'kind': 'clause', 'role': s['role'], 's_id': s['id'],
         'path': '', 'expr': s['expr'], 'guard': s.get('guard')}
        for s in reversed(fixture['t2'][0]['S'])
    ]
    fixture['auxiliary'] = [{'schema': 't3t4-candidate-1', 'nodes': nodes,
                             'roots': [n['id'] for n in nodes]}]
    return fixture


def independent_check(batch, root, report, expected, library, ledger):
    tail = report['versions'][-1]
    raw = (root/'inputs/N.txt').read_bytes()
    package = read_json(root / tail['package'])
    frozen = freeze(package, raw)
    gold = tuple(expand(expr, frozen['names'], role) for expr, role in zip(expected, ('requires', 'ensures')))
    store = ArtifactStore(batch.root/'reference')
    implementation = digest(code_identity())
    checker = Checks(store, frozen, library, 2500, 2, implementation,
                     permit=lambda _: ledger.query(root.name))
    rows = compare(checker, 'reference', gold, reference(frozen), {
        'run_manifest_sha256': sha256_file(root/'manifest.json'), 'reference_sha256': digest(expected),
        'package_sha256': tail['package_sha256'],
    })
    delivered = {'status': status(rows), 'run': store.root.relative_to(batch.root).as_posix(),
                 'checks': rows, 'solver': checker.identity}
    store.write('result.json', delivered)
    store.write('manifest.json', {'files': files(store.root), 'solver': checker.identity,
                                  'reference_sha256': digest(expected)})
    return delivered


def expected_boundary(case, report, root):
    if report['publication_eligible']:
        return False
    reason = report['stop_reason']
    issue_types = {
        'ambiguous_route': {'AMBIGUITY', 'MISSING_INFORMATION'},
        'contradictory_rate': {'CONFLICT'},
        'unsupported_growth': {'UNSUPPORTED'},
    }[case]
    if case == 'contradictory_rate' and reason in ('CONTRACT_CONFLICT', 'INPUT_WITHOUT_OUTPUT'):
        return True
    if any(reason == 'T1_' + issue for issue in issue_types):
        return True
    if reason in ('T2_NEEDS_REVIEW', 'T2_UNSUPPORTED'):
        s = read_json(root/'t2/S.json')
        return any(issue['kind'] in issue_types for issue in s['issues'])
    return False


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--online', action='store_true')
    parser.add_argument('--env', default=str(ROOT/'.env'))
    parser.add_argument('--output', default='runs/nacsl-acceptance')
    parser.add_argument('--libz3', default=DEFAULT_LIBRARY)
    parser.add_argument('--max-calls', type=int, default=36)
    parser.add_argument('--max-tokens', type=int, default=300000)
    parser.add_argument('--suite', choices=('base', 'expanded'), default='base',
                        help='Online expanded suite runs two complex cases before the original six')
    parser.add_argument('--max-output-tokens', type=int,
                        help='Per-response cap. Defaults to 3072 for expanded, otherwise 6144')
    args = parser.parse_args(argv)
    if not 0 <= args.max_calls <= 36 or not 0 <= args.max_tokens <= 300000:
        parser.error('Batch ceiling is 36 requests and 300000 reserved tokens')
    if args.suite == 'expanded' and not args.online:
        parser.error('Expanded suite is for explicit online validation')
    output_cap = args.max_output_tokens
    if output_cap is None:
        output_cap = 3072 if args.suite == 'expanded' else 6144
    if not 128 <= output_cap <= 6144:
        parser.error('Response limit must be between 128 and 6144 tokens')
    batch = ArtifactStore(args.output)
    ledger = Ledger(replace(default_limits(args.max_calls, args.max_tokens), output_tokens=output_cap))
    config = load_config(Path(args.env)) if args.online else None
    references = read_json(EXAMPLES/'offline_reference.json')
    if args.suite == 'expanded':
        references.update(read_json(EXAMPLES/'complex_reference.json'))
    batch.write('reference_input.json', references)
    rows = []
    print('Acceptance:', batch.root, flush=True)
    cases = CASES if args.online else ('access_decision','access_repair')
    if args.suite == 'expanded':
        cases = COMPLEX_CASES + cases
    for case in cases:
        material_case = 'access_decision' if case == 'access_repair' else case
        fixture = None if config else read_json(EXAMPLES/(case+'.fixture.json'))
        if fixture is not None and case == 'access_decision':
            fixture = offline_shadow(fixture)
        root, report = run(
            EXAMPLES/(material_case+'.txt'), EXAMPLES/(material_case+'.interface.json'),
            output=batch.root/case, library=args.libz3, config=config, fixture=fixture, ledger=ledger,
            aux_mode='shadow' if case == 'access_decision' else 'on_failure',
            material_kind='SYNTHETIC',
        )
        evidence = audit(root)
        positive = material_case in references
        formal = independent_check(batch, root, report, references[material_case], args.libz3, ledger) if (
            positive and evidence['integrity'] == 'PASS' and report.get('versions')
            and report['versions'][-1].get('downstream', {}).get('eligible')
        ) else {'status': 'NOT_RUN'}
        if positive:
            outcome = 'PASS' if formal['status'] == 'PASS' and evidence['publication_eligible'] else 'FAIL'
        else:
            outcome = 'PASS' if expected_boundary(case, report, root) else 'FAIL'
        row = {'case': case, 'run': root.relative_to(batch.root).as_posix(), 'mode': report['mode'],
               'status': report['status'], 'stop_reason': report['stop_reason'], 'outcome': outcome,
               'publication_eligible': evidence['publication_eligible'], 'audit': evidence,
               'alignment': report['alignment'], 'repair': report['repair'], 'reference': formal,
               'auxiliary': report.get('downstream', {}).get('auxiliary', 'NOT_RUN'),
               'provider_models': sorted({str(m['model']) for p in root.rglob('response.metadata.json')
                                          if (m := read_json(p)).get('model')})}
        rows.append(row)
        print(case, outcome, row['status'], row['stop_reason'], flush=True)
    valid_normal = sum(row['outcome'] == 'PASS' and row['publication_eligible'] for row in rows)
    summary = {
        'status': 'PASS' if all(r['outcome'] == 'PASS' and r['audit']['integrity'] == 'PASS' for r in rows) else 'PARTIAL',
        'mode': 'ONLINE' if args.online else 'FIXTURE', 'suite': args.suite, 'cases': rows,
        'normal_end_to_end_confirmed': bool(valid_normal and args.online), 'qualified_normals': valid_normal,
        'budget': ledger.snapshot(), 'environment': platform.platform(),
        'reference_exposure': 'OFFLINE_CHECK_ONLY', 'implementation_verification': 'NOT_RUN',
    }
    batch.write('summary.json', summary)
    batch.write('seal.json', {'summary_sha256': sha256_file(batch.root/'summary.json'), 'files': files(batch.root)})
    return 0 if summary['status'] == 'PASS' else 2


if __name__ == '__main__':
    raise SystemExit(main())
