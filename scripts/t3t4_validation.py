"""Offline acceptance with the actual Z3 library and labeled injected controls."""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from spec_agent.artifacts import ArtifactStore, sha256_file
from spec_agent.ir_ab.dataset import build
from spec_agent.t3t4.audit import audit
from spec_agent.t3t4.cli import DEFAULT_LIBRARY
from spec_agent.t3t4.controller import run
from spec_agent.t3t4.input import VERSION


def adapt(store, case):
    """Freeze the original authored synthetic requirement rows from the existing corpus."""
    root = store.root / 'corpus' / case['id']
    root.mkdir(parents=True)
    original = '\n'.join(row['text'] for row in case['R']) + '\n'
    (root / 'requirements.txt').write_text(original, encoding='utf-8')
    data = {k: case[k] for k in ('id', 'params', 'S')}
    data.update(schema=VERSION, data_model=case['profile']['model'], frame='nothing',
                material_id=case['id'], material_kind='SYNTHETIC', guards=case['definitions'],
                R=[{**row, 'lines': [i, i]} for i, row in enumerate(case['R'], 1)])
    store.write(f'corpus/{case["id"]}/R-S.json', data)
    return root / 'R-S.json', root / 'requirements.txt'


def remove_prior_root(index, graph):
    if index == 7:
        graph['roots'].pop(0)
    return graph


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', default='runs/t3t4-acceptance')
    parser.add_argument('--libz3', default=DEFAULT_LIBRARY)
    args = parser.parse_args(argv)
    store = ArtifactStore(args.output)
    rows = []
    print('Acceptance:', store.root, flush=True)

    def execute(case, package, material, expected, **options):
        root, result = run(package, material, output=store.root / case, library=args.libz3, **options)
        evidence = audit(root)
        actual = {'publication_eligible': result['publication_eligible'], 'main': result['main']['status'],
                  't4': result['t4']['status'], 'auxiliary': result['auxiliary']['status'],
                  'online': result['auxiliary']['online']}
        checks = list((root / 'evidence').rglob('check.json'))
        solver = json.loads((root / 'manifest.json').read_text(encoding='utf-8'))['solver']
        accepted = (all(actual[name] == value for name, value in expected.items())
                    and evidence['integrity'] == 'PASS' and bool(checks) and bool((solver or {}).get('sha256')))
        row = {'case': case, 'run': root.relative_to(store.root).as_posix(), 'actual': actual, 'expected': expected,
               'status': 'PASS' if accepted else 'FAIL', 'audit': evidence, 'solver': solver, 'queries': len(checks),
               'fault_injection': result['fault_injection']}
        rows.append(row)
        print(case, row['status'], actual, flush=True)

    for case in build():
        package, material = adapt(store, case)
        execute(case['id'], package, material,
                {'publication_eligible': True, 'main': 'PASS', 't4': 'PASS', 'online': 'NOT_RUN'})

    examples = ROOT / 'examples/t3t4'
    for name, expected, options in [
        ('station_admission', {'publication_eligible': True, 'main': 'PASS', 't4': 'PASS'}, {}),
        ('relay_transition', {'publication_eligible': True, 'main': 'PASS', 't4': 'PASS'}, {'split': False}),
        ('mixing_window', {'publication_eligible': False, 'main': 'FAIL', 't4': 'NOT_RUN'}, {'max_steps': 6}),
        ('payment_route', {'publication_eligible': False, 'main': 'FAIL', 't4': 'NOT_RUN', 'auxiliary': 'PASS'},
         {'inject': remove_prior_root, 'fixture': examples / 'payment_route.fixture.json'}),
    ]:
        execute(name, examples / (name+'.json'), examples / (name+'.txt'),
                {**expected, 'online': 'NOT_RUN'}, **options)
    summary = {'status': 'PASS' if all(r['status'] == 'PASS' for r in rows) else 'FAIL',
               'online': 'NOT_RUN', 'cases': rows}
    store.write('summary.json', summary)
    store.write('seal.json', {'summary_sha256': sha256_file(store.root / 'summary.json'),
                             'runs': {r['run']: r['audit']['manifest_sha256'] for r in rows}})
    return 0 if summary['status'] == 'PASS' else 2


if __name__ == '__main__':
    raise SystemExit(main())
