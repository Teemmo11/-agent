"""Read-only audit of a sealed run. Integrity and publication are separate."""
from pathlib import Path

from ..artifacts import sha256_file
from ..ir_ab.semantics import Invalid, digest, domain, join, pq, read_acsl, smt
from . import acsl, graph
from .checks import reference, xor
from .input import freeze, read_json, source_formula
from .trace import trace_index


def audit(directory, *, manifest_sha256=None):
    root = Path(directory).resolve()
    errors = []
    eligible = False
    seal = None
    try:
        seal = sha256_file(root / 'manifest.json')
        if manifest_sha256 is not None and seal != manifest_sha256:
            raise Invalid('MANIFEST_BINDING')
        manifest = read_json(root / 'manifest.json')
        if manifest['schema'] != 't3t4-manifest-1':
            raise Invalid('MANIFEST_SCHEMA')
        paths = list(root.rglob('*'))
        if any(p.is_symlink() or not p.resolve().is_relative_to(root) for p in paths):
            raise Invalid('UNSAFE_EVIDENCE_PATH')
        actual = {p.relative_to(root).as_posix(): p for p in paths if p.is_file() and p != root / 'manifest.json'}
        if set(actual) != set(manifest['files']):
            errors.append('FILE_SET_CHANGED')
        for name, path in actual.items():
            if sha256_file(path) != manifest['files'].get(name):
                errors.append('HASH_MISMATCH:' + name)
        if any(manifest['files'].get(k) != v for k, v in manifest['initial_inputs'].items()):
            errors.append('INPUT_CHANGED_DURING_RUN')
        report = read_json(root / 'result.json')
        if not errors and 'inputs/frozen.json' in actual:
            frozen = freeze(read_json(root / 'inputs/S-R.json'),
                            actual['inputs/original.txt'].read_bytes() if 'inputs/original.txt' in actual else None)
            if frozen != read_json(root / 'inputs/frozen.json'):
                raise Invalid('FROZEN_INPUT_BINDING')
            for path in sorted((root / 'evidence').rglob('check.json')):
                check_query(root, path, manifest, frozen)
            if 't3/main/graph.json' in actual and report['main']['status'] != 'NOT_RUN':
                audit_graph(root, frozen, report)
        if report['publication_eligible']:
            if (report['status'] != 'PASSED' or report['fault_injection'] or not report['dependencies_valid']
                    or report['main']['status'] != 'PASS' or report['main']['stop'] != 'COMPLETE'
                    or report['main']['completeness'] != 'COMPLETE'
                    or any(report['main'][k] != 'PASS' for k in ('structure', 'source', 'semantics', 'p_feasibility'))
                    or report['p_feasibility']['classification'] != 'FEASIBLE'
                    or report['decision'] != 'MAIN_QUALIFIED' or report['t4']['status'] != 'PASS'
                    or not {'t4/contract.c', 't4/checks.json', 'trace/index.json'} <= set(actual)):
                errors.append('PUBLICATION_GATE')
        eligible = report['publication_eligible'] and not errors
    except (Invalid, OSError, ValueError, TypeError, AttributeError, KeyError, RecursionError) as exc:
        errors.append(getattr(exc, 'code', 'EVIDENCE_READ_ERROR'))
    return {'integrity': 'PASS' if not errors else 'FAIL', 'publication_eligible': eligible,
            'manifest_sha256': seal, 'errors': errors, 'scope': 'READ_ONLY_ARTIFACT_AND_BINDING_AUDIT'}


def check_query(root, path, manifest, frozen):
    row = read_json(path)
    binding = row['binding']
    files = manifest['files']
    expected_artifact = path.relative_to(root).as_posix()
    if (binding['frozen_sha256'] != digest(frozen) or binding['solver'] != manifest['solver']
            or binding['checker_sha256'] != digest(manifest['implementation'])
            or row['binding_sha256'] != digest(binding)
            or binding['predicate_sha256'] != digest(row['predicate']) or binding['expected'] != row['expected']
            or row['artifact'] != expected_artifact):
        raise Invalid('QUERY_DEPENDENCY_BINDING')
    raw = read_json(path.with_name('result.json'))
    if raw['status'] != row['raw_result'] or raw.get('witness') != row['witness']:
        raise Invalid('QUERY_RESULT_BINDING')
    if 'query_sha256' not in row:
        budget_stop = raw['status'] == 'NOT_RUN' and raw.get('reason') == 'GLOBAL_QUERY_BUDGET'
        if not budget_stop and (raw['status'] != 'ERROR' or 'sha256' in binding['solver']):
            raise Invalid('QUERY_MISSING')
        return
    query = path.with_name('query.smt2')
    if files[query.relative_to(root).as_posix()] != row['query_sha256']:
        raise Invalid('QUERY_HASH_BINDING')
    names = {name: f'v{i}' for i, name in enumerate(frozen['names'])}
    script = f"(set-option :timeout {binding['solver']['timeout_ms']})\n"
    script += ''.join(f'(declare-const {v} Int)\n(assert {domain(v)})\n' for v in names.values())
    script += f"(assert {smt(row['predicate'], names)})\n(check-sat)\n"
    if query.read_text(encoding='utf-8') != script:
        raise Invalid('QUERY_PREDICATE_BINDING')
    if raw['status'] in ('SAT', 'UNSAT'):
        expected = 'PASS' if raw['status'] == row['expected'] else 'FAIL'
        if raw['raw'].strip().upper() != raw['status'] or raw.get('errors') or row['status'] != expected:
            raise Invalid('RAW_SOLVER_STATUS')


def audit_graph(root, frozen, report):
    last = graph.empty(frozen)
    version = 0
    before_ref = 't3/initial.json'
    expected_ops = list(graph.operations(frozen, report['policy'] == 'split'))
    rejected = False
    for index, path in enumerate(sorted(root.glob('t3/steps/*/step.json'))):
        step = read_json(path)
        candidate = read_json(path.with_name('candidate.json'))
        if (rejected or index >= len(expected_ops) or step['operation'] != expected_ops[index]
                or step['step'] != index + 1 or step['before']['artifact'] != before_ref
                or step['candidate']['artifact'] != path.with_name('candidate.json').relative_to(root).as_posix()
                or step['before']['sha256'] != digest(last) or step['before']['version'] != version
                or step['candidate']['sha256'] != digest(candidate) or step['candidate']['version'] != version+1
                or step['rule_version'] != frozen['rules']):
            raise Invalid('STEP_BINDING')
        try:
            graph.local_check(last, candidate, step['operation'], frozen)
        except Invalid:
            valid = False
        else:
            valid = True
        if valid != step['committed'] or valid != (step['check']['status'] == 'PASS'):
            raise Invalid('STEP_COMMIT_BINDING')
        if valid:
            last = candidate
            version += 1
            before_ref = step['candidate']['artifact']
        else:
            rejected = True
    main = read_json(root / 't3/main/graph.json')
    if (last != read_json(root / 't3/main/committed.json')
            or digest(last) != report['main']['committed_sha256']
            or digest(main) != report['main']['graph_sha256']
            or report['main'] != read_json(root / 't3/main/checks.json')):
        raise Invalid('MAIN_GRAPH_BINDING')
    if report['main']['status'] == 'PASS':
        view = graph.inspect(main, frozen)
        if view['pending'] or view['issues'] or frozen['source_issues'] or main != last or version != len(expected_ops):
            raise Invalid('MAIN_COVERAGE_GATE')
        p, _ = reference(frozen)
        check_predicate(report['p_feasibility']['check'], 'input/P_FEASIBILITY', p, 'SAT')
        groups = report['main']['groups']
        if [row['s_id'] for row in groups] != list(frozen['S']):
            raise Invalid('GROUP_CHECK_COVERAGE')
        for row in groups:
            sid = row['s_id']
            observed = join('and', [c['expr'] for c in view['clauses'] if c['s_id'] == sid])
            difference = xor(source_formula(frozen, sid), observed)
            if frozen['S'][sid]['role'] == 'ensures':
                difference = ['and', p, difference]
            check_predicate(row, 'main/group/' + sid, difference, 'UNSAT')
        check_comparison(report['main']['global'], 'main/global', reference(frozen), view['pq'], p)
    if report['t4']['status'] == 'PASS':
        path = root / 't4/contract.c'
        actual = path.read_text(encoding='utf-8')
        parsed = read_acsl(actual, frozen)
        view = graph.inspect(main, frozen)
        acsl.check_mapping(read_json(root / 't4/source_map.json'), actual, sha256_file(path), main,
                           view, parsed)
        if (sha256_file(path) != report['t4']['output_sha256']
                or sha256_file(root / 't4/source_map.json') != report['t4']['map_sha256']
                or report['t4'] != read_json(root / 't4/checks.json')):
            raise Invalid('OUTPUT_CHECK_BINDING')
        check_comparison(report['t4']['queries'], 't4', view['pq'], pq(parsed), reference(frozen)[0])
    if (root / 'trace/index.json').is_file():
        if read_json(root / 'trace/index.json') != trace_index(root, frozen, main, report):
            raise Invalid('TRACE_BINDING')
    for check in [report['p_feasibility']['check'], *report['main']['groups'], *report['main']['global'],
                  *report['t4'].get('queries', [])]:
        ref = check['artifact']
        if not ref.startswith('evidence/') or not (root / ref).resolve().is_relative_to(root / 'evidence'):
            raise Invalid('EVIDENCE_REFERENCE')
        named_check = read_json(root / ref)
        if any(check[k] != v for k, v in named_check.items()):
            raise Invalid('EVIDENCE_REFERENCE')


def check_predicate(row, label, predicate, expected):
    if (row['label'] != label or row['predicate'] != predicate or row['raw_result'] != expected
            or row['expected'] != expected or row['status'] != 'PASS'):
        raise Invalid('REQUIRED_PREDICATE_BINDING')


def check_comparison(rows, label, left, right, frozen_p):
    if len(rows) != 2:
        raise Invalid('COMPARISON_CHECK_COVERAGE')
    p, q = left
    other_p, other_q = right
    check_predicate(rows[0], label + '/P', xor(p, other_p), 'UNSAT')
    check_predicate(rows[1], label + '/Q', ['and', frozen_p, p, other_p, xor(q, other_q)], 'UNSAT')
