"""Run the main construction and optional diagnostic path in a new directory."""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from pathlib import Path

from ..artifacts import ArtifactStore, sha256_file
from ..evaluation.models import Limits
from ..ir_ab.semantics import Invalid, digest
from . import acsl, auxiliary, graph
from .checks import Checks, assess, reference
from .input import freeze, fragments, read_json
from .trace import trace_index

SCHEMAS = Path(__file__).resolve().parents[1] / 'schemas'
SCHEMA_FILES = ('t3t4_input.schema.json', 't3t4_b.schema.json', 't3t4_candidate.schema.json',
                't3t4_input_spans.schema.json')


def implementation():
    root = Path(__file__).resolve().parents[1]
    paths = sorted((root / 't3t4').glob('*.py')) + [
        root / name for name in ('ir_ab/semantics.py', 'ir_ab/representation.py', 'llm/parser.py',
                                 'llm/client.py', 'evaluation/models.py')]
    return {p.relative_to(root).as_posix(): sha256_file(p) for p in paths}


def files(root):
    return {path.relative_to(root).as_posix(): sha256_file(path)
            for path in sorted(root.rglob('*')) if path.is_file() and path != root / 'manifest.json'}


def construction(store, frozen, *, split, max_steps, inject):
    committed = graph.empty(frozen)
    store.write('t3/initial.json', committed)
    committed_ref = 't3/initial.json'
    processed = 0
    for index, op in enumerate(graph.operations(frozen, split), start=1):
        if max_steps is not None and processed >= max_steps:
            return committed, committed_ref, None, 'STEP_LIMIT'
        before_hash = digest(committed)
        location = f't3/steps/{index:04d}'
        candidate = graph.apply(committed, op, frozen)
        if inject:
            candidate = inject(index, deepcopy(candidate))
        candidate_ref = location + '/candidate.json'
        store.write(candidate_ref, candidate)
        candidate = read_json(store.root / candidate_ref)
        check = {'status': 'PASS', 'structure': 'PASS', 'source': 'PASS',
                 'semantics': 'PASS', 'method': 'EXACT_AST_AND_GUARD_BINDING_WITH_WRITE_SET'}
        try:
            view = graph.local_check(committed, candidate, op, frozen)
        except Invalid as exc:
            view = None
            check = {'status': 'FAIL', 'code': exc.code, 'detail': exc.detail,
                     'structure': 'NOT_RUN', 'source': 'NOT_RUN', 'semantics': 'NOT_RUN'}
            try:
                view = graph.inspect(candidate, frozen)
                check['structure'] = 'PASS'
                check['source'] = 'FAIL' if view['issues'] else 'PASS'
            except Invalid:
                check['structure'] = 'FAIL'
        source = frozen['S'][op['s_id']]
        action = [op['rule']]
        if source['guard'] and op['rule'] != 'OPEN_GROUP':
            action.append('BIND_EXISTING_GUARD')
        candidate_nodes = candidate.get('nodes', {})
        changed = sorted(k for k in set(committed['nodes']) | set(candidate_nodes)
                         if committed['nodes'].get(k) != candidate_nodes.get(k))
        accepted = check['status'] == 'PASS'
        previous = graph.inspect(committed, frozen)
        store.write(location + '/step.json', {
            'step': index, 'rules': action, 'rule_version': frozen['rules'], 'operation': op,
            'origin': graph.origin(frozen, op['s_id'], op['path']),
            'fragment': fragments(source)[op['path']], 'guard': source['guard'],
            'before': {'version': processed, 'sha256': before_hash, 'artifact': committed_ref},
            'candidate': {'version': processed + 1, 'sha256': digest(candidate), 'artifact': candidate_ref},
            'changed_nodes': changed, 'changed_guards': sorted(k for k in set(committed['guards']) | set(candidate.get('guards', {}))
                                                               if committed['guards'].get(k) != candidate.get('guards', {}).get(k)),
            'covered': view['covered'] if view else [], 'pending': view['pending'] if view else None,
            'before_covered': previous['covered'], 'before_pending': previous['pending'],
            'check': check, 'committed': accepted,
        })
        if not accepted:
            return committed, committed_ref, candidate_ref, 'STEP_REJECTED'
        committed, committed_ref = candidate, candidate_ref
        processed += 1
    return committed, committed_ref, None, 'COMPLETE'


def run(package, material, *, output, library, timeout=2500, query_limit=1024, split=True,
        max_steps=None, mode='on_failure', fixture=None, cached=None, config=None, limits=None,
        inject=None, output_inject=None, checks_factory=Checks, auxiliary_client=None,
        model_gateway=None, query_budget=None):
    if mode not in ('on_failure', 'shadow') or sum(x is not None for x in (fixture, cached, config, model_gateway)) > 1:
        raise Invalid('AUXILIARY_CONFIGURATION')
    if not 1 <= timeout <= 3600000 or not 0 <= query_limit <= 8192 or (max_steps is not None and max_steps < 0):
        raise Invalid('RUN_LIMIT')
    limits = limits or Limits(llm_calls=1, calls_per_function=1, output_tokens=6144, total_tokens=32000)
    limits.validate()
    store = ArtifactStore(output)
    snapshot = store.root / 'inputs'
    snapshot.mkdir()
    (snapshot / 'S-R.json').write_bytes(Path(package).read_bytes())
    if material is not None:
        (snapshot / 'original.txt').write_bytes(Path(material).read_bytes())
    code = implementation()
    for name in SCHEMA_FILES:
        (snapshot / name).write_bytes((SCHEMAS / name).read_bytes())
    inputs = files(store.root)
    report = {'schema': 't3t4-run-1', 'status': 'BLOCKED', 'publication_eligible': False,
              'input': {'syntax': 'NOT_RUN', 'source': 'NOT_RUN'},
              'main': {'status': 'NOT_RUN'}, 'auxiliary': {'status': 'NOT_RUN', 'online': 'NOT_RUN'},
              't4': {'status': 'NOT_RUN'}, 'mode': mode, 'policy': 'split' if split else 'copy',
              'fault_injection': bool(inject or output_inject or checks_factory is not Checks or auxiliary_client),
              'evaluation': {'status': 'NOT_RUN'}}
    identity = None
    frozen = None
    try:
        original = snapshot / 'original.txt'
        frozen = freeze(read_json(snapshot / 'S-R.json'), original.read_bytes() if original.is_file() else None)
        store.write('inputs/frozen.json', frozen)
        inputs['inputs/frozen.json'] = sha256_file(snapshot / 'frozen.json')
        check_options = {'permit': query_budget} if query_budget is not None else {}
        checks = checks_factory(store, frozen, library, timeout, query_limit, digest(code), **check_options)
        identity = checks.identity
        report['input'] = {'syntax': 'PASS', 'source': 'FAIL' if frozen['source_issues'] else 'PASS',
                           'frozen_sha256': digest(frozen), 'issues': frozen['source_issues']}
        p, _ = reference(frozen)
        feasibility = checks.ask('input/P_FEASIBILITY', p, 'SAT', {'P_sha256': digest(p)})
        report['p_feasibility'] = {'status': feasibility['status'], 'check': feasibility,
                                   'classification': {'SAT': 'FEASIBLE', 'UNSAT': 'INFEASIBLE'}.get(
                                       feasibility['raw_result'], feasibility['raw_result'])}
        schema = read_json(snapshot / SCHEMA_FILES[2])
        kwargs = {'fixture': fixture, 'cached': cached, 'config': config, 'limits': limits}
        if model_gateway:
            kwargs['gateway'] = model_gateway
        if auxiliary_client:
            kwargs['client_factory'] = auxiliary_client
        with ThreadPoolExecutor(max_workers=1) as pool:
            shadow = pool.submit(auxiliary.obtain, store, frozen, schema, **kwargs) if mode == 'shadow' else None
            if feasibility['status'] == 'PASS':
                committed, committed_ref, rejected_ref, stop = construction(
                    store, frozen, split=split, max_steps=max_steps, inject=inject)
            else:
                committed, committed_ref, rejected_ref = graph.empty(frozen), None, None
                stop = 'INPUT_P_INFEASIBLE' if feasibility['status'] == 'FAIL' else 'INPUT_P_UNRESOLVED'
            store.write('t3/main/committed.json', committed)
            main_graph = read_json(store.root / rejected_ref) if rejected_ref else committed
            store.write('t3/main/graph.json', main_graph)
            main_graph = read_json(store.root / 't3/main/graph.json')
            main, main_view = assess(main_graph, frozen, checks, feasibility, 'main')
            main['final_checks_status'] = main['status']
            if stop != 'COMPLETE':
                main['status'] = 'UNKNOWN' if stop == 'INPUT_P_UNRESOLVED' else 'FAIL'
                detail = {'code': stop}
                if rejected_ref:
                    detail['step_artifact'] = rejected_ref.replace('candidate.json', 'step.json')
                main['issues'].append(detail)
            main.update(stop=stop, committed_ref=committed_ref, rejected_ref=rejected_ref,
                        committed_sha256=digest(committed))
            report['main'] = main
            store.write('t3/main/checks.json', main)
            if shadow:
                info, other = shadow.result()
            elif main['status'] != 'PASS':
                info, other = auxiliary.obtain(store, frozen, schema, **kwargs)
            else:
                info, other = {'status': 'NOT_RUN', 'online': 'NOT_RUN', 'reason': 'MAIN_PASSED'}, None
        alternative_view = None
        auxiliary_checks = None
        if other is not None:
            auxiliary_checks = checks_factory(store, frozen, library, timeout, query_limit, digest(code),
                                              auxiliary=True, **check_options)
            if auxiliary_checks.identity != identity:
                raise Invalid('SOLVER_IDENTITY_CHANGED')
            assessment, alternative_view = assess(other, frozen, auxiliary_checks, feasibility, 'auxiliary')
            info.update(assessment=assessment, status=assessment['status'])
            store.write('auxiliary/checks.json', info)
        report['auxiliary'] = info
        diagnosis = auxiliary.diagnose(main, main_graph, main_view, info, other, alternative_view,
                                       auxiliary_checks, frozen)
        store.write('diagnostics/comparison.json', diagnosis)
        report['decision'] = diagnosis['decision']
        dependencies_valid = checks.bound() and all(sha256_file(store.root / file) == value for file, value in inputs.items())
        if (main['status'] == 'PASS' and diagnosis['decision'] == 'MAIN_QUALIFIED' and dependencies_valid
                and digest(read_json(store.root / 't3/main/committed.json')) == digest(main_graph)):
            acsl.emission(store, frozen, main_graph, main_view)
            if output_inject:
                output_inject(store.root)
            report['t4'] = acsl.readback(store, frozen, main_graph, main_view, checks)
            store.write('t4/checks.json', report['t4'])
            dependencies_valid = checks.bound() and all(sha256_file(store.root / file) == value for file, value in inputs.items())
            output_bound = report['t4']['status'] == 'PASS' and (
                sha256_file(store.root / 't4/contract.c') == report['t4']['output_sha256']
                and sha256_file(store.root / 't4/source_map.json') == report['t4']['map_sha256']
            )
            committed_bound = all(digest(read_json(store.root / f't3/main/{file}.json')) == digest(main_graph)
                                  for file in ('committed', 'graph'))
            report['publication_eligible'] = (
                report['t4']['status'] == 'PASS' and dependencies_valid and output_bound
                and committed_bound and not report['fault_injection']
            )
        report['dependencies_valid'] = dependencies_valid
        report['query_count'] = checks.count + (auxiliary_checks.count if auxiliary_checks else 0)
        report['status'] = 'PASSED' if report['publication_eligible'] else 'BLOCKED'
        store.write('trace/index.json', trace_index(store.root, frozen, main_graph, report))
    except (Invalid, OSError, ValueError, TypeError, KeyError, RecursionError) as exc:
        report['publication_eligible'] = False
        report['status'] = 'BLOCKED'
        report['failure'] = {'code': getattr(exc, 'code', 'INPUT_OR_WORKFLOW_ERROR'),
                             'type': type(exc).__name__}
        if frozen is None:
            report['input']['syntax'] = 'FAIL'
    except KeyboardInterrupt:
        report.update(status='CANCELLED', publication_eligible=False)
    store.write('result.json', report)
    store.write('manifest.json', {'schema': 't3t4-manifest-1', 'run_id': store.run_id,
                                 'solver': identity, 'initial_inputs': inputs, 'implementation': code,
                                 'files': files(store.root)})
    return store.root, report
