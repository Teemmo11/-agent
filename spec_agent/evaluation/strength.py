"""Spec-Harness-style checks over independently labeled inputs and outputs."""
import re
from pathlib import Path

from ..analysis.functions import SCALARS
from ..artifacts import ArtifactStore, sha256_file
from ..errors import AgentError
from ..llm.parser import strict_json
from ..preflight import doctor
from ..trace import RunTrace
from .controller import publish
from .harness import expressions
from .loader import ParentRun
from .logic import LogicEngine, conjunction
from .models import Budget, Limits, VERSION


LEGACY_METRICS = {'invalid_inputs': 'PreComp', 'invalid_outputs': 'PostComp'}
METRICS = {**LEGACY_METRICS, 'valid_inputs': 'PreCorr'}
STRENGTH_PROTOCOL = 2


def invalid(message):
    return AgentError('STRENGTH_CASES_INVALID', message)


def typed_equality(name, c_type, value, target):
    """Pin a concrete scalar without relying on a lossy C conversion."""
    if c_type not in SCALARS:
        raise invalid(f'{name} has unsupported type {c_type}')
    if c_type == '_Bool':
        minimum, maximum = 0, 1
    elif c_type == 'char':
        # Restrict plain char to values portable across signedness policies.
        minimum, maximum = 0, 127
    else:
        bits = (8 if 'char' in c_type else 16 if 'short' in c_type else
                64 if 'long long' in c_type or ('long' in c_type and target == 'LP64') else 32)
        unsigned = c_type.startswith('unsigned')
        minimum = 0 if unsigned else -(1 << (bits - 1))
        maximum = (1 << (bits if unsigned else bits - 1)) - 1
    if type(value) is not int or not minimum <= value <= maximum:
        raise invalid(f'{name} must be an integer in [{minimum}, {maximum}] for {c_type}')
    if value == -(1 << 63):
        literal = '(-9223372036854775807LL - 1LL)'
    else:
        literal = f'{value}{"ULL" if value > (1 << 63) - 1 else "LL"}'
    return f'{name} == {literal}'


def plan_cases(parent, suite, caps, *, metrics=METRICS):
    if not isinstance(suite, dict) or not suite:
        raise invalid('Expected a nonempty object keyed by function name or specification ID')
    plans = []
    selected = set()
    target = caps.get('cbmc_target_model')
    for selector, groups in suite.items():
        matches = [spec for spec in parent.specs if selector in
                   (spec['spec_id'], parent.functions[spec['function_id']].name)]
        if len(matches) != 1 or matches[0]['spec_id'] in selected:
            raise invalid(f'Unknown, ambiguous or repeated specification: {selector}')
        spec = matches[0]
        sid = spec['spec_id']
        selected.add(sid)
        function = parent.functions[spec['function_id']]
        if not isinstance(groups, dict) or not groups or set(groups) - metrics.keys():
            raise invalid(f'{selector} must define one or more of {", ".join(metrics)}')
        precondition, clauses = expressions(spec, function)
        postcondition = conjunction([clause['effective'] for clause in clauses])
        names = {p.name for p in function.parameters}
        if function.return_type not in SCALARS | {'void'} or any(p.type not in SCALARS for p in function.parameters):
            raise invalid(f'{selector} requires a supported scalar signature')
        rows, ids, bindings = [], set(), set()
        admitted, outside = set(), set()
        for group, metric in metrics.items():
            cases = groups.get(group, [])
            if not isinstance(cases, list):
                raise invalid(f'{selector}.{group} must be an array')
            for case in cases:
                keys = {'id', 'inputs', 'requirement', 'reason'}
                if metric == 'PostComp':
                    keys.add('result')
                if not isinstance(case, dict) or set(case) != keys:
                    raise invalid(f'{selector}.{group} case must contain {", ".join(sorted(keys))}')
                cid = case['id']
                inputs = case['inputs']
                if not isinstance(cid, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,80}', cid) or cid in ids:
                    raise invalid(f'{selector} has an invalid or duplicate case ID')
                if not isinstance(inputs, dict) or set(inputs) != names:
                    raise invalid(f'{selector}/{cid} must pin exactly the function parameters')
                if case['requirement'] not in parent.requirements['ids'] or not isinstance(case['reason'], str) or not case['reason'].strip():
                    raise invalid(f'{selector}/{cid} requires a known requirement ID and a nonempty reason')
                pins = [typed_equality(p.name, p.type, inputs[p.name], target) for p in function.parameters]
                (outside if metric == 'PreComp' else admitted).add(tuple(pins))
                if metric == 'PostComp':
                    pins.append(typed_equality('__sa_result', function.return_type, case['result'], target))
                    condition = [precondition, f'!({postcondition})']
                elif metric == 'PreCorr':
                    condition = [precondition]
                else:
                    condition = [f'!({precondition})']
                binding = (metric, tuple(pins))
                if binding in bindings:
                    raise invalid(f'{selector}/{cid} duplicates a case')
                ids.add(cid)
                bindings.add(binding)
                rows.append({**case, 'metric': metric, 'predicate': conjunction([*pins, *condition])})
        if 'valid_inputs' in metrics and admitted & outside:
            raise invalid(f'{selector} labels the same input as both valid and outside the requirement domain')
        plans.append((sid, function, precondition, rows))
    if not any(rows for _, _, _, rows in plans):
        raise invalid('Provide at least one labeled case')
    return plans


def raw(query):
    return query['raw_result'] if query['status'] == 'DECIDED' else None


def outcomes_for(metric):
    return ('RETAINED', 'EXCLUDED') if metric == 'PreCorr' else ('REJECTED', 'NOT_REJECTED')


def summarize(rows, metric):
    outcomes = [row['outcome'] for row in rows if row['metric'] == metric]
    positive, negative = outcomes_for(metric)
    success, failure = outcomes.count(positive), outcomes.count(negative)
    decided = success + failure
    return {'total': len(outcomes), 'decided': decided, positive.lower(): success, negative.lower(): failure,
            'undecided': len(outcomes) - decided, 'score': success / decided if decided else None,
            'status': ('NO_CASES' if not outcomes else 'UNDECIDED' if not decided else
                       'PARTIAL' if decided < len(outcomes) else 'COMPLETED')}


def assess(plans, engine, *, metrics=METRICS):
    functions = []
    all_cases = []
    for sid, function, precondition, plan in plans:
        cases = []
        feasibility = (engine.query(function, sid, 'STRENGTH_P_FEASIBILITY', conjunction([precondition]))
                       if any(case['metric'] != 'PreCorr' for case in plan) else None)
        for case in plan:
            row = {**case, 'query_id': None, 'raw_result': None, 'outcome': 'UNDECIDED'}
            if case['metric'] == 'PreCorr' or raw(feasibility) == 'SAT':
                query = engine.query(function, sid, case['metric'], case['predicate'])
                result = raw(query)
                positive, negative = outcomes_for(case['metric'])
                row.update(query_id=query['query_id'], raw_result=result,
                           outcome={'SAT': positive, 'UNSAT': negative}.get(result, 'UNDECIDED'))
                if result is None:
                    row['reason_code'] = query.get('error') or query['status']
            else:
                row['reason_code'] = 'P_INFEASIBLE' if raw(feasibility) == 'UNSAT' else 'P_FEASIBILITY_UNDECIDED'
            cases.append(row)
        functions.append({'spec_id': sid, 'function': function.name,
                          'feasibility_query': feasibility['query_id'] if feasibility else None,
                          'metrics': {metric: summarize(cases, metric) for metric in metrics.values()},
                          'cases': cases})
        all_cases.extend(cases)
    return {'label_source': 'SUPPLIED_REQUIREMENT_LABELS', 'suite_ref': 'input/strength_cases.json',
            'metrics': {metric: summarize(all_cases, metric) for metric in metrics.values()},
            'functions': functions}


def evaluate_strength(parent_root, config, cases_file, *, output='evaluations', require_real=False, limits=None):
    parent_path = Path(parent_root).resolve()
    if Path(output).resolve().is_relative_to(parent_path):
        raise AgentError('EVALUATION_CONFIG_INVALID', 'Evaluation output must be outside the immutable parent run')
    limits = limits or Limits()
    limits.validate()
    budget = Budget(limits)
    store = ArtifactStore(output)
    root = store.root
    trace = RunTrace(root, store.run_id, secrets=(config.api_key,))
    report = {
        'evaluation_id': store.run_id, 'schema_version': 1, 'evaluator_version': VERSION,
        'parent_run_ref': str(parent_path), 'parent_run_id': None, 'execution_status': 'BLOCKED',
        'assessment_mode': {'profile': 'strength', 'parent_mode': 'UNAVAILABLE', 'reviewer': 'none',
                            'logic': 'tools', 'tool_mode': config.tool_mode, 'strength_protocol': STRENGTH_PROTOCOL},
        'context_completeness': 'UNAVAILABLE', 'verification_snapshot': {}, 'dimensions': {},
        'findings': [], 'coverage': {}, 'limits': vars(limits), 'stop_reason': 'NOT_STARTED',
        'errors': [], 'contexts': [], 'reviews': [], 'queries': [], 'source_and_spec_hashes': {}, 'logging': {},
    }

    def stage(name):
        store.write('checkpoint.json', {'stage': name, 'resume_supported': False})
        trace.emit('evaluation.stage', stage=name)

    trace.emit('evaluation.started', profile='strength', reviewer='none', logic='tools')
    try:
        stage('LOAD_PARENT')
        parent = ParentRun(parent_path)
        report['parent_run_id'] = parent.manifest['run_id']
        mode = parent.report.get('mode', 'UNAVAILABLE')
        report['assessment_mode']['parent_mode'] = mode
        if config.tool_mode != 'REAL' or mode == 'MOCK_ALL' or require_real and mode != 'REAL':
            raise AgentError('NON_REAL_EVALUATION', 'Strength requires real tools and rejects mock parents')
        report['execution_status'] = 'ERROR'
        report['source_and_spec_hashes'] = dict(parent.dependencies)
        report['verification_snapshot'] = parent.status()['verification_availability']
        store.write('parent_integrity.json', parent.status())
        stage('LOAD_CASES')
        case_path = Path(cases_file)
        if case_path.stat().st_size > 1024 * 1024:
            raise invalid('Labeled case file exceeds 1 MiB')
        suite = strict_json(case_path.read_text(encoding='utf-8'))
        store.write('input/strength_cases.json', suite)
        stage('LOGIC_CHECKS')
        caps = doctor(config, root/'preflight', probe_tools=True, trace=trace)
        store.write('toolchain_manifest.json', caps)
        plans = plan_cases(parent, suite, caps)
        dependencies = {str(parent.root/ref): checksum for ref, checksum in parent.dependencies.items()}
        for ref in ('input/strength_cases.json', 'toolchain_manifest.json'):
            dependencies[str(root/ref)] = sha256_file(root/ref)
        engine = LogicEngine(root, caps, config, budget, trace, dependencies)
        report['strength'] = assess(plans, engine)
        report['queries'] = engine.results
        partial = any(metric['undecided'] for metric in report['strength']['metrics'].values())
        report['execution_status'] = 'PARTIAL' if partial else 'COMPLETED'
        report['context_completeness'] = 'PARTIAL' if partial else 'COMPLETE'
        report['stop_reason'] = 'STRENGTH_CASES_UNDECIDED' if partial else 'STRENGTH_CASES_FINISHED'
    except KeyboardInterrupt:
        report.update(execution_status='CANCELLED', stop_reason='USER_CANCELLED')
    except (AgentError, OSError, ValueError, KeyError, TypeError) as exc:
        code = getattr(exc, 'code', 'STRENGTH_EVALUATION_FAILED')
        report['stop_reason'] = code
        report['errors'].append({'code': code, 'message': str(exc)})

    report['budget'] = budget.snapshot()
    stage(report['execution_status'])
    trace.emit('evaluation.finished', status=report['execution_status'], stop_reason=report['stop_reason'])
    report['logging'] = trace.status()
    return publish(store, report)
