"""A bounded child controller that evaluates or repairs a completed Phase 1 run."""
from pathlib import Path

from ..adapters.cbmc import execution_identity
from ..artifacts import ArtifactStore, digest, sha256_file
from ..controller import run
from ..errors import AgentError
from ..evaluation.loader import ParentRun
from ..evaluation.models import Budget, Limits
from ..evaluation.strength import METRICS, evaluate_strength, plan_cases
from ..llm.parser import strict_json
from ..trace import RunTrace, redact
from .diagnosis import diagnose, route
from .repair import apply, propose


RETRY_ERRORS = {'RIC3_FAILED', 'RIC3_RESULT_INVALID', 'RIC3_UNKNOWN', 'RIC3_TIMEOUT',
                'BTOR_BUILD_FAILED_TIMEOUT', 'BTOR_INVALID_TIMEOUT'}


def error_codes(value):
    if isinstance(value, dict):
        codes = {value['code']} if isinstance(value.get('code'), str) else set()
        for item in value.values():
            codes.update(error_codes(item))
        return codes
    if isinstance(value, list):
        return set().union(*(error_codes(item) for item in value)) if value else set()
    return set()


def status_code(report):
    return {'COMPLETED': 0, 'CANCELLED': 130, 'PARTIAL': 3,
            'NEEDS_REVIEW': 3, 'BLOCKED': 2, 'ERROR': 2}[report['execution_status']]


def followup(parent_root, config, cases_file, *, output='phase2', max_iterations=2,
             limits=None, require_real=False, repair_fixture=None, on_run_created=None, budget=None):
    parent_path = Path(parent_root).resolve()
    if Path(output).resolve().is_relative_to(parent_path):
        raise AgentError('PHASE2_CONFIG_INVALID', 'Child output must be outside its immutable parent run')
    if type(max_iterations) is not int or not 0 <= max_iterations <= 10:
        raise AgentError('PHASE2_CONFIG_INVALID', 'Repair iterations must be between 0 and 10')
    if require_real and repair_fixture:
        raise AgentError('MOCK_IN_REAL_RUN', 'Real-only sub-agent rejects repair fixtures')
    charge_parent = budget is None
    limits = budget.limits if budget is not None else limits or Limits(calls_per_function=max(1, max_iterations), output_tokens=4096)
    limits.validate()
    budget = budget if budget is not None else Budget(limits)
    store = ArtifactStore(output)
    trace = RunTrace(store.root, store.run_id, secrets=(config.api_key,))
    report = {'subagent_id': store.run_id, 'schema_version': 1, 'role': 'EVALUATION_AND_REPAIR',
              'initial_run': str(parent_path), 'final_run': str(parent_path), 'execution_status': 'ERROR',
              'stop_reason': 'NOT_STARTED', 'iterations': [], 'evaluation': None, 'errors': [],
              'proposal_mode': 'FIXTURE_REPAIR' if repair_fixture else 'REAL',
              'max_iterations': max_iterations, 'budget': {}, 'logging': {}}

    def stage(name, iteration=0):
        store.write('checkpoint.json', {'stage': name, 'iteration': iteration, 'resume_supported': False})
        trace.emit('subagent.stage', stage=name, iteration=iteration)

    def stop(status, reason):
        report.update(execution_status=status, stop_reason=reason)

    trace.emit('subagent.started', parent_run=str(parent_path), max_iterations=max_iterations)
    try:
        stage('LOAD_PARENT')
        parent = ParentRun(parent_path)
        if require_real and (config.tool_mode != 'REAL' or parent.report.get('mode') != 'REAL'):
            raise AgentError('NON_REAL_PARENT', 'Real-only sub-agent requires real parent evidence')
        initial = parent
        store.write('input/parent_dependencies.json', parent.dependencies)
        store.write('input/frozen_specifications.json', parent.specs)
        store.write('input/requirements.json', parent.requirements)
        if Path(cases_file).stat().st_size > 1024*1024:
            raise AgentError('STRENGTH_CASES_INVALID', 'Labeled case file exceeds 1 MiB')
        cases = strict_json(Path(cases_file).read_text(encoding='utf-8'))
        store.write('input/strength_cases.json', cases)
        cases_path = store.root/'input/strength_cases.json'
        if parent.specs and route(parent.report) in ('EVALUATE', 'REPAIR_SOURCE'):
            plans = plan_cases(parent, cases, parent.toolchain)
            supplied = {case['metric'] for _, _, _, rows in plans for case in rows}
            if supplied != set(METRICS.values()) or {sid for sid, _, _, _ in plans} != {s['spec_id'] for s in parent.specs}:
                raise AgentError('STRENGTH_CASES_INVALID', 'Supply labeled cases for all specifications and all three metrics')
        for row in parent.report.get('contracts', []) if charge_parent else []:
            probes = [row.get('precondition', {}).get('result'), *row.get('properties', [])]
            for probe in probes:
                if probe and not budget.reserve('query', next(spec['function_id'] for spec in parent.specs if spec['spec_id']==row['spec_id'])):
                    raise AgentError('REPAIR_BUDGET_EXHAUSTED', 'Initial verification exceeds the shared query budget')
        for _ in parent.report.get('static_properties', []) if charge_parent else []:
            if not budget.reserve('query', 'static'):
                raise AgentError('REPAIR_BUDGET_EXHAUSTED', 'Initial static verification exceeds the shared query budget')
        seen = {digest(''.join(sha256_file(path) for path in parent.source_paths))}
        retries = 0
        for iteration in range(max_iterations+1):
            stage('ROUTE', iteration)
            if 'REPAIR_BUDGET_EXHAUSTED' in error_codes(parent.report):
                stop('PARTIAL', 'REPAIR_BUDGET_EXHAUSTED')
                break
            if 'GENERATION_BUDGET_EXHAUSTED' in error_codes(parent.report):
                stop('PARTIAL', 'GENERATION_BUDGET_EXHAUSTED')
                break
            decision = route(parent.report)
            trace.emit('subagent.routed', action=decision, parent_run=str(parent.root))
            if decision == 'CANCELLED':
                stop('CANCELLED', 'PARENT_CANCELLED')
                break
            if decision == 'EVALUATE':
                if not parent.specs:
                    stop('COMPLETED', 'STATIC_ONLY_NO_HOARE_CONTRACTS')
                    break
                stage('EVALUATE', iteration)
                ParentRun(initial.root)
                evaluation_root, evaluation = evaluate_strength(parent.root, config, cases_path,
                    output=store.root/'evaluations', require_real=require_real, budget=budget)
                report['evaluation'] = {'root': str(evaluation_root), 'execution_status': evaluation['execution_status'],
                                        'metrics': evaluation.get('strength', {}).get('metrics', {})}
                status = evaluation['execution_status']
                stop(status if status in ('COMPLETED', 'PARTIAL', 'CANCELLED', 'BLOCKED') else 'ERROR',
                     'QUALITY_EVALUATED' if status == 'COMPLETED' else evaluation['stop_reason'])
                break
            stage('DIAGNOSE', iteration)
            diagnosis = diagnose(parent)
            directory = store.root/'iterations'/f'{iteration+1:03d}'
            store.write(str(directory.relative_to(store.root)/'diagnosis.json'), diagnosis)
            record = {'iteration': iteration+1, 'parent_run': str(parent.root), 'route': decision,
                      'diagnosis': str(directory/'diagnosis.json'), 'trial_run': None}
            report['iterations'].append(record)
            if decision in ('PRECONDITION_REVIEW_REQUIRED', 'NEEDS_VERIFICATION'):
                stop('NEEDS_REVIEW', decision)
                break
            if iteration == max_iterations:
                stop('PARTIAL', 'REPAIR_ITERATION_LIMIT')
                break
            if decision == 'RETRY_OR_REVIEW':
                codes = error_codes(parent.report)
                if not codes and any(p.get('verdict') == 'UNKNOWN' for row in parent.report.get('contracts', [])
                                     for p in row.get('properties', [])):
                    codes = {'RIC3_UNKNOWN'}
                if retries or not codes or not codes <= RETRY_ERRORS:
                    stop('NEEDS_REVIEW', 'UNRECOVERED_PIPELINE_ERROR')
                    break
                retries += 1
                paths = parent.source_paths
                record['action'] = 'RETRY_WITH_FROZEN_SPECIFICATIONS'
            else:
                if not any(finding['map_status'] == 'ATTRIBUTED' and finding['source_locations']
                           for finding in diagnosis['findings']):
                    stop('NEEDS_REVIEW', 'MAPPED_SOURCE_UNAVAILABLE')
                    break
                stage('REPAIR_PROPOSAL', iteration+1)
                proposal = propose(parent, diagnosis, config, directory/'proposal', budget,
                                   iteration+1, fixture=repair_fixture)
                if budget.actual_tokens > limits.total_tokens:
                    stop('PARTIAL', 'PROVIDER_TOKEN_BUDGET_EXCEEDED')
                    break
                if proposal['needs_review']:
                    record['review_reason'] = proposal['explanation']
                    stop('NEEDS_REVIEW', 'REPAIR_PROPOSAL_NEEDS_REVIEW')
                    break
                stage('VALIDATE_SOURCE_EDIT', iteration+1)
                paths, _ = apply(parent, diagnosis, proposal, directory/'candidate')
                fingerprint = digest(''.join(sha256_file(path) for path in paths))
                if fingerprint in seen:
                    stop('PARTIAL', 'DUPLICATE_SOURCE_CANDIDATE')
                    break
                seen.add(fingerprint)
                record['action'] = 'REPAIR_SOURCE'
            stage('REVERIFY', iteration+1)
            # Recheck the parent immediately before using the frozen obligations.
            parent = ParentRun(parent.root)
            approved_hashes = [sha256_file(path) for path in paths]
            branch = parent.report.get('generation', {}).get('branch', 'hoare')
            domain = parent.domain.get('text') if parent.domain else None
            trial_root, trial = run(paths, parent.root/'input/requirements.md', config,
                output=directory/'runs', branch=branch,
                entry=parent.report.get('generation', {}).get('static_entry'), domain=domain,
                require_real=require_real, frozen_parent=parent, verification_budget=budget,
                require_unguarded_posts=bool(parent.constraints and parent.constraints.get('postcondition_guard') == 'NULL_ONLY'),
                on_run_created=on_run_created)
            record.update(trial_run=str(trial_root), execution_status=trial['status'],
                          source_hashes=approved_hashes)
            report['final_run'] = str(trial_root)
            if [item['sha256'] for item in trial.get('input', {}).get('sources', [])] != approved_hashes:
                raise AgentError('REPAIR_SCOPE_CHANGED', 'Candidate source changed while it was being snapshotted')
            if 'REPAIR_BUDGET_EXHAUSTED' in error_codes(trial):
                stop('PARTIAL', 'REPAIR_BUDGET_EXHAUSTED')
                break
            next_parent = ParentRun(trial_root)
            before = [(s['function_spec'], s['callee_expectations']) for s in sorted(initial.specs, key=lambda s: s['spec_id'])]
            after = [(s['function_spec'], s['callee_expectations']) for s in sorted(next_parent.specs, key=lambda s: s['spec_id'])]
            if before != after:
                raise AgentError('REPAIR_SCOPE_CHANGED', 'Source repair changed frozen semantic obligations')
            if execution_identity(initial.toolchain) != execution_identity(next_parent.toolchain):
                stop('NEEDS_REVIEW', 'TOOLCHAIN_IDENTITY_CHANGED')
                break
            parent = next_parent
    except KeyboardInterrupt:
        stop('CANCELLED', 'USER_CANCELLED')
    except (AgentError, OSError, ValueError, KeyError, TypeError) as exc:
        code = getattr(exc, 'code', 'SUBAGENT_FAILED')
        report['errors'].append({'code': code, 'message': redact(str(exc), (config.api_key,))})
        review = code.startswith(('REPAIR_SCOPE', 'REPAIR_EDIT', 'REPAIR_EVIDENCE', 'REPAIR_NO_EDITS'))
        stop('NEEDS_REVIEW' if review else 'PARTIAL' if 'BUDGET' in code else 'ERROR', code)
    report['budget'] = budget.snapshot()
    stage(report['execution_status'])
    trace.emit('subagent.finished', status=report['execution_status'], stop_reason=report['stop_reason'])
    report['logging'] = trace.status()
    store.write('subagent.json', report)
    lines = ['# 第二阶段子 agent', '', f"状态 `{report['execution_status']}`，结束原因 `{report['stop_reason']}`。", '',
             f"第一阶段输入运行 `{report['initial_run']}`。", '', f"最终验证运行 `{report['final_run']}`。", '']
    for item in report['iterations']:
        lines.append(f"- 第 {item['iteration']} 轮 `{item['route']}`，诊断文件 `{item['diagnosis']}`。")
    if report['evaluation']:
        lines.extend(['', f"质量报告位于 `{report['evaluation']['root']}/report.md`。"])
    (store.root/'report.md').write_text('\n'.join(lines)+'\n', encoding='utf-8')
    return store.root, report
