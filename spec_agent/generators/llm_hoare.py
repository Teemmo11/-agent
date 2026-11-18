import json
import time
from pathlib import Path
from shutil import copyfile

from ..artifacts import digest, sha256_file, utc_now, write_json_atomic
from ..errors import AgentError
from ..llm.parser import parse_response
from ..llm.prompts import messages
from ..phase1.agent import RETRYABLE_ERRORS
from ..trace import redact


def _metadata(directory, trace):
    path = directory/'response.metadata.json'
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding='utf-8'))
        if isinstance(data, dict):
            return data
    except (OSError, ValueError):
        pass
    if trace:
        trace.emit('llm.metadata.unavailable', level='WARNING', metadata_file=str(path))
    return None


def _generate_function(function, program, functions, requirements, info, client, directory, domain,
                       partial, guard_constraint, agent, trace):
    fid = function.function_id
    secrets = (getattr(getattr(client, 'config', None), 'api_key', ''),)
    feedback, seen, records = None, set(), []
    directory.mkdir(parents=True, exist_ok=True)
    limit = agent.max_attempts if agent else 1
    for attempt in range(1, limit+1):
        ft = trace.bind(function_id=fid, spec_id='HS-'+fid, attempt_id=attempt) if trace else None
        target = directory/'attempts'/f'{attempt:03d}' if agent else directory
        target.mkdir(parents=True, exist_ok=True)
        stage, started, raw, candidate, metadata = 'prepare_prompt', time.monotonic(), None, None, None
        try:
            if agent:
                prompt, estimated = agent.prepare(function, functions, requirements, domain, feedback,
                                                  require_unguarded_posts=guard_constraint)
                write_json_atomic(target/'prompt.json', redact(prompt, secrets))
                agent.reserve(fid, estimated)
            else:
                prompt = messages(function, requirements, domain, require_unguarded_posts=guard_constraint)
                write_json_atomic(target/'prompt.json', redact(prompt, secrets))
                estimated = None
            stage = 'request'
            request_started = time.monotonic()
            if ft:
                ft.emit('llm.request.started', function=function.name, mode=client.mode,
                        prompt_file=str(target/'prompt.json'), prompt_sha256=sha256_file(target/'prompt.json'),
                        requirement_refs=function.requirement_refs, caller_expectations=function.caller_expectations,
                        caller_expectations_partial=partial, estimated_input_tokens=estimated)
            try:
                raw = agent.request(client, prompt, target) if agent else client.complete(prompt, target)
            finally:
                metadata = _metadata(target, ft)
                if agent and metadata:
                    agent.budget.charge(metadata)
            (target/'response.txt').write_text(redact(raw, secrets), encoding='utf-8')
            if ft:
                ft.emit('llm.response.received', duration_ms=round((time.monotonic()-request_started)*1000,3),
                        response_file=str(target/'response.txt'), response_sha256=sha256_file(target/'response.txt'),
                        characters=len(raw), metadata=metadata)
            if agent and agent.budget.actual_tokens > agent.budget.limits.total_tokens:
                raise AgentError('GENERATION_BUDGET_EXHAUSTED', 'Provider reported usage over the token budget')
            stage = 'parse_and_validate'
            candidate = parse_response(raw, function, requirements, program, require_unguarded_posts=guard_constraint)
            spec = {**candidate, 'spec_id': 'HS-'+fid, 'function_id': fid,
                    'source_sha256': info['source_sha256'], 'requirements_sha256': info['requirements_sha256'],
                    'caller_expectation_refs': [e['expectation_id'] for e in function.caller_expectations],
                    'caller_context': function.callers,
                    'generation': {'mode': client.mode, 'created_at': utc_now(),
                                   'model': getattr(getattr(client,'config',None),'model',None),
                                   'prompt_sha256': sha256_file(target/'prompt.json'), 'caller_expectations_partial': partial}}
            if guard_constraint:
                spec['generation']['constraints'] = {'postcondition_guard': 'NULL_ONLY'}
            if agent:
                stage = 'validate_expressions'
                checks = ft.bind(check='GENERATION_CANDIDATE') if ft else None
                agent.validate_candidate(spec, function, info, checks)
                stage = 'persist_spec'
                records.append({'attempt': attempt, 'status': 'ACCEPTED'})
                files = {p.relative_to(directory).as_posix(): sha256_file(p)
                         for p in sorted((directory/'attempts').glob('*/*')) if p.is_file()}
                write_json_atomic(directory/'attempts.json', {'attempts': records, 'selected_attempt': attempt,
                                                            'artifact_hashes': files})
                spec['generation']['selected_attempt'] = attempt
                spec['generation']['attempts_sha256'] = sha256_file(directory/'attempts.json')
                for filename in ('prompt.json', 'response.txt', 'response.raw.json', 'response.metadata.json'):
                    if (target/filename).is_file():
                        copyfile(target/filename, directory/filename)
            else:
                stage = 'persist_spec'
            write_json_atomic(directory/'spec.json', spec)
            if ft:
                ft.emit('llm.generation.finished', duration_ms=round((time.monotonic()-started)*1000,3))
            return spec, None, ft
        except Exception as exc:
            error = exc.as_dict() if isinstance(exc, AgentError) else {'code': 'GENERATION_FAILED', 'message': type(exc).__name__}
            error = redact(error, secrets)
            item = {'function_id': fid, 'function': function.name, 'error': error}
            retryable = agent and error['code'] in RETRYABLE_ERRORS
            duplicate = False
            if retryable and raw is not None:
                key = digest(json.dumps(candidate, sort_keys=True) if candidate is not None else raw.strip())
                duplicate = key in seen
                seen.add(key)
            retry = retryable and not duplicate and attempt < limit
            if agent:
                stop_reason = ('RETRY' if retry else 'DUPLICATE_CANDIDATE' if duplicate else
                               'ATTEMPT_LIMIT' if retryable else error['code'])
                records.append({'attempt': attempt, 'status': 'REJECTED', 'stage': stage, 'error': error,
                                'decision': stop_reason})
                item.update(attempts=attempt, stop_reason=stop_reason)
                write_json_atomic(target/'error.json', item)
            if retry:
                feedback = {'attempt': attempt, 'stage': stage, 'error': error}
                if raw is not None:
                    feedback['response_excerpt'] = redact(raw[:2048], secrets)
                if ft:
                    ft.emit('llm.generation.retry', level='WARNING', stage=stage, error=error,
                            next_attempt=attempt+1, artifact_directory=str(target))
                continue
            if ft:
                ft.emit('llm.generation.failed', level='ERROR', stage=stage, error=error,
                        duration_ms=round((time.monotonic()-started)*1000,3),
                        artifact_directory=str(target), metadata=metadata, stop_reason=item.get('stop_reason'))
            write_json_atomic(directory/'error.json', item)
            return None, item, ft


def generate(program, requirements, input_info, client, root, domain=None, trace=None, *,
             require_unguarded_posts=False, agent=None):
    specs, failures, done = [], [], set()
    by_id = {function.function_id: function for function in program.functions}
    for fid in program.order:
        function = by_id[fid]
        function.requirement_refs = requirements['ids']
        directory = Path(root)/'functions'/fid
        partial = any(site['caller_function'] not in done for site in function.callers)
        spec, failure, ft = _generate_function(function, program, by_id, requirements, input_info, client,
                                               directory, domain, partial, require_unguarded_posts, agent, trace)
        if failure:
            failures.append(failure)
            continue
        specs.append(spec)
        if ft:
            ft.emit('spec.accepted', function_spec=spec['function_spec'],
                    callee_expectations=spec['callee_expectations'], spec_file=str(directory/'spec.json'))
            fs = spec['function_spec']
            if fs['conflicts'] or fs['ambiguities'] or partial:
                ft.emit('spec.review_needed', level='WARNING', conflicts=fs['conflicts'],
                        ambiguities=fs['ambiguities'], caller_expectations_partial=partial)
        for item in spec['callee_expectations']:
            call = next(site for site in function.callees if site['callsite_id']==item['callsite_id'])
            target = by_id[call['callee_function']]
            expectation = {**item, 'expectation_id': 'EXP-'+item['callsite_id'], 'caller_function_id': fid,
                           'callee_function_id': target.function_id, 'source_spec_id': spec['spec_id']}
            target.caller_expectations.append(expectation)
            if ft:
                ft.emit('expectation.propagated', **expectation)
        done.add(fid)
    result = {'specs': specs, 'failures': failures}
    write_json_atomic(Path(root)/'candidates.json', result)
    return result
