import json
import time
from pathlib import Path
from ..llm.prompts import messages
from ..llm.parser import parse_response
from ..artifacts import write_json_atomic, utc_now, sha256_file
from ..errors import AgentError
from ..trace import redact


def _metadata(directory, trace):
    path = directory/'response.metadata.json'
    if not path.exists(): return None
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        if trace: trace.emit('llm.metadata.unavailable', level='WARNING', metadata_file=str(path))
        return None


def generate(program, requirements, input_info, client, root, domain=None, trace=None,*,require_unguarded_posts=False):
    specs, failures, done = [], [], set()
    byid = {f.function_id:f for f in program.functions}
    secrets = (getattr(getattr(client, 'config', None), 'api_key', ''),)
    for fid in program.order:
        f = byid[fid]
        f.requirement_refs = requirements['ids']
        d = Path(root)/'functions'/fid
        ft = trace.bind(function_id=fid, spec_id='HS-'+fid, attempt_id=1) if trace else None
        stage, started = 'prepare_prompt', time.monotonic()
        try:
            d.mkdir(parents=True, exist_ok=True)
            prompt = messages(f, requirements, domain,require_unguarded_posts=require_unguarded_posts)
            write_json_atomic(d/'prompt.json', redact(prompt, secrets))
            partial = any(s['caller_function'] not in done for s in f.callers)
            stage = 'request'
            request_started = time.monotonic()
            if ft:
                ft.emit('llm.request.started', function=f.name, mode=client.mode,
                        prompt_file=str(d/'prompt.json'), prompt_sha256=sha256_file(d/'prompt.json'),
                        requirement_refs=f.requirement_refs, caller_expectations=f.caller_expectations,
                        caller_expectations_partial=partial)
            raw = client.complete(prompt, d)
            # Custom clients need only return text; the generator owns this artifact.
            (d/'response.txt').write_text(redact(raw,secrets),encoding='utf-8')
            if ft:
                ft.emit('llm.response.received', duration_ms=round((time.monotonic()-request_started)*1000,3),
                        response_file=str(d/'response.txt'), response_sha256=sha256_file(d/'response.txt'),
                        characters=len(raw), metadata=_metadata(d, ft))
            stage = 'parse_and_validate'
            spec = parse_response(raw, f, requirements, program,require_unguarded_posts=require_unguarded_posts)
            spec.update(spec_id='HS-'+fid, function_id=fid, source_sha256=input_info['source_sha256'],
                        requirements_sha256=input_info['requirements_sha256'],
                        caller_expectation_refs=[e['expectation_id'] for e in f.caller_expectations],
                        caller_context=f.callers, generation={'mode':client.mode,'created_at':utc_now(),
                        'model':getattr(getattr(client,'config',None),'model',None),
                        'prompt_sha256':sha256_file(d/'prompt.json'),'caller_expectations_partial':partial})
            if require_unguarded_posts:
                spec['generation']['constraints']={'postcondition_guard':'NULL_ONLY'}
            stage = 'persist_spec'
            write_json_atomic(d/'spec.json', spec)
            # Publish only after persistence succeeds.
            specs.append(spec)
            if ft:
                ft.emit('spec.accepted', function_spec=spec['function_spec'],
                        callee_expectations=spec['callee_expectations'], spec_file=str(d/'spec.json'))
                fs = spec['function_spec']
                if fs['conflicts'] or fs['ambiguities'] or partial:
                    ft.emit('spec.review_needed', level='WARNING', conflicts=fs['conflicts'],
                            ambiguities=fs['ambiguities'], caller_expectations_partial=partial)
            stage = 'propagate_expectations'
            for e in spec['callee_expectations']:
                call = next(s for s in f.callees if s['callsite_id']==e['callsite_id'])
                target = byid[call['callee_function']]
                expectation = {**e,'expectation_id':'EXP-'+e['callsite_id'],'caller_function_id':fid,
                               'callee_function_id':target.function_id,'source_spec_id':spec['spec_id']}
                target.caller_expectations.append(expectation)
                if ft: ft.emit('expectation.propagated', **expectation)
            done.add(fid)
            if ft: ft.emit('llm.generation.finished', duration_ms=round((time.monotonic()-started)*1000,3))
        except Exception as exc:
            error = exc.as_dict() if isinstance(exc,AgentError) else {'code':'GENERATION_FAILED','message':type(exc).__name__}
            if ft:
                ft.emit('llm.generation.failed', level='ERROR', stage=stage, error=error,
                        duration_ms=round((time.monotonic()-started)*1000,3),
                        artifact_directory=str(d), metadata=_metadata(d, ft))
            item = {'function_id':fid,'function':f.name,'error':error}
            failures.append(item)
            write_json_atomic(d/'error.json', redact(item, secrets))
    result = {'specs':specs,'failures':failures}
    write_json_atomic(Path(root)/'candidates.json', result)
    return result
