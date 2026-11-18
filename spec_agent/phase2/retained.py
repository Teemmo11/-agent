"""Carry immutable semantic obligations into a new source verification run."""
import copy
import json
from pathlib import Path

from ..artifacts import sha256_file, write_json_atomic
from ..errors import AgentError
from ..llm.parser import parse_response


def carry(parent, program, requirements, info, root, trace):
    expected = {spec['function_id']: spec for spec in parent.specs}
    functions = {function.function_id: function for function in program.functions}
    if set(expected) != set(functions):
        raise AgentError('REPAIR_SCOPE_CHANGED', 'Every function must retain its existing specification')
    specs = []
    for fid in program.order:
        function = functions[fid]
        original = expected[fid]
        value = {key: copy.deepcopy(original[key]) for key in ('function_spec', 'callee_expectations')}
        parse_response(json.dumps(value), function, requirements, program,
                       require_unguarded_posts=bool(parent.constraints and
                                                   parent.constraints.get('postcondition_guard') == 'NULL_ONLY'))
        directory = Path(root)/'functions'/fid
        directory.mkdir(parents=True)
        prompt = {'origin': 'FROZEN_PARENT_SPECIFICATION', 'parent_run': str(parent.root),
                  'parent_spec_sha256': sha256_file(parent.root/'specs/semantic'/(original['spec_id']+'.json'))}
        write_json_atomic(directory/'prompt.json', prompt)
        (directory/'response.txt').write_text(json.dumps(value, ensure_ascii=False), encoding='utf-8')
        spec = copy.deepcopy(original)
        spec.update(source_sha256=info['source_sha256'], requirements_sha256=info['requirements_sha256'],
                    caller_context=function.callers,
                    caller_expectation_refs=[item['expectation_id'] for item in function.caller_expectations])
        spec['generation'].pop('selected_attempt', None)
        spec['generation'].pop('attempts_sha256', None)
        spec['generation'].update(origin='FROZEN_PARENT_SPECIFICATION', parent_run=str(parent.root),
                                  prompt_sha256=sha256_file(directory/'prompt.json'))
        write_json_atomic(directory/'spec.json', spec)
        specs.append(spec)
        trace.emit('spec.retained', function_id=fid, spec_id=spec['spec_id'], parent_run=str(parent.root))
        for expectation in spec['callee_expectations']:
            site = next(site for site in function.callees if site['callsite_id'] == expectation['callsite_id'])
            functions[site['callee_function']].caller_expectations.append(
                {**expectation, 'expectation_id': 'EXP-'+site['callsite_id'],
                 'source_spec_id': spec['spec_id']})
    result = {'specs': specs, 'failures': []}
    write_json_atomic(Path(root)/'candidates.json', result)
    return result
