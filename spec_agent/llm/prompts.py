import json
from dataclasses import asdict
from pathlib import Path
from .parser import postcondition_evidence_refs, response_schema
SYSTEM=(Path(__file__).parents[1]/'prompts/hoare_generation.md').read_text()

def messages(function,requirements,domain=None,*,require_unguarded_posts=False):
    context={'requirements':requirements,'function':asdict(function),'domain_knowledge':domain,
      'allowed_postcondition_evidence_refs':sorted(postcondition_evidence_refs(function,requirements)),
      'formal_symbols':{'parameters':[asdict(p) for p in function.parameters],
          'result':{'name':'result','type':function.return_type} if function.return_type!='void' else None,
          'old_supported':[p.name for p in function.parameters]},
      'output_schema':response_schema(require_unguarded_posts=require_unguarded_posts),
      'output_instruction':'Output exactly one valid JSON object only. No Markdown fences or prose.'}
    system=SYSTEM
    if require_unguarded_posts:
        context['generation_constraints']={'postcondition_guard':'NULL_ONLY'}
        system+='\nController-required output constraint for this acceptance run: every postcondition guard MUST be JSON null.\n'
        system+='Do not use a string, the string "null", an empty string, a Boolean, or a copy of P as a guard.\n'
        system+='The common precondition belongs only in pre_condition.formal_candidate. Postconditions are unguarded under P.\n'
        system+='This explicit run constraint overrides the general permission to emit caller-specific guards.\n'
    return [{'role':'system','content':system},{'role':'user','content':json.dumps(context,ensure_ascii=False)}]
