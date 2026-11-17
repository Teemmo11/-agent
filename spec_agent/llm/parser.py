import json
from copy import deepcopy
from pathlib import Path
from ..errors import AgentError
from .schema import validate
SCHEMA=json.loads((Path(__file__).parents[1]/'schemas/hoare_spec.schema.json').read_text())

def response_schema(*,require_unguarded_posts=False):
    """Controller-owned constraints; never mutate the shared caller-aware schema."""
    schema=deepcopy(SCHEMA)
    if require_unguarded_posts:
        posts=schema['properties']['function_spec']['properties']['post_conditions']
        posts['items']['properties']['guard']={'type':'null'}
    return schema

def strict_json(text):
    def unique(pairs):
        d={}
        for k,v in pairs:
            if k in d: raise ValueError('duplicate JSON key')
            d[k]=v
        return d
    try: return json.loads(text,object_pairs_hook=unique,parse_constant=lambda _:(_ for _ in ()).throw(ValueError()))
    except (ValueError,TypeError): raise AgentError('LLM_RESPONSE_INVALID','Response must be strict JSON without duplicate keys')


def postcondition_evidence_refs(function, requirements):
    return (set(requirements['ids'])
            | {site['callsite_id'] for site in function.callers}
            | {item['expectation_id'] for item in function.caller_expectations})


def parse_response(text,function,requirements,program,*,require_unguarded_posts=False):
    data=strict_json(text); validate(data,response_schema(require_unguarded_posts=require_unguarded_posts))
    fs=data['function_spec']
    if fs['function']['name']!=function.name or fs['function']['signature']!=function.signature:
        raise AgentError('LLM_RESPONSE_INVALID','Function identity mismatch')
    ids=[q['clause_id'] for q in fs['post_conditions']]
    if len(set(ids))!=len(ids): raise AgentError('LLM_RESPONSE_INVALID','Duplicate clause IDs')
    known=set(requirements['ids'])
    allowed_evidence=postcondition_evidence_refs(function,requirements)
    def refs(values,allowed):
        if not set(values)<=allowed: raise AgentError('LLM_RESPONSE_INVALID','Unknown provenance reference')
    refs(fs['requirement_refs'],known)
    for q in fs['post_conditions']:
        refs(q['requirement_refs'],known); refs(q['evidence_refs'],allowed_evidence)
    outgoing={s['callsite_id']:s for s in function.callees if s['callee_function']}
    seen=set()
    for e in data['callee_expectations']:
        sid=e['callsite_id']; call=outgoing.get(sid)
        if not call or call['callee_name']!=e['callee'] or sid in seen: raise AgentError('LLM_RESPONSE_INVALID','Invalid callee expectation callsite')
        seen.add(sid); refs(e['requirement_refs'],known)
    return data
