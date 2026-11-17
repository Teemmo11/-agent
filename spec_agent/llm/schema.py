"""Minimal JSON Schema subset, shared by published schema and runtime validation."""
from ..errors import AgentError

def validate(value,schema,path='$'):
    t=schema.get('type')
    types=t if isinstance(t,list) else [t]
    matches={'object':isinstance(value,dict),'array':isinstance(value,list),'string':isinstance(value,str),'null':value is None,
             'integer':type(value) is int,'boolean':type(value) is bool}
    if t and not any(matches.get(x,False) for x in types): raise AgentError('LLM_RESPONSE_INVALID',path+': wrong type')
    if 'enum' in schema and value not in schema['enum']: raise AgentError('LLM_RESPONSE_INVALID',path+': enum mismatch')
    if isinstance(value,dict):
        props=schema.get('properties',{})
        if any(k not in value for k in schema.get('required',[])): raise AgentError('LLM_RESPONSE_INVALID',path+': missing required field')
        if schema.get('additionalProperties') is False and set(value)-set(props): raise AgentError('LLM_RESPONSE_INVALID',path+': unexpected fields')
        for k,v in value.items():
            if k in props: validate(v,props[k],path+'.'+k)
    if isinstance(value,list):
        if len(value)<schema.get('minItems',0) or len(value)>schema.get('maxItems',10000): raise AgentError('LLM_RESPONSE_INVALID',path+': array size')
        for i,v in enumerate(value): validate(v,schema.get('items',{}),path+f'[{i}]')
    if isinstance(value,str):
        import re
        if len(value)<schema.get('minLength',0) or len(value)>schema.get('maxLength',65536): raise AgentError('LLM_RESPONSE_INVALID',path+': string size')
        if 'pattern' in schema and not re.fullmatch(schema['pattern'],value): raise AgentError('LLM_RESPONSE_INVALID',path+': pattern mismatch')
