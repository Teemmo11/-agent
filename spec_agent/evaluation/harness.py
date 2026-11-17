"""Controlled C predicates over independent inputs and outputs; no target calls."""
from pathlib import Path
from ..analysis.functions import SCALARS
from ..artifacts import write_json_atomic,sha256_file
from ..errors import AgentError
from ..models import VerificationJob
from ..spec.expressions import ExpressionValidator


def expressions(spec,function):
    names=[p.name for p in function.parameters]
    pre=ExpressionValidator(names).validate(spec['function_spec']['pre_condition']['formal_candidate'])[0]
    clauses=[]
    for q in spec['function_spec']['post_conditions']:
        value=ExpressionValidator(names,allow_result=function.return_type!='void',allow_old=True).validate(q['formal_candidate'])[0]
        guard=ExpressionValidator(names,allow_old=True).validate(q['guard'])[0] if q['guard'] is not None else '1'
        clauses.append({'id':q['clause_id'],'q':value,'guard':guard,'effective':'(!('+guard+') || ('+value+'))'})
    return pre,clauses


def render(function,predicate,label):
    if function.return_type not in SCALARS|{'void'} or any(p.type not in SCALARS for p in function.parameters):
        raise AgentError('EVALUATION_LOGIC_UNSUPPORTED','Only built-in scalar domains supported')
    if any(p.name in ('result','old',function.name) or p.name.startswith('__sa_') for p in function.parameters):
        raise AgentError('EVALUATION_LOGIC_UNSUPPORTED','Reserved formal parameter name')
    lines=[]
    for i,p in enumerate(function.parameters):lines.append(f'extern {p.type} __CPROVER_nondet_input_{i}(void);')
    if function.return_type!='void':lines.append(f'extern {function.return_type} __CPROVER_nondet_output(void);')
    lines.append('int __sa_entry(void) {')
    for i,p in enumerate(function.parameters):
        # External C _Bool values may be represented as unconstrained storage
        # bytes by converters. Comparing with zero produces canonical C values
        # 0/1 without constraining P or removing any valid Boolean value.
        value=f'(__CPROVER_nondet_input_{i}() != 0)' if p.type=='_Bool' else f'__CPROVER_nondet_input_{i}()'
        lines.extend([f'    {p.type} {p.name} = {value};',f'    {p.type} __sa_old_{p.name} = {p.name};'])
    if function.return_type!='void':
        value='(__CPROVER_nondet_output() != 0)' if function.return_type=='_Bool' else '__CPROVER_nondet_output()'
        lines.append(f'    {function.return_type} __sa_result = {value};')
    lines.append(f'    __CPROVER_assume({predicate});')
    line=len(lines)+1
    lines.extend([f'    __CPROVER_assert(0, "{label}");','    return 0;','}',
                  'int main(void) { return __sa_entry(); }'])
    return '\n'.join(lines)+'\n',line


def emit(function,predicate,query_id,spec_id,root,dependencies):
    root=Path(root);root.mkdir(parents=True)
    text,line=render(function,predicate,query_id);path=root/'harness.c';path.write_text(text,encoding='utf-8')
    job=VerificationJob(query_id,'EVALUATION_QUERY',[str(path)],'__sa_entry',spec_id,query_id,
        harness_file=str(path),assertion_line=line,source_hashes={str(path):sha256_file(path),**dependencies},
        provenance={'purpose':'SPECIFICATION_PREDICATE_SATISFIABILITY','query_id':query_id,
                    'target_implementation_called':False,'witness_status':'UNAVAILABLE'})
    write_json_atomic(root/'job.json',job)
    return job
