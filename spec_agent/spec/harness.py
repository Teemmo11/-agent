from pathlib import Path
from ..errors import AgentError
from ..models import VerificationJob
from ..artifacts import sha256_file,write_json_atomic


def emit_harness(function,contract,clause,sources,directory,trace=None):
    """Include target TU (supports static functions); compile other TUs separately.
    C2Btor BTOR2 export requires a real main: user main is renamed via macro while
    included, entry stays __sa_entry (property provenance), and a real main delegates to it.
    """
    if function.harness_issues: raise AgentError('UNSUPPORTED_HARNESS','; '.join(function.harness_issues))
    directory=Path(directory); directory.mkdir(parents=True,exist_ok=True)
    path=directory/'harness.c'
    target=Path(function.source_file)
    if any(c in str(target) for c in ['"','\n','\r','\\']): raise AgentError('UNSUPPORTED_HARNESS','Unsafe include path')
    label=contract.source_spec_id+'.'+(clause.clause_id if clause else 'P-FEASIBILITY')
    lines=[f'#define main __sa_original_main',f'#include "{target}"','#undef main']
    for p in function.parameters: lines.append(f'extern {p.type} __CPROVER_nondet_{p.name}(void);')
    lines+=['int __sa_entry(void) {']
    for p in function.parameters: lines.append(f'    {p.type} {p.name} = __CPROVER_nondet_{p.name}();')
    if clause:
        for name in contract.required_snapshots:
            typ=next(p.type for p in function.parameters if p.name==name)
            lines.append(f'    {typ} __sa_old_{name} = {name};')
        if clause.guard_expr: lines.append(f'    _Bool __sa_guard = ({clause.guard_expr});')
    lines.append(f'    __CPROVER_assume({contract.precondition_expr});')
    if clause:
        call=function.name+'('+', '.join(p.name for p in function.parameters)+')'
        lines.append('    '+(f'{function.return_type} __sa_result = ' if function.return_type!='void' else '')+call+';')
        expr=f'(!__sa_guard || ({clause.expr}))' if clause.guard_expr else clause.expr
    else: expr='0'
    assertion_line=len(lines)+1
    lines+=[f'    __CPROVER_assert({expr}, "{label}");','    return 0;','}',
        'int main(void) {','    return __sa_entry();','}']
    with path.open('x') as f: f.write('\n'.join(lines)+'\n')
    source_files=[str(path),*[str(s) for s in sources if Path(s)!=target]]
    hashes={str(s):sha256_file(s) for s in [*sources,path]}
    job=VerificationJob(label,'HOARE_POSTCONDITION' if clause else 'PRECONDITION_FEASIBILITY',source_files,
        '__sa_entry',contract.source_spec_id,label,harness_file=str(path),assertion_line=assertion_line,source_hashes=hashes)
    write_json_atomic(directory/'job.json',job)
    if trace:
        trace.emit('harness.emitted',function_id=function.function_id,spec_id=contract.source_spec_id,
                   property_id=label,kind=job.kind,precondition=contract.precondition_expr,
                   assertion=lines[assertion_line-1].strip(),assertion_line=assertion_line,
                   harness_file=str(path),harness_sha256=sha256_file(path),
                   guard=clause.guard_expr if clause else None,snapshots=contract.required_snapshots if clause else [],
                   clause_id=clause.clause_id if clause else None,
                   purpose='POSTCONDITION' if clause else 'PRECONDITION_FEASIBILITY_PROBE')
    return job
