#!/usr/bin/env python3
"""Phase 1.5 real acceptance. No mocks, fixtures, automatic repair or fallback."""
import argparse
import json
import sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from spec_agent.artifacts import ArtifactStore,write_json_atomic
from spec_agent.config import load_config
from spec_agent.controller import run
from spec_agent.errors import AgentError
from spec_agent.preflight import doctor
from spec_agent.verification.audit import audit_run
from spec_agent.spec.expressions import ExpressionValidator,PRECEDENCE

CASES={
 'clamp':('clamp/program.c','clamp/requirements.md','hoare','HOLDS'),
 'buggy':('clamp/buggy.c','clamp/requirements.md','hoare','VIOLATED'),
 'infeasible':('clamp/program.c','clamp/infeasible_requirements.md','hoare','VACUOUS'),
 'array':('array_bug/program.c','array_bug/requirements.md','static','VIOLATED'),
 'sum':('array_sum/program.c','array_sum/requirements.md','hoare','HOLDS')}
# Keep the original sequential acceptance suite unchanged; sum is opt-in.
DEFAULT_CASES=('clamp','buggy','infeasible','array')
DOMAIN='''Acceptance benchmark notation: label the lower-bound postcondition Q1 and the
upper-bound postcondition Q2. Emit exactly Q1 and Q2, with guard set to JSON null for BOTH.
Never copy the precondition into a guard, and never use the string "null" or a false guard.
Q1 and Q2 are unconditional under the common P. Unless requirements explicitly
request a contradictory precondition, require low <= high. Requirements express intended
behavior even when the implementation is buggy. Do not add assumptions to hide the bug.'''
SUM_DOMAIN='''Acceptance benchmark notation: sum_array has no arguments. The fixed
local array contains the integers 0 through 9. Require precondition 1 and exactly
one postcondition Q1: result == 45, with guard set to JSON null. No additional
assumptions or guards are permitted. Requirements express intended behavior even
when the implementation is buggy. Do not replace the expected sum with a value
inferred from faulty code.'''

class _BenchmarkAstValidator(ExpressionValidator):
    """Build an AST with the production formal-expression grammar and checks."""
    def atom(self):
        token=self.take()
        if token=='!': return ('not',self.atom())
        if token=='(':
            value=self.expr(0);self.expect(')');return value
        if token=='old':
            if not self.allow_old: raise AgentError('FORMALIZATION_UNSUPPORTED','old is only supported in postconditions/guards')
            self.expect('(');name=self.take();self.expect(')')
            if name not in self.old_symbols: raise AgentError('UNKNOWN_IDENTIFIER','old requires a scalar parameter')
            self.snapshots.add(name);return ('old',name)
        negative=token=='-'
        if negative: token=self.take()
        if token.isdecimal():
            value=int(token)*(-1 if negative else 1)
            if not -(2**31)<=value<2**31: raise AgentError('FORMALIZATION_UNSUPPORTED','Constant outside int32 range')
            return ('integer',value)
        if negative: raise AgentError('FORMALIZATION_UNSUPPORTED','Unary minus only on integer literals')
        if token not in self.symbols: raise AgentError('UNKNOWN_IDENTIFIER','Unknown formal identifier: '+token)
        return ('symbol',token)
    def expr(self,minimum):
        lhs=self.atom()
        while self.peek() in PRECEDENCE and PRECEDENCE[self.peek()]>=minimum:
            op=self.take();rhs=self.expr(PRECEDENCE[op]+1);lhs=('binary',op,lhs,rhs)
        return lhs

def _canonical_ast(node):
    if node[0]=='not': return ('not',_canonical_ast(node[1]))
    if node[0]!='binary': return node
    _,op,lhs,rhs=node;lhs=_canonical_ast(lhs);rhs=_canonical_ast(rhs)
    if op=='>': return ('binary','<',rhs,lhs)
    if op=='>=': return ('binary','<=',rhs,lhs)
    if op in ('==','!=') and repr(rhs)<repr(lhs): lhs,rhs=rhs,lhs
    return ('binary',op,lhs,rhs)

def canonical(expr,result=False):
    tree,_=_BenchmarkAstValidator(['x','low','high'],allow_result=result).validate(expr)
    return _canonical_ast(tree)

def assess(case,root,r):
    """Fixed benchmark assertions, not a spec quality scoring system."""
    errors=[]
    if r.get('mode')!='REAL': errors.append('NON_REAL_RUN')
    if r.get('status')!='COMPLETED': errors.append('RUN_NOT_COMPLETED')
    if case=='array':
        props=r.get('static_properties',[])
        if not any('bound' in p.get('category','').lower() and p.get('verdict')=='VIOLATED' for p in props):
            errors.append('NO_ATTRIBUTED_BOUNDS_VIOLATION')
    else:
        function='sum_array' if case=='sum' else 'clamp'
        cs=[c for c in r.get('contracts',[]) if c['function']==function]
        if len(cs)!=1: return errors+[function.upper()+'_CONTRACT_MISSING']
        c=cs[0]
        if c['verification']['verdict']!=CASES[case][3]: errors.append('UNEXPECTED_CONTRACT_VERDICT')
        expected_p='INFEASIBLE' if case=='infeasible' else 'FEASIBLE'
        if c['precondition']['status']!=expected_p: errors.append('UNEXPECTED_FEASIBILITY')
        try:
            sem=json.loads(Path(c['provenance']['semantic_spec']).read_text())['function_spec']
            wanted='1' if case=='sum' else ('x > 0 && x < 0' if case=='infeasible' else 'low <= high')
            if canonical(sem['pre_condition']['formal_candidate'])!=canonical(wanted): errors.append('PRECONDITION_BENCHMARK_MISMATCH')
            clauses={q['clause_id']:q for q in sem['post_conditions']}
            expected_exprs=[('Q1','result == 45')] if case=='sum' else [('Q1','result >= low'),('Q2','result <= high')]
            if set(clauses)!={q for q,_ in expected_exprs} or len(clauses)!=len(sem['post_conditions']): errors.append('CLAUSE_IDS_BENCHMARK_MISMATCH')
            for q,expr in expected_exprs:
                if clauses[q]['guard'] is not None or canonical(clauses[q]['formal_candidate'],True)!=canonical(expr,True): errors.append(q+'_BENCHMARK_MISMATCH')
            verdicts={q['property_id'].rsplit('.',1)[-1]:q['verdict'] for q in c['properties']}
            expected={'Q1':'HOLDS'} if case=='sum' else {'Q1':'HOLDS','Q2':'VIOLATED' if case=='buggy' else 'HOLDS'}
            if verdicts!=expected: errors.append('UNEXPECTED_CLAUSE_VERDICTS')
        except Exception as exc: errors.append('BENCHMARK_INSPECTION_FAILED:'+type(exc).__name__)
    return errors

def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--env',default=str(ROOT/'.env'));p.add_argument('--output',default=str(ROOT/'runs/phase1.5-real'))
    p.add_argument('--case',choices=['all',*CASES],default='all',help='all runs the original four cases; sum is a separate opt-in case');args=p.parse_args(argv)
    store=ArtifactStore(args.output)
    summary={'phase':'1.5','mode':'REAL_ONLY','status':'BLOCKED','cases':[], 'evaluation':{'status':'NOT_RUN'}}
    try:
        config=load_config(Path(args.env));caps=doctor(config,store.root/'preflight',probe_tools=True)
        needs_llm=args.case!='array'
        ready=caps['ready'] and caps['semantic_probe']['status']=='PASSED' and (not needs_llm or caps['llm']['configured'])
        summary['preflight']=str(store.root/'preflight/toolchain_manifest.json')
        if not ready:
            summary['blockers']=caps['issues']+(caps['llm']['issues'] if needs_llm else [])
            summary['message']='No acceptance run launched. Configure actual credentials and compatible tools; no fake verdict substituted.'
        else:
            summary['status']='PASSED'
            for name in (DEFAULT_CASES if args.case=='all' else [args.case]):
                source,req,branch,_=CASES[name]
                root,r=run([ROOT/'examples'/source],ROOT/'examples'/req,config,output=store.root/name,
                           branch=branch,entry='main' if name=='array' else None,
                           domain=SUM_DOMAIN if name=='sum' else (DOMAIN if branch=='hoare' else None),
                           require_real=True,require_unguarded_posts=branch=='hoare')
                audit=audit_run(root);write_json_atomic(root/'audit.json',audit)
                errors=assess(name,root,r)
                if audit['status']!='PASSED': errors.append('PROVENANCE_AUDIT_FAILED')
                item={'case':name,'status':'FAILED' if errors else 'PASSED','errors':errors,'result':str(root/'result.json'),'audit':str(root/'audit.json')}
                summary['cases'].append(item)
                if errors:
                    summary['status']='FAILED';summary['message']='Stopped in requested order; inspect evidence, no automatic repair';break
    except Exception as exc:
        summary['status']='FAILED';summary['error']={'code':getattr(exc,'code','VALIDATION_ERROR'),'type':type(exc).__name__}
    write_json_atomic(store.root/'summary.json',summary)
    print(json.dumps(summary,indent=2));print('Summary:',store.root/'summary.json')
    return 0 if summary['status']=='PASSED' else 2
if __name__=='__main__':raise SystemExit(main())
