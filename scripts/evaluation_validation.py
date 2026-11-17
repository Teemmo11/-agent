#!/usr/bin/env python3
"""Phase 2 labeled acceptance: fixture specifications, real logical queries; optional live review."""
import argparse
import copy
import json
import sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from spec_agent.artifacts import ArtifactStore,write_json_atomic
from spec_agent.config import load_config
from spec_agent.analysis.functions import CAnalyzer
from spec_agent.controller import run
from spec_agent.evaluation.controller import evaluate
from spec_agent.evaluation.models import Budget,Limits
from spec_agent.evaluation.audit import audit_evaluation

CASES={
 'identity':dict(pre='1',qs=['result == x'],expected=[],forbidden=['TAUTOLOGICAL_CLAUSE','NO_COMMON_SATISFYING_ASSIGNMENT']),
 'tautology':dict(pre='1',qs=['result == result'],expected=['TAUTOLOGICAL_CLAUSE']),
 'infeasible':dict(pre='x > 0 && x < 0',qs=['result == x'],expected=['PRECONDITION_INFEASIBLE']),
 'inactive-guard':dict(pre='x >= 0',qs=['result == x'],guard='x < 0',expected=['GUARD_UNREACHABLE_UNDER_P']),
 'copied-guard':dict(pre='x >= 0',qs=['result == x'],guard='x >= 0',expected=['GUARD_IMPLIED_BY_P'],forbidden=['GUARD_UNREACHABLE_UNDER_P']),
 'duplicate':dict(pre='1',qs=['result >= x','x <= result'],expected=['DUPLICATE_CLAUSE','CLAUSE_ENTAILED_BY_OTHERS']),
 'contradiction':dict(pre='1',qs=['result == 0','result == 1'],expected=['NO_COMMON_SATISFYING_ASSIGNMENT']),
 'conditional':dict(pre='1',qs=['result == 0','result == 1'],guards=['x <= 0','x > 0'],expected=[],forbidden=['NO_COMMON_SATISFYING_ASSIGNMENT','UNSATISFIABLE_CLAUSE']),
 'old-value':dict(pre='1',qs=['result == old(x)'],expected=[],forbidden=['TAUTOLOGICAL_CLAUSE']),
 'unsigned-domain':dict(pre='1',qs=['result >= 0'],source='unsigned int f(int x) { return 0; }\n',expected=['TAUTOLOGICAL_CLAUSE']),
 'weak-sum':dict(pre='1',qs=['result >= 0'],source='int f(void) { int a[10]={0,1,2,3,4,5,6,7,8,9}; int s=0; for(int i=0;i<10;i++) s+=a[i]; return s; }\n',
                 requirements='REQ-1:\nThe function takes no arguments and must return 45, without preconditions.\n',
                 reference_qs=['result == 45'],expected=['CANDIDATE_DOES_NOT_ENTAIL_REFERENCE']),
 'correct-sum':dict(pre='1',qs=['result == 45'],source='int f(void) { int a[10]={0,1,2,3,4,5,6,7,8,9}; int s=0; for(int i=0;i<10;i++) s+=a[i]; return s; }\n',
                    requirements='REQ-1:\nThe function takes no arguments and must return 45, without preconditions.\n',
                    reference_qs=['result == 45'],expected=[],forbidden=['TAUTOLOGICAL_CLAUSE','CANDIDATE_DOES_NOT_ENTAIL_REFERENCE']),
 'shrunk-domain':dict(pre='x == 0',qs=['result == x'],reference_pre='1',reference_qs=['result == x'],expected=['INPUT_DOMAIN_EXCLUDES_REFERENCE']),
 'bug-correct-spec':dict(pre='1',qs=['result == x'],source='int f(int x) { return 0; }\n',verify=True,expected=[],forbidden=['TAUTOLOGICAL_CLAUSE']),
 'uncited-requirement':dict(pre='1',qs=['result == x'],requirements='REQ-1:\nReturn x.\nREQ-2:\nAlso preserve a separately specified property.\n',expected=['REQUIREMENT_UNREFERENCED'])
}

# Reserved from the initial 15-case design set; these labels test typed-domain
# generalization, not live model accuracy or global solver reliability.
HELDOUT={
 'bool-domain':dict(pre='1',qs=['result == 0 || result == 1'],source='_Bool f(_Bool x) { return x; }\n',expected=['TAUTOLOGICAL_CLAUSE']),
 'long-old-value':dict(pre='1',qs=['result == old(x)'],source='long f(long x) { return x; }\n',expected=[],forbidden=['TAUTOLOGICAL_CLAUSE','NO_COMMON_SATISFYING_ASSIGNMENT']),
 'signed-char-domain':dict(pre='1',qs=['result >= -128 && result <= 127'],source='signed char f(signed char x) { return x; }\n',expected=['TAUTOLOGICAL_CLAUSE'])
}


def create_case(store,name,case,config):
    directory=store.root/'cases'/name;directory.mkdir(parents=True)
    source=directory/'program.c';source.write_text(case.get('source','int f(int x) { return x; }\n'),encoding='utf-8')
    req=directory/'requirements.md';req.write_text(case.get('requirements','REQ-1:\nFor every input x, return x.\n'),encoding='utf-8')
    function=CAnalyzer().analyze([source]).functions[0]
    fs={'function':{'name':function.name,'signature':function.signature},'expected_behavior':'Behavior required by REQ-1.',
        'pre_condition':{'natural_language':'Declared input domain.','formal_candidate':case['pre']},
        'post_conditions':[{'clause_id':'Q'+str(i+1),'natural_language':'Required output.','formal_candidate':q,
                            'guard':case.get('guards',[case.get('guard')]*len(case['qs']))[i],
                            'requirement_refs':case.get('clause_requirement_refs',['REQ-1']),'evidence_refs':[]} for i,q in enumerate(case['qs'])],
        'requirement_refs':['REQ-1'],'conflicts':[],'ambiguities':[]}
    fixture=directory/'generation_fixture.json';write_json_atomic(fixture,{'f':{'function_spec':fs,'callee_expectations':[]}})
    parent,result=run([source],req,config,output=directory/'parent',branch='hoare',fixture=fixture,generate_only=not case.get('verify',False))
    reference=None
    if 'reference_qs' in case:
        reference=directory/'reference.json';ref=copy.deepcopy(fs)
        ref['pre_condition']['formal_candidate']=case.get('reference_pre','1')
        ref['post_conditions']=[{**fs['post_conditions'][0],'clause_id':'Q'+str(i+1),'formal_candidate':q,'guard':None} for i,q in enumerate(case['reference_qs'])]
        write_json_atomic(reference,{'function_spec':ref,'callee_expectations':[]})
    return parent,result,reference


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--env',default=str(ROOT/'.env'));parser.add_argument('--output',default=str(ROOT/'runs/evaluation-validation'))
    parser.add_argument('--case',choices=['all',*CASES,*HELDOUT],default='all')
    parser.add_argument('--suite',choices=['design','heldout','all'],default='design')
    parser.add_argument('--reviewer',choices=['none','real'],default='none')
    parser.add_argument('--max-llm-calls',type=int,default=32)
    args=parser.parse_args(argv);store=ArtifactStore(args.output);config=load_config(Path(args.env))
    budget=Budget(Limits(llm_calls=args.max_llm_calls))
    report={'status':'FAILED','scope':'LABELED_FIXTURE_SPECS_REAL_LOGIC; not live generation acceptance',
            'semantic_reviewer':args.reviewer,'dataset_split':args.suite,'cases':[]}
    selected=CASES if args.suite=='design' else HELDOUT if args.suite=='heldout' else {**CASES,**HELDOUT}
    for name in selected if args.case=='all' else [args.case]:
        case={**CASES,**HELDOUT}[name]
        try:
            parent,phase1,reference=create_case(store,name,case,config)
            directory,value=evaluate(parent,config,output=store.root/'evaluations'/name,logic='tools',
                reviewer=args.reviewer,budget=budget,limits=budget.limits,reference_spec=reference)
            audit=audit_evaluation(directory)
            codes={f['code'] for f in value['findings'] if f['evidence_kind']!='LLM_JUDGMENT'}
            passed=value['execution_status']=='COMPLETED' and audit['status']=='PASSED'
            passed &= set(case['expected'])<=codes and not set(case.get('forbidden',[]))&codes
            if case.get('verify'):passed &= phase1['contracts'][0]['verification']['verdict']=='VIOLATED'
            item={'case':name,'status':'PASSED' if passed else 'FAILED','codes':sorted(codes),
                  'expected':case['expected'],'evaluation':str(directory/'evaluation.json'),'audit':audit['status']}
        except Exception as exc:item={'case':name,'status':'FAILED','error':{'code':getattr(exc,'code',type(exc).__name__),'message':str(exc)}}
        report['cases'].append(item);print(json.dumps(item,ensure_ascii=False),flush=True)
    report['status']='PASSED' if report['cases'] and all(c['status']=='PASSED' for c in report['cases']) else 'FAILED'
    report['budget']=budget.snapshot();write_json_atomic(store.root/'summary.json',report)
    print('Summary:',store.root/'summary.json')
    return 0 if report['status']=='PASSED' else 2


if __name__=='__main__':raise SystemExit(main())
