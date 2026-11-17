#!/usr/bin/env python3
"""Controlled candidate fixtures with REAL tools; no online LLM or input binaries."""
import argparse
import copy
import json
import sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'scripts'))
from spec_agent.artifacts import ArtifactStore,write_json_atomic
from spec_agent.config import load_config
from spec_agent.evaluation.controller import evaluate
from spec_agent.evaluation.loader import ParentRun
from spec_agent.evaluation.models import Limits
from spec_agent.refinement.controller import refine
from spec_agent.refinement.audit import audit_refinement
from evaluation_validation import create_case,CASES


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--env',default=str(ROOT/'.env'));parser.add_argument('--output',default=str(ROOT/'runs/refinement-validation'))
    parser.add_argument('--case',choices=['all','improve','expose-bug','weakening','budget'],default='all')
    args=parser.parse_args(argv);config=load_config(Path(args.env));store=ArtifactStore(args.output)
    report={'status':'FAILED','scope':'FIXTURE_REFINEMENT_REAL_TOOLS; live LLM NOT_RUN','cases':[]}
    for name in ('improve','expose-bug','weakening','budget') if args.case=='all' else [args.case]:
        try:
            case=copy.deepcopy(CASES['weak-sum'])
            if name=='expose-bug':case['source']='int f(void) { return 0; }\n'
            if name=='weakening':
                # Missing provenance is a MEDIUM repair target. The proposal repairs
                # that reference but weakens the obligation, which must be blocked.
                case=copy.deepcopy(CASES['identity']);case['clause_requirement_refs']=[]
            parent,_,reference=create_case(store,name,case,config)
            baseline,value=evaluate(parent,config,output=store.root/'baseline'/name,logic='tools',reference_spec=reference)
            p=ParentRun(parent);original=p.specs[0];candidate={'function_spec':copy.deepcopy(original['function_spec']),'callee_expectations':[]}
            if name=='weakening':candidate['function_spec']['post_conditions']=[{**candidate['function_spec']['post_conditions'][0],
                                                                               'formal_candidate':'result >= x','requirement_refs':['REQ-1']}]
            else:candidate['function_spec']['post_conditions'][0]['formal_candidate']='result == 45'
            proposal={'candidate':candidate,'needs_clarification':False,
                      'changes':[{'clause_id':q['clause_id'],'explanation':'Labeled requirement-grounded test candidate.','evidence_ids':['$REQ:0']}
                                 for q in candidate['function_spec']['post_conditions']]}
            fixture=store.root/'fixtures'/(name+'.json');write_json_atomic(fixture,{'f':[proposal]})
            root,result=refine(baseline,config,output=store.root/'refinements'/name,proposer='fixture',candidate_fixture=fixture,
                               limits=Limits(llm_calls=0) if name=='budget' else None)
            audit=audit_refinement(root)
            expected='ACCEPTED' if name in ('improve','expose-bug') else 'NEEDS_REVIEW' if name=='weakening' else 'INCONCLUSIVE'
            passed=result['decision']==expected and audit['status']=='PASSED'
            if name=='expose-bug':passed &= result['selected_candidate'] is not None and result['selected_candidate']['verification_verdict']=='VIOLATED'
            if name=='weakening':passed &= result['stop_reason']=='EXISTING_OBLIGATION_WEAKENED' and not result['iterations'][0]['trial_run']
            if name=='budget':passed &= result['stop_reason']=='REFINEMENT_BUDGET_EXHAUSTED' and result['budget']['llm_calls']==0
            item={'case':name,'status':'PASSED' if passed else 'FAILED','decision':result['decision'],
                  'stop_reason':result['stop_reason'],'audit':audit['status'],'refinement':str(root/'refinement.json'),
                  'errors':result['errors']}
        except Exception as exc:item={'case':name,'status':'FAILED','error':{'code':getattr(exc,'code',type(exc).__name__),'message':str(exc)}}
        report['cases'].append(item);print(json.dumps(item,ensure_ascii=False),flush=True)
    report['status']='PASSED' if report['cases'] and all(r['status']=='PASSED' for r in report['cases']) else 'FAILED'
    write_json_atomic(store.root/'summary.json',report);print('Summary:',store.root/'summary.json')
    return 0 if report['status']=='PASSED' else 2


if __name__=='__main__':raise SystemExit(main())
