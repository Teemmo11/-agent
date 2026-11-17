"""Explicit generate-only fixture artifacts. No fabricated verification results."""
import json
from pathlib import Path
from spec_agent.artifacts import ArtifactStore,write_json_atomic
from spec_agent.analysis.functions import CAnalyzer


def make_parent(directory,*,pre='1',clauses=None,source=None,requirements=None,guard=None):
    directory=Path(directory);directory.mkdir(parents=True,exist_ok=True)
    code=directory/'program.c';req=directory/'requirements.md'
    code.write_text(source or 'int f(int x) { return x; }\n',encoding='utf-8')
    req.write_text(requirements or 'REQ-1:\nReturn the input x.\n',encoding='utf-8')
    store=ArtifactStore(directory/'parent');sources,_,info=store.snapshot([code],req)
    program=CAnalyzer().analyze(sources);f=program.functions[0];sid='HS-'+f.function_id
    fs={'function':{'name':f.name,'signature':f.signature},'expected_behavior':'Return the required value.',
        'pre_condition':{'natural_language':'Allowed inputs.','formal_candidate':pre},
        'post_conditions':[{'clause_id':'Q'+str(i+1),'natural_language':'Expected output.',
                            'formal_candidate':expr,'guard':guard,'requirement_refs':['REQ-1'],'evidence_refs':[]}
                           for i,expr in enumerate(clauses or ['result == x'])],
        'requirement_refs':['REQ-1'],'conflicts':[],'ambiguities':[]}
    semantic={'function_spec':fs,'callee_expectations':[]}
    spec={**semantic,'spec_id':sid,'function_id':f.function_id,**{k:info[k] for k in ('source_sha256','requirements_sha256')},
          'generation':{'mode':'FIXTURE_LLM','caller_expectations_partial':False},'caller_expectation_refs':[]}
    store.write('specs/semantic/'+sid+'.json',spec)
    output=store.root/'generation/llm/functions'/f.function_id/'response.txt';output.parent.mkdir(parents=True)
    output.write_text(json.dumps(semantic),encoding='utf-8')
    store.write('result.json',{'run_id':store.run_id,'mode':'FIXTURE_LLM_REAL_TOOLS','status':'COMPLETED',
                'input':info,'contracts':[{'spec_id':sid,'function':f.name,'precondition':{'status':'NOT_RUN'},
                  'properties':[],'verification':{'verdict':'NOT_RUN'},'evaluation':{'status':'NOT_RUN'}}],
                'static_properties':[],'failures':[],'evaluation':{'status':'NOT_RUN'},
                'generation':{'branch':'hoare'},'verification_scope':{'termination_proved':False}})
    return store.root,spec


def review_response(parent):
    from spec_agent.evaluation.loader import ParentRun
    from spec_agent.evaluation.requirements import index_requirements
    from spec_agent.evaluation.context import ContextBuilder
    from spec_agent.evaluation.models import Limits,DIMENSIONS
    p=ParentRun(parent);builder=ContextBuilder(p,index_requirements(p.requirements_text,p.info['requirements_sha256']),Limits())
    context=builder.build(p.specs[0]);eid=context['evidence_ids'][0]
    value={'spec_id':context['spec_id'],'needs_clarification':False,
           'dimensions':[{'dimension':d,'status':'NO_ISSUE_FOUND','explanation':'Fixture judgment, not proof.','evidence_ids':[eid]} for d in DIMENSIONS],
           'findings':[],'coverage':[{'requirement_item_id':r['item_id'],'clause_ids':['Q1'],
                                    'coverage_status':'SUPPORTED','explanation':'Fixture judgment.','evidence_ids':[r['evidence_id'],eid]}
                                   for r in context['requirements']],'requirement_interpretations':[]}
    return value,context,builder
