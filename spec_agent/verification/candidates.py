"""Verify given semantic candidates with their actual generation provenance."""
import copy
import json
from pathlib import Path
from ..artifacts import ArtifactStore,sha256_file,write_json_atomic
from ..analysis.functions import CAnalyzer
from ..llm.parser import parse_response
from ..spec.formalizer import formalize
from ..preflight import doctor
from ..errors import AgentError
from ..trace import RunTrace
from .contracts import verify_contract


def verify_given_candidates(parent,candidates,config,*,output,generation,proposal_dir,budget,verification=True,target_spec_id=None):
    # Reserve all first-stage P/Q jobs before creating a trial run.
    needed={s['function_id']:1+len(s['function_spec']['post_conditions']) for s in candidates}
    if verification and (budget.query_count+sum(needed.values())>budget.limits.queries or any(
        budget.by_function.get(fid,{}).get('queries',0)+n>budget.limits.queries_per_function for fid,n in needed.items())):
        raise AgentError('REFINEMENT_BUDGET_EXHAUSTED','Insufficient remaining P/Q verification budget')
    if verification:
        for fid,n in needed.items():
            for _ in range(n):budget.reserve('query',fid)
    store=ArtifactStore(output);root=store.root;trace=RunTrace(root,store.run_id,secrets=(config.api_key,))
    result={'run_id':store.run_id,'phase':'1.REVERIFICATION','contracts':[],'static_properties':[],
            'failures':[],'evaluation':{'status':'NOT_RUN'},'mode':'MOCK_ALL' if config.tool_mode=='MOCK' else
            'REAL' if all(s.get('generation',{}).get('mode')=='REAL' for s in candidates) else 'FIXTURE_LLM_REAL_TOOLS'}
    trace.emit('run.started',origin='GIVEN_SEMANTIC_CANDIDATES',generation_mode=generation)
    try:
        for row in parent.info['sources']:parent.check(parent.path(row['snapshot']),row['sha256'])
        sources,req,info=store.snapshot(parent.source_paths,parent.root/'input/requirements.md');result['input']=info
        if [sha256_file(s) for s in sources]!=[r['sha256'] for r in parent.info['sources']]:
            raise AgentError('SOURCE_CHANGED','Candidate trial may not change source bytes')
        for ref in ('input/domain_knowledge.json','input/generation_constraints.json'):
            if parent.path(ref).exists():store.write(ref,parent.read(ref))
        lineage={'parent_run_id':parent.manifest['run_id'],'parent_run_ref':str(parent.root),
                 'generation_mode':generation,'proposal_sha256':sha256_file(proposal_dir/'response.txt'),
                 'candidate_source':'VALIDATED_REFINEMENT_PROPOSAL','source_program_changed':False,
                 'parent_semantic_hashes':{p:h for p,h in parent.dependencies.items() if p.startswith('specs/semantic/')}}
        store.write('input/candidate_lineage.json',lineage)
        caps=doctor(config,root/'preflight',trace=trace);store.write('toolchain_manifest.json',caps)
        if not caps['ready']:raise AgentError('REAL_PREFLIGHT_BLOCKED','Candidate reverification toolchain is not ready')
        program=CAnalyzer().analyze(sources);byid={f.function_id:f for f in program.functions}
        for fid,f in byid.items():f.caller_expectations=copy.deepcopy(parent.functions[fid].caller_expectations)
        store.write('analysis/functions.json',program.functions);store.write('analysis/functions_with_expectations.json',program.functions)
        store.write('analysis/callsites.json',program.callsites);store.write('analysis/callgraph.json',{'order':program.order,'edges':[(s['caller_function'],s['callee_function']) for s in program.callsites]})
        store.write('analysis/unresolved.json',program.unresolved);store.write('input/requirements.json',parent.requirements)
        expected={str(s):sha256_file(s) for s in sources};expected[str(req)]=info['requirements_sha256']
        expected[str(root/'input/candidate_lineage.json')]=sha256_file(root/'input/candidate_lineage.json')
        if (root/'input/generation_constraints.json').exists():expected[str(root/'input/generation_constraints.json')]=sha256_file(root/'input/generation_constraints.json')
        for original in candidates:
            spec=copy.deepcopy(original);function=byid[spec['function_id']];sid=spec['spec_id']
            for key in ('source_sha256','requirements_sha256'):spec[key]=info[key]
            parse_response(json.dumps({'function_spec':spec['function_spec'],'callee_expectations':spec['callee_expectations']}),function,parent.requirements,program,
                           require_unguarded_posts=bool(parent.constraints and parent.constraints.get('postcondition_guard')=='NULL_ONLY'))
            directory=root/'generation/llm/functions'/function.function_id;directory.mkdir(parents=True)
            # Keep the exact proposal as well as its extracted normalized semantic candidate.
            origin=proposal_dir if target_spec_id is None or sid==target_spec_id else parent.root/'generation/llm/functions'/function.function_id
            prompt=origin/'prompt.json'
            if prompt.exists():(directory/'prompt.json').write_bytes(prompt.read_bytes())
            else:store.write(str(directory.relative_to(root)/'prompt.json'),{'origin':'CARRIED_PARENT_SPECIFICATION','parent_run_id':parent.manifest['run_id']})
            (directory/'proposal.response.txt').write_bytes((proposal_dir/'response.txt').read_bytes())
            for filename in ('response.metadata.json','response.raw.json'):
                if (origin/filename).exists():(directory/filename).write_bytes((origin/filename).read_bytes())
            normalized={'function_spec':spec['function_spec'],'callee_expectations':spec['callee_expectations']}
            (directory/'response.txt').write_text(json.dumps(normalized,ensure_ascii=False),encoding='utf-8')
            spec.setdefault('generation',{})['prompt_sha256']=sha256_file(directory/'prompt.json')
            spec['generation']['lineage']=lineage;spec['generation']['response_normalization']='EXTRACTED_OR_CARRIED_VALIDATED_SPECIFICATION'
            spec['generation']['candidate_origin']='REFINEMENT_PROPOSAL' if target_spec_id is None or sid==target_spec_id else 'UNCHANGED_PARENT_SPECIFICATION'
            store.write('specs/semantic/'+sid+'.json',spec);store.write(str(directory.relative_to(root)/'spec.json'),spec)
            row={'spec_id':sid,'function':function.name,'properties':[],'precondition':{'status':'NOT_RUN'},
                 'verification':{'verdict':'NOT_RUN'},'conclusion_gate':{'allowed':False,'reason':'NOT_RUN'},'evaluation':{'status':'NOT_RUN'}}
            result['contracts'].append(row)
            try:
                contract=formalize(spec,function,info);store.write('specs/formal/'+sid+'.json',contract)
                if verification:verify_contract(contract,row,function,sources,info,expected,caps,config,store,trace)
            except AgentError as exc:
                row['precondition']['status']='ERROR';row['verification']={'verdict':'ERROR','error':exc.as_dict()}
        result['status']='COMPLETED_WITH_ERRORS' if any(c['verification']['verdict']=='ERROR' for c in result['contracts']) else 'COMPLETED'
        result['generation']={'branch':'hoare','origin':'GIVEN_CANDIDATES','llm_specs':len(candidates),'cbmc_static_specs':0}
        result['verification_scope']={'contract_semantics':'PARTIAL_CORRECTNESS; initial globals; tool bitvector C model',
            'termination_proved':False,'static_safety_separate':True,'quality_evaluated':False,
            'source_program_changed':False,'parent_run_id':parent.manifest['run_id']}
        if caps.get('cbmc_profile')=='c2btor-source-assertions':
            result['verification_scope'].update(converter_contract='SOURCE_ASSERTIONS_ONLY',property_slicing=False,
                memory_safety_from_hoare=False,malloc_failure_mode='ASSUMED_SUCCESS',undefined_behavior='TOTALIZED_BY_CONVERTER; not a standard-C safety proof',static_discovery='NOT_RUN_HOARE_ONLY')
            if caps.get('converter_policy'):result['verification_scope']['converter_policy']=caps['converter_policy']
    except (AgentError,OSError,KeyError,ValueError) as exc:
        result['status']='FAILED';result['failures'].append(exc.as_dict() if isinstance(exc,AgentError) else {'code':'CANDIDATE_VERIFICATION_FAILED','message':str(exc)})
    trace.emit('run.finished',status=result['status'],origin='GIVEN_SEMANTIC_CANDIDATES');result['logging']=trace.status()
    store.write('result.json',result)
    return root,result
