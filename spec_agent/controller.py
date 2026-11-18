from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from pathlib import Path
from .artifacts import ArtifactStore,sha256_file,write_json_atomic
from .state_machine import StateMachine
from .analysis.functions import CAnalyzer
from .requirements.parser import parse_requirements
from .llm.client import OpenAIClient,FixtureClient
from .generators import llm_hoare,cbmc_static
from .spec.formalizer import formalize
from .spec.harness import emit_harness
from .verification.verifier import verify
from .verification.contracts import verify_contract
from .verification.conclusion import aggregate,precondition_status
from .preflight import doctor
from .models import VerificationJob
from .errors import AgentError
from .trace import RunTrace


def run(sources,requirements,config,*,output='runs',generate_only=False,fixture=None,branch='both',entry=None,domain=None,require_real=False,log_max_bytes=32*1024*1024,require_unguarded_posts=False,on_run_created=None,frozen_parent=None,verification_budget=None,generation_agent=None):
    store=ArtifactStore(output)
    trace=RunTrace(store.root,store.run_id,secrets=(config.api_key,),max_bytes=log_max_bytes)
    store.trace=trace
    trace.emit('run.started',branch=branch,generate_only=generate_only,tool_mode=config.tool_mode,llm_mode='NOT_RUN' if branch=='static' else 'CARRIED_SPECIFICATIONS' if frozen_parent else 'FIXTURE_LLM' if fixture else 'REAL',model=config.model,
               generation_strategy='PHASE1_AGENT' if generation_agent else 'PIPELINE')
    if on_run_created:
        try:on_run_created(store.root)
        except Exception as exc:trace.emit('monitor.attach.failed',level='WARNING',error_type=type(exc).__name__)
    fsm=StateMachine(store)
    result={'run_id':store.run_id,'mode':'MOCK_ALL' if config.tool_mode=='MOCK' else 'FIXTURE_LLM_REAL_TOOLS' if fixture else 'REAL','contracts':[],
            'static_properties':[],'failures':[],'evaluation':{'status':'NOT_RUN'},'phase':'1.1' if generate_only else '1.1+1.2'}
    try:
        if frozen_parent:
            if fixture or generate_only:
                raise AgentError('CONFIG_INVALID','Frozen specifications require an independent verification run')
            result['mode']=frozen_parent.report['mode']
            if require_real and result['mode']!='REAL':
                raise AgentError('MOCK_IN_REAL_RUN','Real-only mode requires a real parent')
        if branch not in ('both','hoare','static'):
            raise AgentError('CONFIG_INVALID','Unknown generation branch')
        if type(require_unguarded_posts) is not bool:
            raise AgentError('CONFIG_INVALID','require_unguarded_posts must be Boolean')
        if require_unguarded_posts and branch=='static':
            raise AgentError('CONFIG_INVALID','Postcondition guard constraints apply only to Hoare generation')
        if config.tool_mode not in ('REAL','MOCK'):
            raise AgentError('CONFIG_INVALID','Unknown evidence mode')
        if require_real and (fixture or config.tool_mode!='REAL'):
            raise AgentError('MOCK_IN_REAL_RUN','Real-only mode rejects fixtures and mock tools')
        sources,req,info=store.snapshot(sources,requirements); result['input']=info
        if frozen_parent:
            if info['requirements_sha256']!=frozen_parent.info['requirements_sha256']:
                raise AgentError('REPAIR_SCOPE_CHANGED','Requirements must stay frozen during source repair')
            lineage={'parent_run':str(frozen_parent.root),'parent_dependencies':frozen_parent.dependencies,
                     'source_program_changed':[row['sha256'] for row in info['sources']]!=[row['sha256'] for row in frozen_parent.info['sources']],
                     'specifications':'FROZEN_PARENT_SPECIFICATIONS'}
            store.write('input/repair_lineage.json',lineage)
        trace.emit('input.snapshotted',input=info,domain_knowledge_provided=domain is not None)
        expected_hashes={r['snapshot']:r['sha256'] for r in info['sources']}
        expected_hashes[str(req)]=info['requirements_sha256']
        if frozen_parent:
            expected_hashes[str(store.root/'input/repair_lineage.json')]=sha256_file(store.root/'input/repair_lineage.json')
        if domain is not None:
            store.write('input/domain_knowledge.json',{'text':domain})
        if require_unguarded_posts:
            constraints={'postcondition_guard':'NULL_ONLY'}
            store.write('input/generation_constraints.json',constraints)
            expected_hashes[str(store.root/'input/generation_constraints.json')]=sha256_file(store.root/'input/generation_constraints.json')
            trace.emit('generation.constraints',branch='hoare',constraints=constraints,artifact='input/generation_constraints.json')
        fsm.transition('INPUT_SNAPSHOTTED'); fsm.transition('PREFLIGHT')
        caps=doctor(config,store.root/'preflight',trace=trace.bind(branch='preflight')); store.write('toolchain_manifest.json',caps)
        result['preflight']={'ready':caps['ready'],'llm':caps['llm'],'missing_capabilities':caps['missing_capabilities']}
        trace.emit('preflight.finished',**result['preflight'],artifact='toolchain_manifest.json')
        if config.tool_mode=='REAL' and caps.get('mock_detected'):
            raise AgentError('MOCK_IN_REAL_RUN','Detected mock executable on PATH')
        if require_real and (not caps['ready'] or (branch!='static' and not frozen_parent and config.llm_issues())):
            raise AgentError('REAL_PREFLIGHT_BLOCKED','Missing real tool capabilities or LLM configuration; run doctor')
        fsm.transition('ANALYZING')
        program=CAnalyzer().analyze(sources); requirements_data=parse_requirements(req.read_text())
        store.write('input/requirements.json',requirements_data)
        store.write('analysis/functions.json',program.functions); store.write('analysis/callsites.json',program.callsites)
        store.write('analysis/unresolved.json',program.unresolved)
        store.write('analysis/callgraph.json',{'order':program.order,'edges':[(s['caller_function'],s['callee_function']) for s in program.callsites]})
        result['analysis_issues']=program.unresolved
        trace.emit('analysis.partitioned',strategy='DETERMINISTIC_C_AST_FUNCTIONS',order=program.order,
                   functions=[{'function_id':f.function_id,'name':f.name,'source_file':f.source_file,
                               'start_line':f.start_line,'end_line':f.end_line,'source_sha256':f.source_sha256,
                               'harness_issues':f.harness_issues} for f in program.functions],
                   callsites=program.callsites,issues=program.unresolved,requirements=requirements_data,
                   artifact='analysis/functions.json')
        for function in program.functions:
            trace.emit('analysis.function',function_id=function.function_id,function=function.name,
                       signature=function.signature,source_file=function.source_file,
                       start_line=function.start_line,end_line=function.end_line,
                       callers=function.callers,callees=function.callees,harness_issues=function.harness_issues,
                       artifact='analysis/functions.json')
        for issue in program.unresolved:
            trace.emit('analysis.issue',level='WARNING',**issue)
        if not program.functions and branch!='static':
            result['failures'].append({'code':'ANALYSIS_UNSUPPORTED','message':'No analyzable function definitions'})
        selected_entry=entry or ('main' if any(f.name=='main' for f in program.functions) else program.functions[0].name if program.functions else 'main')
        # Static branch uses snapshots even when semantic analysis cannot parse the C subset.
        fsm.transition('GENERATING')
        client=(FixtureClient(fixture) if fixture else OpenAIClient(config)) if branch!='static' and not frozen_parent else None
        llm={'specs':[],'failures':[]}; static={'candidates':[],'failures':[]}
        with ThreadPoolExecutor(max_workers=2) as pool:
            tasks={}
            if branch in ('both','hoare'):
                if frozen_parent:
                    from .phase2.retained import carry
                    tasks['llm']=pool.submit(carry,frozen_parent,program,requirements_data,info,store.root/'generation/llm',trace.bind(branch='hoare'))
                else:
                    tasks['llm']=pool.submit(llm_hoare.generate,program,requirements_data,info,client,store.root/'generation/llm',domain,trace.bind(branch='hoare'),require_unguarded_posts=require_unguarded_posts,agent=generation_agent)
            if branch in ('both','static'):
                tasks['static']=pool.submit(cbmc_static.generate,sources,selected_entry,info,caps,config,store.root/'generation/cbmc',trace.bind(branch='static'))
            for name,future in tasks.items():
                try:
                    if name=='llm': llm=future.result()
                    else: static=future.result()
                except Exception as exc:
                    failure={'branch':name,'code':'GENERATION_FAILED','message':type(exc).__name__}
                    result['failures'].append(failure)
                    trace.emit('generation.branch_failed',level='ERROR',**failure)
        result['failures']+=llm['failures']+static['failures']
        trace.emit('generation.finished',llm_specs=len(llm['specs']),static_candidates=static['candidates'],failures=result['failures'])
        result['generation']={'llm_specs':len(llm['specs']),'cbmc_static_specs':len(static['candidates']),
                              'branch':branch,'parallel':branch=='both','static_entry':selected_entry}
        if branch!='static':
            referenced={ref for spec in llm['specs'] for clause in spec['function_spec']['post_conditions'] for ref in clause['requirement_refs']}
            unreferenced=sorted(set(requirements_data['ids'])-referenced)
            trace.emit('requirements.references',level='WARNING' if unreferenced else 'INFO',
                       referenced_by_postconditions=sorted(referenced),unreferenced=unreferenced,
                       scope='Reference inventory only; not semantic coverage or specification quality')
        store.write('analysis/functions_with_expectations.json',program.functions)
        fsm.transition('NORMALIZING')
        for candidate in static['candidates']:
            store.write('specs/static/'+candidate['spec_id']+'.json',candidate)
        for spec in llm['specs']: store.write('specs/semantic/'+spec['spec_id']+'.json',spec)
        fsm.transition('FORMALIZING'); prepared=[]; byid={f.function_id:f for f in program.functions}
        for spec in llm['specs']:
            row={'spec_id':spec['spec_id'],'function':byid[spec['function_id']].name,'properties':[],
                 'precondition':{'status':'NOT_RUN'},'verification':{'verdict':'NOT_RUN'},'conclusion_gate':{'allowed':False,'reason':'NOT_RUN'},'evaluation':{'status':'NOT_RUN'}}
            result['contracts'].append(row)
            if generate_only:
                trace.emit('formalization.skipped',branch='hoare',function_id=spec['function_id'],spec_id=spec['spec_id'],reason='GENERATE_ONLY')
                continue
            try:
                trace.emit('formalization.started',branch='hoare',function_id=spec['function_id'],spec_id=spec['spec_id'])
                contract=formalize(spec,byid[spec['function_id']],info,trace=trace.bind(branch='hoare',function_id=spec['function_id'],spec_id=spec['spec_id']))
                store.write('specs/formal/'+spec['spec_id']+'.json',contract)
                prepared.append((contract,row,byid[spec['function_id']]))
                trace.emit('formalization.accepted',branch='hoare',function_id=spec['function_id'],spec_id=spec['spec_id'],contract=contract)
            except AgentError as exc:
                trace.emit('formalization.rejected',level='ERROR',function_id=spec['function_id'],spec_id=spec['spec_id'],error=exc.as_dict())
                row['precondition']['status']='ERROR'; row['verification']={'verdict':'ERROR','error':exc.as_dict()}; row['conclusion_gate']={'allowed':False,'reason':exc.code}
        fsm.transition('VERIFYING')
        if not generate_only:
            if verification_budget:
                needed=[(contract.function_id,1+len(contract.ensures)) for contract,_,_ in prepared]
                needed.extend(('static',1) for _ in static['candidates'])
                for fid,count in needed:
                    for _ in range(count):
                        if not verification_budget.reserve('query',fid):
                            raise AgentError('REPAIR_BUDGET_EXHAUSTED','P/Q and static verification budget exhausted')
            for contract,row,func in prepared:
                verify_contract(contract,row,func,sources,info,expected_hashes,caps,config,store,trace)
            for candidate in static['candidates']:
                semantic=store.root/'specs/static'/(candidate['spec_id']+'.json')
                discovery=store.root/'generation/cbmc/discovery.execution.json'
                import json
                discovery_record=json.loads(discovery.read_text())
                bound={str(p):sha256_file(p) for p in [semantic,discovery,Path(discovery_record['stdout_path']),Path(discovery_record['stderr_path']),store.root/'toolchain_manifest.json']}
                for path,checksum in candidate.get('discovery_artifacts',{}).items():
                    if sha256_file(Path(path))!=checksum:
                        raise AgentError('ARTIFACT_INTEGRITY_FAILED','Static discovery conversion evidence changed')
                    bound[path]=checksum
                job=VerificationJob(candidate['spec_id'],'CBMC_STATIC_PROPERTY',list(map(str,sources)),selected_entry,
                    candidate['spec_id'],candidate['cbmc_property_id'],cbmc_property_id=candidate['cbmc_property_id'],
                    generation_flags=candidate['generation_flags'],source_hashes={**expected_hashes,**bound},
                    provenance={'source_sha256':info['source_sha256'],'requirements_sha256':info['requirements_sha256'],
                      'semantic_spec':str(semantic),'semantic_spec_sha256':sha256_file(semantic),'static_discovery':str(discovery),
                      'harness':'NOT_APPLICABLE_STATIC_SOURCE_ENTRY'})
                if caps.get('cbmc_profile')=='c2btor-source-assertions':
                    job.provenance.update(static_source_location=candidate['source_location'],static_property_class=candidate['category'])
                d=store.root/'verification'/job.job_id; write_json_atomic(d/'job.json',job)
                result['static_properties'].append({**candidate,**verify(job,caps,config,d,trace=trace.bind(branch='static'))})
        else: result['static_properties']=static['candidates']
        fsm.transition('SUMMARIZING')
        errors=bool(result['failures']) or any(r['verification']['verdict']=='ERROR' for r in result['contracts']) or any(r.get('verdict')=='ERROR' for r in result['static_properties'])
        result['status']='COMPLETED_WITH_ERRORS' if errors else 'COMPLETED'
        result['verification_scope']={'contract_semantics':'PARTIAL_CORRECTNESS; initial globals; tool bitvector C model',
          'termination_proved':False,'static_safety_separate':True,'quality_evaluated':False}
        if caps.get('cbmc_profile')=='c2btor-source-assertions':
            result['verification_scope'].update(converter_contract='SOURCE_ASSERTIONS_ONLY',property_slicing=False,
                memory_safety_from_hoare=False,malloc_failure_mode='ASSUMED_SUCCESS',
                undefined_behavior='TOTALIZED_BY_CONVERTER; not a standard-C safety proof',
                static_discovery='CONVERSION_SOURCE_MAP')
            if caps.get('converter_policy'):result['verification_scope']['converter_policy']=caps['converter_policy']
        store.write('result.json',result); fsm.transition('FINISHED')
        trace.emit('run.finished',status=result['status'],contract_count=len(result['contracts']),static_count=len(result['static_properties']),failure_count=len(result['failures']),result_file='result.json')
    except (Exception,KeyboardInterrupt) as exc:
        failed_stage=fsm.state
        result['status']='CANCELLED' if isinstance(exc,KeyboardInterrupt) else 'FAILED'; result['failures'].append(exc.as_dict() if isinstance(exc,AgentError) else {'code':'RUN_FAILED','message':type(exc).__name__+': '+str(exc)})
        if fsm.state not in ('FINISHED','FAILED'): fsm.transition('FAILED')
        store.write('result.json',result)
        trace.emit('run.cancelled' if isinstance(exc,KeyboardInterrupt) else 'run.failed',level='ERROR',failed_stage=failed_stage,failures=result['failures'])
    result['logging']=trace.status()
    if generation_agent:
        result['phase1_agent']={'max_attempts_per_function':generation_agent.max_attempts,
                                'budget':generation_agent.budget.snapshot()}
    store.write('result.json',result)
    return store.root,result
