"""Phase 2A: fixed stages over an immutable Phase 1 run."""
import json
from pathlib import Path
from ..artifacts import ArtifactStore,write_json_atomic,sha256_file
from ..errors import AgentError
from ..trace import RunTrace
from ..llm.client import OpenAIClient
from ..preflight import doctor
from .models import Limits,Budget,VERSION,finding
from .loader import ParentRun
from .requirements import index_requirements
from .context import ContextBuilder
from .deterministic import check as deterministic_check
from .coverage import inventory,apply_reviews
from .semantic import ReviewFixtureClient,review,review_findings
from .logic import LogicEngine,assess_reference
from .aggregate import dimensions
from .schema import check as check_schema
from .report import markdown


def evaluate(parent_root,config,*,output='evaluations',reviewer='none',logic='off',review_fixture=None,
             require_real=False,limits=None,budget=None,reference_spec=None,logic_scope='full',spec_ids=None):
    if Path(output).resolve().is_relative_to(Path(parent_root).resolve()):
        raise AgentError('EVALUATION_CONFIG_INVALID','Evaluation output must be outside the immutable parent run')
    store=ArtifactStore(output);root=store.root;limits=limits or (budget.limits if budget else Limits());budget=budget or Budget(limits)
    trace=RunTrace(root,store.run_id,secrets=(config.api_key,));parent=None;builder=None;uncertain=[];det=[];logic_findings=[]
    report={'evaluation_id':store.run_id,'schema_version':1,'evaluator_version':VERSION,
            'parent_run_ref':str(Path(parent_root).resolve()),'parent_run_id':None,'execution_status':'ERROR',
            'assessment_mode':{'parent_mode':'UNAVAILABLE','reviewer':reviewer,'logic':logic,'tool_mode':config.tool_mode,'logic_scope':logic_scope},
            'context_completeness':'UNAVAILABLE','verification_snapshot':{},'dimensions':{},'findings':[],
            'coverage':{},'limits':vars(limits),'budget':{},'stop_reason':'NOT_STARTED','errors':[],
            'contexts':[],'reviews':[],'queries':[],'source_and_spec_hashes':{},'logging':{}}
    def stage(name):
        write_json_atomic(root/'checkpoint.json',{'stage':name,'resume_supported':False})
        trace.emit('evaluation.stage',stage=name)
    trace.emit('evaluation.started',reviewer=reviewer,logic=logic)
    try:
        limits.validate()
        if vars(limits)!=vars(budget.limits):raise AgentError('EVALUATION_CONFIG_INVALID','Shared budget and limits disagree')
        if reviewer not in ('none','real','fixture') or logic not in ('off','tools'):
            raise AgentError('EVALUATION_CONFIG_INVALID','Unknown evaluation mode')
        if logic_scope not in ('full','reference') or logic_scope=='reference' and not reference_spec:
            raise AgentError('EVALUATION_CONFIG_INVALID','Invalid logic scope/reference')
        if (reviewer=='fixture')!=bool(review_fixture):raise AgentError('EVALUATION_CONFIG_INVALID','Review fixture requires fixture reviewer')
        stage('LOAD_PARENT');parent=ParentRun(parent_root);report['parent_run_id']=parent.manifest['run_id']
        report['assessment_mode']['parent_mode']=parent.report.get('mode','UNAVAILABLE')
        if require_real and (config.tool_mode!='REAL' or reviewer=='fixture' or parent.report.get('mode')!='REAL'):
            raise AgentError('NON_REAL_EVALUATION','Real-only assessment rejects fixture/mock inputs')
        store.write('parent_integrity.json',parent.status())
        report['verification_snapshot']=parent.status()['verification_availability']
        stage('INDEX_CONTEXT');index=index_requirements(parent.requirements_text,parent.info['requirements_sha256'])
        store.write('requirements_index.json',index);builder=ContextBuilder(parent,index,limits)
        selected=[s for s in parent.specs if spec_ids is None or s['spec_id'] in spec_ids]
        if spec_ids is not None and set(spec_ids)!={s['spec_id'] for s in selected}:
            raise AgentError('EVALUATION_CONFIG_INVALID','Unknown selected specification')
        report['assessment_mode']['selected_specs']=[s['spec_id'] for s in selected]
        contexts=[]
        for spec in selected:
            context=builder.build(spec);check_schema(context,'evaluation_context');contexts.append(context)
            ref='context/'+spec['function_id']+'.json';store.write(ref,context);report['contexts'].append(ref)
        coverage=inventory(index,parent.specs,parent.program.functions)
        stage('DETERMINISTIC_CHECKS')
        for spec,context in zip(selected,contexts):
            det.extend(deterministic_check(spec,parent.functions[spec['function_id']],context['evidence_ids']))
        req_eid=builder.register('input/requirements.md')
        for row in coverage['rows']:
            if not row['links']:
                det.append(finding('REQUIREMENTS','coverage','REQUIREMENT_UNREFERENCED',
                                   '需求原文条目没有任何后置条款引用；语义覆盖仍需复核。',evidence=[req_eid],claim='REVIEW_REQUIRED'))
        store.write('deterministic/findings.json',det);report['findings'].extend(det)
        reference=parent.optional('input/reference_spec.json',None)
        if reference_spec:
            from ..llm.parser import strict_json
            reference=strict_json(Path(reference_spec).read_text(encoding='utf-8'));store.write('input/reference_spec.json',reference)
        if reference:
            store.write('input/reference_spec.json',reference)
            builder.evidence['EV-REFERENCE']={'evidence_id':'EV-REFERENCE','artifact_scope':'EVALUATION',
                'artifact_ref':'input/reference_spec.json','sha256':sha256_file(root/'input/reference_spec.json'),
                'json_pointer':None,'line_range':None,'content':reference,
                'origin':'USER_SUPPLIED_REFERENCE_NOT_ASSUMED_CONFIRMED','completeness':'COMPLETE'}
        report['assessment_mode']['reference']='USER_SUPPLIED_UNCONFIRMED' if reference else 'NONE'
        caps=None
        if logic=='tools':
            stage('LOGIC_CHECKS');caps=doctor(config,root/'preflight',probe_tools=True,trace=trace)
            store.write('toolchain_manifest.json',caps)
            dependencies={str(parent.root/p):h for p,h in parent.dependencies.items()}
            dependencies[str(root/'toolchain_manifest.json')]=sha256_file(root/'toolchain_manifest.json')
            if reference:dependencies[str(root/'input/reference_spec.json')]=sha256_file(root/'input/reference_spec.json')
            engine=LogicEngine(root,caps,config,budget,trace,dependencies)
            for spec,context in zip(selected,contexts):
                function=parent.functions[spec['function_id']]
                if logic_scope=='full':
                    rows,missing=engine.evaluate(spec,function,context['evidence_ids']);logic_findings.extend(rows);uncertain.extend(missing)
                if reference:
                    rows,missing=assess_reference(engine,spec,function,reference,parent.requirements,parent.program,context['evidence_ids'])
                    logic_findings.extend(rows);uncertain.extend(missing)
            report['queries']=engine.results
            report['findings'].extend(logic_findings)
            if not caps['ready']:uncertain.append({'reason':'TOOLCHAIN_NOT_READY'})
        store.write('logic/findings.json',logic_findings)
        stage('SEMANTIC_REVIEW')
        client=OpenAIClient(config) if reviewer=='real' else ReviewFixtureClient(review_fixture) if reviewer=='fixture' else None
        if client:
            for context in contexts:
                value,error=review(context,builder,client,root,budget,trace,config)
                if error:report['errors'].append(error);uncertain.append(error)
                else:report['reviews'].append(value);report['findings'].extend(review_findings(value))
        report['coverage']=apply_reviews(coverage,report['reviews'])
        report['dimensions']=dimensions(report['findings'],report['reviews'],logic=logic if logic_scope=='full' else 'off',uncertain=uncertain,
                                        reference_checked=bool(reference and logic=='tools'),queries=report['queries'])
        stage('SUMMARIZE')
        missing_required=[m for m in parent.missing if m['kind']!='FORMAL_NOT_AVAILABLE']
        partial=bool(missing_required or uncertain or budget.stops or not contexts or any(c['context_completeness']=='PARTIAL' or not c['within_budget'] for c in contexts))
        report['execution_status']='PARTIAL' if partial else 'COMPLETED'
        report['context_completeness']='PARTIAL' if partial else 'COMPLETE'
        report['stop_reason']='REQUESTED_CHECKS_PARTIAL' if partial else 'REQUESTED_CHECKS_FINISHED'
        report['errors'].extend({'code':'INCOMPLETE_CHECK','details':e} for e in uncertain if e not in report['errors'])
    except KeyboardInterrupt:
        report['execution_status']='CANCELLED';report['stop_reason']='USER_CANCELLED'
    except (AgentError,OSError,ValueError,KeyError,TypeError) as exc:
        report['execution_status']='BLOCKED' if parent is None or isinstance(exc,AgentError) and exc.code in ('PARENT_INTEGRITY_FAILED','NON_REAL_EVALUATION') else 'ERROR'
        report['stop_reason']=getattr(exc,'code','EVALUATION_FAILED')
        report['errors'].append(exc.as_dict() if isinstance(exc,AgentError) else {'code':'EVALUATION_FAILED','message':type(exc).__name__+': '+str(exc)})
    report['budget']=budget.snapshot()
    if builder:store.write('context/context_manifest.json',{'evidence':builder.evidence,'omitted_context':builder.omitted})
    if parent:
        report['source_and_spec_hashes']=dict(parent.dependencies)
        store.write('parent_integrity.json',parent.status())
    for value in report['findings']:check_schema(value,'evaluation_finding')
    stage('FINISHED' if report['execution_status'] not in ('ERROR','BLOCKED','CANCELLED') else report['execution_status'])
    trace.emit('evaluation.finished',status=report['execution_status'],stop_reason=report['stop_reason'],finding_count=len(report['findings']))
    report['logging']=trace.status()
    return publish(store,report)


def publish(store, report):
    """Seal and audit the completed evaluation artifacts."""
    root=store.root
    check_schema(report,'evaluation')
    store.write('evaluation.json',report);(root/'report.md').write_text(markdown(report),encoding='utf-8')
    store.write('evaluation_manifest.json',{'schema_version':1,'original_evaluation_root':str(root),
                'parent_run_ref':report['parent_run_ref'],'parent_run_id':report['parent_run_id'],
                'parent_dependencies':report['source_and_spec_hashes'],'evaluator_version':VERSION})
    seal(root)
    from .audit import audit_evaluation
    audit=audit_evaluation(root)
    if audit['status']!='PASSED':
        report['execution_status']='ERROR';report['stop_reason']='EVALUATION_AUDIT_FAILED'
        report['errors'].append({'code':'EVALUATION_AUDIT_FAILED','details':audit['errors']})
        store.write('evaluation.json',report);(root/'report.md').write_text(markdown(report),encoding='utf-8');seal(root)
    store.write('audit.json',audit)
    return root,report


def seal(root):
    write_json_atomic(root/'evidence_hashes.json',{p.relative_to(root).as_posix():sha256_file(p) for p in sorted(root.rglob('*'))
        if p.is_file() and p not in (root/'evidence_hashes.json',root/'audit.json')})
