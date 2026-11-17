"""Phase 2B: bounded, monotone candidates with separate quality and program verdicts."""
import copy
import json
from pathlib import Path
from ..artifacts import ArtifactStore,sha256_file,write_json_atomic,utc_now
from ..errors import AgentError
from ..adapters import cbmc
from ..trace import RunTrace
from ..llm.client import OpenAIClient
from ..evaluation.loader import ParentRun
from ..evaluation.models import Limits,Budget
from ..evaluation.audit import audit_evaluation
from ..evaluation.controller import evaluate,seal
from ..verification.candidates import verify_given_candidates
from .policy import scope_check,SeenCandidates,decide,issue_keys,semantic_delta,quality_delta
from .proposer import CandidateFixtureClient,propose


def refine(evaluation_root,config,*,output='refinements',max_iterations=2,spec_id=None,
           proposer='real',candidate_fixture=None,reviewer='none',review_fixture=None,
           limits=None,require_real=False,parent_root=None):
    initial=Path(evaluation_root).resolve()
    if Path(output).resolve().is_relative_to(initial):raise AgentError('REFINEMENT_CONFIG_INVALID','Output must be outside baseline evaluation')
    # Resolve the immutable parent before ArtifactStore creates any directory.
    baseline=json.loads((initial/'evaluation.json').read_text(encoding='utf-8'))
    if baseline.get('assessment_mode',{}).get('profile')=='strength':
        raise AgentError('REFINEMENT_CONFIG_INVALID','Strength reports are independent measurements; refine requires a diagnostic evaluation')
    initial_parent=Path(parent_root or baseline['parent_run_ref']).resolve()
    if Path(output).resolve().is_relative_to(initial_parent):
        raise AgentError('REFINEMENT_CONFIG_INVALID','Output must be outside parent run')
    store=ArtifactStore(output);root=store.root;trace=RunTrace(root,store.run_id,secrets=(config.api_key,))
    limits=limits or Limits(calls_per_function=max(2,3*max_iterations));budget=Budget(limits)
    report={'refinement_id':store.run_id,'schema_version':1,'baseline_evaluation':str(initial),
            'execution_status':'ERROR','decision':'INCONCLUSIVE','stop_reason':'NOT_STARTED','spec_id':spec_id,
            'proposal_mode':proposer,'reviewer':reviewer,'iterations':[],'selected_candidate':None,
            'source_program_changed':False,'decision_scope':'EXECUTED_CHECKS_AND_SUPPLIED_REFERENCE; not unconditional adequacy',
            'errors':[],'budget':{},'logging':{}}
    def stage(name,iteration=0):
        store.write('checkpoint.json',{'stage':name,'iteration':iteration,'resume_supported':False})
        trace.emit('refinement.stage',stage=name,iteration=iteration)
    trace.emit('refinement.started',max_iterations=max_iterations,proposal_mode=proposer)
    try:
        stage('LOAD_BASELINE')
        limits.validate()
        if type(max_iterations) is not int or not 0<=max_iterations<=16:raise AgentError('REFINEMENT_CONFIG_INVALID','Iteration limit must be 0..16')
        if proposer not in ('real','fixture') or (proposer=='fixture')!=bool(candidate_fixture):
            raise AgentError('REFINEMENT_CONFIG_INVALID','Invalid proposer/fixture combination')
        if reviewer not in ('none','real','fixture') or (reviewer=='fixture')!=bool(review_fixture):
            raise AgentError('REFINEMENT_CONFIG_INVALID','Invalid reviewer/fixture combination')
        audit=audit_evaluation(initial,parent_root=parent_root);store.write('baseline_audit.json',audit)
        if audit['status']!='PASSED':raise AgentError('REFINEMENT_PARENT_AUDIT_FAILED','Baseline evaluation evidence failed audit')
        current=json.loads((initial/'evaluation.json').read_text(encoding='utf-8'));current_root=initial
        parent=ParentRun(parent_root or current['parent_run_ref'])
        if Path(output).resolve().is_relative_to(parent.root):raise AgentError('REFINEMENT_CONFIG_INVALID','Output must be outside parent run')
        if require_real and (proposer=='fixture' or reviewer=='fixture' or parent.report.get('mode')!='REAL' or config.tool_mode!='REAL'):
            raise AgentError('NON_REAL_REFINEMENT','Real-only refinement rejects fixture/mock inputs')
        candidates={f['spec_id'] for f in current['findings'] if f['severity'] in ('HIGH','MEDIUM')} & {s['spec_id'] for s in parent.specs}
        sid=spec_id or next(iter(sorted(candidates)),None);report['spec_id']=sid
        if sid is None:
            report.update(execution_status='COMPLETED',decision='NEEDS_REVIEW' if current['findings'] else 'ACCEPTED',stop_reason='NO_AUTOMATIC_TARGET')
        elif current['execution_status']!='COMPLETED' or current['context_completeness']!='COMPLETE':
            report.update(execution_status='PARTIAL',decision='NEEDS_REVIEW',stop_reason='BASELINE_CONTEXT_INCOMPLETE')
        else:
            original=next((s for s in parent.specs if s['spec_id']==sid),None)
            if original is None:raise AgentError('REFINEMENT_CONFIG_INVALID','Unknown target spec')
            seen=SeenCandidates(original);client=OpenAIClient(config) if proposer=='real' else CandidateFixtureClient(candidate_fixture)
            for iteration in range(1,max_iterations+1):
                if not issue_keys(current,sid):report.update(execution_status='COMPLETED',decision='ACCEPTED',stop_reason='NO_PENDING_TARGET_ISSUES');break
                if original['function_spec']['ambiguities'] or original['function_spec']['conflicts'] or any(r['needs_clarification'] for r in current['reviews']):
                    report.update(execution_status='COMPLETED',decision='NEEDS_REVIEW',stop_reason='REQUIREMENT_CLARIFICATION_REQUIRED');break
                context=next(json.loads((current_root/ref).read_text(encoding='utf-8')) for ref in current['contexts']
                             if json.loads((current_root/ref).read_text(encoding='utf-8'))['spec_id']==sid)
                catalog=json.loads((current_root/'context/context_manifest.json').read_text(encoding='utf-8'))['evidence']
                relevant=[f for f in current['findings'] if f['spec_id']==sid]
                stage('PROPOSE_CANDIDATE',iteration)
                proposal,proposal_dir=propose(context,catalog,relevant,report['iterations'],client,root,iteration,budget,trace,config)
                record={'iteration':iteration,'proposal':str(proposal_dir/'proposal.json'),'candidate_hash':None,
                        'decision':'INCONCLUSIVE','reason':'NOT_CHECKED','trial_run':None,'gate_evaluation':None,
                        'candidate_evaluation':None,'verification_verdict':None,
                        'verification_before':parent.verified.get(sid,{}).get('verification',{}).get('verdict','NOT_RUN'),
                        'semantic_delta':semantic_delta(original,proposal['candidate'])}
                report['iterations'].append(record)
                if proposal['needs_clarification']:
                    record.update(decision='NEEDS_REVIEW',reason='REQUIREMENT_CLARIFICATION_REQUIRED');report.update(execution_status='COMPLETED',decision='NEEDS_REVIEW',stop_reason=record['reason']);break
                candidate=proposal['candidate'];fresh,key=seen.add(candidate);record['candidate_hash']=key
                if not fresh:
                    record.update(decision='REJECTED',reason='DUPLICATE_CANDIDATE');report.update(execution_status='COMPLETED',decision='REJECTED',stop_reason=record['reason']);break
                changes=scope_check(original,candidate,parent);record['scope_changes']=changes
                trace.emit('refinement.scope.checked',iteration=iteration,candidate_hash=key,changes=changes)
                if changes:
                    record.update(decision='NEEDS_REVIEW',reason='PROTECTED_SCOPE_CHANGED');report.update(execution_status='COMPLETED',decision='NEEDS_REVIEW',stop_reason=record['reason']);break
                updated={**copy.deepcopy(original),**candidate}
                updated['generation']={**updated.get('generation',{}),'mode':'REAL' if proposer=='real' else 'FIXTURE_REFINEMENT',
                                       'stage':'REFINEMENT','created_at':utc_now(),'model':config.model if proposer=='real' else None}
                all_specs=[updated if s['spec_id']==sid else copy.deepcopy(s) for s in parent.specs]
                stage('CHECK_STRENGTH',iteration)
                declaration,_=verify_given_candidates(parent,all_specs,config,output=root/'declarations'/str(iteration),
                    generation=client.mode,proposal_dir=proposal_dir,budget=budget,verification=False,target_spec_id=sid)
                reference=root/'references'/(str(iteration)+'.json');write_json_atomic(reference,
                    {'function_spec':original['function_spec'],'callee_expectations':original['callee_expectations']})
                gate_root,gate=evaluate(declaration,config,output=root/'gates'/str(iteration),logic='tools',
                    reviewer='none',reference_spec=reference,logic_scope='reference',spec_ids=[sid],budget=budget,limits=limits)
                record['gate_evaluation']=str(gate_root)
                old_tools=current_root/'toolchain_manifest.json';new_tools=gate_root/'toolchain_manifest.json'
                if old_tools.exists() and new_tools.exists():
                    before_caps=json.loads(old_tools.read_text(encoding='utf-8'));after_caps=json.loads(new_tools.read_text(encoding='utf-8'))
                    if cbmc.execution_identity(before_caps)!=cbmc.execution_identity(after_caps):
                        record.update(decision='NEEDS_REVIEW',reason='TOOLCHAIN_IDENTITY_CHANGED');report.update(execution_status='COMPLETED',decision='NEEDS_REVIEW',stop_reason=record['reason']);break
                if gate['execution_status']!='COMPLETED':
                    record.update(decision='INCONCLUSIVE',reason='STRENGTH_GATE_INCOMPLETE');report.update(execution_status='PARTIAL',decision='INCONCLUSIVE',stop_reason=record['reason']);break
                if any(f['code'] in ('CANDIDATE_DOES_NOT_ENTAIL_REFERENCE','INPUT_DOMAIN_EXCLUDES_REFERENCE') for f in gate['findings']):
                    record.update(decision='NEEDS_REVIEW',reason='EXISTING_OBLIGATION_WEAKENED');report.update(execution_status='COMPLETED',decision='NEEDS_REVIEW',stop_reason=record['reason']);break
                stage('REVERIFY_IMPLEMENTATION',iteration)
                trial,phase1=verify_given_candidates(parent,all_specs,config,output=root/'trials'/str(iteration),
                    generation=client.mode,proposal_dir=proposal_dir,budget=budget,target_spec_id=sid)
                record['trial_run']=str(trial)
                row=next((c for c in phase1['contracts'] if c['spec_id']==sid),{})
                record['verification_verdict']=row.get('verification',{}).get('verdict','ERROR')
                original_reference=initial/'input/reference_spec.json'
                stage('REASSESS_CANDIDATE',iteration)
                judged_root,judged=evaluate(trial,config,output=root/'evaluations'/str(iteration),logic='tools',
                    reviewer=reviewer,review_fixture=review_fixture,reference_spec=original_reference if original_reference.exists() else None,
                    spec_ids=[sid],budget=budget,limits=limits)
                record['candidate_evaluation']=str(judged_root)
                decision,reason=decide(current,judged,sid,record['verification_verdict'],has_reference=original_reference.exists())
                record['quality_delta']=quality_delta(current,judged,sid)
                record.update(decision=decision,reason=reason);report.update(decision=decision,stop_reason=reason)
                trace.emit('refinement.candidate.decided',**record)
                if decision=='ACCEPTED':
                    report['selected_candidate']={'trial_run':str(trial),'evaluation':str(judged_root),'candidate_hash':key,
                                                  'verification_verdict':record['verification_verdict']}
                    parent=ParentRun(trial);original=next(s for s in parent.specs if s['spec_id']==sid);current=judged;current_root=judged_root
                    if not issue_keys(current,sid):report.update(execution_status='COMPLETED',stop_reason='NO_PENDING_TARGET_ISSUES');break
                elif decision in ('NEEDS_REVIEW','INCONCLUSIVE'):
                    report['execution_status']='PARTIAL' if decision=='INCONCLUSIVE' else 'COMPLETED';break
            else:report.update(execution_status='PARTIAL',stop_reason='ITERATION_LIMIT')
    except KeyboardInterrupt:report.update(execution_status='CANCELLED',stop_reason='USER_CANCELLED')
    except (AgentError,OSError,ValueError,KeyError,TypeError,StopIteration) as exc:
        code=getattr(exc,'code','REFINEMENT_FAILED')
        report.update(execution_status='PARTIAL' if code=='REFINEMENT_BUDGET_EXHAUSTED' else 'ERROR',stop_reason=code)
        report['errors'].append(exc.as_dict() if isinstance(exc,AgentError) else {'code':code,'message':str(exc)})
    for record in report['iterations']:store.write('versions/'+str(record['iteration'])+'.json',record)
    stage(report['execution_status'])
    report['budget']=budget.snapshot();trace.emit('refinement.finished',status=report['execution_status'],stop_reason=report['stop_reason'])
    report['logging']=trace.status()
    from ..evaluation.schema import check as check_schema
    check_schema(report,'refinement');store.write('refinement.json',report)
    (root/'report.md').write_text('# 规约修订报告\n\n'+
        f"状态：{report['execution_status']}；候选决策：{report['decision']}；停止原因：{report['stop_reason']}\n\n"+
        '\n'.join(f"- 第 {s['iteration']} 轮：{s['decision']}；{s['reason']}；实现验证={s['verification_verdict']}" for s in report['iterations'])+
        '\n\n候选决策仅限已执行的检查与参考范围，原始源码及运行证据不回写。\n',encoding='utf-8')
    store.write('refinement_manifest.json',{'original_root':str(root),'baseline_evaluation':str(initial),
        'baseline_report_sha256':sha256_file(initial/'evaluation.json') if (initial/'evaluation.json').exists() else None})
    seal(root)
    from .audit import audit_refinement
    audit=audit_refinement(root,parent_root=parent_root);store.write('audit.json',audit)
    if audit['status']!='PASSED':
        report.update(execution_status='ERROR',stop_reason='REFINEMENT_AUDIT_FAILED');report['errors'].append({'code':'REFINEMENT_AUDIT_FAILED','details':audit['errors']})
        store.write('refinement.json',report);seal(root)
    return root,report
