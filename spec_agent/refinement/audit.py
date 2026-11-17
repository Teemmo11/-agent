"""Read-only audit of a bounded candidate lineage and its decision evidence."""
from pathlib import Path
from ..artifacts import sha256_file
from ..errors import AgentError
from ..adapters import cbmc
from ..llm.parser import strict_json
from ..llm.schema import validate
from ..verification.audit import audit_run
from ..evaluation.audit import audit_evaluation
from ..evaluation.loader import ParentRun,pure_path
from ..evaluation.schema import check as check_schema
from .policy import scope_check,SeenCandidates,candidate_hash,decide,semantic_delta,quality_delta
from .proposer import PROPOSAL_SCHEMA


def audit_refinement(directory,*,parent_root=None):
    root=Path(directory).resolve();errors=[];checked=[]
    def read(path):return strict_json(Path(path).read_text(encoding='utf-8'))
    def local(value):
        p=pure_path(str(value))
        if '..' in p.parts:raise ValueError('Unsafe refinement artifact path')
        if p.is_absolute():p=p.relative_to(pure_path(manifest['original_root']))
        target=root.joinpath(*p.parts);current=root
        for part in p.parts:
            current=current/part
            if current.is_symlink():raise ValueError('Symlink in refinement artifact')
        if not target.resolve().is_relative_to(root):raise ValueError('Refinement path escape')
        return target
    try:
        manifest=read(root/'refinement_manifest.json');report=read(root/'refinement.json');check_schema(report,'refinement')
        hashes=read(root/'evidence_hashes.json')
        if not {'refinement.json','refinement_manifest.json'}<=set(hashes):errors.append('UNBOUND_REFINEMENT_REPORT')
        for ref,checksum in hashes.items():
            if sha256_file(local(ref))!=checksum:errors.append('ARTIFACT_HASH_MISMATCH:'+ref)
        baseline=Path(manifest['baseline_evaluation']);before=read(baseline/'evaluation.json')
        if sha256_file(baseline/'evaluation.json')!=manifest['baseline_report_sha256']:errors.append('BASELINE_REPORT_CHANGED')
        baseline_audit=audit_evaluation(baseline,parent_root=parent_root)
        if baseline_audit['status']!='PASSED':
            if report['stop_reason']!='REFINEMENT_PARENT_AUDIT_FAILED':errors.append('BASELINE_AUDIT_FAILED')
            return {'status':'PASSED' if not errors else 'FAILED','checked':['RECORDED_BLOCKED_BASELINE'],'errors':errors}
        parent=ParentRun(parent_root or before['parent_run_ref'])
        current_caps=read(baseline/'toolchain_manifest.json') if (baseline/'toolchain_manifest.json').exists() else None
        original=next((s for s in parent.specs if s['spec_id']==report['spec_id']),None)
        seen=SeenCandidates(original) if original else None;last_accepted=None
        for step in report['iterations']:
            gate_caps=None
            if not original or not seen:raise ValueError('Candidate without baseline spec')
            proposal=read(local(step['proposal']));validate(proposal,PROPOSAL_SCHEMA)
            if proposal!=strict_json((local(step['proposal']).parent/'response.txt').read_text(encoding='utf-8')):errors.append('PROPOSAL_RESPONSE_MISMATCH')
            candidate=proposal['candidate'];fresh,key=seen.add(candidate)
            version=root/'versions'/(str(step['iteration'])+'.json')
            if version.exists() and read(version)!=step:errors.append('VERSION_RECORD_MISMATCH')
            if 'semantic_delta' in step and step['semantic_delta']!=semantic_delta(original,candidate):errors.append('SEMANTIC_DELTA_MISMATCH')
            if 'verification_before' in step and step['verification_before']!=parent.verified.get(report['spec_id'],{}).get('verification',{}).get('verdict','NOT_RUN'):
                errors.append('BASELINE_VERIFICATION_MISMATCH')
            if step['candidate_hash'] is not None and key!=step['candidate_hash']:errors.append('CANDIDATE_HASH_MISMATCH')
            if step['reason']=='DUPLICATE_CANDIDATE':
                if fresh or step['decision']!='REJECTED':errors.append('DUPLICATE_DECISION_MISMATCH')
                continue
            if proposal['needs_clarification']:
                if step['decision']!='NEEDS_REVIEW':errors.append('CLARIFICATION_GATE_BYPASSED')
                continue
            changes=scope_check(original,candidate,parent)
            if changes!=step.get('scope_changes'):errors.append('SCOPE_CHANGE_SUMMARY_MISMATCH')
            if changes:
                if step['decision']!='NEEDS_REVIEW' or step['trial_run']:errors.append('PROTECTED_SCOPE_GATE_BYPASSED')
                continue
            if step['gate_evaluation']:
                gate_root=local(step['gate_evaluation']);gate=read(gate_root/'evaluation.json')
                declaration=local(gate['parent_run_ref'])
                gate_audit=audit_evaluation(gate_root,parent_root=declaration)
                if gate_audit['status']!='PASSED':errors.append('STRENGTH_GATE_AUDIT_FAILED')
                if read(gate_root/'input/reference_spec.json')!={'function_spec':original['function_spec'],'callee_expectations':original['callee_expectations']}:
                    errors.append('STRENGTH_REFERENCE_CHANGED')
                gate_caps=read(gate_root/'toolchain_manifest.json') if (gate_root/'toolchain_manifest.json').exists() else None
                if current_caps and gate_caps and cbmc.execution_identity(current_caps)!=cbmc.execution_identity(gate_caps):
                    if step['decision']!='NEEDS_REVIEW' or step['reason']!='TOOLCHAIN_IDENTITY_CHANGED' or step['trial_run']:
                        errors.append('MODEL_POLICY_CHANGE_GATE_BYPASSED')
                    continue
                weak=any(f['code'] in ('CANDIDATE_DOES_NOT_ENTAIL_REFERENCE','INPUT_DOMAIN_EXCLUDES_REFERENCE') for f in gate['findings'])
                if weak and (step['decision']!='NEEDS_REVIEW' or step['trial_run']):errors.append('WEAKENING_GATE_BYPASSED')
                if step['decision']=='ACCEPTED' and (gate['execution_status']!='COMPLETED' or weak):errors.append('UNPROVED_STRENGTH_ACCEPTED')
            elif step['decision']=='ACCEPTED':errors.append('MISSING_STRENGTH_GATE')
            if step['trial_run']:
                trial=local(step['trial_run']);trial_report=read(trial/'result.json');trial_parent=ParentRun(trial)
                if gate_caps and cbmc.execution_identity(gate_caps)!=cbmc.execution_identity(read(trial/'toolchain_manifest.json')):
                    errors.append('TRIAL_MODEL_POLICY_CHANGED')
                if [r['sha256'] for r in parent.info['sources']]!=[r['sha256'] for r in trial_parent.info['sources']]:errors.append('SOURCE_PROGRAM_CHANGED')
                actual=next(s for s in trial_parent.specs if s['spec_id']==report['spec_id'])
                if candidate_hash(actual)!=candidate_hash(candidate):errors.append('VERIFIED_CANDIDATE_MISMATCH')
                for other in parent.specs:
                    copied=next(s for s in trial_parent.specs if s['spec_id']==other['spec_id'])
                    if other['spec_id']!=report['spec_id'] and candidate_hash(copied)!=candidate_hash(other):errors.append('UNRELATED_SPEC_CHANGED')
                verdict=next(c for c in trial_report['contracts'] if c['spec_id']==report['spec_id'])['verification']['verdict']
                if verdict!=step['verification_verdict']:errors.append('VERIFICATION_VERDICT_CHANGED')
                if step['candidate_evaluation']:
                    after_root=local(step['candidate_evaluation']);after=read(after_root/'evaluation.json')
                    if audit_evaluation(after_root,parent_root=trial)['status']!='PASSED':errors.append('CANDIDATE_ASSESSMENT_AUDIT_FAILED')
                    after_caps=read(after_root/'toolchain_manifest.json')
                    if gate_caps and cbmc.execution_identity(gate_caps)!=cbmc.execution_identity(after_caps):
                        errors.append('ASSESSMENT_MODEL_POLICY_CHANGED')
                    expected,reason=decide(before,after,report['spec_id'],verdict,has_reference=(baseline/'input/reference_spec.json').exists())
                    if 'quality_delta' in step and step['quality_delta']!=quality_delta(before,after,report['spec_id']):errors.append('QUALITY_DELTA_MISMATCH')
                    if (expected,reason)!=(step['decision'],step['reason']):errors.append('CANDIDATE_DECISION_MISMATCH')
                    if step['decision']=='ACCEPTED':
                        if audit_run(trial,require_real=False)['status']!='PASSED':errors.append('ACCEPTED_WITHOUT_PHASE1_EVIDENCE')
                        last_accepted={'trial_run':step['trial_run'],'evaluation':step['candidate_evaluation'],
                                       'candidate_hash':key,'verification_verdict':verdict}
                        original=actual;parent=trial_parent;before=after
                        current_caps=after_caps
            checked.append(step['iteration'])
        if last_accepted!=report['selected_candidate']:errors.append('SELECTED_CANDIDATE_MISMATCH')
        if report['source_program_changed'] is not False:errors.append('SOURCE_CHANGE_NOT_ALLOWED')
    except (AgentError,OSError,ValueError,KeyError,TypeError,StopIteration) as exc:
        errors.append(getattr(exc,'code',type(exc).__name__)+': '+str(exc))
    return {'status':'PASSED' if not errors else 'FAILED','checked':checked,'errors':errors,
            'scope':'Read-only candidate provenance, protected scope, proof and decision replay'}
