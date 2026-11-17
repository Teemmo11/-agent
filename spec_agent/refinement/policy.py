"""Deterministic scope guards and repeat detection, independent of the LLM."""
import json
from ..artifacts import digest
from ..errors import AgentError
from ..llm.parser import parse_response
from ..spec.formalizer import formalize
from ..evaluation.deterministic import canonical


def candidate_hash(value):
    return digest(json.dumps({'function_spec':value['function_spec'],'callee_expectations':value['callee_expectations']},ensure_ascii=False,sort_keys=True))


class SeenCandidates:
    def __init__(self,original):self.seen={candidate_hash(original)}
    def add(self,value):
        key=candidate_hash(value)
        if key in self.seen:return False,key
        self.seen.add(key);return True,key


def scope_check(original,candidate,parent):
    function=parent.functions[original['function_id']]
    parse_response(json.dumps(candidate),function,parent.requirements,parent.program,
        require_unguarded_posts=bool(parent.constraints and parent.constraints.get('postcondition_guard')=='NULL_ONLY'))
    assembled={**original,**candidate};formalize(assembled,function,parent.info)
    old=original['function_spec'];new=candidate['function_spec'];reasons=[]
    if canonical(old['pre_condition']['formal_candidate'],function,post=False)!=canonical(new['pre_condition']['formal_candidate'],function,post=False):reasons.append('PRECONDITION_CHANGED')
    before={q['clause_id']:q for q in old['post_conditions']};after={q['clause_id']:q for q in new['post_conditions']}
    if not set(before)<=set(after):reasons.append('OBLIGATION_REMOVED')
    for cid in set(before)&set(after):
        if canonical(before[cid]['guard'] or '1',function)!=canonical(after[cid]['guard'] or '1',function):reasons.append('GUARD_CHANGED:'+cid)
        if not set(before[cid]['requirement_refs'])<=set(after[cid]['requirement_refs']):reasons.append('REQUIREMENT_REFERENCE_REMOVED:'+cid)
    if not set(old['requirement_refs'])<=set(new['requirement_refs']):reasons.append('REQUIREMENT_REFERENCE_REMOVED')
    if original['callee_expectations']!=candidate['callee_expectations']:reasons.append('CALLEE_EXPECTATIONS_CHANGED')
    return reasons


def issue_keys(report,sid):
    return {(f['dimension'],f['code'],tuple(sorted(f['clause_ids']))) for f in report['findings']
            if f['spec_id']==sid and f['severity'] in ('HIGH','MEDIUM')}


def semantic_delta(original,candidate):
    old=original['function_spec'];new=candidate['function_spec']
    before={q['clause_id']:q for q in old['post_conditions']};after={q['clause_id']:q for q in new['post_conditions']}
    return {'before_hash':candidate_hash(original),'after_hash':candidate_hash(candidate),
            'precondition':{'before':old['pre_condition'],'after':new['pre_condition']},
            'clauses':[{'clause_id':cid,'before':before.get(cid),'after':after.get(cid)}
                       for cid in sorted(set(before)|set(after)) if before.get(cid)!=after.get(cid)],
            'expected_behavior':{'before':old['expected_behavior'],'after':new['expected_behavior']}}


def quality_delta(before,after,sid):
    old=issue_keys(before,sid);new=issue_keys(after,sid)
    return {'resolved_issues':[[k[0],k[1],list(k[2])] for k in sorted(old-new)],
            'new_issues':[[k[0],k[1],list(k[2])] for k in sorted(new-old)],
            'coverage_before':before['coverage'],'coverage_after':after['coverage']}


def decide(before,after,sid,verification,*,has_reference=False):
    if after['execution_status']!='COMPLETED' or verification not in ('HOLDS','VIOLATED'):
        return 'INCONCLUSIVE','VERIFICATION_OR_ASSESSMENT_INCOMPLETE'
    if any(r['needs_clarification'] for r in after['reviews']):return 'NEEDS_REVIEW','REQUIREMENT_CLARIFICATION_REQUIRED'
    old=issue_keys(before,sid);new=issue_keys(after,sid)
    if new-old:return 'REJECTED','NEW_QUALITY_ISSUES'
    if not old-new:return 'REJECTED','NO_QUALITY_PROGRESS'
    semantic=[r for r in after['reviews'] if r['spec_id']==sid]
    previous=[r for r in before.get('reviews',[]) if r['spec_id']==sid]
    prior_semantic_issues=any(f.get('evidence_kind')=='LLM_JUDGMENT' and f['spec_id']==sid and f['severity'] in ('HIGH','MEDIUM') for f in before['findings'])
    if prior_semantic_issues and not semantic:return 'NEEDS_REVIEW','PREVIOUS_SEMANTIC_CHECK_NOT_REPEATED'
    if previous and semantic and previous[0].get('reviewer_identity')!=semantic[0].get('reviewer_identity'):
        return 'NEEDS_REVIEW','REVIEWER_IDENTITY_CHANGED'
    if not semantic and not has_reference:return 'NEEDS_REVIEW','SEMANTIC_REVIEW_OR_REFERENCE_REQUIRED'
    return 'ACCEPTED','IMPROVED_WITHIN_EXECUTED_CHECKS'
