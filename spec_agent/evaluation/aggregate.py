"""Execution completeness, issue severity and quality are independent axes."""
from .models import DIMENSIONS,SEVERITIES


def dimensions(findings,reviews,*,logic,uncertain,reference_checked=False,queries=None):
    output={}
    for name in DIMENSIONS:
        related=[f['finding_id'] for f in findings if f['dimension']==name]
        judgments=[{'spec_id':r['spec_id'],**d,'evidence_kind':'LLM_JUDGMENT'} for r in reviews for d in r['dimensions'] if d['dimension']==name]
        if related:status='ISSUES_FOUND'
        elif name in ('nontriviality','consistency') and logic=='tools':
            executed=queries is None or any(q['kind']==('P_FEASIBILITY' if name=='nontriviality' else 'JOINT_ASSIGNMENT_EXISTS') for q in queries)
            status='UNKNOWN' if uncertain else 'NO_ISSUE_FOUND' if executed else 'NOT_RUN'
        elif name=='strength' and reference_checked:
            status='UNKNOWN' if uncertain else 'NO_ISSUE_FOUND'
        elif judgments:
            states={d['status'] for d in judgments}
            status='UNKNOWN' if 'UNKNOWN' in states or len(states)>1 else next(iter(states))
        elif name in ('redundancy','clarity'):status='NO_ISSUE_FOUND'
        else:status='NOT_RUN'
        output[name]={'status':status,'finding_ids':related,'semantic_judgments':judgments,
                      'scope':'Only executed checks; absence of findings is not a completeness proof'}
    return output


def exit_code(report,threshold='MEDIUM'):
    if report['execution_status']=='CANCELLED':return 130
    if report['execution_status'] in ('ERROR','BLOCKED'):return 2
    if report['execution_status']=='PARTIAL':return 3
    return 1 if any(SEVERITIES[f['severity']]>=SEVERITIES[threshold] for f in report['findings']) else 0
