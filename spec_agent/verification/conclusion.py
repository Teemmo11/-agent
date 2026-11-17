from pathlib import Path
from ..artifacts import sha256_file

def integrity(hashes):
    return all(Path(path).is_file() and sha256_file(path)==h for path,h in hashes.items())

def gate(result,*,commands,hashes,bad_nodes,target_node):
    """Only verified evidence permits a per-property claim."""
    if result['verdict'] not in ('HOLDS','VIOLATED'):
        blockers=[(result.get('error') or {}).get('code','INCONCLUSIVE')]
        if not integrity(hashes):
            blockers.append('ARTIFACT_INTEGRITY_FAILED'); result.update(verdict='ERROR',error={'code':'ARTIFACT_INTEGRITY_FAILED','message':'Evidence changed'})
        result['conclusion_gate']={'allowed':False,'blockers':blockers,'scope':'NO_PROOF_PUBLISHED'}
        return result
    blockers=[]
    if not commands or not all(c.ok for c in commands): blockers.append('UPSTREAM_EXECUTION_FAILED')
    if not result['model_validated'] or not result['model_sha256']: blockers.append('MODEL_NOT_VALIDATED')
    contract=result.get('model_contract')
    if contract and contract.get('status') not in ('PASSED','NOT_REQUIRED'): blockers.append('MODEL_CONTRACT_BLOCKED')
    if not integrity(hashes): blockers.append('ARTIFACT_INTEGRITY_FAILED')
    if len(bad_nodes)!=1 or target_node not in bad_nodes or result['attribution_status']!='SINGLE_PROPERTY': blockers.append('ATTRIBUTION_UNKNOWN')
    expected='SAT' if result['verdict']=='VIOLATED' else 'UNSAT'
    if result['raw_result']!=expected: blockers.append('RAW_RESULT_MISMATCH')
    if blockers: result.update(verdict='ERROR',error={'code':'CONCLUSION_BLOCKED','message':', '.join(blockers)})
    result['conclusion_gate']={'allowed':not blockers,'blockers':blockers,'scope':'CURRENT_MODEL_AND_ASSUMPTIONS'}
    return result

def precondition_status(result):
    return {'VIOLATED':'FEASIBLE','HOLDS':'INFEASIBLE','UNKNOWN':'UNKNOWN','ERROR':'ERROR'}[result['verdict']]

def aggregate(precondition,clauses):
    if precondition=='ERROR' or any(c['verdict']=='ERROR' for c in clauses): return 'ERROR'
    if precondition=='INFEASIBLE': return 'VACUOUS'
    if precondition!='FEASIBLE': return 'UNKNOWN'
    if any(c['verdict']=='VIOLATED' for c in clauses): return 'VIOLATED'
    if not clauses or any(c['verdict']!='HOLDS' for c in clauses): return 'UNKNOWN'
    return 'HOLDS'
