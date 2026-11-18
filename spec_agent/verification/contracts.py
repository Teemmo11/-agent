"""Shared verification of a validated formal contract, without generation."""
import json

from ..artifacts import sha256_file,write_json_atomic
from ..errors import AgentError
from ..spec.harness import emit_harness
from .verifier import verify
from .conclusion import aggregate,precondition_status


def verify_contract(contract,row,func,sources,info,expected_hashes,caps,config,store,trace):
    job_trace=trace.bind(branch='hoare',function_id=func.function_id,spec_id=contract.source_spec_id)
    try:
        semantic=store.root/'specs/semantic'/(contract.source_spec_id+'.json')
        formal=store.root/'specs/formal'/(contract.source_spec_id+'.json')
        trace_dir=store.root/'generation/llm/functions'/func.function_id
        bound={str(p):sha256_file(p) for p in [semantic,formal,trace_dir/'prompt.json',trace_dir/'response.txt',store.root/'toolchain_manifest.json']}
        if (trace_dir/'response.raw.json').exists():bound[str(trace_dir/'response.raw.json')]=sha256_file(trace_dir/'response.raw.json')
        if (trace_dir/'attempts.json').is_file():
            attempts=trace_dir/'attempts.json'
            recorded=json.loads(attempts.read_text(encoding='utf-8'))
            recorded_hash=sha256_file(attempts)
            generation=json.loads(semantic.read_text(encoding='utf-8'))['generation']
            if generation.get('attempts_sha256')!=recorded_hash:
                raise AgentError('ARTIFACT_INTEGRITY_FAILED','Generation attempt manifest changed')
            bound[str(attempts)]=recorded_hash
            for relative,checksum in recorded['artifact_hashes'].items():
                path=(trace_dir/relative).resolve()
                if not path.is_relative_to(trace_dir/'attempts'):
                    raise AgentError('ARTIFACT_INTEGRITY_FAILED','Generation attempt artifact outside run')
                bound[str(path)]=checksum
        if (store.root/'input/domain_knowledge.json').exists():bound[str(store.root/'input/domain_knowledge.json')]=sha256_file(store.root/'input/domain_knowledge.json')
        provenance={'source_sha256':info['source_sha256'],'requirements_sha256':info['requirements_sha256'],
                    'semantic_spec':str(semantic),'semantic_spec_sha256':bound[str(semantic)],
                    'formal_contract':str(formal),'formal_contract_sha256':bound[str(formal)]}
        row['provenance']=provenance
        pdir=store.root/'verification'/(contract.source_spec_id+'.P-FEASIBILITY')
        job=emit_harness(func,contract,None,sources,pdir,trace=job_trace)
        job.source_hashes.update({**expected_hashes,**bound});job.provenance=provenance;write_json_atomic(pdir/'job.json',job)
        presult=verify(job,caps,config,pdir,trace=job_trace)
        row['precondition']={'status':precondition_status(presult),'result':presult}
        job_trace.emit('precondition.classified',status=row['precondition']['status'],raw_result=presult['raw_result'],result_file=str(pdir/'result.json'))
        for clause in contract.ensures:
            qdir=store.root/'verification'/(contract.source_spec_id+'.'+clause.clause_id)
            job=emit_harness(func,contract,clause,sources,qdir,trace=job_trace)
            job.source_hashes.update({**expected_hashes,**bound});job.provenance=provenance;write_json_atomic(qdir/'job.json',job)
            row['properties'].append(verify(job,caps,config,qdir,trace=job_trace))
        row['verification']={'verdict':aggregate(row['precondition']['status'],row['properties'])}
        row['conclusion_gate']={'allowed':row['verification']['verdict'] in ('HOLDS','VIOLATED','VACUOUS'),
            'reason':'DETERMINISTIC_FEASIBILITY_AGGREGATION','precondition_result':str(pdir/'result.json'),
            'property_results':[str(store.root/'verification'/p['property_id']/'result.json') for p in row['properties']]}
    except (AgentError,OSError) as exc:
        error=exc.as_dict() if isinstance(exc,AgentError) else {'code':'HARNESS_ERROR','message':str(exc)}
        job_trace.emit('verification.failed',level='ERROR',spec_id=contract.source_spec_id,error=error)
        row['verification']={'verdict':'ERROR','error':error}
    job_trace.emit('contract.concluded',precondition=row['precondition']['status'],verification=row['verification'],conclusion_gate=row['conclusion_gate'])
    return row
