"""Typed, bounded logical probes using the existing strict model execution path."""
import json
from dataclasses import asdict
from ..artifacts import digest,write_json_atomic,sha256_file
from ..errors import AgentError
from ..adapters import cbmc
from ..verification.verifier import verify
from .harness import expressions,emit
from .models import finding


def conjunction(parts):return '('+' && '.join('('+x+')' for x in parts)+')' if parts else '1'


def query_key(function,predicate,caps):
    identity={'symbol_domain':{'parameters':[asdict(p) for p in function.parameters],
                              'return_type':function.return_type},'predicate':predicate,
              'tools':{k:v.get('sha256') for k,v in caps.get('tools',{}).items()},'profile':caps.get('cbmc_profile')}
    if function.return_type=='_Bool' or any(p.type=='_Bool' for p in function.parameters):
        identity['symbol_domain']['bool_value_normalization']='NONZERO_TO_ONE; canonical C values 0/1'
    if cbmc.source_policy(caps): identity['converter_policy']=cbmc.source_policy(caps)
    return identity,digest(json.dumps(identity,sort_keys=True))


class LogicEngine:
    def __init__(self,root,caps,config,budget,trace,dependencies):
        self.root,self.caps,self.config,self.budget,self.trace,self.dependencies=root,caps,config,budget,trace,dependencies
        self.results=[];self.cache={}
    def query(self,function,spec_id,kind,predicate,clauses=()):
        identity,key=query_key(function,predicate,self.caps)
        if key in self.cache:return self.cache[key]
        qid='EQ-'+digest(spec_id+':'+kind+':'+key)[:20];directory=self.root/'queries'/qid
        result={'query_id':qid,'evidence_id':'EV-'+qid,'spec_id':spec_id,'kind':kind,'clause_ids':list(clauses),
                'predicate':predicate,'symbol_domain':identity['symbol_domain'],'cache_key':key,
                'raw_result':None,'status':'NOT_RUN','witness_status':'UNAVAILABLE',
                'meaning':'SAT means this predicate has an assignment; not a function verification verdict'}
        if not self.budget.reserve('query',function.function_id):result['error']='BUDGET_EXHAUSTED'
        elif not self.caps.get('ready'):result['status']='UNKNOWN';result['error']='TOOLCHAIN_NOT_READY'
        else:
            try:
                job=emit(function,predicate,qid,spec_id,directory,self.dependencies)
                write_json_atomic(directory/'query.json',result)
                execution=verify(job,self.caps,self.config,directory,trace=self.trace)
                decided=execution['conclusion_gate']['allowed'] and execution['raw_result'] in ('SAT','UNSAT')
                result.update(status=('DECIDED' if self.config.tool_mode=='REAL' and not self.caps.get('mock_detected') else 'SIMULATED') if decided else execution['verdict'],
                              raw_result=execution['raw_result'] if decided else None,
                              error=execution.get('error'),execution_result=str(directory/'result.json'),
                              evidence_manifest=execution['evidence_manifest'])
            except (AgentError,OSError) as exc:
                result.update(status='UNKNOWN',error=exc.as_dict() if isinstance(exc,AgentError) else {'code':'QUERY_IO_ERROR','message':str(exc)})
        directory.mkdir(parents=True,exist_ok=True);write_json_atomic(directory/'query.json',result)
        self.results.append(result);self.cache[key]=result
        if self.trace:self.trace.emit('evaluation.query.finished',**result)
        return result

    def evaluate(self,spec,function,evidence):
        sid=spec['spec_id'];findings=[];used=[]
        try:pre,clauses=expressions(spec,function)
        except AgentError as exc:return [],[{'spec_id':sid,'reason':exc.code}]
        def ask(kind,parts,ids=()):
            result=self.query(function,sid,kind,conjunction(parts),ids);used.append(result)
            return result
        def raw(q):return q['raw_result'] if q['status']=='DECIDED' else None
        def add(dimension,code,message,queries,ids=(),severity='MEDIUM'):
            findings.append(finding(sid,dimension,code,message,clauses=ids,severity=severity,
                            evidence=[*evidence,*[q['evidence_id'] for q in queries]],kind='FORMAL',claim='PROVED'))
        p=ask('P_FEASIBILITY',[pre])
        if raw(p)=='UNSAT':
            add('nontriviality','PRECONDITION_INFEASIBLE','规约前提不可满足。',[p],severity='HIGH')
            return findings,[]
        if raw(p)!='SAT':return findings,[{'spec_id':sid,'reason':'PRECONDITION_UNDECIDED'}]
        effective=[c['effective'] for c in clauses]
        joint=ask('JOINT_ASSIGNMENT_EXISTS',[pre,*effective])
        if raw(joint)=='UNSAT':add('consistency','NO_COMMON_SATISFYING_ASSIGNMENT','在 P 下，全部后置义务不存在共同满足赋值。',[p,joint],severity='HIGH')
        for i,c in enumerate(clauses):
            ids=[c['id']];active=ask('GUARD_ACTIVE',[pre,c['guard']],ids)
            if raw(active)=='UNSAT':
                add('nontriviality','GUARD_UNREACHABLE_UNDER_P','P 可行，但该 guard 在 P 下不可达。',[p,active],ids,'HIGH');continue
            if raw(active)!='SAT':continue
            not_guard=ask('GUARD_OPTIONAL',[pre,'!('+c['guard']+')'],ids)
            original=spec['function_spec']['post_conditions'][i]
            if original['guard'] is not None and raw(not_guard)=='UNSAT':
                add('redundancy','GUARD_IMPLIED_BY_P','P 已蕴含该 guard；它不造成不可达，但适用条件重复。',[p,not_guard],ids,'LOW')
            counter=ask('CLAUSE_NONTRIVIAL',[pre,c['guard'],'!('+c['q']+')'],ids)
            if raw(counter)=='UNSAT':add('nontriviality','TAUTOLOGICAL_CLAUSE','对独立的类型正确输入/输出，该条款在活跃域恒成立。',[active,counter],ids,'HIGH')
            success=ask('CLAUSE_SATISFIABLE',[pre,c['guard'],c['q']],ids)
            if raw(success)=='UNSAT':add('consistency','UNSATISFIABLE_CLAUSE','该条款有活跃输入域，但没有满足赋值。',[active,success],ids,'HIGH')
            if len(clauses)>1:
                others=effective[:i]+effective[i+1:]
                base=ask('OTHER_CLAUSES_SATISFIABLE',[pre,*others],ids)
                if raw(base)=='SAT':
                    redundant=ask('CLAUSE_ENTAILED_BY_OTHERS',[pre,*others,'!('+c['effective']+')'],ids)
                    if raw(redundant)=='UNSAT':add('redundancy','CLAUSE_ENTAILED_BY_OTHERS','其他条款在非空满足域内蕴含该条款。',[base,redundant],ids,'LOW')
        # Cached evidence can originate from another function/specification with
        # the same typed domain. Its uncertainty must propagate to this consumer.
        uncertain=[{'query_id':r['query_id'],'reason':r.get('error') or r['status']} for r in used
                   if r['status']!='DECIDED']
        return findings,uncertain

    def compare(self,function,sid,pre,left,right,kind='REFERENCE_ENTAILMENT'):
        base=self.query(function,sid,kind+'_BASE',conjunction([pre,*left]))
        query=self.query(function,sid,kind,conjunction([pre,*left,'!('+conjunction(right)+')']))
        status=('PROVED' if base['raw_result']=='SAT' and query['raw_result']=='UNSAT' else 'DISPROVED' if query['raw_result']=='SAT' else 'UNKNOWN') if base['status']==query['status']=='DECIDED' else 'UNKNOWN'
        return {'status':status,'base_query':base['query_id'],'counterexample_query':query['query_id']}


class ReplayLogic(LogicEngine):
    """Reinterpret only recorded predicates; never invokes a tool."""
    def __init__(self,rows,caps):self.results=rows;self.caps=caps;self.used=set()
    def query(self,function,spec_id,kind,predicate,clauses=()):
        identity,key=query_key(function,predicate,self.caps)
        matches=[r for r in self.results if r['cache_key']==key]
        if len(matches)!=1:raise AgentError('QUERY_PLAN_MISMATCH','Missing or ambiguous recorded predicate')
        if matches[0]['predicate']!=predicate or matches[0]['symbol_domain']!=identity['symbol_domain']:
            raise AgentError('QUERY_PLAN_MISMATCH','Recorded predicate/domain differs from the plan')
        self.used.add(matches[0]['query_id']);return matches[0]


def assess_reference(engine,spec,function,reference,parent_requirements,program,evidence):
    from ..llm.parser import parse_response
    target=reference if 'function_spec' in reference else reference.get(spec['spec_id'],reference.get(function.name))
    if not target:return [],[{'spec_id':spec['spec_id'],'reason':'REFERENCE_FUNCTION_MISSING'}]
    target={'function_spec':target['function_spec'],'callee_expectations':target.get('callee_expectations',[])}
    parse_response(json.dumps(target),function,parent_requirements,program)
    pre,qs=expressions(spec,function);ref_pre,ref_qs=expressions(target,function)
    outside=engine.query(function,spec['spec_id'],'REFERENCE_INPUT_EXCLUDED',conjunction([ref_pre,'!('+pre+')']))
    findings=[];uncertain=[]
    if outside['status']=='DECIDED' and outside['raw_result']=='SAT':
        findings.append(finding(spec['spec_id'],'strength','INPUT_DOMAIN_EXCLUDES_REFERENCE',
            '相对于所提供参考输入域，P 排除了某些允许输入；参考本身并未被自动确认。',
            evidence=['EV-REFERENCE',outside['evidence_id'],*evidence],kind='FORMAL',claim='PROVED',severity='HIGH'))
    comparison=engine.compare(function,spec['spec_id'],conjunction([pre,ref_pre]),
        [q['effective'] for q in qs],[q['effective'] for q in ref_qs])
    if comparison['status']=='DISPROVED':
        findings.append(finding(spec['spec_id'],'strength','CANDIDATE_DOES_NOT_ENTAIL_REFERENCE',
            '在共同输入域内，候选不蕴含所提供参考；这只是相对参考的形式关系。',
            evidence=['EV-REFERENCE','EV-'+comparison['counterexample_query'],*evidence],kind='FORMAL',claim='PROVED',severity='HIGH'))
    if comparison['status']=='UNKNOWN' or outside['status']!='DECIDED':uncertain.append({'spec_id':spec['spec_id'],'reason':'REFERENCE_COMPARISON_UNDECIDED'})
    return findings,uncertain
