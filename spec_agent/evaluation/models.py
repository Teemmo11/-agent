"""Versioned evaluation vocabulary and run-wide resource accounting."""
from dataclasses import dataclass, field
from ..artifacts import digest
from ..errors import AgentError

VERSION='2.0.0'
DIMENSIONS=('alignment','strength','nontriviality','coverage','redundancy','clarity','usefulness','consistency')
SEVERITIES={'INFO':0,'LOW':1,'MEDIUM':2,'HIGH':3}


@dataclass
class Limits:
    input_tokens: int = 16000
    output_tokens: int = 2048
    llm_calls: int = 64
    total_tokens: int = 128000
    queries: int = 1000
    queries_per_function: int = 128
    calls_per_function: int = 2
    callsites: int = 8
    def validate(self):
        for key,value in vars(self).items():
            if type(value) is not int or value<0 or value>1000000:
                raise AgentError('EVALUATION_CONFIG_INVALID','Invalid limit: '+key)
        if self.input_tokens<512 or not 128<=self.output_tokens<=65536:
            raise AgentError('EVALUATION_CONFIG_INVALID','Context/output limits outside supported range')


@dataclass
class Budget:
    limits: Limits = field(default_factory=Limits)
    calls: int = 0
    reserved_tokens: int = 0
    query_count: int = 0
    actual_tokens: int = 0
    by_function: dict = field(default_factory=dict)
    stops: list = field(default_factory=list)
    def reserve(self,kind,fid,tokens=0):
        row=self.by_function.setdefault(fid,{'calls':0,'queries':0})
        if kind=='llm':
            allowed=(self.calls<self.limits.llm_calls and row['calls']<self.limits.calls_per_function
                     and self.reserved_tokens+tokens<=self.limits.total_tokens and self.actual_tokens<self.limits.total_tokens)
            if allowed:self.calls+=1;row['calls']+=1;self.reserved_tokens+=tokens
        else:
            allowed=self.query_count<self.limits.queries and row['queries']<self.limits.queries_per_function
            if allowed:self.query_count+=1;row['queries']+=1
        if not allowed:self.stops.append({'kind':kind,'function_id':fid,'reason':'BUDGET_EXHAUSTED'})
        return allowed
    def snapshot(self):
        return {'limits':vars(self.limits),'llm_calls':self.calls,'reserved_tokens':self.reserved_tokens,
                'token_counting':'CONSERVATIVE_BYTE_ESTIMATE_NOT_EXACT','provider_reported_tokens':self.actual_tokens,'queries':self.query_count,
                'by_function':self.by_function,'stops':self.stops}
    def charge(self,metadata):
        usage=metadata.get('usage') or {}
        total=usage.get('total_tokens',usage.get('prompt_tokens',0)+usage.get('completion_tokens',0))
        if type(total) is int and total>=0:self.actual_tokens+=total
        if self.actual_tokens>self.limits.total_tokens:
            self.stops.append({'kind':'llm','reason':'PROVIDER_TOKEN_BUDGET_EXCEEDED'})


def finding(spec_id,dimension,code,explanation,*,clauses=(),severity='MEDIUM',
            evidence=(),kind='DETERMINISTIC',claim='OBSERVED',action='复核原文和适用范围。'):
    value={'spec_id':spec_id,'clause_ids':list(clauses),'dimension':dimension,'code':code,
           'severity':severity,'evidence_kind':kind,'claim_status':claim,'evidence_ids':list(evidence),
           'explanation':explanation,'suggested_action':action}
    value['finding_id']='FIND-'+digest(str(value))[:16]
    return value
