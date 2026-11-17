"""Small source-referenced context packages and explicit omission records."""
import json
import math
from dataclasses import asdict
from ..artifacts import digest
from ..errors import AgentError
from .models import VERSION


def pointer(value,path):
    for part in path.strip('/').split('/') if path else []:
        part=part.replace('~1','/').replace('~0','~')
        value=value[int(part)] if isinstance(value,list) else value[part]
    return value


def estimated_tokens(value):
    return math.ceil(len(json.dumps(value,ensure_ascii=False).encode('utf-8'))/2)


class ContextBuilder:
    def __init__(self,parent,index,limits):
        self.parent,self.index,self.limits=parent,index,limits;self.evidence={};self.omitted=[]
    def register(self,artifact,*,json_pointer=None,lines=None,origin='SOURCE_TEXT'):
        text=self.parent.text(artifact);path=self.parent.path(artifact)
        value=pointer(self.parent.read(artifact),json_pointer) if json_pointer is not None else text
        if lines:
            start,end=lines
            if not 1<=start<=end<=len(text.splitlines()):raise AgentError('CONTEXT_INVALID','Invalid source span')
            value=''.join(text.splitlines(keepends=True)[start-1:end])
        row={'artifact_ref':path.relative_to(self.parent.root).as_posix(),'sha256':self.parent.dependencies[path.relative_to(self.parent.root).as_posix()],
             'json_pointer':json_pointer,'line_range':list(lines) if lines else None,'content':value,
             'origin':origin,'completeness':'COMPLETE'}
        eid='EV-'+digest(json.dumps(row,ensure_ascii=False,sort_keys=True))[:20]
        self.evidence[eid]=dict(evidence_id=eid,**row);return eid
    def build(self,spec):
        f=self.parent.functions[spec['function_id']];sid=spec['spec_id'];fs=spec['function_spec']
        ids=[self.register('specs/semantic/'+sid+'.json',json_pointer='/function_spec',origin='GENERATED_SPECIFICATION')]
        requested=set(fs['requirement_refs'])|{r for q in fs['post_conditions'] for r in q['requirement_refs']}
        relevant=[r for r in self.index['items'] if r['requirement_id'] in requested] or self.index['items']
        requirement_items=[]
        for r in relevant:
            eid=self.register('input/requirements.md',lines=(r['start_line'],r['end_line']))
            ids.append(eid);requirement_items.append({**r,'evidence_id':eid})
        source=self.register(f.source_file,lines=(f.start_line,f.end_line),origin='IMPLEMENTATION_FACT')
        # The implementation remains in the catalog, not the blinded review input.
        function={'function_id':f.function_id,'name':f.name,'signature':f.signature,
                  'parameters':[asdict(p) for p in f.parameters],'return_type':f.return_type}
        sites=[s for s in self.parent.program.callsites if f.function_id in (s['caller_function'],s['callee_function'])]
        selected=sites[:self.limits.callsites]
        omissions=[{'kind':'CALLSITE','callsite_id':s['callsite_id'],'reason':'CALLSITE_BUDGET'} for s in sites[len(selected):]]
        source_ids={}
        for site in selected:
            loc=site['location'];line=loc['line']
            source_ids[site['callsite_id']]=self.register(loc['file'],lines=(line,line),origin='CALLSITE_FACT')
        neighbors=[]
        neighbor_ids={s['callee_function'] for s in selected}|{s['caller_function'] for s in selected}
        for other in self.parent.specs:
            if other['function_id']!=f.function_id and other['function_id'] in neighbor_ids:
                eid=self.register('specs/semantic/'+other['spec_id']+'.json',json_pointer='/function_spec',origin='GENERATED_SPECIFICATION')
                neighbors.append({'spec_id':other['spec_id'],'function_spec':other['function_spec'],'evidence_id':eid})
        optional={}
        for name,ref in [('domain_knowledge','input/domain_knowledge.json'),('generation_constraints','input/generation_constraints.json')]:
            if self.parent.path(ref).exists():
                eid=self.register(ref);ids.append(eid);optional[name]=self.parent.read(ref)
        issues=[x for x in self.parent.program.unresolved if x.get('function_id')==f.function_id or x.get('source')==f.source_file]
        normalized_sites=[{**s,'location':{**s['location'],'file':self.parent.path(s['location']['file']).relative_to(self.parent.root).as_posix()},
                           'evidence_id':source_ids[s['callsite_id']]} for s in selected]
        context={'schema_version':1,'evaluator_version':VERSION,'spec_id':sid,'function':function,
                 'requirements':requirement_items,'function_spec':fs,'evidence_ids':ids,
                 'callsites':normalized_sites,
                 'related_specs':neighbors,'caller_expectations':f.caller_expectations,
                 'context_issues':issues,'omitted_context':omissions,'optional':optional,
                 'implementation_evidence_id':source,
                 'review_policy':'REQUIREMENTS_FIRST; implementation and verification verdict withheld'}
        while estimated_tokens(context)>self.limits.input_tokens and context['related_specs']:
            value=context['related_specs'].pop();context['omitted_context'].append({'kind':'RELATED_SPEC','spec_id':value['spec_id'],'reason':'CONTEXT_BUDGET'})
        while estimated_tokens(context)>self.limits.input_tokens and context['callsites']:
            value=context['callsites'].pop();context['omitted_context'].append({'kind':'CALLSITE','callsite_id':value['callsite_id'],'reason':'CONTEXT_BUDGET'})
        context['context_completeness']='PARTIAL' if issues or context['omitted_context'] or spec.get('generation',{}).get('caller_expectations_partial') else 'COMPLETE'
        context['estimated_input_tokens']=estimated_tokens(context)
        context['within_budget']=context['estimated_input_tokens']<=self.limits.input_tokens
        context['cache_key']=digest(json.dumps({'context':context,'version':VERSION},sort_keys=True,ensure_ascii=False))
        self.omitted.extend(context['omitted_context'])
        return context
    def review_view(self,context):
        view={k:v for k,v in context.items() if k not in ('implementation_evidence_id','cache_key','estimated_input_tokens','within_budget')}
        allowed=set(context['evidence_ids'])|{s['evidence_id'] for s in context['callsites']}|{s['evidence_id'] for s in context['related_specs']}
        return {'context':view,'evidence_catalog':{k:self.evidence[k] for k in sorted(allowed)}}
