"""Strict A/B candidate gates. Schema checks do not infer missing information."""
from collections import Counter

from .dataset import definitions
from .semantics import Invalid, expand, join, named, normal, symbols, KEYWORDS


def fields(obj, required, optional=()):
    if not isinstance(obj,dict) or not set(required)<=obj.keys()<=set(required)|set(optional):
        raise Invalid('SCHEMA_FIELDS')


def array(value, cap=128):
    if not isinstance(value,list) or len(value)>cap: raise Invalid('SCHEMA_ARRAY')
    return value


def ids(value):
    array(value)
    if not all(named(n) and n not in KEYWORDS for n in value) or len(set(value))!=len(value):
        raise Invalid('INVALID_IDS')
    return value


def source_fragments(case):
    """Paths address the authored body AST, not the expanded guard wrapper."""
    defs=definitions(case); frags={}; roles={}
    for s in case['S']:
        sid=s['id']; expr=s['expr']; roles[sid]=s['role']
        pieces={'':expr}
        if isinstance(expr,list) and expr[0]=='and': pieces.update({f'/args/{i}':a for i,a in enumerate(expr[1:])})
        frags[sid]={p:['implies',defs[s['guard']],e] if 'guard' in s else e for p,e in pieces.items()}
    return frags,roles


def validate_shape(mode, candidate):
    fields(candidate,('clauses',) if mode=='A' else ('roots','nodes','guards'))
    if mode=='B':
        array(candidate['roots']);
        if not isinstance(candidate['guards'],dict) or len(candidate['guards'])>48: raise Invalid('SCHEMA_GUARDS')
    for n in array(candidate['clauses' if mode=='A' else 'nodes']):
        if mode=='A':
            fields(n,('id','kind','expr','from')); array(n['from'],8)
            for r in n['from']: fields(r,('s_id','path'))
        else:
            fields(n,('id','kind','semantic','origin'),('links',));fields(n['origin'],('s_refs',),('r_refs',))
            for r in array(n['origin']['s_refs'],8): fields(r,('s_id','path'))
            if n['kind']=='group':
                fields(n['semantic'],('role','combine')); fields(n.get('links'),('member',));array(n['links']['member'])
            elif n['kind']=='clause':
                fields(n['semantic'],('role','expr'),('guard_ref',))
                if 'links' in n: raise Invalid('SCHEMA_CLAUSE_LINKS')
            else: raise Invalid('SCHEMA_NODE_KIND')


def normalize_ir(mode, candidate, case):
    validate_shape(mode,candidate)
    fragments,roles=source_fragments(case); names=symbols(case)
    req={s['id']:set(s['requirement_refs']) for s in case['S']}
    def origins(rr, role):
        if not rr: raise Invalid('MISSING_SOURCE')
        pairs=[]
        for r in rr:
            sid,p=r['s_id'],r['path']
            if not isinstance(sid,str) or not isinstance(p,str) or sid not in fragments or p not in fragments[sid]:
                raise Invalid('SOURCE_PATH')
            if roles[sid]!=role: raise Invalid('SOURCE_ROLE',sid)
            pairs.append((sid,p))
        if len(set(pairs))!=len(pairs): raise Invalid('DUPLICATE_SOURCE_PATH')
        return pairs
    clauses=[]; seen_nodes=set(); used_guards=set()
    if mode=='A':
        ids([n['id'] for n in candidate['clauses']])
        for n in candidate['clauses']:
            role=n['kind']; refs=origins(n['from'],role)
            clauses.append({'id':n['id'],'role':role,'expr':expand(n['expr'],names,role),'sources':refs})
    else:
        nodes={n['id']:n for n in candidate['nodes'] if named(n['id'])}
        ids([n['id'] for n in candidate['nodes']]); ids(candidate['roots'])
        guards=candidate['guards']; ids(list(guards)); known=definitions(case)
        gv=set(); gc={}
        def guard(name,depth=0):
            if not named(name) or name not in guards or name not in known: raise Invalid('GUARD_REFERENCE')
            if name in gv: raise Invalid('GUARD_CYCLE')
            if depth>20: raise Invalid('GRAPH_LIMIT')
            used_guards.add(name)
            if name not in gc:
                gv.add(name);gc[name]=expand(guards[name],names,'requires',lambda x:guard(x,depth+1));gv.remove(name)
                if normal(gc[name])!=normal(known[name]): raise Invalid('GUARD_CHANGED',name)
            return gc[name]
        visiting=set()
        def visit(nid,depth=0):
            if depth>20: raise Invalid('GRAPH_LIMIT')
            if nid in visiting: raise Invalid('GRAPH_CYCLE')
            if nid not in nodes: raise Invalid('NODE_REFERENCE')
            if nid in seen_nodes: raise Invalid('DUPLICATE_GRAPH_MEMBERSHIP')
            visiting.add(nid);seen_nodes.add(nid)
            n=nodes[nid]; sem=n['semantic'];role=sem['role']; refs=origins(n['origin']['s_refs'],role)
            if 'r_refs' in n['origin'] and set(ids(n['origin']['r_refs']))!=set().union(*(req[s] for s,_ in refs)):
                raise Invalid('REQUIREMENT_REFERENCE')
            if n['kind']=='group':
                children=ids(n['links']['member'])
                if sem['combine']!='and' or not children: raise Invalid('GROUP_COMBINE')
                descendant=[]
                for child in children: descendant.extend(visit(child,depth+1))
                if any(c['role']!=role for c in descendant): raise Invalid('GROUP_ROLE')
                group_sources={s for c in descendant for s,_ in c['sources']}
                if group_sources!={s for s,_ in refs} or any(p for _,p in refs): raise Invalid('GROUP_SOURCE')
                result=descendant
            else:
                expr=expand(sem['expr'],names,role)
                if 'guard_ref' in sem:
                    if role!='ensures': raise Invalid('GUARD_IN_REQUIRES')
                    expr=['implies',guard(sem['guard_ref']),expr]
                result=[{'id':nid,'role':role,'expr':expr,'sources':refs}]
            visiting.remove(nid)
            return result
        for root in candidate['roots']: clauses.extend(visit(root))
        if seen_nodes!=set(nodes): raise Invalid('UNREACHABLE_NODE')
        if used_guards!=set(guards): raise Invalid('UNUSED_GUARD')
    return clauses


def structural(clauses,case):
    """Same COPY/SPLIT language for A and B; no semantic-changing rewrites."""
    frags,_=source_fragments(case); counts=Counter(); issues=[]
    for c in clauses:
        refs=c['sources'];counts.update(refs)
        if len(refs)!=1:
            issues.append({'code':'MULTI_SOURCE_NOT_IN_MAIN_RULES','node':c['id'],'sources':refs});continue
        s,p=refs[0];expected=frags[s][p]
        if normal(c['expr'])!=normal(expected):
            issues.append({'code':'SOURCE_FRAGMENT_CHANGED','node':c['id'],'sources':refs})
    for s,paths in frags.items():
        observed={p for sid,p in counts if sid==s}
        if observed not in ({''},set(paths)-{''}) or not observed or any(counts[s,p]!=1 for p in observed):
            issues.append({'code':'SOURCE_FRAGMENT_COVERAGE','source':s,'observed':sorted(observed),'expected_options':[[''],sorted(set(paths)-{''})]})
    return issues


def canonical_ir(case,mode):
    frags,roles=source_fragments(case); a=[]; b=[]; roots=[]
    for s in case['S']:
        sid=s['id']; body=s['expr']; role=roles[sid]
        split=len(frags[sid])>1 and role=='ensures'; paths=list(frags[sid])[1:] if split else ['']; members=[]
        for i,p in enumerate(paths,1):
            nid=f'I{sid}_{i}'; members.append(nid); refs=[{'s_id':sid,'path':p}]
            a.append({'id':nid,'kind':role,'expr':frags[sid][p],'from':refs})
            sem={'role':role,'expr':body[i] if split else body}
            if 'guard' in s: sem['guard_ref']=s['guard']
            b.append({'id':nid,'kind':'clause','semantic':sem,'origin':{'s_refs':refs}})
        if split:
            gid='G'+sid; roots.append(gid)
            b.append({'id':gid,'kind':'group','semantic':{'role':role,'combine':'and'},'origin':{'s_refs':[{'s_id':sid,'path':''}]},'links':{'member':members}})
        else: roots.extend(members)
    return {'clauses':a} if mode=='A' else {'roots':roots,'nodes':b,'guards':case['definitions']}


SCHEMA={
    'version':'ir-ab-v1',
    'common':{'expr':'Boolean true/false; [and, ...], [or, ...], [not, e], [implies, g, e]; [eq|ne|lt|le|gt|ge, operand, operand]. Operands are parameter names, result in ensures, or signed int32 literals. For and/or give at least 2 children.',
              'paths':'Each leaf has exactly one source. path="" means whole S.body; /args/i means i-th child of top-level AND in S.expr (i zero-based). Use one whole leaf or all children exactly once. Reapply the original source guard to every split leaf. No rewrites except AND/OR regrouping/reordering. Keep roles unchanged.',
              'example_source':{'id':'S7','role':'ensures','expr':['le','result','high']}},
    'A':{'shape':{'clauses':[{'id':'I7','kind':'ensures','expr':['le','result','high'],'from':[{'s_id':'S7','path':''}]}]},'guard':'Expand every guard and all nested guard refs as [implies, expandedGuard, body]. No ref opcode in A. Do not duplicate preconditions.'},
    'B':{'shape':{'roots':['I7'],'nodes':[{'id':'I7','kind':'clause','semantic':{'role':'ensures','expr':['le','result','high']},'origin':{'s_refs':[{'s_id':'S7','path':''}]}}],'guards':{}},
         'guard':'Copy used guard definitions under their source names, preserving [ref,name] inside definitions; use semantic.guard_ref on guarded leaves, or inline the expanded implication. Include only transitively used guards. Guard refs never appear in clause expr.',
         'groups':'Optional group {id,kind:"group",semantic:{role,combine:"and"},origin:{s_refs:[{s_id,path:""}]},links:{member:[childIds]}}. Same-role members, all nodes reachable once from roots, no cycle. Group origin source IDs match descendant source IDs. Optional origin.r_refs must exactly match source links.'},
    'Direct':{'shape':'one plain ACSL /*@ ... */ comment then the exact C prototype; no Markdown, implementation, macro or additional annotation. One assigns \\nothing;. requires/ensures use supported comparisons, &&, ||, !, ==>, \\true, \\false and \\result.'},
}
