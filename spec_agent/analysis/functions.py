"""Strict unpreprocessed C subset using pycparser; never guess macro semantics."""
import re
from pathlib import Path
from pycparser import c_parser, c_ast, c_generator
from ..artifacts import digest, sha256_file
from ..models import FunctionContext, Parameter, ProgramModel

GEN=c_generator.CGenerator()
SCALARS={'int','unsigned int','unsigned','signed int','signed','short','short int','unsigned short',
         'unsigned short int','long','long int','unsigned long','unsigned long int','long long',
         'long long int','unsigned long long','unsigned long long int','char','signed char','unsigned char','_Bool'}

def clean_comments(text):
    token=r'//[^\n]*|/\*[\s\S]*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\''
    return re.sub(token,lambda m: re.sub(r'[^\n]',' ',m[0]) if m[0].startswith(('//','/*')) else m[0],text)

def typename(node):
    if isinstance(node,c_ast.TypeDecl) and isinstance(node.type,c_ast.IdentifierType) and not node.quals:
        return ' '.join(node.type.names)
    return GEN.visit(node)

def all_nodes(node):
    yield node
    for _,child in node.children(): yield from all_nodes(child)

class CAnalyzer:
    def analyze(self,sources):
        funcs,sites,unresolved,asts=[],[],[],{}
        for source in sources:
            source=Path(source); text=source.read_text(); cleaned=clean_comments(text)
            if re.search(r'^\s*#',cleaned,re.M):
                unresolved.append({'source':str(source),'code':'ANALYSIS_UNSUPPORTED','reason':'Preprocessor directives require an explicit preprocessed input; not silently expanded'})
                continue
            try: ast=c_parser.CParser().parse(cleaned,filename=str(source))
            except Exception as exc:
                unresolved.append({'source':str(source),'code':'ANALYSIS_UNSUPPORTED','reason':str(exc)}); continue
            for node in ast.ext:
                if not isinstance(node,c_ast.FuncDef): continue
                identity='/'.join(source.parts[-2:])
                fid='F-'+digest(identity+':'+node.decl.name)[:12]
                decl=node.decl.type; params=[]; issues=[]
                raw=decl.args.params if decl.args else []
                if len(raw)==1 and isinstance(raw[0],c_ast.Typename) and typename(raw[0].type)=='void': raw=[]
                if decl.args is None: issues.append('Old-style unspecified parameter list')
                for p in raw:
                    if not isinstance(p,c_ast.Decl) or not p.name: issues.append('Variadic/unnamed parameter'); continue
                    t=typename(p.type); params.append(Parameter(p.name,t))
                    if t not in SCALARS: issues.append('Unsupported parameter type: '+t)
                    if p.name in {'result','old',node.decl.name} or p.name.startswith('__sa_'): issues.append('Reserved formal/harness parameter name')
                ret=typename(decl.type)
                if ret not in SCALARS|{'void'}: issues.append('Unsupported return type: '+ret)
                start=node.decl.coord.line
                # Match braces lexically, excluding comments/strings; includes closing brace.
                mask=re.sub(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',lambda m:' '*len(m[0]),cleaned)
                offset=sum(len(l) for l in cleaned.splitlines(keepends=True)[:start-1])
                begin=mask.find('{',offset); depth=1; end=begin+1
                while depth and end<len(mask):
                    depth+=(mask[end]=='{')-(mask[end]=='}'); end+=1
                finish=mask.count('\n',0,end)+1
                body='\n'.join(text.splitlines()[start-1:finish])
                if re.search(r'\b__sa_',cleaned): issues.append('Source uses reserved __sa_ namespace')
                f=FunctionContext(fid,node.decl.name,GEN.visit(node.decl),ret,params,str(source),start,finish,body,sha256_file(source),storage=node.decl.storage,harness_issues=issues)
                funcs.append(f); asts[fid]=node
        for f in funcs:
            node=asts[f.function_id]
            local_names={p.name for p in f.parameters}|{n.name for n in all_nodes(node.body) if isinstance(n,c_ast.Decl) and not isinstance(n.type,c_ast.FuncDecl)}
            def walk(n,guards=(),parent=None):
                if isinstance(n,c_ast.If):
                    walk(n.cond,guards,n)
                    walk(n.iftrue,(*guards,GEN.visit(n.cond)),n)
                    if n.iffalse: walk(n.iffalse,(*guards,'!('+GEN.visit(n.cond)+')'),n)
                    return
                if isinstance(n,c_ast.FuncCall):
                    name=n.name.name if isinstance(n.name,c_ast.ID) else None
                    matches=[g for g in funcs if g.name==name and (g.source_file==f.source_file or 'static' not in g.storage)]
                    local=[g for g in matches if g.source_file==f.source_file and 'static' in g.storage]
                    if local: matches=local
                    target=matches[0] if len(matches)==1 and name not in local_names else None
                    line=n.coord.line; col=n.coord.column
                    cid='CALL-'+digest(f.function_id+':'+str(line)+':'+str(col))[:12]
                    lines=Path(f.source_file).read_text().splitlines()
                    bind=parent.name if isinstance(parent,c_ast.Decl) else GEN.visit(parent.lvalue) if isinstance(parent,c_ast.Assignment) else None
                    site={'callsite_id':cid,'caller_function':f.function_id,'callee_function':target.function_id if target else None,
                      'callee_name':name,'location':{'file':f.source_file,'line':line,'column':col},
                      'call_expression':GEN.visit(n),'arguments':[GEN.visit(a) for a in n.args.exprs] if n.args else [],
                      'result_binding':bind,'lexical_guards':list(guards),'guard_precision':'LEXICAL_ONLY',
                      'code_before':'\n'.join(lines[max(f.start_line-1,line-5):line-1]),
                      'code_after':'\n'.join(lines[line:min(f.end_line,line+4)])}
                    sites.append(site); f.callees.append(site)
                    if target: target.callers.append(site)
                    else:
                        unresolved.append({'code':'UNRESOLVED_CALL','function_id':f.function_id,'callsite_id':cid,'expression':GEN.visit(n)})
                        f.harness_issues.append('Unresolved external/indirect call: '+GEN.visit(n))
                for _,child in n.children(): walk(child,guards,n)
            walk(node.body)
        # Reject reachable unresolved calls, not just those directly in the target.
        byid={f.function_id:f for f in funcs}
        for f in funcs:
            todo=[f.function_id]; seen=set()
            while todo:
                v=todo.pop()
                if v in seen: continue
                seen.add(v)
                g=byid[v]
                if v!=f.function_id and any('Unresolved' in x for x in g.harness_issues): f.harness_issues.append('Reachable unresolved call in '+g.name)
                todo.extend(s['callee_function'] for s in g.callees if s['callee_function'])
        order,cycles=top_down(funcs)
        unresolved.extend({'code':'CYCLIC_EXPECTATIONS_PARTIAL','function_id':f} for f in cycles)
        return ProgramModel(funcs,sites,unresolved,order)

def top_down(funcs):
    edges={f.function_id:{s['callee_function'] for s in f.callees if s['callee_function']} for f in funcs}
    incoming={x:0 for x in edges}
    for targets in edges.values():
        for x in targets: incoming[x]+=1
    ready=sorted(x for x,n in incoming.items() if not n); order=[]
    while ready:
        x=ready.pop(0); order.append(x)
        for y in sorted(edges[x]):
            incoming[y]-=1
            if not incoming[y]: ready.append(y); ready.sort()
    cycles=sorted(set(edges)-set(order))
    return order+cycles,cycles
