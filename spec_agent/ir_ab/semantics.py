"""Signed int32 comparisons over independent inputs and return; no program execution."""
import ctypes as C
import hashlib
import json
import re
from pathlib import Path
from time import perf_counter

from ..artifacts import write_json_atomic, sha256_file

MIN, MAX = -(2**31), 2**31-1
IDENT = re.compile(r'[A-Za-z][A-Za-z0-9_]{0,63}\Z')
KEYWORDS = set('auto break case char const continue default do double else enum extern float for goto if int long register return short signed sizeof static struct switch typedef union unsigned void volatile while inline restrict requires ensures assigns result true false'.split())
CMPS = dict(eq='==', ne='!=', lt='<', le='<=', gt='>', ge='>=')
SMT = dict(eq='=', ne='distinct', lt='<', le='<=', gt='>', ge='>=', implies='=>', **{'and':'and','or':'or','not':'not'})
PROFILE = {'model':'LP64', 'int_bits':32, 'signed':True, 'frame':'nothing',
           'scope':'normal-return P/Q; no body, heap, termination or ACSL behaviors'}


class Invalid(ValueError):
    def __init__(self, code, detail=''):
        super().__init__(code, detail)
        self.code, self.detail = code, detail


def canon(obj):
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(',', ':'))


def digest(obj):
    return hashlib.sha256(canon(obj).encode()).hexdigest()


def named(s):
    return isinstance(s,str) and bool(IDENT.fullmatch(s))


def symbols(case):
    params=case['params']
    if len(set(params))!=len(params) or not all(named(p) and p not in KEYWORDS for p in params):
        raise Invalid('INVALID_SIGNATURE')
    return params+['result']


def expand(expr, names, role, lookup=None, depth=0, budget=None):
    """Check grammar and scope while producing a typed, reference-free AST."""
    if budget is None: budget=[4096]
    budget[0]-=1
    if depth>48 or budget[0]<0: raise Invalid('EXPRESSION_LIMIT')
    if type(expr) is bool: return expr
    if not isinstance(expr,list) or not expr or not isinstance(expr[0],str): raise Invalid('EXPRESSION_TYPE')
    op,*args=expr
    if op=='ref' and len(args)==1 and lookup is not None and named(args[0]):
        # lookup returns a raw expression; a caller-supplied resolver checks cycles.
        return expand(lookup(args[0]),names,role,None,depth+1,budget)
    if op in CMPS and len(args)==2:
        for x in args:
            if type(x) is int and MIN<=x<=MAX: continue
            if isinstance(x,str) and x in names and (x!='result' or role=='ensures'): continue
            raise Invalid('SYMBOL_OR_INTEGER_DOMAIN',str(x)[:80])
        return expr
    if (op in ('and','or') and 2<=len(args)<=64 or op=='not' and len(args)==1 or op=='implies' and len(args)==2):
        return [op,*[expand(x,names,role,lookup,depth+1,budget) for x in args]]
    raise Invalid('UNSUPPORTED_EXPRESSION',op)


def join(op, values):
    values=list(values)
    return [op,*values] if len(values)>1 else values[0] if values else op=='and'


def normal(expr):
    if not isinstance(expr,list): return expr
    op,*args=expr
    if op not in ('and','or'): return [op,*[normal(a) for a in args]]
    flat=[]
    for a in map(normal,args):
        flat.extend(a[1:] if isinstance(a,list) and a[0]==op else [a])
    return join(op,sorted(flat,key=canon))


def render(expr):
    if type(expr) is bool: return r'\true' if expr else r'\false'
    if type(expr) is int: return str(expr)
    if isinstance(expr,str): return r'\result' if expr=='result' else expr
    op,*xs=expr
    if op=='not': return '(!'+render(xs[0])+')'
    symbol=(CMPS|{'and':'&&','or':'||','implies':'==>'})[op]
    return '('+f' {symbol} '.join(map(render,xs))+')'


def signature(case):
    if not named(case['id']) or case['id'] in KEYWORDS: raise Invalid('INVALID_SIGNATURE')
    return f"int {case['id']}({', '.join('int '+s for s in symbols(case)[:-1]) or 'void'});"


def emit(case, clauses):
    return ('/*@\n' + r'  assigns \nothing;'+'\n'+''.join(
        f"  {c['role']} {c['id']}: {render(c['expr'])};\n" for c in clauses)+'*/\n'+signature(case)+'\n')


TOKEN=re.compile(r'\s*(\\(?:result|true|false|nothing)\b|[A-Za-z][A-Za-z0-9_]*|[0-9]+|==>|==|!=|<=|>=|&&|\|\||[():;,!<>-])')
INFIX={'==>':(1,'implies'),'||':(2,'or'),'&&':(3,'and'),
       **{v:(4,k) for k,v in CMPS.items()}}


class Parser:
    def __init__(self,text):
        if len(text)>100000: raise Invalid('OUTPUT_LIMIT')
        text=text.strip(); pos=0; self.ts=[]; self.i=0
        while pos<len(text):
            t=TOKEN.match(text,pos)
            if not t: raise Invalid('UNSUPPORTED_ACSL_TOKEN',str(pos))
            self.ts.append(t[1]); pos=t.end()
        if len(self.ts)>12000: raise Invalid('OUTPUT_LIMIT')

    def peek(self): return self.ts[self.i] if self.i<len(self.ts) else None

    def take(self,expect=None):
        t=self.peek()
        if t is None or expect is not None and t!=expect: raise Invalid('ACSL_SYNTAX',f'expected {expect}')
        self.i+=1
        return t

    def expr(self,minimum=0,depth=0):
        if depth>64: raise Invalid('EXPRESSION_LIMIT')
        t=self.take()
        if t=='(':
            a=self.expr(0,depth+1); self.take(')')
        elif t=='!': a=['not',self.expr(5,depth+1)]
        elif t in (r'\true',r'\false'): a=t==r'\true'
        elif t==r'\result': a='result'
        elif t=='result': raise Invalid('ACSL_RESULT_KEYWORD')
        elif t=='-' or t.isdecimal():
            n=self.take() if t=='-' else t
            if not re.fullmatch(r'0|[1-9][0-9]{0,9}',n): raise Invalid('UNSUPPORTED_INTEGER_LITERAL')
            a=int(n)*(-1 if t=='-' else 1)
        elif named(t): a=t
        else: raise Invalid('ACSL_SYNTAX')
        while self.peek() in INFIX:
            priority,op=INFIX[self.peek()]
            if priority<minimum: break
            self.take(); a=[op,a,self.expr(priority+(op!='implies'),depth+1)]
        return a


def read_acsl(text,case):
    """Strict whole-file readback, not clause extraction. Reject everything outside the profile."""
    m=re.fullmatch(r'\s*/\*@((?:(?!\*/)[\s\S])*)\*/\s*(.*?)\s*',text,re.S)
    if not m: raise Invalid('ACSL_FILE_SHAPE')
    if Parser(m[2]).ts!=Parser(signature(case)).ts: raise Invalid('SIGNATURE_MISMATCH')
    p=Parser(m[1]); clauses=[]; frames=0; labels=set()
    while p.peek() is not None:
        role=p.take()
        if role=='assigns':
            p.take(r'\nothing'); p.take(';'); frames+=1; continue
        if role not in ('requires','ensures'): raise Invalid('UNSUPPORTED_ACSL_CLAUSE',role)
        label=None
        if p.i+1<len(p.ts) and p.ts[p.i+1]==':':
            label=p.take(); p.take(':')
            if not named(label) or label in KEYWORDS or label in labels: raise Invalid('INVALID_LABEL')
            labels.add(label)
        expr=expand(p.expr(),symbols(case),role);p.take(';')
        clauses.append({'id':label,'role':role,'expr':expr})
    if frames!=1: raise Invalid('FRAME_MISMATCH')
    return clauses


def smt(expr, env):
    if type(expr) is bool: return str(expr).lower()
    if type(expr) is int: return str(expr) if expr>=0 else f'(- {-expr})'
    if isinstance(expr,str): return env[expr]
    op,*xs=expr
    return '('+SMT[op]+' '+' '.join(smt(x,env) for x in xs)+')'


def domain(name): return f'(and (<= (- {-MIN}) {name}) (<= {name} {MAX}))'


class Solver:
    """Real libz3 C API, with replayable SMT-LIB and separately validated SAT evidence."""
    def __init__(self, library, root=None, timeout=2500, cache=None, quota=4096):
        self.path=Path(library).resolve(strict=True)
        self.identity={'library':str(self.path),'sha256':sha256_file(self.path)}
        self.lib=C.CDLL(str(self.path)); self.root=root; self.timeout=timeout
        self.cache={} if cache is None else cache; self.rows=[]; self.quota=quota
        for name,ret,args in [
            ('Z3_mk_config',C.c_void_p,[]),('Z3_del_config',None,[C.c_void_p]),
            ('Z3_mk_context',C.c_void_p,[C.c_void_p]),('Z3_del_context',None,[C.c_void_p]),
            ('Z3_eval_smtlib2_string',C.c_char_p,[C.c_void_p,C.c_char_p]),
            ('Z3_get_full_version',C.c_char_p,[]),('Z3_set_error_handler',None,[C.c_void_p,C.c_void_p]),
        ]:
            f=getattr(self.lib,name); f.restype=ret; f.argtypes=args
        self.identity['version']=self.lib.Z3_get_full_version().decode()

    def run_raw(self, script):
        cfg=self.lib.Z3_mk_config(); ctx=self.lib.Z3_mk_context(cfg); self.lib.Z3_del_config(cfg)
        errors=[]
        callback=C.CFUNCTYPE(None,C.c_void_p,C.c_int)(lambda _, code: errors.append(code))
        self.lib.Z3_set_error_handler(ctx,callback)
        try:
            out=self.lib.Z3_eval_smtlib2_string(ctx,script.encode())
            return out.decode(errors='replace') if out else '',errors
        finally: self.lib.Z3_del_context(ctx)

    def ask(self, label, names, predicate, *, total=False, reuse=True):
        # Internal totality probe: P && !exists result.(domain(result) && Q).
        env={n:f'v{i}' for i,n in enumerate(names)}
        variables=list(env.values())
        if total:
            p,q=predicate; r=env['result']; variables.remove(r)
            formula=f'(and {smt(p,env)} (not (exists (({r} Int)) (and {domain(r)} {smt(q,env)}))))'
        else: formula=smt(predicate,env)
        script=f'(set-option :timeout {self.timeout})\n'+''.join(f'(declare-const {v} Int)\n(assert {domain(v)})\n' for v in variables)+f'(assert {formula})\n(check-sat)\n'
        key=digest([self.identity['sha256'],PROFILE,names,script]); start=perf_counter()
        previous=self.cache.get(key) if reuse else None
        index=len(self.rows)+1
        if previous:
            row={**previous,'label':label,'key':key,'reused':True,'time_ms':0}
        elif index>self.quota:
            row={'label':label,'key':key,'status':'NOT_RUN','reason':'QUERY_BUDGET','reused':False,'time_ms':0}
        else:
            out,errors=self.run_raw(script); first=out.strip()
            status=first.upper() if not errors and first in ('sat','unsat','unknown') else 'ERROR'
            witness=None; witness_output=None; witness_errors=[]; witness_script=None
            if status=='SAT' and variables:
                # Ask the same query plus get-value, then replay the assignment by asserting it.
                witness_script=script+f"(get-value ({' '.join(variables)}))\n"
                witness_output,witness_errors=self.run_raw(witness_script)
                if not witness_errors and witness_output.startswith('sat\n'):
                    pairs=re.findall(r'\((v[0-9]+)\s+(-?[0-9]+|\(-\s+[0-9]+\))\)',witness_output)
                    model={v:int(s[2:-1].strip())*-1 if s.startswith('(-') else int(s) for v,s in pairs}
                    if len(pairs)==len(variables) and set(model)==set(variables) and all(MIN<=x<=MAX for x in model.values()):
                        fixed=''.join(f'(assert (= {v} {smt(x,env)}))\n' for v,x in model.items())
                        replay=script.removesuffix('(check-sat)\n')+fixed+'(check-sat)\n'
                        replay_out,replay_errors=self.run_raw(replay)
                        if replay_out.strip()=='sat' and not replay_errors: witness={n:model[v] for n,v in env.items() if v in model}
                    else: replay=replay_out=None; replay_errors=[]
                else: replay=replay_out=None; replay_errors=[]
            else: replay=replay_out=None; replay_errors=[]
            row={'label':label,'key':key,'status':status,'raw':out,'errors':errors,'witness':witness,
                 'witness_script':witness_script,'witness_raw':witness_output,'witness_errors':witness_errors,
                 'witness_replay_script':replay,'witness_replay_raw':replay_out,'witness_replay_errors':replay_errors,
                 'witness_status':'REPLAYED' if witness is not None else 'UNAVAILABLE','reused':False,
                 'time_ms':round((perf_counter()-start)*1000,3),'origin':str(self.root or '')}
            if status in ('SAT','UNSAT'): self.cache[key]=row
        self.rows.append(row)
        if self.root is not None:
            d=self.root/f'{index:04d}';d.mkdir(parents=True,exist_ok=False)
            (d/'query.smt2').write_text(script,encoding='utf-8');write_json_atomic(d/'result.json',row)
        return row


def pq(clauses):
    return tuple(join('and',(c['expr'] for c in clauses if c['role']==role)) for role in ('requires','ensures'))


def compare(solver, names, old, new, label, *, pre=True, reuse=True):
    p,q=old; r,s=new
    plan=[('P_REF_FEASIBLE',p,'SAT'),('P_CAND_FEASIBLE',r,'SAT'),
          ('P_SHRUNK',['and',p,['not',r]],'UNSAT'),('P_EXPANDED',['and',r,['not',p]],'UNSAT')] if pre else []
    plan += [('Q_WEAKENED',['and',p,r,s,['not',q]],'UNSAT'),('Q_STRENGTHENED',['and',p,r,q,['not',s]],'UNSAT')]
    rows=[(k,solver.ask(label+'/'+k,names,f,reuse=reuse),expected) for k,f,expected in plan]
    bad=[k for k,x,e in rows if x['status'] in ('SAT','UNSAT') and x['status']!=e]
    other=[x['status'] for _,x,_ in rows if x['status'] not in ('SAT','UNSAT')]
    status='FAIL' if bad else 'ERROR' if 'ERROR' in other else 'UNKNOWN' if other else 'PASS'
    return {'status':status,'differences':bad,'queries':[dict(kind=k,key=x['key'],raw_status=x['status'],witness=x.get('witness'),reused=x['reused']) for k,x,_ in rows]}
