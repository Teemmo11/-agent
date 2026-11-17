"""Small total expression language: comparisons, !, &&, ||, old(scalar).

Arithmetic is intentionally deferred to avoid silent signed-overflow/division UB.
Only decimal integer constants within signed 32-bit range are accepted.
"""
import re
from ..errors import AgentError
TOKEN=re.compile(r'\s*(old\b|[A-Za-z_][A-Za-z_0-9]*|0|[1-9][0-9]*|&&|\|\||==|!=|<=|>=|[()!<>-])')
PRECEDENCE={'||':1,'&&':2,'==':3,'!=':3,'<':4,'<=':4,'>':4,'>=':4}

class ExpressionValidator:
    def __init__(self,symbols,*,allow_result=False,allow_old=False):
        self.symbols=set(symbols)|({'result'} if allow_result else set())
        self.old_symbols=set(symbols); self.allow_old=allow_old
    def validate(self,text):
        if not isinstance(text,str) or not text.strip(): raise AgentError('FORMALIZATION_UNSUPPORTED','Missing formal expression')
        if len(text)>4096: raise AgentError('FORMALIZATION_UNSUPPORTED','Expression too large')
        self.tokens=[]; pos=0; self.snapshots=set()
        text=text.strip()
        while pos<len(text):
            m=TOKEN.match(text,pos)
            if not m: raise AgentError('FORMALIZATION_UNSUPPORTED','Unsupported expression token')
            self.tokens.append(m[1]); pos=m.end()
        if len(self.tokens)>256: raise AgentError('FORMALIZATION_UNSUPPORTED','Expression too complex')
        self.index=0
        result=self.expr(0)
        if self.index!=len(self.tokens): raise AgentError('FORMALIZATION_UNSUPPORTED','Trailing tokens')
        return result,sorted(self.snapshots)
    def take(self):
        if self.index>=len(self.tokens): raise AgentError('FORMALIZATION_UNSUPPORTED','Incomplete expression')
        token=self.tokens[self.index]; self.index+=1; return token
    def peek(self): return self.tokens[self.index] if self.index<len(self.tokens) else None
    def expect(self,t):
        if self.take()!=t: raise AgentError('FORMALIZATION_UNSUPPORTED','Invalid expression syntax')
    def atom(self):
        t=self.take()
        if t=='!': return '(!'+self.atom()+')'
        if t=='(':
            v=self.expr(0); self.expect(')'); return '('+v+')'
        if t=='old':
            if not self.allow_old: raise AgentError('FORMALIZATION_UNSUPPORTED','old is only supported in postconditions/guards')
            self.expect('('); name=self.take(); self.expect(')')
            if name not in self.old_symbols: raise AgentError('UNKNOWN_IDENTIFIER','old requires a scalar parameter')
            self.snapshots.add(name); return '__sa_old_'+name
        negative=t=='-'
        if negative: t=self.take()
        if t.isdecimal():
            value=int(t)*(-1 if negative else 1)
            if not -(2**31)<=value<2**31: raise AgentError('FORMALIZATION_UNSUPPORTED','Constant outside int32 range')
            # INT_MIN emitted without a positive out-of-range literal.
            return '(-2147483647 - 1)' if value==-(2**31) else str(value)
        if negative: raise AgentError('FORMALIZATION_UNSUPPORTED','Unary minus only on integer literals')
        if t not in self.symbols: raise AgentError('UNKNOWN_IDENTIFIER','Unknown formal identifier: '+t)
        return '__sa_result' if t=='result' else t
    def expr(self,minimum):
        lhs=self.atom()
        while self.peek() in PRECEDENCE and PRECEDENCE[self.peek()]>=minimum:
            op=self.take(); rhs=self.expr(PRECEDENCE[op]+1); lhs=f'({lhs} {op} {rhs})'
        return lhs
