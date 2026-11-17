"""Conservative lexical/AST facts, not natural-language truth judgments."""
from ..spec.expressions import ExpressionValidator,PRECEDENCE
from ..errors import AgentError
from .models import finding


class AstValidator(ExpressionValidator):
    def atom(self):
        value=self.take()
        if value=='!':return ('not',self.atom())
        if value=='(':
            result=self.expr(0);self.expect(')');return result
        if value=='old':
            if not self.allow_old:raise AgentError('FORMALIZATION_UNSUPPORTED','old unsupported here')
            self.expect('(');name=self.take();self.expect(')')
            if name not in self.old_symbols:raise AgentError('UNKNOWN_IDENTIFIER','Unknown old parameter')
            self.snapshots.add(name);return ('symbol',name) # Entry snapshots equal unchanged query inputs.
        negative=value=='-'
        if negative:value=self.take()
        if value.isdecimal():
            number=int(value)*(-1 if negative else 1)
            if not -(2**31)<=number<2**31:raise AgentError('FORMALIZATION_UNSUPPORTED','Constant outside int32')
            return ('integer',number)
        if negative or value not in self.symbols:raise AgentError('UNKNOWN_IDENTIFIER','Invalid formal symbol')
        return ('symbol',value)
    def expr(self,minimum):
        left=self.atom()
        while self.peek() in PRECEDENCE and PRECEDENCE[self.peek()]>=minimum:
            op=self.take();right=self.expr(PRECEDENCE[op]+1)
            if op in ('>','>='):left=('binary','<' if op=='>' else '<=',right,left)
            else:
                if op in ('==','!=') and repr(right)<repr(left):left,right=right,left
                left=('binary',op,left,right)
        return left


def canonical(expression,function,*,post=True):
    return AstValidator([p.name for p in function.parameters],allow_result=post and function.return_type!='void',allow_old=post).validate(expression)[0]


def check(spec,function,evidence):
    sid=spec['spec_id'];fs=spec['function_spec'];rows=[];seen={}
    try:canonical(fs['pre_condition']['formal_candidate'],function,post=False)
    except AgentError as exc:
        rows.append(finding(sid,'clarity','FORMAL_EXPRESSION_UNSUPPORTED',exc.message if hasattr(exc,'message') else str(exc),severity='HIGH',evidence=evidence))
    for q in fs['post_conditions']:
        try:
            # Guard validation disallows result even though Q allows it.
            if q['guard'] is not None:
                ExpressionValidator([p.name for p in function.parameters],allow_old=True).validate(q['guard'])
            value=(canonical(q['formal_candidate'],function),canonical(q['guard'] or '1',function))
            if value in seen:
                rows.append(finding(sid,'redundancy','DUPLICATE_CLAUSE','同一适用条件下存在保守 AST 规范化后相同的条款。',
                                    clauses=[seen[value],q['clause_id']],severity='LOW',evidence=evidence))
            else:seen[value]=q['clause_id']
        except AgentError as exc:
            rows.append(finding(sid,'clarity','FORMAL_EXPRESSION_UNSUPPORTED',str(exc),clauses=[q['clause_id']],severity='HIGH',evidence=evidence))
        if not q['requirement_refs']:
            rows.append(finding(sid,'alignment','MISSING_REQUIREMENT_REFERENCE','条款没有明确需求引用；是否合理需要语义复核。',clauses=[q['clause_id']],evidence=evidence,claim='REVIEW_REQUIRED'))
    if fs['ambiguities'] or fs['conflicts']:
        rows.append(finding(sid,'clarity','DECLARED_AMBIGUITY_OR_CONFLICT','生成规格已声明歧义或冲突，应逐项复核。',evidence=evidence,claim='REVIEW_REQUIRED'))
    return rows
