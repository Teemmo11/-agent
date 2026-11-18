from ..models import FormalContract, FormalEnsures
from ..errors import AgentError
from .expressions import ExpressionValidator


def formalize(spec, function, input_info, trace=None):
    if function.harness_issues:
        raise AgentError('UNSUPPORTED_HARNESS', '; '.join(function.harness_issues))
    names = [p.name for p in function.parameters]

    def expression(value, validator, field, clause_id=None):
        try:
            converted, snapshots = validator.validate(value)
        except AgentError as exc:
            if trace:
                trace.emit('expression.rejected', level='ERROR', field=field,
                           clause_id=clause_id, original=value, error=exc.as_dict())
            clause = f' ({clause_id})' if clause_id else ''
            raise AgentError(exc.code, f'{field}{clause}: {exc}') from exc
        if trace:
            trace.emit('expression.validated', field=field, clause_id=clause_id,
                       original=value, converted=converted, snapshots=sorted(snapshots))
        return converted, snapshots

    pre, _ = expression(spec['function_spec']['pre_condition']['formal_candidate'],
                        ExpressionValidator(names), 'pre_condition.formal_candidate')
    clauses, snapshots = [], set()
    for q in spec['function_spec']['post_conditions']:
        expr, old = expression(q['formal_candidate'],
                               ExpressionValidator(names, allow_result=function.return_type!='void', allow_old=True),
                               'post_conditions.formal_candidate', q['clause_id'])
        snapshots.update(old)
        guard = None
        if q['guard'] is not None:
            guard, old = expression(q['guard'], ExpressionValidator(names, allow_old=True),
                                    'post_conditions.guard', q['clause_id'])
            snapshots.update(old)
        clauses.append(FormalEnsures(q['clause_id'], expr, guard))
    return FormalContract('FC-'+spec['spec_id'], spec['spec_id'], function.function_id,
                          pre, clauses, sorted(snapshots), input_info['source_sha256'],
                          input_info['requirements_sha256'])
