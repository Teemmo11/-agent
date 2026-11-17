"""Z3 checks over frozen scalar domains. No implementation body participates."""
from pathlib import Path

from ..artifacts import sha256_file, write_json_atomic
from ..ir_ab.semantics import Invalid, Solver, digest, join, pq
from . import graph
from .input import source_formula


class Checks:
    def __init__(self, store, frozen, library, timeout, quota, implementation, *, auxiliary=False, permit=None):
        self.store = store
        self.frozen = frozen
        self.implementation = implementation
        self.count = 0
        self.artifacts = {}
        self.permit = permit
        self.budget_stopped = False
        self.directory = 'evidence/auxiliary' if auxiliary else 'evidence'
        self.solver = None
        self.unavailable = None
        try:
            self.solver = Solver(library, timeout=timeout, quota=quota)
        except (OSError, AttributeError):
            self.unavailable = 'SOLVER_UNAVAILABLE'
        self.identity = ({**self.solver.identity, 'backend': 'Z3_C_API', 'timeout_ms': timeout,
                          'domain': frozen['domain']} if self.solver else
                         {'backend': 'Z3_C_API', 'reason': self.unavailable, 'domain': frozen['domain']})

    def ask(self, label, predicate, expected, dependencies, *, total=False):
        self.count += 1
        directory = f'{self.directory}/{self.count:04d}'
        binding = {
            'frozen_sha256': digest(self.frozen), 'checker_sha256': self.implementation,
            'solver': self.identity, 'dependencies': dependencies,
            'predicate_sha256': digest(predicate), 'expected': expected,
        }
        if self.solver is None:
            raw = {'status': 'ERROR', 'reason': self.unavailable}
        elif self.budget_stopped or (self.permit is not None and not self.permit(label)):
            self.budget_stopped = True
            raw = {'status': 'NOT_RUN', 'reason': 'GLOBAL_QUERY_BUDGET'}
        else:
            self.solver.root = self.store.root / self.directory
            raw = self.solver.ask(label, self.frozen['names'], predicate, reuse=False, total=total)
        value = raw['status']
        terminal = value in ('SAT', 'UNSAT')
        reason = raw.get('reason')
        if value == 'UNKNOWN':
            reason = 'SOLVER_UNKNOWN'
            try:
                query = (self.store.root / directory / 'query.smt2').read_text(encoding='utf-8')
                detail, errors = self.solver.run_raw(query + '(get-info :reason-unknown)\n')
                self.store.write(directory + '/unknown.json', {'raw': detail, 'errors': errors})
                if not errors and ('"timeout"' in detail or '"canceled"' in detail):
                    reason = 'TIMEOUT_OR_CANCELLED'
            except (OSError, ValueError):
                pass
        record = {
            'label': label, 'status': ('PASS' if value == expected else 'FAIL') if terminal else 'UNKNOWN',
            'reason': reason or ('EXPECTED_RESULT' if value == expected else 'COUNTEREXAMPLE_OR_EMPTY_DOMAIN'
                                 if terminal else 'TOOL_ERROR'),
            'raw_result': value, 'expected': expected, 'binding': binding, 'binding_sha256': digest(binding),
            'predicate': predicate,
            **({'encoding': 'NO_OUTPUT_FOR_SOME_INPUT'} if total else {}),
            'witness': raw.get('witness'), 'witness_status': raw.get('witness_status', 'UNAVAILABLE'),
            'artifact': directory + '/check.json',
        }
        query = self.store.root / directory / 'query.smt2'
        if query.is_file():
            record['query_sha256'] = sha256_file(query)
        if self.solver is None or self.budget_stopped:
            self.store.write(directory + '/result.json', raw)
        self.store.write(record['artifact'], record)
        self.artifacts.update({p: sha256_file(p) for p in query.parent.iterdir() if p.is_file()})
        return record

    def bound(self):
        if not self.solver:
            return False
        try:
            return (sha256_file(self.solver.path) == self.identity['sha256']
                    and all(sha256_file(path) == checksum for path, checksum in self.artifacts.items()))
        except OSError:
            return False


def reference(frozen):
    return pq([{'role': row['role'], 'expr': source_formula(frozen, sid)} for sid, row in frozen['S'].items()])


def xor(left, right):
    return ['or', ['and', left, ['not', right]], ['and', right, ['not', left]]]


def status(rows):
    values = {row['status'] for row in rows}
    return 'FAIL' if 'FAIL' in values else 'UNKNOWN' if 'UNKNOWN' in values else 'PASS' if values == {'PASS'} else 'NOT_RUN'


def compare(checks, label, original, replacement, dependencies):
    p, q = original
    other_p, other_q = replacement
    return [
        checks.ask(label + '/P', xor(p, other_p), 'UNSAT', dependencies),
        checks.ask(label + '/Q', ['and', reference(checks.frozen)[0], p, other_p, xor(q, other_q)],
                   'UNSAT', dependencies),
    ]


def assess(candidate, frozen, checks, feasibility, label):
    result = {
        'graph_sha256': digest(candidate), 'completeness': 'DRAFT', 'structure': 'FAIL',
        'source': 'NOT_RUN', 'semantics': 'NOT_RUN', 'groups': [], 'global': [],
        'status': 'FAIL', 'p_feasibility': feasibility['status'], 'issues': [],
    }
    try:
        view = graph.inspect(candidate, frozen)
    except Invalid as exc:
        result['issues'].append({'code': exc.code, 'detail': exc.detail})
        return result, None
    result.update(structure='PASS', covered=view['covered'], pending=view['pending'])
    result['completeness'] = 'DRAFT' if view['pending'] else 'COMPLETE'
    result['issues'] = view['issues'] + frozen['source_issues']
    result['source'] = 'FAIL' if result['issues'] or view['pending'] else 'PASS'
    if view['pending']:
        result['issues'].extend({'code': 'MISSING_SOURCE_FRAGMENT', 's_id': sid, **detail}
                                for sid, detail in view['pending'].items())
    p, _ = reference(frozen)
    dependencies = {'graph_sha256': result['graph_sha256'], 'P_sha256': digest(p)}
    for sid in view['covered']:
        observed = join('and', [c['expr'] for c in view['clauses'] if c['s_id'] == sid])
        difference = xor(source_formula(frozen, sid), observed)
        if frozen['S'][sid]['role'] == 'ensures':
            difference = ['and', p, difference]
        row = checks.ask(label + '/group/' + sid, difference, 'UNSAT', {**dependencies, 's_id': sid})
        result['groups'].append({'s_id': sid, **row})
    if result['completeness'] == 'COMPLETE':
        result['global'] = compare(checks, label + '/global', reference(frozen), view['pq'], dependencies)
        result['semantics'] = status(result['groups'] + result['global'])
    gates = [result['structure'], result['source'], result['semantics'], feasibility['status']]
    result['status'] = ('FAIL' if 'FAIL' in gates else 'PASS' if all(x == 'PASS' for x in gates) else 'UNKNOWN')
    return result, view
