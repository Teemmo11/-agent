"""Controller for frozen requirements, scoped model requests and verified conversion."""
from pathlib import Path

from ..artifacts import ArtifactStore, sha256_file
from ..errors import AgentError
from ..evaluation.models import Limits
from ..ir_ab.semantics import Invalid, canon, digest, normal
from ..llm.parser import strict_json
from ..t3t4.audit import audit as audit_child
from ..t3t4.checks import Checks, reference
from ..t3t4.controller import files, run as convert
from ..t3t4.input import read_json
from . import domains, protocol, review
from .gateway import Gateway, Ledger

PROMPTS = Path(__file__).resolve().parents[1] / 'prompts'
NOT_RUN = 'NOT_RUN'


class Stop(Exception):
    def __init__(self, reason, status='NEEDS_REVIEW'):
        self.reason, self.status = reason, status


def default_limits(calls=36, tokens=300000, queries=2048):
    return Limits(input_tokens=20000, output_tokens=6144, llm_calls=calls, calls_per_function=calls,
                  total_tokens=tokens, queries=queries, queries_per_function=queries)


def code_identity():
    root = Path(__file__).resolve().parents[1]
    tracked = sorted((root / 'nacsl').glob('*.py')) + [
        root / rel for rel in ('ir_ab/semantics.py', 't3t4/checks.py', 't3t4/input.py',
                               'llm/client.py', 'llm/parser.py', 'llm/schema.py', 'evaluation/models.py')
    ]
    return {p.relative_to(root).as_posix(): sha256_file(p) for p in tracked}


class Workflow:
    def __init__(self, store, ledger, library, timeout, aux_mode, max_repairs, gateway, material_kind, code):
        self.store, self.ledger, self.gateway = store, ledger, gateway
        self.library, self.timeout, self.aux_mode = library, timeout, aux_mode
        self.max_repairs, self.material_kind, self.code = max_repairs, material_kind, code
        self.calls = 0
        self.semantic_versions = set()
        self.transitions = []
        self.report = {
            'schema': 'nacsl-report-1', 'mode': gateway.mode, 'status': 'BLOCKED',
            'source_gate_version': domains.VERSION,
            'publication_eligible': False, 'source_integrity': NOT_RUN,
            'alignment': NOT_RUN, 'conversion': NOT_RUN, 'repair': NOT_RUN,
            'implementation_verification': NOT_RUN, 'evaluation': {'status': NOT_RUN}, 'versions': [],
        }
        self.r, self.s = None, None
        self.input_domain = []
        self.child, self.source_checks = None, {}
        self.review_records = []

    def state(self, name, **details):
        self.transitions.append({'state': name, **details})
        self.store.write('progress.json', {'history': self.transitions, 'resume_supported': False})

    def model(self, stage, context, validator, retries=0):
        schema_name = 't2' if stage == 'repair' else stage
        prompt_name = 'review' if stage in ('alignment', 'diagnosis') else 'analysis'
        prompt = (self.store.root / 'inputs' / f'{prompt_name}.md').read_text(encoding='utf-8')
        schema = protocol.protocol_prompt(schema_name, context.get('allowed_issue_refs'))
        for attempt in range(retries+1):
            self.calls += 1
            location = self.store.root / f'agents/{self.calls:03d}-{stage}'
            messages = [{'role': 'system', 'content': prompt},
                        {'role': 'user', 'content': canon({
                            'stage': stage.upper(), 'schema': schema, 'input': context})}]
            try:
                value = validator(strict_json(self.gateway.call(stage, messages, location)))
                self.store.write(location.relative_to(self.store.root) / 'validation.json', {'status': 'PASS'})
                return value
            except (Invalid, AgentError) as exc:
                code = exc.code
                # Validation locations and internally generated feedback are recorded without provider text.
                safe_detail = exc.detail if isinstance(exc, Invalid) and isinstance(exc.detail, (str, int)) else ''
                self.store.write(location.relative_to(self.store.root) / 'validation.json',
                                 {'status': 'FAIL', 'code': code, 'detail': safe_detail})
                if code == 'LLM_BUDGET_EXHAUSTED':
                    raise Stop('BUDGET_EXHAUSTED', 'BLOCKED') from None
                technical = code in ('LLM_TIMEOUT', 'LLM_CONNECTION_FAILED', 'LLM_HTTP_ERROR')
                validation = isinstance(exc, Invalid) or code == 'LLM_RESPONSE_INVALID'
                if attempt == retries or not (technical or validation):
                    status = 'TOOL_ERROR' if technical else 'NEEDS_REVIEW' if validation else 'BLOCKED'
                    raise Stop(code, status) from None
                context = {**context, 'retry_feedback': {'code': code, 'detail': safe_detail}}
        raise AssertionError('Unreachable retry loop')

    def run(self, interface, material):
        self.interface = interface
        self.material = material
        self.text = material.decode('utf-8')
        self.lines = protocol.source_lines(self.text)
        if not self.text.strip() or len(self.lines) > 512 or len(material) > 65536:
            raise Stop('REQUIREMENT_INPUT_SIZE', 'UNSUPPORTED')
        self.input_domain = domains.declarations(interface, self.lines)
        self.report['input_domain'] = self.input_domain
        unresolved = next((entry['issue'] for entry in self.input_domain if 'issue' in entry), None)
        if unresolved:
            self.report['source_integrity'] = 'FAIL'
            raise Stop(unresolved)
        policy_stop = None
        try:
            self.analyze()
        except Stop as exc:
            policy_stop = exc
        try:
            quality, diagnosis = self.assess()
        except Stop as exc:
            if policy_stop:
                self.report['review_stop_reason'] = exc.reason
                raise policy_stop
            raise
        if policy_stop and policy_stop.reason != 'UNMAPPED_REQUIREMENTS':
            raise policy_stop
        for _ in range(self.max_repairs):
            if not quality:
                break
            allowed = {r['id'] for r in self.r['rows'] if r['kind'] == 'REQUIREMENT'}
            plans = review.additions(quality, diagnosis, allowed)
            if not plans:
                break
            version = len(self.report['versions']) + 1
            self.state('REPAIR', version=version)
            self.report['repair'] = 'PROPOSED'
            prior = self.s
            candidate = self.formalize(repair={'findings': quality, 'proposals': plans, 'prior_S': prior})
            self.store.write(f'versions/{version:03d}/S.json', candidate)
            violations = protocol.protected(prior, candidate)
            permitted = {rid for p in plans for rid in p['allowed_requirements']}
            prior_ids = {x['id'] for x in prior['S']}
            new = [x for x in candidate['S'] if x['id'] not in prior_ids]
            violations += [{'out_of_scope': s['id']} for s in new if not set(s['requirement_refs']) <= permitted]
            if violations or candidate['status'] != 'OK':
                self.report['repair'] = 'NEEDS_REVIEW'
                self.store.write(f'versions/{version:03d}/decision.json', {
                    'status': 'NEEDS_REVIEW', 'violations': violations, 'parent_version': version-1,
                    'proposals': plans,
                })
                raise Stop('REPAIR_PROTECTION')
            self.report['versions'].append({'version': version, 'parent_version': version-1,
                                            'S': f'versions/{version:03d}/S.json', 'proposals': plans,
                                            'decision': 'PENDING'})
            self.s = candidate
            try:
                self.convert_version(version, prior=prior)
            except Stop as exc:
                if exc.reason != 'UNMAPPED_REQUIREMENTS':
                    self.report['versions'][-1].update(decision='REJECTED', reason=exc.reason)
                    self.report['repair'] = 'REJECTED'
                    raise
                # A protected append can still be incomplete. Review the draft
                # again within the original global budget, never publish it.
                self.report['versions'][-1].update(decision='NEEDS_REVIEW', reason=exc.reason)
            quality, diagnosis = self.assess(version)
            if quality or self.report['versions'][-1]['unmapped_R']:
                self.report['versions'][-1]['decision'] = 'NEEDS_REVIEW'
                self.report['repair'] = 'NEEDS_REVIEW'
            else:
                self.report['versions'][-1]['decision'] = 'ACCEPTED'
                self.report['repair'] = 'ACCEPTED'
        if quality:
            if self.report['repair'] == NOT_RUN:
                self.report['repair'] = 'NEEDS_REVIEW'
            reason = ('REPAIR_LIMIT_EXHAUSTED' if self.max_repairs and
                      len(self.report['versions']) - 1 >= self.max_repairs else 'ALIGNMENT_FINDINGS')
            raise Stop(reason)
        if self.report['versions'][-1]['unmapped_R']:
            raise Stop('UNMAPPED_REQUIREMENTS')
        self.report['publication_eligible'] = self.child['eligible']
        self.report['status'] = 'COMPLETED'
        self.report['stop_reason'] = 'QUALIFIED'

    def analyze(self):
        self.state('T1')

        def validate_r(data):
            r = protocol.parse_r(data, self.text)
            missing = domains.missing_spans(self.input_domain, r)
            if missing and not r['issues']:
                raise Invalid('INPUT_DOMAIN_NOT_REQUIREMENT', ', '.join(
                    f'{entry["ref"]}: {entry["excerpt"]}' for entry in missing))
            if r['unclassified'] and not r['issues']:
                refs = ', '.join(g['ref'] for g in r['unclassified'])
                raise Invalid('UNCLASSIFIED_SOURCE', refs)
            return r

        context = {
            'interface': self.interface,
            'lines': [{**row, 'ref': f'N:L{row["line"]}'} for row in self.lines],
            'allowed_issue_refs': [f'N:L{row["line"]}' for row in self.lines],
            'input_domain': self.input_domain,
        }
        try:
            self.r = self.model('t1', context, validate_r, retries=1)
        except Stop as exc:
            if exc.reason == 'INPUT_DOMAIN_NOT_REQUIREMENT':
                self.report['source_integrity'] = 'FAIL'
            raise
        self.store.write('t1/R.json', self.r)
        if domains.missing_spans(self.input_domain, self.r):
            self.report['source_integrity'] = 'FAIL'
        else:
            self.report['source_integrity'] = 'PASS' if not self.r['unclassified'] else 'PARTIAL'
        if self.r['issues']:
            reason = self.r['issues'][0]['kind']
            raise Stop('T1_' + reason, 'UNSUPPORTED' if reason == 'UNSUPPORTED' else 'NEEDS_REVIEW')
        if not any(row['kind'] == 'REQUIREMENT' for row in self.r['rows']):
            raise Stop('NO_BUSINESS_REQUIREMENTS')
        self.state('T2', version=1)
        self.s = self.formalize()
        self.store.write('t2/S.json', self.s)
        self.report['versions'].append({'version': 1, 'parent_version': None, 'S': 't2/S.json',
                                        'decision': 'INITIAL'})
        if self.s['status'] != 'OK':
            raise Stop('T2_' + self.s['status'], self.s['status'])
        self.convert_version(1)

    def formalize(self, repair=None):
        requirements = [row for row in self.r['rows'] if row['kind'] == 'REQUIREMENT']
        refs = [row['id'] for row in requirements]
        issue_refs = ['R:' + rid for rid in refs]
        def validate_s(data):
            s = protocol.parse_s(data, self.r)
            protocol.issue_refs(s['issues'], set(issue_refs))
            if s['status'] == 'OK':
                protocol.adapt(self.interface, self.r, s, self.material, self.material_kind)
            return s
        context = {'interface': self.interface, 'R': requirements, 'allowed_requirement_refs': refs,
                   'allowed_issue_refs': issue_refs, 'input_domain': self.input_domain}
        if repair:
            context['repair'] = repair
        return self.model('repair' if repair else 't2', context, validate_s, retries=1)

    def convert_version(self, version, prior=None):
        path = f'versions/{version:03d}/R-S.json'
        package, frozen = protocol.adapt(self.interface, self.r, self.s, self.material, self.material_kind)
        self.store.write(path, package)
        row = self.report['versions'][-1]
        row.update(package=path, package_sha256=sha256_file(self.store.root / path),
                   R_sha256=digest(self.r), S_sha256=digest(self.s))
        missing = domains.coverage(self.input_domain, self.r, self.s)
        row.update(missing)
        self.child, self.source_checks = None, {}
        self.report['conversion'] = NOT_RUN
        self.report.pop('downstream', None)
        if missing['domain_without_requires']:
            raise Stop('INPUT_DOMAIN_REQUIRES_MISSING')
        if missing['unmapped_R']:
            raise Stop('UNMAPPED_REQUIREMENTS')
        p, q = reference(frozen)
        semantic_key = digest([frozen['domain'], normal(p), normal(q)])
        if semantic_key in self.semantic_versions:
            raise Stop('DUPLICATE_CANDIDATE')
        self.semantic_versions.add(semantic_key)
        row['semantic_key'] = semantic_key
        bound = {'package_sha256': row['package_sha256'], 'version': version}
        local = ArtifactStore(self.store.root / f'versions/{version:03d}/logic')
        checks = Checks(local, frozen, self.library, self.timeout, 128, digest(self.code),
                        permit=lambda _: self.ledger.query(self.gateway.case))
        row.update(source_checks=self.source_checks, solver=checks.identity)
        self.source_query(checks, 'P_FEASIBILITY', p, 'SAT', bound, 'INPUT_P_INFEASIBLE')
        if self.input_domain:
            self.source_query(checks, 'INPUT_DOMAIN_PRESERVATION', domains.mismatch(self.input_domain, p),
                              'UNSAT', bound, 'INPUT_DOMAIN_LOOSENED')
            self.source_query(checks, 'INPUT_DOMAIN_NOT_STRENGTHENED',
                              domains.strengthening(self.input_domain, self.r, self.s),
                              'UNSAT', bound, 'INPUT_DOMAIN_STRENGTHENED')
        self.source_query(checks, 'P_Q_CONSISTENCY', ['and', p, q], 'SAT', bound, 'CONTRACT_CONFLICT')
        self.source_query(checks, 'TOTAL_OUTPUT', (p, q), 'UNSAT', bound, 'INPUT_WITHOUT_OUTPUT', total=True)
        if prior is not None:
            self.check_repair(checks, frozen, prior, p, q, bound)
        if not checks.bound():
            raise Stop('SOURCE_CHECK_BINDING', 'TOOL_ERROR')
        self.state('T3', version=version)
        child_root, result = convert(
            self.store.root / path, self.store.root / 'inputs/N.txt', output=self.store.root / 'downstream',
            library=self.library, timeout=self.timeout, mode=self.aux_mode,
            model_gateway=self.gateway if self.gateway.mode != 'OFFLINE' else None,
            query_budget=lambda _: self.ledger.query(self.gateway.case))
        evidence = audit_child(child_root)
        self.child = {
            'run': child_root.relative_to(self.store.root).as_posix(), 'seal': evidence['manifest_sha256'],
            'integrity': evidence['integrity'], 'eligible': evidence['publication_eligible'],
            'T3': result['main']['status'], 'T4': result['t4']['status'],
            'auxiliary': result['auxiliary']['status'], 'solver': read_json(child_root/'manifest.json')['solver'],
        }
        row['downstream'] = self.child
        self.state('T4', version=version, status=self.child['T4'])
        self.report['conversion'] = 'PASS' if self.child['eligible'] else 'BLOCKED'
        self.report['downstream'] = self.child
        if evidence['integrity'] != 'PASS' or not self.child['eligible']:
            query_stops = self.ledger.snapshot()['stops']
            reason = 'BUDGET_EXHAUSTED' if any(x['kind'] == 'query' for x in query_stops) else 'CONVERSION_BLOCKED'
            if self.child['integrity'] != 'PASS':
                reason = 'DOWNSTREAM_INTEGRITY'
            raise Stop(reason, 'BLOCKED')

    def source_query(self, checks, label, predicate, expected, bound, failure, *, total=False):
        record = checks.ask(label, predicate, expected, bound, total=total)
        self.source_checks[label] = {**record, 'artifact': (
            checks.store.root.relative_to(self.store.root).as_posix() + '/' + record['artifact'])}
        if record['status'] == 'FAIL':
            raise Stop(failure)
        if record['status'] != 'PASS':
            reason = record['reason']
            raise Stop('BUDGET_EXHAUSTED' if 'BUDGET' in reason else reason, 'TOOL_ERROR' if 'BUDGET' not in reason else 'BLOCKED')

    def check_repair(self, checks, frozen, prior, p, q, bound):
        _, old = protocol.adapt(self.interface, self.r, prior, self.material, self.material_kind)
        old_p, old_q = reference(old)
        old_bound = {**bound, 'parent_frozen_sha256': digest(old)}
        self.source_query(checks, 'PRESERVE_OLD', ['and', p, q, ['not', old_q]], 'UNSAT', old_bound, 'REPAIR_WEAKENS')
        self.source_query(checks, 'REPAIR_NOVELTY', ['and', old_p, old_q, ['not', q]], 'SAT', old_bound, 'DUPLICATE_CANDIDATE')

    def assess(self, version=1):
        self.state('ALIGNMENT', version=version)
        base = review.material_refs(self.lines, self.r, self.s)
        acsl = None
        if self.child and self.child['T4'] == 'PASS':
            acsl = (self.store.root / self.child['run'] / 't4/contract.c').read_text(encoding='utf-8')
        # Supply interpretations, formulas and actual output, with no producer verdicts or self-assessment.
        context = review.alignment_context(self.interface, self.lines, self.r, self.s, acsl)
        quality = self.model('alignment', context, lambda obj: review.findings(obj, base), retries=1)
        review_record = {'version': version, 'alignment': 'ISSUES_FOUND' if quality else 'NO_ISSUES_FOUND',
                         'scope': 'CONVERTED_OUTPUT' if acsl else 'DRAFT_DIAGNOSTIC_ONLY',
                         'findings': quality, 'diagnosis': NOT_RUN, 'proposals': []}
        self.review_records.append(review_record)
        self.report['alignment'] = review_record['alignment']
        self.report['alignment_scope'] = review_record['scope']
        self.store.write(f'reviews/{version:03d}.json', review_record)
        if quality or not self.child or not self.child['eligible']:
            self.state('DIAGNOSIS', version=version)
            conversion = review.conversion_refs(self.store.root, self.child)
            source = {'EV:'+key: {k: v for k, v in row.items() if k not in ('predicate', 'binding')}
                      for key, row in self.source_checks.items()}
            refs = {**base, **conversion, **source}
            if self.report['versions'] and 'package' in self.report['versions'][-1]:
                row = self.report['versions'][-1]
                refs['EV:SOURCE_COVERAGE'] = {
                    'unmapped_R': row['unmapped_R'], 'domain_without_requires': row['domain_without_requires'],
                    'artifact': row['package'],
                }
            context = {
                'findings': quality, 'evidence': refs,
                'input_issues': (self.r['issues'] if self.r else []) + (self.s['issues'] if self.s else []),
                'capabilities': review.CAPABILITIES,
            }
            proposals = self.model('diagnosis', context, lambda obj: review.proposals(obj, quality, refs), retries=1)
            review_record.update(diagnosis='COMPLETED', proposals=proposals,
                                 evidence_refs=list(refs))
            self.store.write(f'reviews/{version:03d}.json', review_record)
        return quality, review_record['proposals']


def run(n_path, interface_path, *, output, library, timeout=2500, aux_mode='on_failure',
        max_repairs=2, config=None, fixture=None, ledger=None, material_kind='AUTHORED'):
    if not 0 <= max_repairs <= 2 or aux_mode not in ('on_failure','shadow') or not 1 <= timeout <= 3600000:
        raise Invalid('WORKFLOW_CONFIG')
    if (config is not None and fixture is not None) or material_kind not in ('AUTHORED', 'SYNTHETIC'):
        raise Invalid('WORKFLOW_CONFIG')
    store = ArtifactStore(output)
    root = store.root
    (root/'inputs').mkdir()
    sources = {'N.txt': Path(n_path), 'interface.json': Path(interface_path),
               'protocol.json': protocol.SCHEMA_FILE, 'analysis.md': PROMPTS/'nacsl_analysis.md',
               'review.md': PROMPTS/'nacsl_review.md'}
    if fixture is not None:
        store.write('inputs/fixture.json', fixture)
    for name, source in sources.items():
        (root/'inputs'/name).write_bytes(source.read_bytes())
    initial = files(root)
    shared = ledger or Ledger(default_limits())
    gateway = Gateway(store.run_id, shared, config=config, fixture=fixture)
    code = code_identity()
    workflow = Workflow(store, shared, library, timeout, aux_mode, max_repairs, gateway, material_kind, code)
    try:
        interface = protocol.check_interface(read_json(root/'inputs/interface.json'))
        workflow.run(interface, (root/'inputs/N.txt').read_bytes())
    except Stop as exc:
        workflow.report.update(status=exc.status, stop_reason=exc.reason, publication_eligible=False)
    except (Invalid, OSError, ValueError, TypeError, KeyError, RecursionError) as exc:
        workflow.report.update(status='UNSUPPORTED' if getattr(exc, 'code', '') == 'UNSUPPORTED_EXPRESSION'
                               else 'BLOCKED', stop_reason=getattr(exc, 'code', 'WORKFLOW_ERROR'),
                               publication_eligible=False)
    except KeyboardInterrupt:
        workflow.report.update(status='CANCELLED', stop_reason='CANCELLED', publication_eligible=False)
    report = workflow.report
    if shared.snapshot()['provider_reported_tokens'] > shared.snapshot()['limits']['total_tokens']:
        report.update(status='BLOCKED', stop_reason='PROVIDER_TOKEN_BUDGET_EXCEEDED', publication_eligible=False)
    if any(sha256_file(root / file) != checksum for file, checksum in initial.items()):
        report.update(status='BLOCKED', stop_reason='INPUT_CHANGED_DURING_RUN', publication_eligible=False)
    workflow.state('TERMINAL', status=report['status'], reason=report['stop_reason'])
    report.update(budget=shared.snapshot(), reviews=workflow.review_records, material_kind=material_kind)
    from .trace import make_index
    store.write('trace/index.json', make_index(root, workflow.r, report))
    store.write('report.json', report)
    markdown = ['# 自然语言需求到 ACSL', '', f"运行状态：{report['status']}（{report['stop_reason']}）",
                f"来源完整性：{report['source_integrity']}", f"转换保真：{report['conversion']}",
                f"需求对齐评审：{report['alignment']}", f"修复：{report['repair']}",
                '实现验证：NOT_RUN', f"发射资格：{report['publication_eligible']}", '',
                '逐版本及对应证据见 report.json，原文和条款映射见 trace/index.json。']
    (root/'report.md').write_text('\n'.join(markdown)+'\n', encoding='utf-8')
    store.write('manifest.json', {'schema': 'nacsl-manifest-1', 'run_id': store.run_id, 'inputs': initial,
                                 'implementation': code, 'files': files(root)})
    return root, report
