"""Read-only chain audit of versions, scoped calls and sealed T3/T4 runs."""
from pathlib import Path

from ..artifacts import sha256_file
from ..ir_ab.semantics import Invalid, digest, domain, smt
from ..llm.parser import strict_json
from ..errors import AgentError
from ..t3t4.audit import audit as audit_child
from ..t3t4.checks import reference
from ..t3t4.input import read_json
from . import domains, protocol, review
from .trace import make_index


def audited_path(root, value):
    path = root / value
    if Path(value).is_absolute() or not path.resolve().is_relative_to(root) or '..' in Path(value).parts:
        raise Invalid('UNSAFE_ARTIFACT_REFERENCE')
    return path


def audit(directory, manifest_sha256=None):
    root = Path(directory).resolve()
    seal, report = None, None
    errors = []
    try:
        seal = sha256_file(root/'manifest.json')
        if manifest_sha256 and seal != manifest_sha256:
            raise Invalid('MANIFEST_BINDING')
        manifest = read_json(root/'manifest.json')
        if manifest['schema'] != 'nacsl-manifest-1':
            raise Invalid('MANIFEST_SCHEMA')
        entries = list(root.rglob('*'))
        if any(p.is_symlink() or not p.resolve().is_relative_to(root) for p in entries):
            raise Invalid('UNSAFE_EVIDENCE_PATH')
        actual = {p.relative_to(root).as_posix(): sha256_file(p) for p in entries if p.is_file() and p != root/'manifest.json'}
        if actual != manifest['files'] or any(actual.get(p) != h for p,h in manifest['inputs'].items()):
            raise Invalid('ARTIFACT_HASH_MISMATCH')
        report = read_json(root/'report.json')
        if report.get('source_gate_version') not in (None, domains.LEGACY_VERSION, domains.VERSION):
            raise Invalid('UNKNOWN_SOURCE_GATE')
        n = (root/'inputs/N.txt').read_bytes()
        rows = read_json(root/'t1/R.json') if (root/'t1/R.json').is_file() else None
        if 'input_domain' in report:
            interface = protocol.check_interface(read_json(root/'inputs/interface.json'))
            declared = domains.declarations(interface, protocol.source_lines(n.decode('utf-8')))
            if declared != report['input_domain']:
                raise Invalid('DECLARED_INPUT_DOMAIN_BINDING')
        for path in root.rglob('call.json'):
            call = read_json(path)
            if digest(read_json(path.with_name('request.json'))) != call['request_sha256']:
                raise Invalid('CALL_REQUEST_BINDING')
            if call['status'] == 'RESPONSE_RECEIVED':
                response = path.with_name('response.txt').read_bytes().decode('utf-8')
                if digest(response) != call['response_sha256']:
                    raise Invalid('CALL_RESPONSE_BINDING')
        if rows is not None:
            records = [p.parent for p in root.glob('agents/*-t1/validation.json') if read_json(p)['status'] == 'PASS']
            if len(records) != 1 or protocol.parse_r(read_json(records[0]/'response.txt'), n.decode('utf-8')) != rows:
                raise Invalid('R_RESPONSE_BINDING')
        if report['versions']:
            audit_versions(root, manifest, report, rows, n)
        audit_reviews(root, report)
        if report.get('source_gate_version') == domains.VERSION:
            audit_rejections(root, report)
            if report['reviews'] and (report['alignment'] != report['reviews'][-1]['alignment']
                                     or report['alignment_scope'] != report['reviews'][-1]['scope']):
                raise Invalid('FINAL_REVIEW_BINDING')
            if report['publication_eligible'] and (
                report.get('downstream') != report['versions'][-1].get('downstream')
                or report['versions'][-1]['decision'] not in ('INITIAL', 'ACCEPTED')
                or report['stop_reason'] != 'QUALIFIED'
            ):
                raise Invalid('FINAL_VERSION_BINDING')
        if read_json(root/'trace/index.json') != make_index(root, rows, report):
            raise Invalid('TRACE_BINDING')
        if report['publication_eligible'] and not qualified(report):
            raise Invalid('PUBLICATION_GATE')
    except (Invalid, AgentError, KeyError, ValueError, TypeError, OSError, AttributeError, RecursionError) as exc:
        errors.append(getattr(exc, 'code', 'EVIDENCE_READ_ERROR'))
    current_policy = bool(report and report.get('source_gate_version') == domains.VERSION)
    recorded = bool(report and report['publication_eligible'])
    return {'integrity': 'FAIL' if errors else 'PASS', 'manifest_sha256': seal, 'errors': errors,
            'qualification_policy': domains.VERSION if current_policy else 'LEGACY_UNCHECKED',
            'recorded_publication_eligible': recorded,
            'publication_eligible': bool(not errors and current_policy and recorded)}


def qualified(report):
    return (report['status'] == 'COMPLETED' and report['source_integrity'] == 'PASS'
            and report['alignment'] == 'NO_ISSUES_FOUND' and report['conversion'] == 'PASS'
            and report['implementation_verification'] == 'NOT_RUN'
            and report['budget']['provider_reported_tokens'] <= report['budget']['limits']['total_tokens']
            and bool(report['versions'])
            and report['versions'][-1].get('downstream', {}).get('eligible') is True
            and not report['versions'][-1]['unmapped_R']
            and all(check['status'] == 'PASS' for check in report['versions'][-1]['source_checks'].values())
            and any(r['version'] == report['versions'][-1]['version'] and not r['findings']
                    and (not report.get('source_gate_version') or r['scope'] == 'CONVERTED_OUTPUT')
                    for r in report['reviews']))


def audit_versions(root, manifest, report, r, n):
    interface = protocol.check_interface(read_json(root/'inputs/interface.json'))
    last = None
    prior_frozen = None
    current_policy = report.get('source_gate_version') in (domains.LEGACY_VERSION, domains.VERSION)
    strict = report.get('source_gate_version') == domains.VERSION
    declared = report.get('input_domain', [])
    if current_policy and (any('issue' in entry for entry in declared) or domains.missing_spans(declared, r)):
        raise Invalid('T1_INPUT_DOMAIN_GATE')
    validated = [(p.parent.name.rsplit('-', 1)[-1], read_json(p.parent/'response.txt'))
                 for p in sorted(root.glob('agents/*/validation.json'))
                 if p.parent.name.endswith(('-t2', '-repair')) and read_json(p)['status'] == 'PASS']
    for number, version in enumerate(report['versions'], 1):
        s = protocol.parse_s(read_json(audited_path(root, version['S'])), r)
        if (number != version['version'] or version['parent_version'] != (number-1 if number > 1 else None)
                or not any(s == output and stage == ('t2' if number == 1 else 'repair') for stage, output in validated)):
            raise Invalid('S_RESPONSE_OR_PARENT_BINDING')
        if 'package' not in version:
            continue
        package, frozen = protocol.adapt(interface, r, s, n, report['material_kind'])
        package_path = audited_path(root, version['package'])
        if (read_json(package_path) != package or sha256_file(package_path) != version['package_sha256']
                or digest(r) != version['R_sha256'] or digest(s) != version['S_sha256']):
            raise Invalid('S_PACKAGE_BINDING')
        if last is not None and protocol.protected(last, s):
            raise Invalid('REPAIR_PROTECTION')
        if strict and number > 1:
            prior_review = next((row for row in report['reviews'] if row['version'] == number-1), None)
            plans = review.additions(prior_review['findings'], prior_review['proposals'],
                                     {row['id'] for row in r['rows'] if row['kind'] == 'REQUIREMENT'}) if prior_review else []
            if not plans or version.get('proposals') != plans:
                raise Invalid('REPAIR_AUTHORIZATION')
            permitted = {rid for plan in plans for rid in plan['allowed_requirements']}
            old_ids = {row['id'] for row in last['S']}
            if any(not set(row['requirement_refs']) <= permitted for row in s['S'] if row['id'] not in old_ids):
                raise Invalid('REPAIR_SOURCE_SCOPE')
        if current_policy:
            coverage = domains.coverage(declared, r, s)
            if any(version.get(key) != value for key, value in coverage.items()):
                raise Invalid('COVERAGE_EVIDENCE_BINDING')
            if version.get('downstream') and any(coverage.values()):
                raise Invalid('DOWNSTREAM_COVERAGE_GATE')
        last = s
        for label, check in version.get('source_checks', {}).items():
            audit_query(root, label, check, frozen, digest(manifest['implementation']), version, prior_frozen,
                        declared, r, s, strict)
        prior_frozen = frozen
        if version.get('downstream'):
            child = version['downstream']
            directory = audited_path(root, child['run'])
            if (not directory.is_relative_to(root/'downstream')
                    or (directory/'inputs/S-R.json').read_bytes() != package_path.read_bytes()
                    or (directory/'inputs/original.txt').read_bytes() != n):
                raise Invalid('DOWNSTREAM_INPUT_BINDING')
            result = audit_child(directory, manifest_sha256=child['seal'])
            if result['integrity'] != 'PASS' or result['publication_eligible'] != child['eligible']:
                raise Invalid('DOWNSTREAM_AUDIT')
            child_result = read_json(directory/'result.json')
            if (child['T3'] != child_result['main']['status'] or child['T4'] != child_result['t4']['status']
                    or child['auxiliary'] != child_result['auxiliary']['status']
                    or child['solver'] != read_json(directory/'manifest.json')['solver']):
                raise Invalid('DOWNSTREAM_RESULT_BINDING')
            required = {'P_FEASIBILITY', 'P_Q_CONSISTENCY', 'TOTAL_OUTPUT'}
            if declared:
                required.add('INPUT_DOMAIN_PRESERVATION')
                if strict:
                    required.add('INPUT_DOMAIN_NOT_STRENGTHENED')
            if number > 1:
                required.update(('PRESERVE_OLD', 'REPAIR_NOVELTY'))
            if not required <= set(version['source_checks']) or any(
                version['source_checks'][k]['status'] != 'PASS' for k in required
            ):
                raise Invalid('CONSISTENCY_GATE')


def audit_reviews(root, report):
    strict = report.get('source_gate_version') == domains.VERSION
    r = read_json(root/'t1/R.json') if (root/'t1/R.json').is_file() else None
    interface = protocol.check_interface(read_json(root/'inputs/interface.json'))
    lines = protocol.source_lines((root/'inputs/N.txt').read_bytes().decode('utf-8'))
    review_calls = [p.parent for p in sorted(root.glob('agents/*-alignment/validation.json'))
                    if read_json(p)['status'] == 'PASS']
    if len(review_calls) != len(report['reviews']):
        raise Invalid('ALIGNMENT_RECORDS')
    for path, row in zip(review_calls, report['reviews']):
        request = strict_json(read_json(path/'request.json')[-1]['content'])['input']
        if strict:
            version = next((v for v in report['versions'] if v['version'] == row['version']), None)
            s = read_json(audited_path(root, version['S'])) if version else None
            child = version.get('downstream') if version else None
            acsl = (audited_path(root, child['run'])/'t4/contract.c').read_text(encoding='utf-8') if (
                child and child['T4'] == 'PASS') else None
            expected = review.alignment_context(interface, lines, r, s, acsl)
            if {k: v for k, v in request.items() if k != 'retry_feedback'} != expected:
                raise Invalid('ALIGNMENT_CONTEXT_BINDING')
            if read_json(root/f'reviews/{row["version"]:03d}.json') != row:
                raise Invalid('REVIEW_RECORD_BINDING')
            if row['alignment'] != ('ISSUES_FOUND' if row['findings'] else 'NO_ISSUES_FOUND'):
                raise Invalid('ALIGNMENT_STATUS_BINDING')
            if row['scope'] != ('CONVERTED_OUTPUT' if acsl else 'DRAFT_DIAGNOSTIC_ONLY'):
                raise Invalid('ALIGNMENT_SCOPE_BINDING')
        if review.findings(read_json(path/'response.txt'), request['allowed_refs']) != row['findings']:
            raise Invalid('FINDING_BINDING')
    diagnostics = [p.parent for p in sorted(root.glob('agents/*-diagnosis/validation.json'))
                   if read_json(p)['status'] == 'PASS']
    completed = [row for row in report['reviews'] if row['diagnosis'] == 'COMPLETED']
    if len(diagnostics) != len(completed):
        raise Invalid('DIAGNOSIS_RECORDS')
    for path, row in zip(diagnostics, completed):
        context = strict_json(read_json(path/'request.json')[-1]['content'])['input']
        if strict:
            version = next((v for v in report['versions'] if v['version'] == row['version']), None)
            s = read_json(audited_path(root, version['S'])) if version else None
            child = version.get('downstream') if version else None
            refs = {**review.material_refs(lines, r, s), **review.conversion_refs(root, child)}
            if version:
                refs.update({'EV:'+key: {k: v for k, v in value.items() if k not in ('predicate', 'binding')}
                             for key, value in version.get('source_checks', {}).items()})
                if 'package' in version:
                    refs['EV:SOURCE_COVERAGE'] = {k: version[k] for k in ('unmapped_R', 'domain_without_requires')}
                    refs['EV:SOURCE_COVERAGE']['artifact'] = version['package']
            if (context['evidence'] != refs or context['findings'] != row['findings']
                    or context['input_issues'] != ((r['issues'] if r else []) + (s['issues'] if s else []))
                    or context.get('capabilities') != review.CAPABILITIES):
                raise Invalid('DIAGNOSIS_CONTEXT_BINDING')
        if (list(context['evidence']) != sorted(row['evidence_refs'])
                or review.proposals(read_json(path/'response.txt'), row['findings'], context['evidence']) != row['proposals']):
            raise Invalid('DIAGNOSIS_BINDING')


def audit_rejections(root, report):
    """A protected rejected candidate is valid evidence, never an accepted version."""
    for path in root.glob('versions/*/decision.json'):
        decision = read_json(path)
        parent = next((v for v in report['versions'] if v['version'] == decision['parent_version']), None)
        if parent is None or decision['status'] != 'NEEDS_REVIEW':
            raise Invalid('REJECTED_CANDIDATE_PARENT')
        old = read_json(audited_path(root, parent['S']))
        new = read_json(path.with_name('S.json'))
        responses = [read_json(p.parent/'response.txt') for p in root.glob('agents/*-repair/validation.json')
                     if read_json(p)['status'] == 'PASS']
        if new not in responses or int(path.parent.name) != parent['version'] + 1:
            raise Invalid('REJECTED_CANDIDATE_RESPONSE')
        plans = decision['proposals']
        previous = next((r for r in report['reviews'] if r['version'] == parent['version']), None)
        r = read_json(root/'t1/R.json')
        expected = review.additions(previous['findings'], previous['proposals'],
                                    {x['id'] for x in r['rows'] if x['kind'] == 'REQUIREMENT'}) if previous else []
        if not expected or plans != expected:
            raise Invalid('REJECTED_CANDIDATE_AUTHORIZATION')
        permitted = {rid for p in plans for rid in p['allowed_requirements']}
        prior_ids = {s['id'] for s in old['S']}
        violations = protocol.protected(old, new)
        violations += [{'out_of_scope': s['id']} for s in new['S']
                       if s['id'] not in prior_ids and not set(s['requirement_refs']) <= permitted]
        if decision['violations'] != violations or (not violations and new['status'] == 'OK'):
            raise Invalid('REJECTED_CANDIDATE_DECISION')


def audit_query(root, label, record, frozen, implementation, version, prior, declared, r, s, strict):
    path = audited_path(root, record['artifact'])
    actual = read_json(path)
    binding = record['binding']
    if ({**actual, 'artifact': record['artifact']} != record
            or digest(binding) != record['binding_sha256'] or binding['frozen_sha256'] != digest(frozen)
            or binding['checker_sha256'] != implementation
            or binding['solver'] != version['solver']
            or binding['dependencies']['package_sha256'] != version['package_sha256']
            or binding['dependencies']['version'] != version['version']
            or binding['expected'] != record['expected']
            or binding['predicate_sha256'] != digest(record['predicate']) or label != record['label']):
        raise Invalid('LOGIC_QUERY_BINDING')
    raw = read_json(path.with_name('result.json'))
    if raw['status'] != record['raw_result']:
        raise Invalid('RAW_QUERY_RESULT')
    if raw['status'] in ('SAT', 'UNSAT'):
        expected_status = 'PASS' if raw['status'] == record['expected'] else 'FAIL'
        if (record['status'] != expected_status or raw.get('errors')
                or raw.get('raw', '').strip().upper() != raw['status']
                or raw.get('witness') != record.get('witness')):
            raise Invalid('RAW_QUERY_RESULT')
    elif record['status'] != 'UNKNOWN':
        raise Invalid('RAW_QUERY_RESULT')
    if not record.get('query_sha256'):
        if record['status'] == 'PASS':
            raise Invalid('LOGIC_QUERY_MISSING')
        return
    p, q = reference(frozen)
    required = {'P_FEASIBILITY': (p, 'SAT'), 'P_Q_CONSISTENCY': (['and', p, q], 'SAT'),
                'TOTAL_OUTPUT': ([p, q], 'UNSAT')}
    if declared:
        required['INPUT_DOMAIN_PRESERVATION'] = (domains.mismatch(declared, p), 'UNSAT')
        if strict:
            required['INPUT_DOMAIN_NOT_STRENGTHENED'] = (domains.strengthening(declared, r, s), 'UNSAT')
    elif label == 'INPUT_DOMAIN_PRESERVATION':
        raise Invalid('UNBOUND_INPUT_DOMAIN_QUERY')
    if prior is not None:
        old_p, old_q = reference(prior)
        required.update(PRESERVE_OLD=(['and', p, q, ['not', old_q]], 'UNSAT'),
                        REPAIR_NOVELTY=(['and', old_p, old_q, ['not', q]], 'SAT'))
    if label in ('PRESERVE_OLD', 'REPAIR_NOVELTY') and (
        prior is None or binding['dependencies'].get('parent_frozen_sha256') != digest(prior)
    ):
        raise Invalid('REPAIR_QUERY_PARENT')
    if label not in required or (record['predicate'], record['expected']) != required[label]:
        raise Invalid('LOGIC_REQUIRED_PREDICATE')
    if record['status'] == 'PASS' and (raw.get('errors') or raw['raw'].strip().upper() != record['expected']):
        raise Invalid('RAW_QUERY_RESULT')
    env = {name: f'v{i}' for i, name in enumerate(frozen['names'])}
    variables = list(env.values())
    if label == 'TOTAL_OUTPUT':
        result = variables.pop()
        formula = f'(and {smt(p, env)} (not (exists (({result} Int)) (and {domain(result)} {smt(q, env)}))))'
    else:
        formula = smt(record['predicate'], env)
    expected = f"(set-option :timeout {binding['solver']['timeout_ms']})\n"
    expected += ''.join(f'(declare-const {v} Int)\n(assert {domain(v)})\n' for v in variables)
    expected += f'(assert {formula})\n(check-sat)\n'
    query = path.with_name('query.smt2')
    if query.read_text(encoding='utf-8') != expected or sha256_file(query) != record['query_sha256']:
        raise Invalid('LOGIC_QUERY_TEXT')
