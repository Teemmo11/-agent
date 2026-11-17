"""Blinded alignment and evidence-scoped repair proposals."""
from .protocol import validate_message
from ..ir_ab.semantics import Invalid
from ..t3t4.input import read_json

CAPABILITIES = {
    'expressions': 'int32 scalar comparisons and Boolean connectives; entry-only guards',
    'unsupported': ['arithmetic operands', 'pointers', 'quantifiers', 'heap', 'loops'],
    'frame': 'assigns nothing; normal-return contract only',
    'authority': 'LLM_JUDGMENT, not a formal verdict; missing artifacts are not missing requirements',
}


def alignment_context(interface, lines, r, s, acsl):
    return {'interface': interface, 'N': lines, 'R': r['rows'] if r else [],
            'S': s['S'] if s else [], 'guards': s['guards'] if s else {},
            'ACSL': acsl, 'allowed_refs': list(material_refs(lines, r, s)),
            'capabilities': CAPABILITIES,
            'availability': {'R': r is not None, 'S': s is not None, 'ACSL': acsl is not None}}


def material_refs(lines, r, s):
    refs = {f'N:L{line["line"]}': line for line in lines}
    if r:
        refs.update({f'R:{row["id"]}': row for row in r['rows']})
    if s:
        refs.update({f'S:{row["id"]}': row for row in s['S']})
    return refs


def conversion_refs(root, child):
    if child is None:
        return {}
    run_ref = child['run']
    index_file = root / run_ref / 'trace/index.json'
    refs = {
        'EV:T3': {'status': child['T3'], 'artifact': run_ref + '/t3/main/checks.json'},
        'EV:T4': {'status': child['T4'], 'artifact': run_ref + '/result.json'},
    }
    if not (root / refs['EV:T3']['artifact']).is_file():
        refs['EV:T3']['artifact'] = run_ref + '/result.json'
    if index_file.is_file():
        trace = read_json(index_file)
        refs.update({f'IR:{key}': value for key, value in trace['nodes'].items()})
        for data in trace['obligations'].values():
            for entry in data['output']:
                refs['OUT:' + entry['node']] = {**entry, 'file': run_ref + '/' + entry['file']}
    return refs


def findings(response, allowed):
    validate_message(response, 'alignment')
    rows = []
    for index, row in enumerate(response['findings'], 1):
        if not row['refs'] or not set(row['refs']) <= set(allowed):
            raise Invalid('UNPROVIDED_REVIEW_REFERENCE')
        rows.append({'id': f'F{index}', **row, 'evidence_kind': 'LLM_JUDGMENT'})
    return rows


def proposals(response, rows, allowed):
    validate_message(response, 'diagnosis')
    known = {r['id'] for r in rows}
    output = []
    for index, row in enumerate(response['proposals'], 1):
        if (not row['evidence_refs'] or not set(row['evidence_refs']) <= set(allowed)
                or not set(row['finding_refs']) <= known):
            raise Invalid('UNPROVIDED_DIAGNOSIS_REFERENCE')
        output.append({'id': f'D{index}', **row, 'evidence_kind': 'LLM_JUDGMENT'})
    return output


def additions(rows, plan, allowed):
    if not rows:
        return []
    by_id = {r['id']: r for r in rows}
    selected = []
    for proposal in plan:
        refs = proposal['finding_refs']
        if (proposal['stage'] != 'T2' or proposal['action'] != 'ADD_POSTCONDITION' or not refs
                or any(by_id[r]['category'] != 'OMISSION' for r in refs)):
            return []
        # Authorization for a change is constrained to the R IDs cited in the finding.
        source_refs = {ref[2:] for key in refs for ref in by_id[key]['refs'] if ref.startswith('R:')}
        if not source_refs or not source_refs <= allowed:
            return []
        selected.append({**proposal, 'allowed_requirements': sorted(source_refs)})
    return selected if {f for p in selected for f in p['finding_refs']} == set(by_id) else []
