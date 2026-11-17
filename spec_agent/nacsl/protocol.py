"""Versioned role protocols, exact source coordinates and lossless T3 adapter."""
from pathlib import Path

from ..errors import AgentError
from ..ir_ab.semantics import Invalid, digest, signature
from ..llm.schema import validate
from ..t3t4.input import SPAN_VERSION, freeze, read_json

SCHEMA_FILE = Path(__file__).resolve().parents[1] / 'schemas/nacsl_protocol.schema.json'
SCHEMA = read_json(SCHEMA_FILE)
DEFS = SCHEMA['$defs']


def check(value, schema, path='$', depth=0):
    """Validate the additional schema keywords used by these versioned protocols."""
    if depth > 80 or schema is False:
        raise Invalid('PROTOCOL_STRUCTURE', path)
    again = depth + 1
    if '$ref' in schema:
        return check(value, DEFS[schema['$ref'].split('/')[-1]], path, again)
    if 'oneOf' in schema:
        matches = 0
        for case in schema['oneOf']:
            try:
                check(value, case, path, again)
            except Invalid:
                continue
            matches += 1
        if matches != 1:
            raise Invalid('PROTOCOL_ALTERNATIVE', path)
        return
    if 'const' in schema and (type(value) is not type(schema['const']) or value != schema['const']):
        raise Invalid('PROTOCOL_VERSION_OR_CONSTANT', path)
    shallow = {k: v for k, v in schema.items() if k not in ('properties', 'items', 'additionalProperties')}
    try:
        validate(value, shallow, path)
    except AgentError as exc:
        raise Invalid('PROTOCOL_SHAPE', str(exc)) from None
    if type(value) is int and not schema.get('minimum', value) <= value <= schema.get('maximum', value):
        raise Invalid('PROTOCOL_INTEGER_RANGE', path)
    if isinstance(value, dict):
        properties = schema.get('properties', {})
        if len(value) > schema.get('maxProperties', 10000):
            raise Invalid('PROTOCOL_OBJECT_SIZE', path)
        for k, v in value.items():
            if 'propertyNames' in schema:
                check(k, schema['propertyNames'], path, again)
            check(v, properties.get(k, schema.get('additionalProperties', {})), f'{path}.{k}', again)
    if isinstance(value, list):
        prefix = schema.get('prefixItems', [])
        for index, child in enumerate(value):
            child_schema = prefix[index] if index < len(prefix) else schema.get('items', {})
            check(child, child_schema, f'{path}[{index}]', again)


def validate_message(data, stage):
    check(data, DEFS[stage])
    return data


def source_lines(text):
    rows = []
    offset = 0
    for i, line in enumerate(text.splitlines(keepends=True), 1):
        rows.append({'line': i, 'start': offset, 'text': line.rstrip('\r\n\v\f\x1c\x1d\x1e\x85\u2028\u2029')})
        offset += len(line)
    return rows


def anchor(selector, lines):
    index, quote = selector['line'], selector['quote']
    if index > len(lines) or not quote.strip():
        raise Invalid('ANCHOR_RANGE', index)
    row = lines[index-1]
    matches = []
    position = row['text'].find(quote)
    while position >= 0:
        matches.append(position)
        position = row['text'].find(quote, position+1)
    occurrence = selector.get('occurrence')
    if occurrence is None and len(matches) != 1:
        raise Invalid('ANCHOR_MISSING_OR_AMBIGUOUS', index)
    if occurrence is not None and occurrence > len(matches):
        raise Invalid('ANCHOR_OCCURRENCE', index)
    start = row['start'] + matches[(occurrence or 1) - 1]
    return {'start': start, 'end': start+len(quote), 'excerpt': quote}


def issue_refs(issues, allowed):
    for item in issues:
        if not item['refs'] or not set(item['refs']) <= allowed:
            raise Invalid('UNKNOWN_ISSUE_REFERENCE')


def parse_r(data, text):
    validate_message(data, 't1')
    lines = source_lines(text)
    allowed = {f'N:L{row["line"]}' for row in lines}
    issue_refs(data['issues'], allowed)
    rows = []
    covered = set()
    for index, item in enumerate(data['items'], 1):
        spans = sorted((anchor(x, lines) for x in item['anchors']), key=lambda x: x['start'])
        if any(b['start'] < a['end'] for a,b in zip(spans, spans[1:])):
            raise Invalid('OVERLAPPING_ITEM_SPANS')
        rows.append({'id': f'R{index}', 'kind': item['kind'], 'interpretation': item['interpretation'], 'spans': spans})
        for span in spans:
            covered.update(range(span['start'], span['end']))
    gaps = []
    for row in lines:
        chars = [row['start']+i for i, ch in enumerate(row['text'])
                 if row['start']+i not in covered and not ch.isspace() and ch not in '，。；：、,.!！?？;:']
        if chars:
            first, last = min(chars), max(chars)+1
            gaps.append({'ref': f'N:L{row["line"]}', 'start': first, 'end': last, 'excerpt': text[first:last]})
    return {'schema': 'nacsl-r-1', 'rows': rows, 'issues': data['issues'], 'unclassified': gaps}


def check_interface(interface):
    validate_message(interface, 'interface')
    signature({'id': interface['function'], 'params': interface['parameters']})
    params = set(interface['parameters'])
    if any(target not in params or (alias in params and alias != target)
           for alias, target in interface.get('parameter_aliases', {}).items()):
        raise Invalid('INVALID_PARAMETER_ALIAS')
    return interface


def adapt(interface, r, s, material, material_kind):
    requirement_rows = [row for row in r['rows'] if row['kind'] == 'REQUIREMENT']
    package = {
        'schema': SPAN_VERSION, 'id': interface['function'], 'params': interface['parameters'],
        'data_model': interface['data_model'], 'frame': interface['frame'],
        'material_id': 'original', 'material_kind': material_kind, 'guards': s['guards'], 'S': s['S'],
        'R': [{'id': row['id'], 'text': '\n'.join(x['excerpt'] for x in row['spans']), 'spans': row['spans']}
              for row in requirement_rows],
    }
    frozen = freeze(package, material)
    return package, frozen


def parse_s(data, r):
    # Give actionable operand feedback before the recursive union hides its path.
    if isinstance(data, dict):
        def operands(expr, path):
            if not isinstance(expr, list) or not expr:
                return
            if expr[0] in ('eq', 'ne', 'le', 'lt', 'ge', 'gt'):
                for i, child in enumerate(expr[1:], 1):
                    if not (type(child) is int or isinstance(child, str)):
                        raise Invalid('T2_OPERAND_TYPE', path + f'[{i}]: expected int32 literal or symbol; '
                                      'nested arithmetic/Boolean expressions are not operands. '
                                      'If required behavior is unsupported, return status UNSUPPORTED, '
                                      'S: [], guards: {}, and a source-linked UNSUPPORTED issue.')
            else:
                for i, child in enumerate(expr[1:], 1):
                    operands(child, path + f'[{i}]')
        for i, row in enumerate(data.get('S', []) if isinstance(data.get('S'), list) else []):
            if isinstance(row, dict):
                operands(row.get('expr'), f'$.S[{i}].expr')
    validate_message(data, 't2')
    known = {f'R:{row["id"]}' for row in r['rows']}
    issue_refs(data['issues'], known)
    if (data['status'] == 'OK') == bool(data['issues']):
        raise Invalid('T2_STATUS_ISSUES_MISMATCH')
    return data


def protected(old, new):
    anchors = {s['id']: s for s in new['S']}
    changes = [{'obligation': s['id']} for s in old['S'] if anchors.get(s['id']) != s]
    old_ids = {s['id'] for s in old['S']}
    changes += [{'guard': k} for k, v in old['guards'].items() if new['guards'].get(k) != v]
    changes += [{'new_precondition': s['id']} for s in new['S'] if s['role'] == 'requires' and s['id'] not in old_ids]
    return changes


def protocol_prompt(stage, issue_ref_choices=None):
    """Only the stage schema and its referenced definitions enter the request."""
    root = DEFS[stage]
    dependencies = {}

    def walk(item):
        if isinstance(item, dict):
            if '$ref' in item:
                name = item['$ref'].split('/')[-1]
                if name not in dependencies:
                    dependencies[name] = DEFS[name]
                    walk(DEFS[name])
            for child in item.values():
                walk(child)
        elif isinstance(item, list):
            for child in item:
                walk(child)

    walk(root)
    if issue_ref_choices and 'issue' in dependencies:
        from copy import deepcopy
        dependencies['issue'] = deepcopy(dependencies['issue'])
        dependencies['issue']['properties']['refs']['items'] = {'enum': issue_ref_choices}
    return {**root, '$defs': dependencies}
