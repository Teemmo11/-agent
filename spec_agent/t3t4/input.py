"""Validate and bind the authored R/S package to frozen source bytes."""
import hashlib
from pathlib import Path

from ..ir_ab.semantics import Invalid, PROFILE, digest, expand, named, signature, symbols
from ..ir_ab.representation import array, fields, ids
from ..errors import AgentError
from ..llm.parser import strict_json

VERSION = 't3t4-input-1'
SPAN_VERSION = 't3t4-input-spans-1'
RULES = 't3t4-rules-1'
GRAPH = 't3t4-b-1'
CANDIDATE = 't3t4-candidate-1'


def read_json(path):
    try:
        return strict_json(Path(path).read_text(encoding='utf-8'))
    except AgentError:
        raise Invalid('INVALID_JSON') from None


def resolve_guards(definitions, names):
    resolved = {}
    active = set()

    def resolve(name):
        if name not in definitions:
            raise Invalid('UNKNOWN_GUARD', name)
        if name in active:
            raise Invalid('GUARD_CYCLE', name)
        if len(active) >= 20:
            raise Invalid('GUARD_DEPTH')
        if name not in resolved:
            active.add(name)
            resolved[name] = expand(definitions[name], names, 'requires', resolve)
            active.remove(name)
        return resolved[name]

    for name in definitions:
        resolve(name)
    return resolved


def freeze(package, material):
    fields(package, ('schema', 'id', 'params', 'data_model', 'frame', 'R', 'S', 'guards'),
           ('material_id', 'material_kind'))
    if package['schema'] not in (VERSION, SPAN_VERSION) or package['data_model'] not in ('LP64', 'ILP32'):
        raise Invalid('INPUT_PROFILE_UNSUPPORTED')
    if package['frame'] != 'nothing':
        raise Invalid('FRAME_UNSUPPORTED')
    ids(package['params'])
    names = symbols(package)
    sig = signature(package)
    guards = package['guards']
    if not isinstance(guards, dict) or len(guards) > 48:
        raise Invalid('INVALID_GUARDS')
    ids(list(guards))
    resolved = resolve_guards(guards, names)
    original_text = material.decode('utf-8') if material is not None else ''
    original = original_text.splitlines()
    material_hash = hashlib.sha256(material).hexdigest() if material is not None else None
    material_id = package.get('material_id', 'requirements')
    if not named(material_id) or package.get('material_kind', 'AUTHORED') not in ('AUTHORED', 'SYNTHETIC'):
        raise Invalid('INVALID_MATERIAL_IDENTITY')
    requirements = {}
    source_issues = []
    for row in array(package['R']):
        spans_mode = package['schema'] == SPAN_VERSION
        fields(row, ('id', 'text', 'spans') if spans_mode else ('id', 'text'),
               ('review',) if spans_mode else ('lines', 'review'))
        rid, text = row['id'], row['text']
        if not named(rid) or rid in requirements or not isinstance(text, str) or not text.strip():
            raise Invalid('INVALID_REQUIREMENT')
        review = row.get('review', 'NOT_REVIEWED')
        if review not in ('NOT_REVIEWED', 'REVIEWED', 'AMBIGUOUS', 'UNEXPRESSIBLE'):
            raise Invalid('INVALID_REVIEW_STATUS')
        anchor = None
        extent = row.get('lines')
        if material is None:
            source_issues.append({'code': 'SOURCE_UNAVAILABLE', 'requirement': rid})
        elif spans_mode:
            spans = validate_spans(row['spans'], original_text, text)
            anchor = {'material_id': material_id, 'sha256': material_hash,
                      'coordinate': 'UNICODE_CODEPOINT_ZERO_BASED_HALF_OPEN',
                      'spans': spans, 'excerpt': text}
        elif (not isinstance(extent, list) or len(extent) != 2 or
              any(type(n) is not int for n in extent) or not 1 <= extent[0] <= extent[1] <= len(original) or
              '\n'.join(original[extent[0]-1:extent[1]]) != text):
            source_issues.append({'code': 'SOURCE_ANCHOR_MISMATCH', 'requirement': rid})
        else:
            anchor = {'material_id': material_id, 'sha256': material_hash, 'lines': extent, 'excerpt': text}
        requirements[rid] = {'text': text, 'anchor': anchor, 'interpretation_review': review}
    obligations = {}
    for row in array(package['S']):
        fields(row, ('id', 'role', 'expr', 'requirement_refs'), ('guard',))
        sid, role = row['id'], row['role']
        if not named(sid) or sid in obligations or role not in ('requires', 'ensures'):
            raise Invalid('INVALID_OBLIGATION')
        refs = ids(row['requirement_refs'])
        if not refs or any(ref not in requirements for ref in refs):
            raise Invalid('INVALID_REQUIREMENT_REFERENCE', sid)
        body = expand(row['expr'], names, role)
        guard = row.get('guard')
        if 'guard' in row and (role != 'ensures' or not named(guard) or guard not in resolved):
            raise Invalid('INVALID_OBLIGATION_GUARD', sid)
        obligations[sid] = {'role': role, 'expr': body, 'guard': guard, 'requirement_refs': refs,
                            'version': digest(row)}
    if not obligations or not any(o['role'] == 'ensures' for o in obligations.values()):
        raise Invalid('POSTCONDITION_REQUIRED')
    return {
        'id': package['id'], 'params': package['params'], 'signature': sig, 'names': names,
        'S': obligations, 'R': requirements, 'guards': guards, 'resolved_guards': resolved,
        'domain': {**PROFILE, 'model': package['data_model']},
        'symbols': {n: {'type': 'signed int32', 'state': 'return' if n == 'result' else 'entry'} for n in names},
        'material': {'id': material_id, 'kind': package.get('material_kind', 'AUTHORED'), 'sha256': material_hash},
        'input_sha256': digest(package), 'source_issues': source_issues, 'rules': RULES, 'schema': GRAPH,
    }


def validate_spans(spans, original, text):
    previous = 0
    excerpts = []
    for span in array(spans, 32):
        fields(span, ('start', 'end', 'excerpt'))
        start, end = span['start'], span['end']
        if (type(start) is not int or type(end) is not int or not previous <= start < end <= len(original)
                or original[start:end] != span['excerpt'] or not original[start:end].strip()):
            raise Invalid('SOURCE_SPAN_MISMATCH')
        previous = end
        excerpts.append(span['excerpt'])
    if not excerpts or '\n'.join(excerpts) != text:
        raise Invalid('SOURCE_SPAN_TEXT_MISMATCH')
    return spans


def fragments(obligation):
    expr = obligation['expr']
    parts = {'': expr}
    if isinstance(expr, list) and expr[0] == 'and':
        parts.update({f'/args/{i}': term for i, term in enumerate(expr[1:])})
    return parts


def guard_subset(frozen, references):
    selected = {}

    def visit(expr):
        if isinstance(expr, list):
            if expr[0] == 'ref':
                add(expr[1])
            else:
                for child in expr[1:]:
                    visit(child)

    def add(name):
        if not named(name) or name not in frozen['guards']:
            raise Invalid('UNKNOWN_GUARD')
        if name not in selected:
            definition = frozen['guards'][name]
            selected[name] = definition
            visit(definition)

    for name in references:
        add(name)
    return selected


def source_formula(frozen, sid):
    obligation = frozen['S'][sid]
    guard = obligation['guard']
    return ['implies', frozen['resolved_guards'][guard], obligation['expr']] if guard else obligation['expr']
