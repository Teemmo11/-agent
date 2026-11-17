"""Deterministic ACSL emission and checking of the on-disk file."""
import hashlib
import re

from ..artifacts import sha256_file
from ..ir_ab.semantics import Invalid, digest, normal, pq, read_acsl, render
from .checks import compare, status
from ..llm.parser import strict_json
from ..errors import AgentError


def emission(store, frozen, graph, view):
    path = store.root / 't4/contract.c'
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = ['/*@', r'  assigns \nothing;']
    entries = {}
    parents = {child: key for key, node in graph['nodes'].items() if node['kind'] == 'group'
               for child in node['members']}
    for clause in view['clauses']:
        key = clause['id']
        lines.append(f"  {clause['role']} {key}: {render(clause['expr'])};")
        groups, ancestor = [], parents.get(key)
        while ancestor:
            groups.append(ancestor)
            ancestor = parents.get(ancestor)
        entries[key] = {'line': len(lines), 'origin': graph['nodes'][key]['origin'], 'groups': groups}
    with path.open('x', encoding='utf-8', newline='\n') as stream:
        stream.write('\n'.join([*lines, '*/', frozen['signature'], '']))
    store.write('t4/source_map.json', {
        'schema': 't3t4-output-map-1', 'graph_sha256': digest(graph),
        'output_sha256': sha256_file(path), 'clauses': entries,
    })


def readback(store, frozen, graph, view, checks):
    path = store.root / 't4/contract.c'
    result = {'status': 'FAIL', 'readback': 'FAIL', 'source': 'NOT_RUN',
              'semantics': 'NOT_RUN', 'issues': [], 'queries': []}
    try:
        raw = path.read_bytes()
        text = raw.decode('utf-8')
        parsed = read_acsl(text, frozen)
    except (Invalid, OSError, UnicodeError) as exc:
        result['issues'].append({'code': getattr(exc, 'code', 'OUTPUT_READ_ERROR')})
        return result
    # The parser reads both the signature and the unique fixed frame from the file.
    result.update(readback='PASS', output_sha256=hashlib.sha256(raw).hexdigest())
    actual_signature = text.split('*/', 1)[1].strip()
    store.write('t4/readback.json', {'signature': actual_signature, 'frame': 'nothing', 'clauses': parsed})
    try:
        mapping_bytes = (store.root / 't4/source_map.json').read_bytes()
        mapping = strict_json(mapping_bytes.decode('utf-8'))
        check_mapping(mapping, text, result['output_sha256'], graph, view, parsed)
        result['source'] = 'PASS'
        result['map_sha256'] = hashlib.sha256(mapping_bytes).hexdigest()
    except (Invalid, AgentError, OSError, ValueError, TypeError, KeyError, AttributeError) as exc:
        result['source'] = 'FAIL'
        result['issues'].append({'code': getattr(exc, 'code', 'OUTPUT_MAP_INVALID'),
                                 'detail': getattr(exc, 'detail', '')})
    result['queries'] = compare(checks, 't4', view['pq'], pq(parsed), {
        'graph_sha256': digest(graph), 'output_sha256': result['output_sha256'],
        'P_sha256': digest(view['pq'][0]),
    })
    result['semantics'] = status(result['queries'])
    result['status'] = 'FAIL' if result['source'] == 'FAIL' else result['semantics']
    return result


def check_mapping(mapping, text, output_hash, graph, view, parsed):
    if (not isinstance(mapping, dict) or set(mapping) != {'schema', 'graph_sha256', 'output_sha256', 'clauses'}
            or mapping['schema'] != 't3t4-output-map-1' or mapping['graph_sha256'] != digest(graph)
            or mapping['output_sha256'] != output_hash):
        raise Invalid('OUTPUT_MAP_BINDING')
    clauses = {c['id']: c for c in parsed}
    expected = {c['id']: c for c in view['clauses']}
    if set(clauses) != set(expected) or set(mapping['clauses']) != set(expected):
        raise Invalid('OUTPUT_CLAUSE_COVERAGE', {
            'missing_nodes': sorted(set(expected) - set(clauses)),
            'missing_mappings': sorted(set(expected) - set(mapping['clauses'])),
        })
    ancestry = {}

    def visit(key, ancestors):
        node = graph['nodes'][key]
        if node['kind'] == 'clause':
            ancestry[key] = ancestors
        else:
            for child in node['members']:
                visit(child, [key, *ancestors])

    for key in graph['roots']:
        visit(key, [])
    lines = text.splitlines()
    for key, expected_clause in expected.items():
        actual = clauses[key]
        entry = mapping['clauses'][key]
        line = entry['line']
        if (set(entry) != {'line', 'origin', 'groups'} or type(line) is not int or not 1 <= line <= len(lines)
                or not re.match(rf"\s*{expected_clause['role']}\s+{key}\s*:", lines[line-1])
                or actual['role'] != expected_clause['role'] or entry['origin'] != graph['nodes'][key]['origin']
                or entry['groups'] != ancestry[key] or normal(actual['expr']) != normal(expected_clause['expr'])):
            raise Invalid('OUTPUT_CLAUSE_BINDING', key)
