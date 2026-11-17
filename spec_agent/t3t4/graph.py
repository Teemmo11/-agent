"""B graph construction and independent validation of actual snapshots."""
from collections import Counter
from copy import deepcopy

from ..ir_ab.representation import array, fields
from ..ir_ab.semantics import Invalid, digest, expand, named, pq
from .input import CANDIDATE, fragments, guard_subset, resolve_guards


def header(frozen):
    keys = ('schema', 'rules', 'signature', 'domain', 'symbols', 'material', 'input_sha256')
    return {**{key: frozen[key] for key in keys}, 'frozen_sha256': digest(frozen)}


def empty(frozen):
    return {'header': header(frozen), 'roots': [], 'nodes': {}, 'guards': {}}


def node_id(sid, path, kind):
    return 'N' + digest([sid, path, kind])[:24]


def origin(frozen, sid, path):
    return {'s_id': sid, 'path': path, 's_version': frozen['S'][sid]['version']}


def operations(frozen, split=True):
    for sid, source in frozen['S'].items():
        paths = list(fragments(source))[1:] if split else []
        if paths:
            yield {'rule': 'OPEN_GROUP', 's_id': sid, 'path': ''}
        for path in paths or ['']:
            yield {'rule': 'SPLIT_TOP_AND' if path else 'COPY', 's_id': sid, 'path': path}


def apply(graph, op, frozen):
    """Rule executor. Its output is always treated as an unchecked candidate."""
    graph = deepcopy(graph)
    sid, path, rule = op['s_id'], op['path'], op['rule']
    source = frozen['S'][sid]
    kind = 'group' if rule == 'OPEN_GROUP' else 'clause'
    key = node_id(sid, path, kind)
    node = {'kind': kind, 'role': source['role'], 'origin': origin(frozen, sid, path)}
    if kind == 'group':
        node.update(combine='and', members=[])
    else:
        node.update(expr=fragments(source)[path], guard=source['guard'])
        if node['guard']:
            graph['guards'].update(guard_subset(frozen, [node['guard']]))
    graph['nodes'][key] = node
    if rule == 'SPLIT_TOP_AND':
        graph['nodes'][node_id(sid, '', 'group')]['members'].append(key)
    else:
        graph['roots'].append(key)
    return graph


def inspect(graph, frozen):
    """Separate decodable graph structure from exact fragment coverage."""
    fields(graph, ('header', 'roots', 'nodes', 'guards'))
    if graph['header'] != header(frozen):
        raise Invalid('HEADER_BINDING')
    nodes, guards = graph['nodes'], graph['guards']
    if not isinstance(nodes, dict) or not isinstance(guards, dict) or len(nodes) > 4096 or len(guards) > 48:
        raise Invalid('GRAPH_SIZE')
    if not all(named(key) for key in (*nodes, *guards)):
        raise Invalid('INVALID_GRAPH_ID')
    resolved = resolve_guards(guards, frozen['names'])
    seen, active = set(), set()
    clauses, issues, counts = [], [], Counter()
    used_guards = []

    def visit(key, depth=0):
        if depth > 20:
            raise Invalid('GRAPH_DEPTH')
        if not named(key) or key not in nodes:
            raise Invalid('NODE_REFERENCE', str(key))
        if key in active:
            raise Invalid('GRAPH_CYCLE', key)
        if key in seen:
            raise Invalid('DUPLICATE_MEMBERSHIP', key)
        active.add(key)
        seen.add(key)
        node = nodes[key]
        fields(node, ('kind', 'role', 'origin'), ('expr', 'guard', 'members', 'combine'))
        kind, role, ref = node['kind'], node['role'], node['origin']
        if role not in ('requires', 'ensures'):
            raise Invalid('INVALID_ROLE', key)
        fields(ref, ('s_id', 'path', 's_version'))
        sid, path = ref['s_id'], ref['path']
        if not isinstance(sid, str) or not isinstance(path, str):
            raise Invalid('SOURCE_REFERENCE', key)
        source = frozen['S'].get(sid)
        parts = fragments(source) if source else {}
        if path not in parts or ref['s_version'] != source['version'] or role != source['role']:
            issues.append({'code': 'SOURCE_REFERENCE', 'node': key, 's_id': sid, 'path': path})
        if kind == 'group':
            fields(node, ('kind', 'role', 'origin', 'combine', 'members'))
            if node['combine'] != 'and':
                raise Invalid('GROUP_COMBINE', key)
            children = [visit(child, depth+1) for child in array(node['members'], 4096)]
            if any(child_role != role for child_role, _ in children):
                raise Invalid('GROUP_ROLE', key)
            descendants = set().union(*(sources for _, sources in children))
            if path or descendants - {sid}:
                issues.append({'code': 'GROUP_SOURCE', 'node': key, 's_id': sid})
        elif kind == 'clause':
            fields(node, ('kind', 'role', 'origin', 'expr', 'guard'))
            body = expand(node['expr'], frozen['names'], role)
            guard = node['guard']
            if guard is not None:
                if role != 'ensures' or not named(guard) or guard not in resolved:
                    raise Invalid('GUARD_SCOPE_OR_REFERENCE', key)
                used_guards.append(guard)
            if not source or body != parts.get(path) or guard != source['guard']:
                issues.append({'code': 'FRAGMENT_OR_GUARD_CHANGED', 'node': key, 's_id': sid, 'path': path})
            counts[sid, path] += 1
            formula = ['implies', resolved[guard], body] if guard is not None else body
            clauses.append({'id': key, 'role': role, 'expr': formula, 's_id': sid, 'path': path})
            descendants = {sid}
        else:
            raise Invalid('NODE_KIND', key)
        active.remove(key)
        return role, descendants

    for key in array(graph['roots'], 4096):
        visit(key)
    if seen != set(nodes):
        raise Invalid('UNREACHABLE_NODE', sorted(set(nodes) - seen))
    expected_guards = guard_subset(frozen, used_guards)
    if guards != expected_guards:
        issues.append({'code': 'GUARD_DEFINITION_BINDING'})
    pending, covered = {}, []
    for sid, source in frozen['S'].items():
        paths = [path for s, path in counts if s == sid]
        split = set(fragments(source)) - {''}
        if paths and (set(paths) == {''} or set(paths) == split) and all(counts[sid, p] == 1 for p in paths):
            covered.append(sid)
        else:
            pending[sid] = {'observed': paths, 'whole': '', 'split': sorted(split),
                            'duplicates': [p for p in paths if counts[sid, p] > 1]}
    for (sid, path), count in counts.items():
        if count > 1 or (path and counts[sid, '']):
            issues.append({'code': 'OVERLAPPING_SOURCE', 's_id': sid, 'path': path})
    for key, item in nodes.items():
        if item['kind'] == 'group' and not item['members'] and item['origin']['s_id'] in covered:
            issues.append({'code': 'EMPTY_GROUP', 'node': key, 's_id': item['origin']['s_id']})
    return {'issues': issues, 'covered': covered, 'pending': pending, 'clauses': clauses, 'pq': pq(clauses),
            'organization': {'roots': len(graph['roots']),
                             'groups': sum(n['kind'] == 'group' for n in nodes.values()),
                             'clauses': len(clauses), 'guards': dict(Counter(used_guards))}}


def local_check(before, candidate, op, frozen):
    """Check the new fragment and the permitted write set against the previous graph."""
    view = inspect(candidate, frozen)
    if view['issues']:
        raise Invalid('LOCAL_SOURCE_CHECK', view['issues'])
    sid, path, rule = op['s_id'], op['path'], op['rule']
    kind = 'group' if rule == 'OPEN_GROUP' else 'clause'
    key = node_id(sid, path, kind)
    prior = before['nodes']
    if key in prior or set(candidate['nodes']) != set(prior) | {key}:
        raise Invalid('LOCAL_NODE_WRITE_SET')
    parent = node_id(sid, '', 'group') if rule == 'SPLIT_TOP_AND' else None
    if parent and parent not in prior:
        raise Invalid('LOCAL_MISSING_GROUP')
    for nid, old in prior.items():
        expected = {**old, 'members': [*old['members'], key]} if nid == parent else old
        if candidate['nodes'][nid] != expected:
            raise Invalid('LOCAL_PRIOR_NODE_CHANGED', nid)
    expected_roots = before['roots'] if parent else [*before['roots'], key]
    new = candidate['nodes'][key]
    if candidate['roots'] != expected_roots or new['origin'] != origin(frozen, sid, path) or new['kind'] != kind:
        raise Invalid('LOCAL_ROOT_OR_ORIGIN')
    if kind == 'group' and new['members']:
        raise Invalid('LOCAL_GROUP_NOT_EMPTY')
    if any(candidate['guards'].get(k) != v for k, v in before['guards'].items()):
        raise Invalid('LOCAL_PRIOR_GUARD_CHANGED')
    return view


def normalize(proposal, frozen):
    fields(proposal, ('schema', 'roots', 'nodes'))
    if proposal['schema'] != CANDIDATE:
        raise Invalid('CANDIDATE_SCHEMA')
    graph = empty(frozen)
    mapping = {}
    for node in array(proposal['nodes'], 4096):
        fields(node, ('id', 'kind', 'role', 's_id', 'path'), ('expr', 'guard', 'members', 'combine'))
        label, sid, path, kind = (node[k] for k in ('id', 's_id', 'path', 'kind'))
        if not named(label) or label in mapping or not named(sid) or sid not in frozen['S'] or not isinstance(path, str):
            raise Invalid('CANDIDATE_ID_OR_ORIGIN')
        key = node_id(sid, path, kind)
        if key in graph['nodes']:
            raise Invalid('DUPLICATE_SOURCE_NODE')
        mapping[label] = key
        graph['nodes'][key] = {k: v for k, v in node.items() if k not in ('id', 's_id', 'path')}
        graph['nodes'][key]['origin'] = origin(frozen, sid, path)

    def linked(label):
        if not named(label) or label not in mapping:
            raise Invalid('CANDIDATE_LINK')
        return mapping[label]

    graph['roots'] = [linked(label) for label in array(proposal['roots'], 4096)]
    for node in graph['nodes'].values():
        if 'members' in node:
            node['members'] = [linked(label) for label in array(node['members'], 4096)]
    graph['guards'] = guard_subset(frozen, [n['guard'] for n in graph['nodes'].values() if n.get('guard') is not None])
    return graph, mapping
