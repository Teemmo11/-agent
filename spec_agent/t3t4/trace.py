"""Trace actual nodes, artifacts and failures through S to frozen original text."""
from ..ir_ab.semantics import Invalid, digest
from .graph import inspect
from .input import guard_subset, read_json


def trace_index(root, frozen, graph, report):
    main = report['main']
    obligations = {}
    for sid, source in frozen['S'].items():
        obligations[sid] = {
            'source': source, 'requirements': source['requirement_refs'],
            'checks': [c['artifact'] for c in main['groups'] if c['s_id'] == sid],
            'related_global_checks': [c['artifact'] for c in main['global']],
            'nodes': [], 'output': [], 'issues': [], 'steps': [],
        }
    for path in sorted((root / 't3/steps').glob('*/step.json')):
        step = read_json(path)
        record = {
            'artifact': path.relative_to(root).as_posix(), 'committed': step['committed'],
            'status': step['check']['status'],
        }
        related = {step['origin']['s_id']}
        if not step['committed']:
            previous = read_json(root / step['before']['artifact'])
            proposed = read_json(path.with_name('candidate.json'))
            roots_changed = set(previous['roots']) ^ set(proposed.get('roots', []))
            for key in set(step['changed_nodes']) | roots_changed:
                for snap in (previous, proposed):
                    ref = snap.get('nodes', {}).get(key, {}).get('origin', {})
                    if ref.get('s_id') in obligations:
                        related.add(ref['s_id'])
            record['failure'] = step['check']
        for sid in related:
            obligations[sid]['steps'].append(record)
    for issue in main['issues']:
        sid = issue.get('s_id')
        if sid in obligations:
            obligations[sid]['issues'].append(issue)
    nodes = {}
    try:
        inspect(graph, frozen)
    except Invalid:
        pass
    else:
        for key, node in graph['nodes'].items():
            ref = node['origin']
            if ref['s_id'] in obligations:
                nodes[key] = ref
                obligations[ref['s_id']]['nodes'].append(key)
    t4 = report['t4']
    for issue in t4.get('issues', []):
        detail = issue.get('detail')
        if isinstance(detail, str):
            related = [detail]
        elif isinstance(detail, dict):
            related = detail.get('missing_nodes', []) + detail.get('missing_mappings', [])
        else:
            related = []
        for sid in {nodes[key]['s_id'] for key in related if key in nodes}:
            obligations[sid]['issues'].append(issue)
    if t4.get('source') == 'PASS':
        mapping = read_json(root / 't4/source_map.json')
        for key, entry in mapping['clauses'].items():
            obligations[nodes[key]['s_id']]['output'].append({
                'node': key, 'line': entry['line'], 'file': 't4/contract.c',
                'sha256': mapping['output_sha256'], 'qualified': report['publication_eligible'],
                'checks': [q['artifact'] for q in t4['queries']],
            })
    guards = {name: {'version': digest(expr), 'obligations': []} for name, expr in frozen['guards'].items()}
    for sid, source in frozen['S'].items():
        if source['guard']:
            for name in guard_subset(frozen, [source['guard']]):
                guards[name]['obligations'].append(sid)
    requirements = {}
    for rid, source in frozen['R'].items():
        linked = [sid for sid, row in obligations.items() if rid in row['requirements']]
        gaps = []
        if not linked:
            gaps.append('NO_S_OBLIGATION')
        if source['anchor'] is None:
            gaps.append('SOURCE_ANCHOR_UNAVAILABLE')
        if source['interpretation_review'] != 'REVIEWED':
            gaps.append(source['interpretation_review'])
        if any(sid in main.get('pending', {}) for sid in linked):
            gaps.append('INCOMPLETE_GRAPH_COVERAGE')
        if linked and t4.get('source') != 'PASS':
            gaps.append('NO_CHECKED_OUTPUT_MAPPING')
        requirements[rid] = {**source, 'obligations': linked, 'gaps': gaps}
    evidence = {}
    for path in sorted((root / 'evidence').rglob('check.json')):
        record = read_json(path)
        sid = record['binding']['dependencies'].get('s_id')
        evidence[record['artifact']] = {'scope': 'OBLIGATION' if sid else 'CONTRACT',
                                        'obligations': [sid] if sid else list(obligations)}
    return {'schema': 't3t4-trace-1', 'material': frozen['material'], 'requirements': requirements,
            'obligations': obligations, 'nodes': nodes, 'guards': guards, 'evidence': evidence,
            'main_issues': main['issues'], 't4_issues': t4.get('issues', []),
            'original_snapshot': 'inputs/original.txt' if frozen['material']['sha256'] else None,
            'coverage_claim': 'REFERENCE_LINKS_ONLY'}


def lookup(index, *, requirement=None, item=None):
    if requirement is not None:
        row = index['requirements'][requirement]
        return {'id': requirement, **row, 'original_snapshot': index['original_snapshot'],
                'details': {sid: index['obligations'][sid] for sid in row['obligations']}}
    if item in index['nodes']:
        sids = [index['nodes'][item]['s_id']]
    elif item in index['obligations']:
        sids = [item]
    elif item in index['evidence']:
        sids = index['evidence'][item]['obligations']
    elif item in index['guards']:
        sids = index['guards'][item]['obligations']
    else:
        sids = [sid for sid, row in index['obligations'].items()
                if any(step['artifact'] == item for step in row['steps'])]
        if not sids:
            raise KeyError(item)
    return {'item': item, 'details': {sid: index['obligations'][sid] for sid in sids},
            'original_snapshot': index['original_snapshot'],
            'requirements': {rid: index['requirements'][rid] for sid in sids
                             for rid in index['obligations'][sid]['requirements']}}
