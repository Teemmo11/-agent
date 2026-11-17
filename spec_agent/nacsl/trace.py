"""Join the frozen source spans with findings, versions and downstream evidence."""
from .protocol import source_lines
from ..t3t4.input import read_json


def make_index(root, r, report):
    text = (root/'inputs/N.txt').read_bytes().decode('utf-8', errors='replace')
    lines = {f'N:L{x["line"]}': x for x in source_lines(text)}
    rows = {row['id']: {**row, 'versions': []} for row in (r['rows'] if r else [])}
    backward = {}
    for line, row in lines.items():
        start, end = row['start'], row['start'] + len(row['text'])
        backward[line] = [rid for rid, req in rows.items()
                          if any(s['start'] < end and s['end'] > start for s in req['spans'])]
    for version in report['versions']:
        number = version['version']
        s = read_json(root / version['S'])
        child = version.get('downstream')
        path = root / child['run'] / 'trace/index.json' if child else None
        index = read_json(path) if path and path.is_file() else {}
        for label, check in version.get('source_checks', {}).items():
            linked = {req for obligation in s['S']
                      if label not in ('P_FEASIBILITY', 'INPUT_DOMAIN_PRESERVATION') or obligation['role'] == 'requires'
                      for req in obligation['requirement_refs']}
            for key in (f'V{number}:EV:{label}', check['artifact']):
                backward[key] = sorted(linked)
        for req, row in rows.items():
            obligations = {}
            for obligation in s['S']:
                if req not in obligation['requirement_refs']:
                    continue
                sid = obligation['id']
                evidence = index.get('obligations', {}).get(sid, {})
                obligations[sid] = {'formula': obligation, 'downstream': evidence}
                backward.setdefault(f'V{number}:S:{sid}', []).append(req)
                for node in evidence.get('nodes', []):
                    backward.setdefault(f'V{number}:IR:{node}', []).append(req)
                for output in evidence.get('output', []):
                    backward.setdefault(f'V{number}:OUT:{output["node"]}', []).append(req)
                if child:
                    for item in (*evidence.get('checks', []), *evidence.get('related_global_checks', [])):
                        backward.setdefault(child['run']+'/'+item, []).append(req)
            row['versions'].append({'version': number, 'decision': version['decision'], 'obligations': obligations,
                                    'unmapped': req in version.get('unmapped_R', []),
                                    'run': child['run'] if child else None, 'proposals': version.get('proposals', []),
                                    'source_checks': [check['artifact'] for check in version.get('source_checks', {}).values()
                                                      if req in backward[check['artifact']]]})
    for record in report['reviews']:
        number = record['version']
        for finding in record['findings']:
            related = []
            for ref in finding['refs']:
                if ref.startswith('R:'):
                    related.append(ref[2:])
                else:
                    related.extend(backward.get(ref if ref.startswith('N:') else f'V{number}:'+ref, []))
            backward[f'V{number}:{finding["id"]}'] = sorted(set(related))
        for proposal in record['proposals']:
            keys = [*proposal['finding_refs'], *proposal['evidence_refs']]
            related = set()
            for key in keys:
                if key.startswith('R:'):
                    related.add(key[2:])
                else:
                    related.update(backward.get(key if key.startswith('N:') else f'V{number}:'+key, []))
            backward[f'V{number}:{proposal["id"]}'] = sorted(related)
    return {'schema': 'nacsl-trace-1', 'original': 'inputs/N.txt', 'lines': lines,
            'requirements': rows, 'unclassified': r['unclassified'] if r else list(lines),
            'backward': {key: sorted(set(value)) for key, value in backward.items()}}


def lookup(index, item):
    if item.startswith('R:'):
        item = item[2:]
    ids = [item] if item in index['requirements'] else index['backward'][item]
    return {'item': item, 'original': index['original'], 'source_line': index['lines'].get(item),
            'requirements': {rid: index['requirements'][rid] for rid in ids}}
