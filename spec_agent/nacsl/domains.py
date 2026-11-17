"""Bridge explicit scalar range declarations in N to checked entry predicates."""
import re

from ..ir_ab.semantics import MAX, MIN, join

VERSION = 'nacsl-source-gate-2'
LEGACY_VERSION = 'nacsl-source-gate-1'
NUMBER = r'[+-]?[0-9]+'
GROUP = r'[A-Za-z_\u3400-\u9fff][A-Za-z0-9_\u3400-\u9fff、 \t]*?'
DECLARATION = re.compile(
    rf'(?P<labels>{GROUP})\s*(?:均\s*)?(?:取值范围\s*)?(?:只允许(?:为)?|范围为|为|在)\s*'
    rf'(?P<values>{NUMBER}(?:\s*(?:到|至|~|～)\s*{NUMBER}|(?:\s*或\s*{NUMBER})*))'
    r'(?:\s*的整数)?'
)


def declarations(interface, lines):
    """Recognize only complete standalone declarations, never branch conditions."""
    symbols = {name: name for name in interface['parameters']}
    symbols.update(interface.get('parameter_aliases', {}))
    found = []
    for line in lines:
        for sentence in re.finditer(r'[^。；;！？!?]+', line['text']):
            segments = list(re.finditer(r'[^，,]+', sentence[0]))
            entries = []
            for segment in segments:
                quote = segment[0].strip()
                match = DECLARATION.fullmatch(quote)
                if not match:
                    break
                labels = re.split(r'\s*(?:、|和|及)\s*', match['labels'].strip())
                raw_values = re.findall(NUMBER, match['values'])
                values = [int(x) for x in raw_values] if all(len(x) <= 11 for x in raw_values) else []
                start = line['start'] + sentence.start() + segment.start() + len(segment[0]) - len(segment[0].lstrip())
                entry = {'ref': f'N:L{line["line"]}', 'start': start, 'end': start + len(quote),
                         'excerpt': quote, 'labels': labels, 'predicate': None}
                unknown = [name for name in labels if name not in symbols]
                if unknown:
                    entry['issue'] = 'INPUT_DOMAIN_SYMBOL_UNBOUND'
                elif not values or any(n < MIN or n > MAX for n in values):
                    entry['issue'] = 'INPUT_DOMAIN_UNSUPPORTED'
                else:
                    is_range = bool(re.search(r'到|至|~|～', match['values']))
                    predicates = []
                    for name in labels:
                        term = symbols[name]
                        if is_range:
                            predicates.extend([['ge', term, values[0]], ['le', term, values[1]]])
                        else:
                            predicates.append(join('or', (['eq', term, n] for n in values)))
                    entry['predicate'] = join('and', predicates)
                entries.append(entry)
            else:
                found.extend(entries)
    return found


def missing_spans(entries, r, allowed=None):
    ranges = sorted((s['start'], s['end']) for row in r['rows']
                    if row['kind'] == 'REQUIREMENT' and (allowed is None or row['id'] in allowed)
                    for s in row['spans'])
    missing = []
    for entry in entries:
        cursor = entry['start']
        for start, end in ranges:
            if start > cursor:
                break
            cursor = max(cursor, end)
            if cursor >= entry['end']:
                break
        if cursor < entry['end']:
            missing.append(entry)
    return missing


def coverage(entries, r, s):
    all_refs = {ref for row in s['S'] for ref in row['requirement_refs']}
    p_refs = {ref for row in s['S'] if row['role'] == 'requires' for ref in row['requirement_refs']}
    return {'unmapped_R': [row['id'] for row in r['rows'] if row['kind'] == 'REQUIREMENT' and row['id'] not in all_refs],
            'domain_without_requires': missing_spans(entries, r, p_refs)}


def mismatch(entries, p):
    return ['and', p, ['not', join('and', (entry['predicate'] for entry in entries))]]


def strengthening(entries, r, s):
    """Check only preconditions whose cited source is entirely recognized domain text.

    Other caller obligations may legitimately narrow D_N. Never treat the partial
    natural-language recognizer as a complete specification of the input domain.
    """
    covered = {i for entry in entries for i in range(entry['start'], entry['end'])}
    domain_refs = set()
    for row in r['rows']:
        if row['kind'] != 'REQUIREMENT':
            continue
        substantive = {span['start'] + i for span in row['spans']
                       for i, ch in enumerate(span['excerpt'])
                       if not ch.isspace() and ch not in '，。；：、,.!！?？;:'}
        if substantive and substantive <= covered:
            domain_refs.add(row['id'])
    predicates = [row['expr'] for row in s['S'] if row['role'] == 'requires'
                  and set(row['requirement_refs']) <= domain_refs]
    return ['and', join('and', (entry['predicate'] for entry in entries)),
            ['not', join('and', predicates)]]
