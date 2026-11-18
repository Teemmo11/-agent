"""Read verified mappings without claiming a counterexample execution trace."""
from pathlib import Path

from ..errors import AgentError
from ..models import VerificationJob
from ..verification.verifier import inventory, resolve_mapping


def route(report):
    if report.get('status') == 'CANCELLED':
        return 'CANCELLED'
    if report.get('phase') == '1.1':
        return 'NEEDS_VERIFICATION'
    contracts = report.get('contracts', [])
    properties = [p for row in contracts for p in row.get('properties', [])]
    properties += report.get('static_properties', [])
    if any(row.get('precondition', {}).get('status') == 'INFEASIBLE' or
           row.get('verification', {}).get('verdict') == 'VACUOUS' for row in contracts):
        return 'PRECONDITION_REVIEW_REQUIRED'
    healthy = (report.get('status') == 'COMPLETED' and not report.get('failures') and
               all(row.get('precondition', {}).get('status') == 'FEASIBLE' and
                   row.get('verification', {}).get('verdict') == 'HOLDS' for row in contracts) and
               all(p.get('verdict') == 'HOLDS' and p.get('conclusion_gate', {}).get('allowed')
                   for p in properties) and bool(contracts or properties))
    if healthy:
        return 'EVALUATE'
    errors = [p for p in properties if p.get('verdict') in ('ERROR', 'UNKNOWN')]
    errors += [row.get('precondition', {}).get('result', {}) for row in contracts
               if row.get('precondition', {}).get('status') in ('ERROR', 'UNKNOWN')]
    if errors or report.get('status') != 'COMPLETED' or report.get('failures'):
        return 'RETRY_OR_REVIEW'
    if any(p.get('verdict') == 'VIOLATED' for p in properties):
        return 'REPAIR_SOURCE'
    return 'NEEDS_VERIFICATION'


def diagnose(parent):
    report = parent.report
    findings, locations, jobs = [], [], []
    contracts = report.get('contracts', [])
    for row in contracts:
        probe = row.get('precondition', {}).get('result')
        if probe:
            jobs.append(probe)
        jobs.extend(row.get('properties', []))
    jobs.extend(report.get('static_properties', []))
    sources = {path.resolve(): index for index, path in enumerate(parent.source_paths)}
    for prop in jobs:
        if prop.get('verdict') == 'HOLDS' or prop.get('kind') == 'PRECONDITION_FEASIBILITY' and prop.get('raw_result') == 'SAT':
            continue
        finding = {'property_id': prop['property_id'], 'verdict': prop.get('verdict'),
                   'raw_result': prop.get('raw_result'), 'error': prop.get('error'),
                   'map_status': 'UNAVAILABLE', 'source_locations': [], 'witness_status': 'UNAVAILABLE'}
        findings.append(finding)
        manifest = prop.get('evidence_manifest')
        if not manifest:
            continue
        directory = parent.path(manifest).parent
        mapping = directory/'source_map.json'
        if not mapping.is_file():
            continue
        data = parent.read(mapping)
        job = VerificationJob(**parent.read(directory/'job.json'))
        # Validate exact attribution again for any decided violation. Error maps
        # remain diagnostic data and cannot justify an automatic source edit.
        if prop.get('verdict') == 'VIOLATED':
            target = resolve_mapping(mapping, job, prop['cbmc_property_id'],
                                     inventory(directory/'model.btor2'), directory/'cbmc')
            if target != prop.get('bad_node') or not prop.get('conclusion_gate', {}).get('allowed'):
                raise AgentError('REPAIR_ATTRIBUTION_INVALID', 'Violation lacks a unique evidence-gated bad')
            finding.update(map_status='ATTRIBUTED', bad_node=target,
                           cbmc_property_id=prop['cbmc_property_id'])
        else:
            finding['map_status'] = 'DIAGNOSTIC_ONLY'
        finding['source_map'] = str(mapping)
        for row in data.get('source_properties', []):
            if row.get('property_id') == prop.get('cbmc_property_id'):
                finding['assertion_location'] = row.get('source')
        seen = set()
        for instruction in data.get('instructions', []):
            source = instruction.get('source', {})
            raw_file = source.get('file_name', source.get('file'))
            if not raw_file:
                continue
            raw_path = Path(raw_file)
            if not raw_path.is_absolute():
                raw_path = directory/'cbmc'/raw_path
            try:
                path = parent.path(raw_path)
            except AgentError:
                continue
            index = sources.get(path.resolve())
            function = next((function for function in parent.functions.values()
                             if function.source_file == str(path) and function.name == source.get('function')), None)
            try:
                line = int(source.get('line', 0))
            except (TypeError, ValueError):
                continue
            key = (index, source.get('function'), line)
            if index is None or function is None or key in seen or not function.start_line <= line <= function.end_line:
                continue
            seen.add(key)
            eid = 'MAP-'+str(len(locations)+1)
            lines = parent.text(path).splitlines()
            location = {'evidence_id': eid, 'source_index': index, 'function_id': function.function_id,
                        'function': function.name, 'line': line, 'text': lines[line-1],
                        'source_map': str(mapping), 'pc': instruction.get('pc'),
                        'property_id': prop['property_id'],
                        'origin': 'MAPPED_INSTRUCTION; candidate location, not executed witness'}
            locations.append(location)
            finding['source_locations'].append(eid)
    return {'route': route(report), 'parent_run': str(parent.root), 'findings': findings,
            'locations': locations, 'failures': report.get('failures', []),
            'witness_status': 'UNAVAILABLE', 'localization_scope': 'ASSERTION_AND_STATIC_SOURCE_INSTRUCTIONS'}
