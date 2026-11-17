"""Read-only Phase 2 evidence audit; no models or tools are launched."""
import json
import re
from pathlib import Path
from ..artifacts import sha256_file
from ..errors import AgentError
from ..models import CommandResult,VerificationJob,FunctionContext,Parameter
from ..llm.parser import strict_json
from ..adapters import c2btor
from ..adapters import cbmc
from ..adapters.ric3 import normalize
from ..verification.verifier import inventory
from .loader import ParentRun,pure_path
from .harness import render
from .schema import check as check_schema
from .models import DIMENSIONS


def resolve_query_mapping(data,job,property_id,bad_nodes,converter_cwd,resolve):
    """Attribute after explicit relocation, without host-OS path guessing."""
    rows=data.get('source_properties',data.get('instructions'))
    if not isinstance(rows,list):raise AgentError('ATTRIBUTION_UNKNOWN','Invalid evaluation conversion map')
    matches=[]
    for row in rows:
        if 'source_properties' not in data and row.get('kind')!='ASSERT':continue
        if row.get('property_id')!=property_id or int(row.get('bad_node',0)) not in bad_nodes:continue
        src=row.get('source',{});source=pure_path(src.get('file_name',src.get('file','')))
        if not source.is_absolute():source=pure_path(converter_cwd)/source
        if (resolve(str(source))==resolve(job.harness_file) and int(src.get('line',-1))==job.assertion_line
                and src.get('function')==job.entry and row.get('property_class')=='assertion'):
            matches.append(int(row['bad_node']))
    if len(set(matches))!=1:raise AgentError('ATTRIBUTION_UNKNOWN','No unique relocated harness/bad match')
    return matches[0]


def audit_evaluation(directory,*,parent_root=None):
    root=Path(directory).resolve();errors=[];checked=[]
    def local(ref):
        path=pure_path(str(ref))
        if '..' in path.parts:raise ValueError('Unsafe evaluation path')
        if path.is_absolute():path=path.relative_to(pure_path(manifest['original_evaluation_root']))
        target=root.joinpath(*path.parts)
        current=root
        for part in path.parts:
            current=current/part
            if current.is_symlink():raise ValueError('Symlink in evaluation evidence')
        if not target.resolve().is_relative_to(root):raise ValueError('Evaluation path escape')
        return target
    def read(path):return strict_json(Path(path).read_text(encoding='utf-8'))
    try:
        manifest=read(root/'evaluation_manifest.json');report=read(root/'evaluation.json')
        check_schema(report,'evaluation')
        strength_mode=report['assessment_mode'].get('profile')=='strength'
        hashes=read(root/'evidence_hashes.json')
        if 'evaluation.json' not in hashes or 'evaluation_manifest.json' not in hashes:errors.append('UNBOUND_REPORT')
        for ref,checksum in hashes.items():
            if sha256_file(local(ref))!=checksum:errors.append('ARTIFACT_HASH_MISMATCH:'+ref)
        parent=None
        if report['execution_status']!='BLOCKED':
            parent=ParentRun(parent_root or manifest['parent_run_ref'])
            if parent.manifest['run_id']!=report['parent_run_id']:errors.append('PARENT_IDENTITY_MISMATCH')
            for ref,checksum in manifest['parent_dependencies'].items():parent.check(parent.path(ref),checksum)
            if report['source_and_spec_hashes']!=manifest['parent_dependencies']:errors.append('DEPENDENCY_SUMMARY_MISMATCH')
        if report['dimensions'] and set(report['dimensions'])!=set(DIMENSIONS):errors.append('DIMENSION_INVENTORY_MISMATCH')
        if 'strength' in report and not strength_mode:errors.append('STRENGTH_PROFILE_MISMATCH')
        catalog=read(root/'context/context_manifest.json')['evidence'] if (root/'context/context_manifest.json').exists() else {}
        for eid,row in catalog.items():
            if row.get('artifact_scope')=='EVALUATION':path=local(row['artifact_ref'])
            elif parent:path=parent.path(row['artifact_ref'])
            else:continue
            if sha256_file(path)!=row['sha256']:errors.append('CONTEXT_EVIDENCE_HASH_MISMATCH:'+eid)
            from .context import pointer
            if row.get('json_pointer') is not None:content=pointer(read(path),row['json_pointer'])
            elif row.get('line_range'):
                a,b=row['line_range'];content=''.join(path.read_text(encoding='utf-8').splitlines(keepends=True)[a-1:b])
            else:
                content=read(path) if row.get('artifact_scope')=='EVALUATION' else path.read_text(encoding='utf-8')
            if row['content']!=content:errors.append('CONTEXT_QUOTE_MISMATCH:'+eid)
        queries={q['query_id']:q for q in report['queries']}
        caps=read(root/'toolchain_manifest.json') if (root/'toolchain_manifest.json').exists() else {}
        for q in report['queries']:
            if not re.fullmatch(r'EQ-[a-f0-9]{20}',q['query_id']):raise ValueError('Invalid query ID')
            qdir=root/'queries'/q['query_id'];disk=read(qdir/'query.json')
            if disk!=q:errors.append('QUERY_SUMMARY_MISMATCH')
            if q['status']!='DECIDED':continue
            result=read(local(q['execution_result']))
            if result.get('raw_result')!=q['raw_result'] or not result['conclusion_gate']['allowed']:errors.append('QUERY_GATE_MISMATCH')
            job=VerificationJob(**read(qdir/'job.json'))
            if strength_mode:
                original=pure_path(manifest['original_evaluation_root'])
                original_parent=pure_path(manifest['parent_run_ref'])
                bindings={str(original_parent/pure_path(ref)):checksum
                          for ref,checksum in manifest['parent_dependencies'].items()}
                for ref in ('input/strength_cases.json','toolchain_manifest.json'):
                    bindings[str(original/pure_path(ref))]=hashes[ref]
                if any(job.source_hashes.get(path)!=checksum for path,checksum in bindings.items()):
                    errors.append('STRENGTH_QUERY_INPUT_BINDING_MISMATCH')
            if job.entry!='__sa_entry' or len(job.source_files)!=1 or local(job.source_files[0])!=qdir/'harness.c':errors.append('QUERY_SOURCE_INVENTORY_MISMATCH')
            domain=q['symbol_domain'];f=FunctionContext('query','query','',domain['return_type'],
                [Parameter(**p) for p in domain['parameters']],'',0,0,'','')
            expected,line=render(f,q['predicate'],q['query_id'])
            if (qdir/'harness.c').read_text(encoding='utf-8')!=expected or job.assertion_line!=line or job.kind!='EVALUATION_QUERY':errors.append('QUERY_HARNESS_MISMATCH')
            commands={}
            for name,ref in result['execution_refs'].items():
                command=CommandResult(**read(local(ref)));commands[name]=command
                if not command.ok:errors.append('QUERY_COMMAND_FAILED:'+name)
                if sha256_file(local(command.stdout_path))!=command.stdout_sha256 or sha256_file(local(command.stderr_path))!=command.stderr_sha256:
                    errors.append('QUERY_LOG_HASH_MISMATCH')
                logical='ric3' if name.startswith('ric3') else 'catbtor' if name.startswith('catbtor') else 'cbmc'
                if command.argv[0]!=caps.get('tools',{}).get(logical,{}).get('executable'):errors.append('QUERY_EXECUTABLE_MISMATCH')
                if name=='ric3_boundaries':
                    _,boundary_raw,boundary_error=normalize(command,local(command.stdout_path).read_text(encoding='utf-8'),local(command.stderr_path).read_text(encoding='utf-8'))
                    if boundary_error or boundary_raw!='UNSAT':errors.append('BOUNDARY_RAW_RESULT_MISMATCH')
            required={'cbmc','catbtor','ric3'}
            if caps.get('cbmc_profile') in ('c2btor-2',cbmc.SOURCE_PROFILE):required.add('catbtor_converter')
            if not required<=set(commands):errors.append('QUERY_COMMAND_EVIDENCE_MISSING')
            command=commands['ric3'];_,raw,error=normalize(command,local(command.stdout_path).read_text(encoding='utf-8'),local(command.stderr_path).read_text(encoding='utf-8'))
            if error or raw!=q['raw_result']:errors.append('QUERY_RAW_RESULT_MISMATCH')
            model=qdir/'model.btor2';target=resolve_query_mapping(read(qdir/'source_map.json'),job,result['cbmc_property_id'],inventory(model),commands['cbmc'].cwd,local)
            if inventory(model)!=[target] or sha256_file(model)!=result['model_sha256']:errors.append('QUERY_ATTRIBUTION_MISMATCH')
            contract=result.get('model_contract')
            conversion_model=contract['converter_model'] if contract else str(pure_path(manifest['original_evaluation_root'])/'queries'/q['query_id']/'model.btor2')
            mapping_ref=str(pure_path(manifest['original_evaluation_root'])/'queries'/q['query_id']/'source_map.json')
            expected_args=cbmc.build_command(job,conversion_model,mapping_ref,caps,result['cbmc_property_id'])
            # Compare artifact arguments after relocation; compare all remaining argv literally.
            actual_args=commands['cbmc'].argv[1:];expected_args=expected_args[1:]
            if len(actual_args)!=len(expected_args):errors.append('QUERY_CONVERSION_ARGV_MISMATCH')
            else:
                for actual,expected_arg in zip(actual_args,expected_args):
                    if actual!=expected_arg:errors.append('QUERY_CONVERSION_ARGV_MISMATCH');break
            if contract:
                source,boundary,_=c2btor.queries(local(contract['converter_model']),qdir/'source_map.json',target,result['cbmc_property_id'],profile=contract['profile'])
                if cbmc.source_policy(caps):
                    _,source_data=c2btor.source_inventory(local(contract['converter_model']),qdir/'source_map.json')
                    c2btor.validate_source_policy(source_data,caps)
                    if contract.get('converter_policy')!=cbmc.source_policy(caps):errors.append('QUERY_CONVERTER_POLICY_MISMATCH')
                if source!=model.read_text(encoding='utf-8'):errors.append('QUERY_DERIVATION_MISMATCH')
                if boundary and local(contract['boundary_model']).read_text(encoding='utf-8')!=boundary:errors.append('BOUNDARY_DERIVATION_MISMATCH')
                if boundary and (contract['status']!='PASSED' or contract['raw_result']!='UNSAT'):errors.append('BOUNDARY_NOT_PROVED')
            for name,command in commands.items():
                if name.startswith('ric3') or name.startswith('catbtor'):
                    actual=command.argv[2] if name.startswith('ric3') else command.argv[1]
                    expected_model=(contract['boundary_model'] if 'boundaries' in name else contract['converter_model'] if name=='catbtor_converter' else str(qdir/'model.btor2'))
                    expected_path=local(expected_model) if pure_path(expected_model).is_absolute() and not Path(expected_model).is_relative_to(root) else Path(expected_model)
                    if local(actual)!=expected_path:errors.append('QUERY_EXECUTION_MODEL_MISMATCH')
            checked.append(q['query_id'])
        for finding in report['findings']:
            check_schema(finding,'evaluation_finding')
            for eid in finding['evidence_ids']:
                if eid in catalog:continue
                if not eid.startswith('EV-EQ-') or eid[3:] not in queries:errors.append('FINDING_REFERENCE_INVALID:'+eid)
                elif finding['evidence_kind']=='FORMAL' and queries[eid[3:]]['status']!='DECIDED':errors.append('UNDECIDED_PROOF_CLAIM')
            if finding['evidence_kind']=='LLM_JUDGMENT' and finding['claim_status']!='JUDGMENT':errors.append('LLM_CLAIM_UPGRADED')
        if strength_mode:
            from .logic import ReplayLogic
            from .strength import LEGACY_METRICS,METRICS,STRENGTH_PROTOCOL,assess,plan_cases
            protocol=report['assessment_mode'].get('strength_protocol',1)
            if type(protocol) is not int or protocol not in (1,STRENGTH_PROTOCOL):
                raise ValueError('Unknown strength protocol')
            metrics=LEGACY_METRICS if protocol==1 else METRICS
            if any(report[k] for k in ('dimensions','coverage','contexts','reviews','findings')):
                errors.append('UNEXPECTED_DIAGNOSTICS_IN_STRENGTH_REPORT')
            if 'strength' in report:
                ref='input/strength_cases.json'
                if ref not in hashes or 'toolchain_manifest.json' not in hashes:errors.append('UNBOUND_STRENGTH_INPUT')
                replay=ReplayLogic(report['queries'],caps)
                plans=plan_cases(parent,read(local(ref)),caps,metrics=metrics)
                expected=assess(plans,replay,metrics=metrics)
                if expected!=report['strength']:errors.append('STRENGTH_METRIC_DERIVATION_MISMATCH')
                if replay.used!=set(queries):errors.append('UNPLANNED_QUERY')
                partial=any(m['undecided'] for m in expected['metrics'].values())
                if report['execution_status']!='ERROR' and report['execution_status']!=('PARTIAL' if partial else 'COMPLETED'):
                    errors.append('STRENGTH_EXECUTION_STATUS_MISMATCH')
            elif report['execution_status'] in ('COMPLETED','PARTIAL') or report['queries']:
                errors.append('MISSING_STRENGTH_RESULTS')
        elif parent:
            from .context import ContextBuilder
            from .models import Limits
            from .semantic import parse_review,review_findings
            builder=ContextBuilder(parent,read(root/'requirements_index.json'),Limits(**report['limits']))
            contexts={}
            for ref in report['contexts']:
                context=read(local(ref));check_schema(context,'evaluation_context');contexts[context['spec_id']]=context
            expected_det=[];expected_formal=[];uncertain=[]
            from .deterministic import check as deterministic_check
            from .coverage import inventory as coverage_inventory,apply_reviews
            from .logic import ReplayLogic,assess_reference
            from .models import finding as make_finding
            replay=ReplayLogic(report['queries'],caps)
            reference=read(root/'input/reference_spec.json') if (root/'input/reference_spec.json').exists() else None
            selected=set(report['assessment_mode'].get('selected_specs',[s['spec_id'] for s in parent.specs]))
            for spec in [s for s in parent.specs if s['spec_id'] in selected]:
                context=contexts[spec['spec_id']];function=parent.functions[spec['function_id']]
                expected_context=builder.build(spec)
                if context!=expected_context:errors.append('CONTEXT_DERIVATION_MISMATCH:'+spec['spec_id'])
                expected_det.extend(deterministic_check(spec,function,context['evidence_ids']))
                if report['assessment_mode']['logic']=='tools':
                    if report['assessment_mode'].get('logic_scope','full')=='full':
                        fs,missing=replay.evaluate(spec,function,context['evidence_ids']);expected_formal.extend(fs);uncertain.extend(missing)
                    if reference:
                        fs,missing=assess_reference(replay,spec,function,reference,parent.requirements,parent.program,context['evidence_ids'])
                        expected_formal.extend(fs);uncertain.extend(missing)
            expected_coverage=coverage_inventory(read(root/'requirements_index.json'),parent.specs,parent.program.functions)
            requirement_eid=builder.register('input/requirements.md')
            for row in expected_coverage['rows']:
                if not row['links']:
                    expected_det.append(make_finding('REQUIREMENTS','coverage','REQUIREMENT_UNREFERENCED',
                        '需求原文条目没有任何后置条款引用；语义覆盖仍需复核。',evidence=[requirement_eid],claim='REVIEW_REQUIRED'))
            if expected_det!=read(root/'deterministic/findings.json'):errors.append('DETERMINISTIC_DERIVATION_MISMATCH')
            if expected_formal!=read(root/'logic/findings.json'):errors.append('FORMAL_FINDING_DERIVATION_MISMATCH')
            if report['assessment_mode']['logic']=='tools' and replay.used!=set(queries):errors.append('UNPLANNED_QUERY')
            expected_findings=[*expected_det,*expected_formal]
            for review in report['reviews']:
                context=contexts[review['spec_id']]
                allowed=set(context['evidence_ids'])|{s['evidence_id'] for s in context['callsites']}|{s['evidence_id'] for s in context['related_specs']}
                value={k:v for k,v in review.items() if k not in ('assessment_mode','cache_key','reviewer_identity')}
                parse_review(json.dumps(value),context,allowed)
                records=[p for p in (root/'semantic'/context['function']['function_id']).glob('*/review.json') if read(p)==review]
                if len(records)!=1:errors.append('REVIEW_ARTIFACT_MISMATCH')
                else:
                    record=records[0]
                    if record.relative_to(root).as_posix() not in hashes:errors.append('UNBOUND_REVIEW_ARTIFACT')
                    if read(record.parent/'response.txt')!=value:errors.append('REVIEW_RESPONSE_MISMATCH')
                mode={'real':'REAL','fixture':'FIXTURE_REVIEW'}.get(report['assessment_mode']['reviewer'])
                if review['assessment_mode']!=mode or review.get('reviewer_identity',{}).get('mode')!=mode:
                    errors.append('REVIEW_SOURCE_MISMATCH')
                for row in review_findings(review):
                    if row not in report['findings']:errors.append('REVIEW_FINDING_OMITTED')
                    expected_findings.append(row)
            if report['findings']!=expected_findings:errors.append('FINDINGS_SUMMARY_MISMATCH')
            if apply_reviews(expected_coverage,report['reviews'])!=report['coverage']:errors.append('COVERAGE_DERIVATION_MISMATCH')
            from .aggregate import dimensions
            incomplete=uncertain or report['errors']
            dimension_logic=report['assessment_mode']['logic'] if report['assessment_mode'].get('logic_scope','full')=='full' else 'off'
            if dimensions(expected_findings,report['reviews'],logic=dimension_logic,uncertain=incomplete,
                          reference_checked=bool(reference and report['assessment_mode']['logic']=='tools'),queries=report['queries'])!=report['dimensions']:
                errors.append('DIMENSION_DERIVATION_MISMATCH')
        checked.append('artifact_integrity')
    except (AgentError,OSError,ValueError,KeyError,TypeError,IndexError,AttributeError) as exc:
        errors.append(getattr(exc,'code',type(exc).__name__)+': '+str(exc))
    return {'status':'PASSED' if not errors else 'FAILED','checked':checked,'errors':errors,
            'scope':'Read-only Phase 2 provenance audit; not a new model check or semantic truth judgment'}
