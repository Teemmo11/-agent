"""Read-only evidence audit. No tool launches and no new verification verdicts."""
import json
from pathlib import Path
from ..artifacts import sha256_file
from ..errors import AgentError
from ..models import CommandResult, VerificationJob
from ..adapters.ric3 import normalize
from ..adapters.c2btor import queries
from ..adapters import cbmc,c2btor
from ..preflight import MOCK_MARKER
from .conclusion import aggregate, precondition_status
from .verifier import inventory, resolve_mapping

def audit_run(root,*,require_real=True):
    root=Path(root).resolve(); errors=[]; checked=[]
    try:
        report=json.loads((root/'result.json').read_text())
        manifest=json.loads((root/'run_manifest.json').read_text())
        original=Path(manifest['input']['sources'][0]['snapshot']).parents[3]
        def local(value):
            p=Path(value)
            if p.is_absolute():
                try: p=root/p.relative_to(original)
                except ValueError: raise ValueError('Artifact path outside recorded run')
            else: p=root/p
            p=p.resolve()
            if not p.is_relative_to(root): raise ValueError('Artifact escapes run directory')
            return p
        def read(path): return json.loads(local(path).read_text())
        if report.get('input')!=manifest['input']: errors.append('INPUT_MANIFEST_MISMATCH')
        for source in manifest['input']['sources']:
            if sha256_file(local(source['snapshot']))!=source['sha256']: errors.append('SOURCE_HASH_MISMATCH')
        if sha256_file(root/'input/requirements.md')!=manifest['input']['requirements_sha256']: errors.append('REQUIREMENTS_HASH_MISMATCH')
        if report.get('evaluation')!={'status':'NOT_RUN'}: errors.append('EVALUATION_NOT_DISABLED')
        if require_real and report.get('mode')!='REAL': errors.append('NON_REAL_RUN')
        toolchain=read('toolchain_manifest.json')
        if require_real and toolchain.get('mock_detected'): errors.append('MOCK_TOOLCHAIN')
        for t in toolchain.get('tools',{}).values():
            if not t.get('available') or not t.get('sha256'): errors.append('TOOL_IDENTITY_MISSING')
        def check_property(prop):
            pid=prop['property_id']; jobdir=local(prop['evidence_manifest']).parent
            disk=json.loads((jobdir/'result.json').read_text())
            for k in ('property_id','spec_id','verdict','raw_result','model_sha256','provenance','conclusion_gate','evidence_mode',
                      'model_contract','bad_node','cbmc_property_id','model_validated','attribution_status','execution_refs'):
                if prop.get(k)!=disk.get(k): errors.append(pid+': SUMMARY_MISMATCH:'+k)
            if require_real and prop.get('evidence_mode')!='REAL': errors.append(pid+': MOCK_PROPERTY')
            if prop.get('evaluation')!={'status':'NOT_RUN'}: errors.append(pid+': EVALUATION_NOT_DISABLED')
            hashes=read(prop['evidence_manifest'])
            if not hashes: errors.append(pid+': EMPTY_HASH_MANIFEST')
            for path,checksum in hashes.items():
                if sha256_file(local(path))!=checksum: errors.append(pid+': ARTIFACT_HASH_MISMATCH:'+Path(path).name)
            def require_bound(path):
                if str(path) not in hashes: errors.append(pid+': UNBOUND_ARTIFACT:'+str(path))
            job_data=json.loads((jobdir/'job.json').read_text()); job=VerificationJob(**job_data)
            for path in job.source_hashes: require_bound(path)
            provenance=prop['provenance']; sem_path=provenance['semantic_spec']; require_bound(sem_path)
            sem=read(sem_path)
            if sha256_file(local(sem_path))!=provenance['semantic_spec_sha256']: errors.append(pid+': SEMANTIC_HASH_MISMATCH')
            for key in ('source_sha256','requirements_sha256'):
                if sem.get(key)!=manifest['input'][key] or provenance.get(key)!=manifest['input'][key]: errors.append(pid+': SPEC_INPUT_MISMATCH')
            if job.harness_file:
                require_bound(job.harness_file); formal_path=provenance['formal_contract']; require_bound(formal_path)
                if sha256_file(local(formal_path))!=provenance['formal_contract_sha256']: errors.append(pid+': FORMAL_HASH_MISMATCH')
                if require_real and sem['generation']['mode']!='REAL': errors.append(pid+': FIXTURE_LLM')
            else:
                require_bound(provenance['static_discovery'])
                if toolchain.get('cbmc_profile')==cbmc.SOURCE_PROFILE:
                    artifacts=sem.get('discovery_artifacts',{})
                    if not artifacts: errors.append(pid+': STATIC_CONVERSION_EVIDENCE_MISSING')
                    for path,checksum in artifacts.items():
                        require_bound(path)
                        if sha256_file(local(path))!=checksum: errors.append(pid+': STATIC_DISCOVERY_HASH_MISMATCH')
                    discovery_model=next((p for p in artifacts if Path(p).name=='discovery_model.btor2'),None)
                    discovery_map=next((p for p in artifacts if Path(p).name=='discovery_map.json'),None)
                    if not discovery_model or not discovery_map: errors.append(pid+': STATIC_CONVERSION_MAP_MISSING')
                    else:
                        _,discovery_data=c2btor.source_inventory(local(discovery_model),local(discovery_map))
                        c2btor.validate_source_policy(discovery_data,toolchain)
                        matches=[p for p in discovery_data['source_properties'] if p['property_id']==prop['cbmc_property_id']]
                        if len(matches)!=1: errors.append(pid+': STATIC_DISCOVERY_IDENTITY_MISMATCH')
                        else:
                            src=matches[0]['source'];loc=sem['source_location']
                            if (src['file_name']!=loc['file'] or str(src['line'])!=str(loc['line']) or
                                src['function']!=loc['function'] or matches[0]['property_class']!=sem['category']):
                                errors.append(pid+': STATIC_DISCOVERY_SOURCE_MISMATCH')
            if prop['verdict'] not in ('HOLDS','VIOLATED'):
                errors.append(pid+': NO_PROOF_'+prop['verdict'])
                if prop.get('conclusion_gate',{}).get('allowed'): errors.append(pid+': ERROR_GATE_ALLOWED')
                checked.append(pid);return
            if not prop.get('conclusion_gate',{}).get('allowed'): errors.append(pid+': GATE_BLOCKED')
            profile=toolchain.get('cbmc_profile');source_profile=profile==cbmc.SOURCE_PROFILE
            modern=profile in ('c2btor-2',cbmc.SOURCE_PROFILE)
            contract=prop.get('model_contract')
            if modern and not contract: errors.append(pid+': MODEL_CONTRACT_MISSING')
            if contract and not modern: errors.append(pid+': MODEL_CONTRACT_PROFILE_MISMATCH')
            if contract and contract.get('profile')!=profile: errors.append(pid+': MODEL_CONTRACT_PROFILE_MISMATCH')
            if source_profile and contract:
                expected_policy={'query_derivation':'REMOVE_OTHER_BAD_DECLARATIONS_ONLY','property_slicing':False,
                    'large_block_encoding':False,'checks_enabled':job.kind=='CBMC_STATIC_PROPERTY',
                    'memory_semantics':'SOURCE_ASSERTIONS_ONLY; UB totalized by converter; malloc succeeds',
                    'memory_safety_proven':False}
                if any(contract.get(k)!=v for k,v in expected_policy.items()): errors.append(pid+': SOURCE_CONTRACT_POLICY_MISMATCH')
                if contract.get('obligations')!=[]: errors.append(pid+': UNEXPECTED_BOUNDARY_OBLIGATIONS')
                if cbmc.source_policy(toolchain) and contract.get('converter_policy')!=cbmc.source_policy(toolchain):
                    errors.append(pid+': CONVERTER_POLICY_MISMATCH')
            names=['cbmc','catbtor','ric3']
            if modern:
                names.append('catbtor_converter')
                if contract and contract.get('obligations'): names+=['catbtor_boundaries','ric3_boundaries']
            for name in names:
                ref=prop['execution_refs'][name]; require_bound(ref); command=CommandResult(**read(ref))
                if not command.ok: errors.append(pid+': '+name.upper()+'_FAILED')
                out=local(command.stdout_path);err=local(command.stderr_path)
                require_bound(command.stdout_path);require_bound(command.stderr_path)
                if sha256_file(out)!=command.stdout_sha256 or sha256_file(err)!=command.stderr_sha256: errors.append(pid+': LOG_HASH_MISMATCH')
                if require_real and MOCK_MARKER.search(out.read_text()+err.read_text()): errors.append(pid+': MOCK_OUTPUT')
                if name=='cbmc':
                    args=command.argv
                    if source_profile:
                        expected=cbmc.build_command(job,contract['converter_model'],str(Path(prop['evidence_manifest']).parent/'source_map.json'),
                                                    toolchain,prop['cbmc_property_id'])
                        if args[1:]!=expected[1:]: errors.append(pid+': SOURCE_CONVERSION_ARGV_MISMATCH')
                        if not toolchain.get('source_conversion_probe',{}).get('status')=='PASSED':
                            errors.append(pid+': SOURCE_CONTRACT_PROBE_MISSING')
                    else:
                        if '--property' not in args or args[args.index('--property')+1]!=prop['cbmc_property_id']:
                            errors.append(pid+': CBMC_PROPERTY_SELECTION_MISMATCH')
                        if '--function' not in args or args[args.index('--function')+1]!=job.entry:
                            errors.append(pid+': CBMC_ENTRY_MISMATCH')
                if name=='ric3':
                    verdict,raw,error=normalize(command,out.read_text(),err.read_text())
                    if error or verdict!=prop['verdict'] or raw!=prop['raw_result']: errors.append(pid+': RAW_VERDICT_MISMATCH')
                if name=='ric3_boundaries':
                    _,raw,error=normalize(command,out.read_text(),err.read_text())
                    if error or raw!='UNSAT' or contract.get('raw_result')!=raw: errors.append(pid+': MODEL_BOUNDARY_NOT_PROVEN')
                if name in ('catbtor','ric3','catbtor_boundaries','ric3_boundaries','catbtor_converter'):
                    expected=(contract['boundary_model'] if 'boundaries' in name else
                              contract['converter_model'] if name=='catbtor_converter' else str(Path(prop['evidence_manifest']).parent/'model.btor2'))
                    argument=command.argv[2] if name.startswith('ric3') else command.argv[1]
                    if local(argument)!=local(expected): errors.append(pid+': QUERY_EXECUTION_MISMATCH:'+name)
            model=jobdir/'model.btor2'
            if sha256_file(model)!=prop['model_sha256'] or not prop['model_validated']: errors.append(pid+': MODEL_MISMATCH')
            if require_real and MOCK_MARKER.search(model.read_text()): errors.append(pid+': MOCK_MODEL')
            # Source map records original paths; the join is against the original job identity.
            nodes=inventory(model)
            cbmc_record=read(prop['execution_refs']['cbmc'])
            target=resolve_mapping(jobdir/'source_map.json',job,prop['cbmc_property_id'],nodes,cbmc_record['cwd'])
            if len(nodes)!=1 or target!=prop['bad_node']: errors.append(pid+': ATTRIBUTION_MISMATCH')
            if source_profile and not job.harness_file:
                selected=[p for p in json.loads((jobdir/'source_map.json').read_text())['source_properties'] if p['property_id']==prop['cbmc_property_id']]
                if len(selected)!=1: errors.append(pid+': STATIC_CONVERSION_IDENTITY_MISMATCH')
                else:
                    src=selected[0]['source'];loc=sem['source_location']
                    if (src['file_name']!=loc['file'] or str(src['line'])!=str(loc['line']) or src['function']!=loc['function'] or
                        selected[0]['property_class']!=sem['category']): errors.append(pid+': STATIC_CONVERSION_SOURCE_MISMATCH')
            if modern and contract:
                require_bound(contract['converter_model']); require_bound(str(Path(prop['evidence_manifest']).parent/'source_map.json'))
                converted=local(contract['converter_model'])
                if sha256_file(converted)!=contract['converter_model_sha256']: errors.append(pid+': CONVERTER_MODEL_MISMATCH')
                source_text,boundary_text,obligations=queries(converted,jobdir/'source_map.json',target,prop['cbmc_property_id'],profile=profile)
                if source_profile:
                    _,source_data=c2btor.source_inventory(converted,jobdir/'source_map.json')
                    c2btor.validate_source_policy(source_data,toolchain)
                if source_text!=model.read_text() or obligations!=contract['obligations']: errors.append(pid+': QUERY_DERIVATION_MISMATCH')
                if source_profile and contract.get('map_format_version')!=json.loads((jobdir/'source_map.json').read_text())['format_version']:
                    errors.append(pid+': SOURCE_MAP_VERSION_MISMATCH')
                if boundary_text:
                    require_bound(contract['boundary_model']);boundary=local(contract['boundary_model'])
                    if boundary.read_text()!=boundary_text or sha256_file(boundary)!=contract['boundary_model_sha256']:
                        errors.append(pid+': BOUNDARY_QUERY_MISMATCH')
                    if contract['status']!='PASSED': errors.append(pid+': MODEL_CONTRACT_BLOCKED')
                elif contract['status']!='NOT_REQUIRED' or contract.get('raw_result') is not None:
                    errors.append(pid+': EMPTY_CONTRACT_MISMATCH')
            checked.append(pid)
        for c in report['contracts']:
            p=c['precondition'].get('result')
            if not p: errors.append(c['spec_id']+': NO_FEASIBILITY');continue
            check_property(p)
            for q in c['properties']: check_property(q)
            status=precondition_status(p)
            if c['precondition']['status']!=status or c['verification']['verdict']!=aggregate(status,c['properties']): errors.append(c['spec_id']+': AGGREGATION_MISMATCH')
        for p in report['static_properties']: check_property(p)
        if not checked: errors.append('NO_VERIFIED_PROPERTIES')
        if report.get('failures'): errors.append('RUN_HAS_FAILURES')
    except (OSError,ValueError,KeyError,TypeError,AttributeError,IndexError,AgentError) as exc:
        errors.append(type(exc).__name__+': '+str(exc))
    return {'status':'PASSED' if not errors else 'FAILED','require_real':require_real,'checked_properties':checked,
            'errors':errors,'scope':'Artifact integrity and deterministic provenance; not a new solver proof or spec quality evaluation',
            'evaluation':{'status':'NOT_RUN'}}
