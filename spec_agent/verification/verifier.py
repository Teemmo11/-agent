import json
import re
from pathlib import Path
from ..adapters import cbmc,catbtor,ric3,c2btor
from ..artifacts import sha256_file,write_json_atomic
from ..errors import AgentError
from ..process import invoke
from ..preflight import pinned_command,MOCK_MARKER
from .conclusion import gate,integrity


def inventory(path):
    nodes=[]
    for line in Path(path).read_text(encoding='utf-8').splitlines():
        line=line.split(';',1)[0].strip()
        m=re.match(r'^(\d+)\s+bad\s+(-?\d+)(?:\s|$)',line)
        if m: nodes.append(int(m[1]))
    return nodes

def resolve_mapping(mapping,job,property_id,bad_nodes,converter_cwd=None):
    try:
        data=json.loads(Path(mapping).read_text()); rows=data.get('source_properties',data.get('instructions'))
        if not isinstance(rows,list): raise ValueError()
        matches=[]
        for row in rows:
            if not isinstance(row,dict): raise ValueError()
            if 'source_properties' not in data and row.get('kind')!='ASSERT': continue
            if row.get('property_id')!=property_id: continue
            node=int(row.get('bad_node',0))
            if node not in bad_nodes: continue
            if job.harness_file:
                src=row.get('source',{}); file=src.get('file_name',src.get('file',''))
                target=Path(file)
                if not target.is_absolute(): target=Path(converter_cwd or Path(mapping).parent)/target
                if (target.resolve()!=Path(job.harness_file).resolve() or int(src.get('line',-1))!=job.assertion_line or
                    src.get('function')!=job.entry or row.get('property_class')!='assertion'): continue
            else:
                src=row.get('source',{}); target=Path(src.get('file_name',src.get('file','')))
                if not target.is_absolute(): target=Path(converter_cwd or Path(mapping).parent)/target
                if target.resolve() not in {Path(p).resolve() for p in job.source_files}: continue
            matches.append(node)
        distinct=set(matches)
        if len(distinct)!=1: raise ValueError()
        return distinct.pop()
    except (ValueError,TypeError,KeyError,AttributeError): raise AgentError('ATTRIBUTION_UNKNOWN','No unique selected-property/source-map/bad-node match')

def source_harness_property(mapping,job,converter_cwd):
    """Discover the target from exact harness provenance in the conversion map."""
    data=json.loads(Path(mapping).read_text());matches=[]
    for row in data['source_properties']:
        src=row['source'];path=Path(src['file_name'])
        if not path.is_absolute(): path=Path(converter_cwd)/path
        if (path.resolve()==Path(job.harness_file).resolve() and int(src['line'])==job.assertion_line and
            src['function']==job.entry and row['property_class']=='assertion'):
            matches.append(row['property_id'])
    if len(matches)!=1: raise AgentError('ATTRIBUTION_UNKNOWN','Harness assertion lacks unique conversion-map provenance')
    return matches[0]

def verify(job,caps,config,directory,trace=None):
    if trace:
        trace=trace.bind(spec_id=job.spec_id,property_id=job.property_id,job_id=job.job_id)
        trace.emit('verification.started',kind=job.kind,evidence_mode=config.tool_mode)
    root=Path(directory); root.mkdir(parents=True,exist_ok=True)
    result={'property_id':job.property_id,'spec_id':job.spec_id,'kind':job.kind,'verdict':'ERROR','raw_result':None,
            'model_sha256':None,'model_validated':False,'attribution_status':'UNRESOLVED','execution_refs':{},
            'error':None,'provenance':job.provenance,'conclusion_gate':{'allowed':False,'blockers':['NOT_REACHED']},'evidence_mode':config.tool_mode,'evaluation':{'status':'NOT_RUN'}}
    commands=[]; hashes=dict(job.source_hashes)
    if (root/'job.json').is_file(): hashes[str(root/'job.json')]=sha256_file(root/'job.json')
    def state(value):
        write_json_atomic(root/'checkpoint.json',{'state':value,'resume_supported':False})
        if trace: trace.emit('verification.stage',state=value)
    def run(argv,name):
        d=root/name; d.mkdir(exist_ok=True)
        r=invoke(pinned_command(argv,caps,config),cwd=d,timeout=config.tool_timeout,trace=trace)
        commands.append(r); result['execution_refs'][name]=str(d/'tool.execution.json')
        hashes.update({r.stdout_path:r.stdout_sha256,r.stderr_path:r.stderr_sha256,
                       str(d/'tool.execution.json'):sha256_file(d/'tool.execution.json')})
        if config.tool_mode=='REAL' and MOCK_MARKER.search(Path(r.stdout_path).read_text()+Path(r.stderr_path).read_text()):
            raise AgentError('MOCK_IN_REAL_RUN','Mock output is forbidden')
        return r
    def successful(r,code):
        if r.timed_out: raise AgentError(code+'_TIMEOUT','Tool exceeded configured timeout')
        if not r.ok: raise AgentError(code,'Tool failed; inspect execution_refs')
    try:
        state('PENDING')
        if not integrity(hashes): raise AgentError('ARTIFACT_INTEGRITY_FAILED','Input snapshot changed')
        source_profile=caps.get('cbmc_profile')==cbmc.SOURCE_PROFILE
        cbmc.require(caps,cbmc.SOURCE_BUILD_FLAGS if source_profile else cbmc.BUILD_FLAGS)
        if source_profile and not caps.get('ready'):
            raise AgentError('REAL_PREFLIGHT_BLOCKED','Source-assertions contract probe must pass before conversion')
        if config.tool_mode=='REAL' and not job.provenance:
            raise AgentError('PROVENANCE_MISSING','Real verification requires bound specification provenance')
        property_id=job.cbmc_property_id
        if job.harness_file and not source_profile:
            state('HARNESS_READY')
            argv=cbmc.discovery_command(job.source_files,job.entry,['--no-standard-checks'],caps)
            r=run(argv,'property_discovery'); successful(r,'CBMC_FAILED')
            props=cbmc.parse_properties(Path(r.stdout_path).read_text())
            # Labels and entry are deterministic; map adds exact file/line binding below.
            matches=[p for p in props if p.get('description')==job.property_id and
                     p.get('sourceLocation',{}).get('function')==job.entry]
            if len(matches)!=1: raise AgentError('ATTRIBUTION_UNKNOWN','Target harness assertion missing/ambiguous in CBMC discovery')
            property_id=matches[0]['name']
        if not property_id and not (source_profile and job.harness_file):
            raise AgentError('ATTRIBUTION_UNKNOWN','Missing selected CBMC property')
        if property_id: result['cbmc_property_id']=property_id
        state('MODEL_BUILDING')
        model=root/'model.btor2'; mapping=root/'source_map.json'
        modern=caps.get('cbmc_profile') in ('c2btor-2',cbmc.SOURCE_PROFILE)
        converted=root/'converter_model.btor2' if modern else model
        if model.exists() or converted.exists() or mapping.exists(): raise AgentError('ARTIFACT_COLLISION','Refuse overwritten model')
        r=run(cbmc.build_command(job,converted,mapping,caps,property_id),'cbmc'); successful(r,'BTOR_BUILD_FAILED')
        logs=Path(r.stdout_path).read_text(errors='replace')+Path(r.stderr_path).read_text(errors='replace')
        if re.search(r'unsupported|not supported|under.?approximat',logs,re.I):
            raise AgentError('BTOR_BUILD_UNSUPPORTED','Converter reported unsupported semantics')
        if not converted.is_file() or not converted.stat().st_size or not mapping.is_file(): raise AgentError('BTOR_BUILD_FAILED','Model/source map missing')
        model_text=converted.read_text()
        if config.tool_mode=='REAL' and MOCK_MARKER.search(model_text): raise AgentError('MOCK_IN_REAL_RUN','Mock BTOR2 is forbidden')
        if re.search(r'unsupported|not supported|under.?approximat',model_text,re.I): raise AgentError('BTOR_BUILD_UNSUPPORTED','Model records unsupported semantics')
        if modern:
            state('MODEL_CONTRACT_CHECKING')
            hashes[str(converted)]=sha256_file(converted);hashes[str(mapping)]=sha256_file(mapping)
            r=run(catbtor.check_command(converted),'catbtor_converter');successful(r,'BTOR_INVALID')
            if source_profile:
                _,source_data=c2btor.source_inventory(converted,mapping)
                c2btor.validate_source_policy(source_data,caps)
                if source_data['format_version']!='1': raise AgentError('MODEL_CONTRACT_INVALID','Converter ignored --goto-btor2-no-lbe')
                if job.harness_file: property_id=source_harness_property(mapping,job,root/'cbmc')
                else:
                    selected=[p for p in source_data['source_properties'] if p['property_id']==property_id]
                    if len(selected)!=1: raise AgentError('ATTRIBUTION_UNKNOWN','Static property missing from conversion')
                    src=selected[0]['source'];expected=job.provenance.get('static_source_location',{})
                    if (src['file_name']!=expected.get('file') or str(src['line'])!=str(expected.get('line')) or
                        src['function']!=expected.get('function') or selected[0]['property_class']!=job.provenance.get('static_property_class')):
                        raise AgentError('ATTRIBUTION_UNKNOWN','Static discovery/conversion source mismatch')
            target=resolve_mapping(mapping,job,property_id,inventory(converted),root/'cbmc')
            source_text,boundary_text,obligations=c2btor.queries(converted,mapping,target,property_id,profile=caps['cbmc_profile'])
            model.write_text(source_text)
            result['model_contract']={'profile':caps['cbmc_profile'],'converter_model':str(converted),
                'converter_model_sha256':hashes[str(converted)],'obligations':obligations,
                'status':'PENDING' if boundary_text else 'NOT_REQUIRED','raw_result':None}
            if source_profile:
                result['model_contract'].update(query_derivation='REMOVE_OTHER_BAD_DECLARATIONS_ONLY',
                    property_slicing=False,large_block_encoding=False,checks_enabled=job.kind=='CBMC_STATIC_PROPERTY',
                    memory_semantics='SOURCE_ASSERTIONS_ONLY; UB totalized by converter; malloc succeeds',
                    memory_safety_proven=False,map_format_version=json.loads(mapping.read_text())['format_version'])
                if cbmc.source_policy(caps):
                    result['model_contract']['converter_policy']=cbmc.source_policy(caps)
            if boundary_text:
                boundary=root/'boundaries.btor2'
                if boundary.exists(): raise AgentError('ARTIFACT_COLLISION','Refuse overwritten boundary query')
                boundary.write_text(boundary_text);hashes[str(boundary)]=sha256_file(boundary)
                result['model_contract'].update(boundary_model=str(boundary),boundary_model_sha256=hashes[str(boundary)])
                r=run(catbtor.check_command(boundary),'catbtor_boundaries');successful(r,'BTOR_INVALID')
            if trace: trace.emit('verification.model_contract',**result['model_contract'])
        elif 'c2btor-proof-contract' in model_text or 'source_properties' in json.loads(mapping.read_text()):
            raise AgentError('TOOLCHAIN_UNSUPPORTED','Modern model requires the C2Btor proof-contract profile')
        result['cbmc_property_id']=property_id
        if trace: trace.emit('verification.property_selected',cbmc_property_id=property_id)
        result['model_sha256']=sha256_file(model)
        hashes[str(model)]=result['model_sha256']; hashes[str(mapping)]=sha256_file(mapping)
        state('MODEL_VALIDATING')
        r=run(catbtor.check_command(model),'catbtor'); successful(r,'BTOR_INVALID')
        result['model_validated']=True
        nodes=inventory(model); target=resolve_mapping(mapping,job,property_id,nodes,root/'cbmc')
        if len(nodes)!=1:
            result['attribution_status']='AGGREGATE_ONLY'
            raise AgentError('ATTRIBUTION_UNKNOWN','Converter did not isolate the selected property; refusing aggregate attribution')
        result['attribution_status']='SINGLE_PROPERTY'; result['bad_node']=target
        if trace: trace.emit('verification.attributed',cbmc_property_id=property_id,bad_node=target,source_map=str(mapping),model_sha256=result['model_sha256'])
        state('VERIFYING')
        r=run(ric3.check_command(model,caps),'ric3')
        verdict,raw,error=ric3.normalize(r,Path(r.stdout_path).read_text(errors='replace'),Path(r.stderr_path).read_text(errors='replace'))
        result.update(verdict=verdict,raw_result=raw,error={'code':error,'message':'See rIC3 execution evidence'} if error else None)
        contract=result.get('model_contract')
        if contract and contract['status']=='PENDING':
            state('MODEL_BOUNDARY_VERIFYING')
            r=run(ric3.check_command(boundary,caps),'ric3_boundaries')
            _,boundary_raw,boundary_error=ric3.normalize(r,Path(r.stdout_path).read_text(errors='replace'),Path(r.stderr_path).read_text(errors='replace'))
            contract.update(status='PASSED' if not boundary_error and boundary_raw=='UNSAT' else 'BLOCKED',raw_result=boundary_raw)
            if contract['status']!='PASSED' and result['verdict'] in ('HOLDS','VIOLATED'):
                code=boundary_error or ('MODEL_BOUNDARY_REACHABLE' if boundary_raw=='SAT' else 'MODEL_BOUNDARY_UNKNOWN')
                result.update(verdict='UNKNOWN' if code not in ('RIC3_FAILED','RIC3_RESULT_INVALID') else 'ERROR',
                    error={'code':code,'message':'Boundary obligations are not proven unreachable; see ric3_boundaries evidence'})
            if trace: trace.emit('verification.model_boundaries',**contract)
        state('CONCLUSION_GATE')
        gate(result,commands=commands,hashes=hashes,bad_nodes=nodes,target_node=target)
    except AgentError as exc:
        result.update(verdict='UNKNOWN' if exc.code.endswith('_TIMEOUT') else 'ERROR',error=exc.as_dict())
    except (OSError,ValueError,KeyError,TypeError,AttributeError) as exc:
        result.update(verdict='ERROR',error={'code':'VERIFICATION_ERROR','message':type(exc).__name__+': '+str(exc)})
    if result['conclusion_gate']['blockers']==['NOT_REACHED']:
        result['conclusion_gate']={'allowed':False,'blockers':[(result.get('error') or {}).get('code','INCONCLUSIVE')],'scope':'NO_PROOF_PUBLISHED'}
    result['evidence_manifest']=str(root/'evidence_hashes.json')
    write_json_atomic(root/'evidence_hashes.json',hashes)
    write_json_atomic(root/'result.json',result); state('DONE')
    if trace:
        trace.emit('verification.finished',level='ERROR' if result['verdict']=='ERROR' else 'WARNING' if result['verdict']=='UNKNOWN' else 'INFO',
                   verdict=result['verdict'],raw_result=result['raw_result'],error=result['error'],
                   conclusion_gate=result['conclusion_gate'],result_file=str(root/'result.json'))
    return result
