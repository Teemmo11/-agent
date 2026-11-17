from pathlib import Path
from ..adapters import cbmc,catbtor,c2btor
from ..process import invoke
from ..artifacts import write_json_atomic,digest,sha256_file
from ..errors import AgentError
from ..preflight import pinned_command,MOCK_MARKER

def generate(sources,entry,input_info,caps,config,root,trace=None):
    if trace: trace.emit('static.discovery.started',entry=entry)
    root=Path(root); root.mkdir(parents=True,exist_ok=True)
    result={'candidates':[],'failures':[],'entry':entry,'unsupported_categories':
            [f for f in cbmc.SAFETY_FLAGS if f not in caps.get('safety_flags',[])]}
    try:
        flags=caps.get('safety_flags',[])
        if not flags: raise AgentError('TOOLCHAIN_UNSUPPORTED','No supported static safety flags')
        source_profile=caps.get('cbmc_profile')==cbmc.SOURCE_PROFILE
        if source_profile:
            if not caps.get('ready'): raise AgentError('REAL_PREFLIGHT_BLOCKED','Source contract probe failed')
            model=root/'discovery_model.btor2';mapping=root/'discovery_map.json'
            argv=cbmc.source_command(sources,entry,flags,model,mapping,caps,checks=True)
        else: argv=cbmc.discovery_command(sources,entry,flags,caps)
        r=invoke(pinned_command(argv,caps,config),cwd=root,timeout=config.tool_timeout,prefix='discovery',trace=trace)
        if not r.ok: raise AgentError('CBMC_FAILED','Static discovery failed; inspect discovery.execution.json')
        if config.tool_mode=='REAL' and MOCK_MARKER.search(Path(r.stdout_path).read_text()+Path(r.stderr_path).read_text()):
            raise AgentError('MOCK_IN_REAL_RUN','Mock output in static discovery')
        discovery_artifacts={}
        if source_profile:
            if not model.is_file() or not mapping.is_file() or not model.stat().st_size:
                raise AgentError('BTOR_BUILD_FAILED','Static discovery conversion model/map missing')
            if MOCK_MARKER.search(model.read_text()) and config.tool_mode=='REAL':
                raise AgentError('MOCK_IN_REAL_RUN','Mock conversion model')
            valid=invoke(pinned_command(catbtor.check_command(model),caps,config),cwd=root,
                         timeout=config.tool_timeout,prefix='catbtor_discovery',trace=trace)
            if not valid.ok: raise AgentError('BTOR_INVALID','Static discovery model is invalid')
            _,data=c2btor.source_inventory(model,mapping)
            c2btor.validate_source_policy(data,caps)
            if data['format_version']!='1':
                raise AgentError('MODEL_CONTRACT_INVALID','Converter ignored --goto-btor2-no-lbe')
            props=[{'name':p['property_id'],'description':p['property_id'],'class':p['property_class'],
                    'sourceLocation':{'file':p['source']['file_name'],'line':p['source']['line'],
                                      'function':p['source']['function']}}
                   for p in data['source_properties']]
            paths=[model,mapping,root/'catbtor_discovery.execution.json',Path(valid.stdout_path),Path(valid.stderr_path)]
            discovery_artifacts={str(p):sha256_file(p) for p in paths}
        else: props=cbmc.parse_properties(Path(r.stdout_path).read_text())
        write_json_atomic(root/'raw_properties.json',props)
        for p in props:
            result['candidates'].append({'spec_id':'CBMC-'+digest(entry+':'+p['name'])[:16],
                'cbmc_property_id':p['name'],'category':p.get('class','unknown'),
                'description':p.get('description',''),'source_location':p.get('sourceLocation'),
                'generation_flags':flags,'source_sha256':input_info['source_sha256'],
                'requirements_sha256':input_info['requirements_sha256'],'entry':entry,
                'origin':'CBMC_STATIC','evaluation':{'status':'NOT_RUN'},
                **({'discovery_artifacts':discovery_artifacts,'discovery_scope':'CONVERSION_SOURCE_MAP'} if source_profile else {})})
    except AgentError as exc: result['failures'].append(exc.as_dict())
    write_json_atomic(root/'candidates.json',result)
    if trace:
        for candidate in result['candidates']: trace.emit('static.candidate',**candidate)
        trace.emit('static.discovery.finished',level='ERROR' if result['failures'] else 'INFO',count=len(result['candidates']),failures=result['failures'],unsupported_categories=result['unsupported_categories'],artifact=str(root/'candidates.json'))
    return result
