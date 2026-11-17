import json
from pathlib import Path
from ..errors import AgentError

BUILD_FLAGS=['--goto-btor2','--goto-btor2-out','--goto-btor2-map-out','--function','--property','--inline','--memory','--array']
SOURCE_PROFILE='c2btor-source-assertions'
SOURCE_SCHEMA='c2btor-source-map-1'
SOURCE_SCHEMA_FLAGS=['--goto-btor2-no-merge-bads','--goto-btor2-no-optimize-state',
                     '--goto-btor2-no-scalar-blocks','--goto-btor2-scalar-slice','--32','--64']
SOURCE_BUILD_FLAGS=['--goto-btor2','--goto-btor2-out','--goto-btor2-map-out','--inline','--memory','--array',
                    '--goto-btor2-no-slice-property','--goto-btor2-no-lbe','--goto-btor2-checks']
SAFETY_FLAGS=['--bounds-check','--pointer-check','--div-by-zero-check','--signed-overflow-check']

def require(caps,flags):
    missing=[f for f in flags if f not in caps.get('cbmc_flags',[])]
    if missing: raise AgentError('TOOLCHAIN_UNSUPPORTED','CBMC missing capabilities: '+', '.join(missing))

def source_policy(caps):
    """Recorded execution policy for the versioned source-map interface."""
    if caps.get('cbmc_source_schema')!=SOURCE_SCHEMA: return None
    model=caps.get('cbmc_target_model')
    if model not in ('ILP32','LP64'): raise AgentError('CONFIG_INVALID','Unknown C2BTOR target data model')
    return {'schema_version':SOURCE_SCHEMA,'data_model':model,'array':'bv','memory':'object',
            'lbe':False,'property_slicing':False,'merge_bads':False,'optimize_state':False,
            'scalar_blocks':False,'scalar_projection':'none','logical_arrays':False,'array_blocks':False,
            'array_loop_summary':False,'scalar_loop_summary':False,'symbolic_heap':False,
            'symbolic_heap_arrays':False,'symbolic_heap_wide_offsets':False,
            'symbolic_heap_compact':False,'symbolic_heap_bv_array_fallback':False}

def execution_identity(caps):
    """Refinement evidence is comparable only under the same model policy."""
    return (caps.get('cbmc_profile'),{k:v.get('sha256') for k,v in caps.get('tools',{}).items()},source_policy(caps))

def command(sources,entry,flags):
    return ['cbmc','--function',entry,*flags,*map(str,sources)]

def build_command(job,model,mapping,caps,property_id):
    if caps.get('cbmc_profile')==SOURCE_PROFILE:
        return source_command(job.source_files,job.entry,job.generation_flags if job.kind=='CBMC_STATIC_PROPERTY' else [],
                              model,mapping,caps,checks=job.kind=='CBMC_STATIC_PROPERTY')
    require(caps,BUILD_FLAGS)
    if job.kind=='CBMC_STATIC_PROPERTY': flags=job.generation_flags
    else:
        require(caps,['--no-standard-checks']); flags=['--no-standard-checks']
    return command(job.source_files,job.entry,[*flags,'--property',property_id,
        '--inline','--memory','object','--array','bv',
        '--goto-btor2','--goto-btor2-out',str(model),'--goto-btor2-map-out',str(mapping)])

def source_command(sources,entry,flags,model,mapping,caps,*,checks=False):
    """All assertions, no slicing or merging; property selection happens in BTOR2."""
    require(caps,SOURCE_BUILD_FLAGS)
    # The new converter always encodes main. Hoare harnesses provide a main
    # delegating to __sa_entry; custom static entries need a separate harness.
    if entry not in ('main','__sa_entry') or (checks and entry!='main'):
        raise AgentError('TOOLCHAIN_UNSUPPORTED','New C2BTOR conversion requires main or the generated __sa_entry harness')
    if not checks and flags:
        raise AgentError('CONFIG_INVALID','Hoare source conversion cannot add static checks')
    require(caps,flags)
    policy=source_policy(caps)
    extra=[]
    if policy:
        require(caps,SOURCE_SCHEMA_FLAGS)
        extra=['--32' if policy['data_model']=='ILP32' else '--64',
               '--goto-btor2-no-merge-bads','--goto-btor2-no-optimize-state',
               '--goto-btor2-no-scalar-blocks','--goto-btor2-scalar-slice','none']
    return ['cbmc',*flags,*(['--goto-btor2-checks'] if checks else []),
            '--inline','--memory','object','--array','bv','--goto-btor2-no-slice-property','--goto-btor2-no-lbe',*extra,
            '--goto-btor2','--goto-btor2-out',str(model),'--goto-btor2-map-out',str(mapping),*map(str,sources)]

def discovery_command(sources,entry,flags,caps):
    require(caps,['--show-properties','--json-ui','--function',*flags])
    return command(sources,entry,[*flags,'--show-properties','--json-ui'])

def parse_properties(text):
    try:
        data=json.loads(text)
        if not isinstance(data,list): raise ValueError()
        props=[]; found=False
        for item in data:
            if not isinstance(item,dict): raise ValueError()
            if item.get('messageType')=='ERROR': raise ValueError()
            if 'properties' in item:
                found=True
                if not isinstance(item['properties'],list): raise ValueError()
                props.extend(item['properties'])
        if not found: raise ValueError()
        seen=set()
        for p in props:
            if not isinstance(p,dict) or not isinstance(p.get('name'),str) or not p['name'] or p['name'] in seen: raise ValueError()
            seen.add(p['name'])
        return props
    except (ValueError,TypeError): raise AgentError('CBMC_PROPERTIES_INVALID','Expected CBMC JSON properties with unique names')
