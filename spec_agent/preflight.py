"""Observable CLI compatibility; optional actual semantic smoke probes, never fake fallback."""
import json
import re
import shutil
import sys
from pathlib import Path
from .process import invoke
from .adapters.cbmc import BUILD_FLAGS, SAFETY_FLAGS
from .adapters import cbmc,c2btor
from .adapters.ric3 import normalize
from .artifacts import write_json_atomic, sha256_file
from .errors import AgentError

MOCK_MARKER=re.compile(r'\bMOCK(?:_ALL)?\b|fixture-label:|NOT A FORMAL PROOF',re.I)

def logs(r):
    return Path(r.stdout_path).read_text(errors='replace')+'\n'+Path(r.stderr_path).read_text(errors='replace')

def pinned_command(argv,caps,config):
    """Keep the executable observed by preflight; reject replacement/PATH drift."""
    name=argv[0]; info=caps.get('tools',{}).get(name,{})
    if config.tool_mode=='REAL' and (caps.get('mock_detected') or info.get('mock_detected')):
        raise AgentError('MOCK_IN_REAL_RUN','Mock tool evidence is forbidden in real execution')
    exe=info.get('executable'); checksum=info.get('sha256')
    if not exe or not checksum or not Path(exe).is_file() or sha256_file(exe)!=checksum:
        raise AgentError('TOOL_IDENTITY_CHANGED',name+' is absent or changed since preflight')
    return [exe,*argv[1:]]

def doctor(config,root,*,check_llm=False,probe_tools=False,trace=None):
    root=Path(root).resolve(); root.mkdir(parents=True,exist_ok=True)
    tools={}; flags=[]; profile=None; issues=[]; cbmc_profile='legacy-cbmc-btor2'
    source_schema=None
    for name in ('cbmc','catbtor','ric3'):
        configured=config.cbmc_command if name=='cbmc' else name
        if name=='cbmc' and configured not in ('cbmc','c2btor'):
            raise AgentError('CONFIG_INVALID','Unsupported PATH tool name')
        executable=shutil.which(configured)
        if not executable:
            tools[name]={'available':False,'status':'MISSING','version_status':'NOT_RUN'}
            issues.append(name.upper()+'_MISSING')
            if trace: trace.emit('preflight.tool_missing',level='WARNING',tool=name)
            continue
        executable=str(Path(executable).resolve()); d=root/name; d.mkdir(exist_ok=True)
        r=invoke([executable,'--help'],cwd=d,timeout=min(config.tool_timeout,10),prefix='help',trace=trace)
        v=invoke([executable,'--version'],cwd=d,timeout=min(config.tool_timeout,10),prefix='version',trace=trace)
        text=logs(r); version=logs(v).strip()
        info={'available':True,'executable':executable,'configured_command':configured,'sha256':sha256_file(executable),
              'help_execution':r.to_dict(),'version_execution':v.to_dict(),
              'version_status':'REPORTED' if v.ok and version else 'UNSUPPORTED_OR_FAILED',
              'version':version[:1000] if v.ok else None,
              'status':'PROBED' if r.ok else 'HELP_FAILED',
              'mock_detected':bool(MOCK_MARKER.search(text+'\n'+version))}
        tools[name]=info
        help_usable=r.ok or (name=='catbtor' and r.returncode==1 and re.search(r'usage|catbtor|btor2',text,re.I) and not (r.spawn_error or r.timed_out or r.resource_limit))
        if not help_usable: issues.append(name.upper()+'_HELP_FAILED')
        if info['mock_detected'] and config.tool_mode=='REAL': issues.append(name.upper()+'_MOCK_DETECTED')
        if name=='cbmc':
            if r.ok: flags=sorted(set(re.findall(r'--(?:[a-z][a-z0-9-]*|32|64)\b',text)))
            if r.ok and re.search(r'\bC2BTOR\b',text,re.I): cbmc_profile='c2btor-2'
            if cbmc_profile=='c2btor-2' and all(f in flags for f in ('--goto-btor2-checks','--goto-btor2-no-slice-property')):
                cbmc_profile=cbmc.SOURCE_PROFILE
                if '--goto-btor2-no-merge-bads' in flags: source_schema=cbmc.SOURCE_SCHEMA
            if not v.ok: issues.append('CBMC_VERSION_FAILED')
        if name=='ric3' and r.ok and re.search(r'\bcheck\b',text):
            sub=invoke([executable,'check','--help'],cwd=d,timeout=min(config.tool_timeout,10),prefix='check_help',trace=trace)
            info['check_help_execution']=sub.to_dict()
            if sub.ok and re.search(r'\bportfolio\b',logs(sub)):
                profile='btor-ric3-check-portfolio'
            else: issues.append('RIC3_CHECK_PORTFOLIO_UNSUPPORTED')
        elif name=='ric3': issues.append('RIC3_CLI_UNSUPPORTED')
    required=(cbmc.SOURCE_BUILD_FLAGS if cbmc_profile==cbmc.SOURCE_PROFILE else
              BUILD_FLAGS+['--no-standard-checks','--show-properties','--json-ui'])
    if source_schema: required=required+cbmc.SOURCE_SCHEMA_FLAGS
    missing=[x for x in required if x not in flags]
    if missing: issues.append('CBMC_CAPABILITIES_MISSING')
    llm={'configured':not config.llm_issues(),'issues':config.llm_issues(),'model':config.model,
         'configuration_presence':{'base_url':bool(config.base_url),'model':bool(config.model),'api_key':bool(config.api_key)},
         'connection_status':'NOT_RUN','probe':None}
    report={'python':sys.version.split()[0],'llm':llm,'tools':tools,'cbmc_flags':flags,
      'ric3_profile':profile,'cbmc_profile':cbmc_profile,'ready':not issues,'issues':issues,'missing_capabilities':missing,
      'mock_detected':any(t.get('mock_detected',False) for t in tools.values()),
      'safety_flags':[f for f in SAFETY_FLAGS if f in flags],
      'probe_scope':'Help/version only unless explicitly requested; missing version support is recorded, not fabricated',
      'semantic_probe':{'status':'NOT_RUN'},'real_validation_ready':False,'evaluation':{'status':'NOT_RUN'}}
    if source_schema:
        report.update(cbmc_source_schema=source_schema,cbmc_target_model=config.c2btor_data_model)
        report['converter_policy']=cbmc.source_policy(report)
    if cbmc_profile==cbmc.SOURCE_PROFILE:
        report['probe_scope']='New property contract requires an actual C-to-BTOR2/map probe; solver probes remain opt-in'
        if report['ready']:
            report['source_conversion_probe']=probe_source_contract(config,root/'source-contract-probe',report,trace=trace)
            if report['source_conversion_probe']['status']!='PASSED':
                issues.append('SOURCE_CONTRACT_PROBE_FAILED');report['ready']=False
        else: report['source_conversion_probe']={'status':'BLOCKED'}
    if probe_tools:
        if not report['ready'] or config.tool_mode!='REAL':
            report['semantic_probe']={'status':'BLOCKED','reason':'Compatible non-mock tools required'}
        else:
            report['semantic_probe']=probe_semantics(config,root/'semantic-probe',report,trace=trace)
            if report['semantic_probe']['status']!='PASSED': issues.append('SEMANTIC_PROBE_FAILED');report['ready']=False
    if check_llm:
        if not llm['configured']: llm['connection_status']='BLOCKED'
        else:
            from .llm.client import OpenAIClient
            d=root/'llm-probe';d.mkdir()
            try:
                text=OpenAIClient(config).complete([{'role':'user','content':'Return exactly the JSON object {"ok":true} and no other text.'}],d)
                if json.loads(text)!={'ok':True}: raise AgentError('LLM_PROBE_INVALID','Expected JSON acknowledgement')
                llm['connection_status']='PASSED'
            except Exception as exc:
                llm['connection_status']='FAILED'
                llm['probe']=exc.as_dict() if isinstance(exc,AgentError) else {'code':'LLM_PROBE_INVALID','message':type(exc).__name__}
    report['real_validation_ready']=(report['ready'] and llm['configured'] and report['semantic_probe']['status']=='PASSED' and not report['mock_detected'])
    write_json_atomic(root/'toolchain_manifest.json',report)
    return report

def probe_source_contract(config,root,caps,trace=None):
    """Confirm the advertised new protocol by conversion, not version strings."""
    root.mkdir(parents=True);source=root/'probe.c';model=root/'model.btor2';mapping=root/'source_map.json'
    source.write_text('int main(void) { __CPROVER_assert(0, "probe_false"); __CPROVER_assert(1, "probe_true"); return 0; }\n')
    argv=cbmc.source_command([source],'main',[],model,mapping,caps)
    command=invoke(pinned_command(argv,caps,config),cwd=root,timeout=min(config.tool_timeout,10),prefix='converter',trace=trace)
    result={'status':'FAILED','converter':command.to_dict(),'source_sha256':sha256_file(source),
            'scope':'Protocol and attribution probe, not specification verification'}
    try:
        if not command.ok: raise AgentError('BTOR_BUILD_FAILED','Source contract probe conversion failed')
        if config.tool_mode=='REAL' and MOCK_MARKER.search(logs(command)+model.read_text()):
            raise AgentError('MOCK_IN_REAL_RUN','Mock source contract probe')
        _,data=c2btor.source_inventory(model,mapping)
        c2btor.validate_source_policy(data,caps)
        if data['format_version']!='1': raise AgentError('MODEL_CONTRACT_INVALID','Converter ignored --goto-btor2-no-lbe')
        if len(data['source_properties'])!=2: raise AgentError('MODEL_CONTRACT_INVALID','Probe did not preserve both assertions')
        valid=invoke(pinned_command(['catbtor',str(model)],caps,config),cwd=root,
                     timeout=min(config.tool_timeout,10),prefix='catbtor',trace=trace)
        result['catbtor']=valid.to_dict()
        if not valid.ok: raise AgentError('BTOR_INVALID','Probe model is invalid')
        result.update(status='PASSED',model_sha256=sha256_file(model),map_sha256=sha256_file(mapping))
    except (AgentError,OSError,ValueError) as exc:
        result['error']=exc.as_dict() if isinstance(exc,AgentError) else {'code':'SOURCE_CONTRACT_PROBE_FAILED','message':str(exc)}
    write_json_atomic(root/'result.json',result)
    return result

def probe_semantics(config,root,caps,trace=None):
    """Analytically known one-bit models; these are real tool tests, not C proofs."""
    root.mkdir(parents=True); checks=[]
    for label,bit,expected in [('reachable_bad','one','SAT'),('unreachable_bad','zero','UNSAT')]:
        d=root/label;d.mkdir();model=d/'model.btor2'
        model.write_text(f'1 sort bitvec 1\n2 {bit} 1\n3 bad 2\n')
        valid=invoke(pinned_command(['catbtor',str(model)],caps,config),cwd=d,timeout=min(config.tool_timeout,10),prefix='catbtor',trace=trace)
        r=invoke(pinned_command(['ric3','check',str(model),'portfolio'],caps,config),cwd=d,timeout=min(config.tool_timeout,10),prefix='ric3',trace=trace)
        _,raw,error=normalize(r,Path(r.stdout_path).read_text(),Path(r.stderr_path).read_text())
        checks.append({'name':label,'expected_raw':expected,'raw':raw,'passed':valid.ok and error is None and raw==expected,
                       'catbtor':valid.to_dict(),'ric3':r.to_dict(),'model_sha256':sha256_file(model)})
    d=root/'invalid';d.mkdir();model=d/'invalid.btor2';model.write_text('this is not BTOR2\n')
    r=invoke(pinned_command(['catbtor',str(model)],caps,config),cwd=d,timeout=min(config.tool_timeout,10),prefix='catbtor',trace=trace)
    checks.append({'name':'invalid_btor_rejected','passed':r.returncode is not None and r.returncode>0 and not (r.spawn_error or r.timed_out or r.resource_limit),
                   'catbtor':r.to_dict()})
    status='PASSED' if all(x['passed'] for x in checks) else 'FAILED'
    result={'status':status,'checks':checks,'scope':'catbtor acceptance/rejection and rIC3 raw semantics; CBMC translation checked in integration cases'}
    write_json_atomic(root/'result.json',result)
    return result
