import re
from ..errors import AgentError

def check_command(model,caps):
    if caps.get('ric3_profile')!='btor-ric3-check-portfolio':
        raise AgentError('TOOLCHAIN_UNSUPPORTED','Expected rIC3 check <model> portfolio profile')
    return ['ric3','check',str(model),'portfolio']

def normalize(cmd,stdout,stderr):
    if cmd.spawn_error or cmd.resource_limit: return 'ERROR',None,'RIC3_EXECUTION_FAILED'
    if cmd.timed_out: return 'UNKNOWN',None,'RIC3_TIMEOUT'
    if cmd.returncode!=0 or re.search(r'panic|panicked|segmentation fault|unsupported|not supported',stdout+'\n'+stderr,re.I):
        return 'ERROR',None,'RIC3_FAILED'
    ansi=re.compile(r'\x1b\[[0-?]*[ -/]*[@-~]')
    records=lambda s:[x.strip().upper() for x in ansi.sub('',s).splitlines() if re.fullmatch('SAT|UNSAT|UNKNOWN',x.strip(),re.I)]
    out,err=records(stdout),records(stderr)
    if len(out)!=1 or err: return 'ERROR',None,'RIC3_RESULT_INVALID'
    raw=out[0]
    return {'SAT':'VIOLATED','UNSAT':'HOLDS','UNKNOWN':'UNKNOWN'}[raw],raw,None
