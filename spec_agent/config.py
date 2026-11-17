import os
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit
from .errors import AgentError

@dataclass
class Config:
    base_url: str = ''
    model: str = ''
    api_key: str = field(default='', repr=False)
    llm_timeout: float = 60
    tool_timeout: float = 60
    llm_max_concurrency: int = 2
    verify_max_concurrency: int = 1
    tool_mode: str = 'REAL'  # Test harness may explicitly set MOCK; not an env switch.
    cbmc_command: str = 'cbmc'  # Explicit PATH entry; never silently select another tool.
    c2btor_data_model: str = 'LP64'
    def llm_issues(self):
        issues=[]
        for n,v in [('LLM_BASE_URL',self.base_url),('LLM_MODEL',self.model),('LLM_API_KEY',self.api_key)]:
            if not v.strip(): issues.append(n+'_MISSING')
        if self.base_url:
            try: p=urlsplit(self.base_url); p.port
            except ValueError:
                issues.append('LLM_BASE_URL_INVALID'); return issues
            if (not p.hostname or p.username or p.password or p.query or p.fragment or
                not (p.scheme=='https' or (p.scheme=='http' and p.hostname in ('localhost','127.0.0.1','::1')))):
                issues.append('LLM_BASE_URL_INVALID')
        if any(c in self.api_key for c in '\r\n') or any(c in self.model for c in '\r\n'):
            issues.append('LLM_CONFIG_INVALID')
        return issues

def load_config(path=Path('.env')):
    values={}
    if Path(path).exists():
        for i,line in enumerate(Path(path).read_text().splitlines(),1):
            line=line.strip()
            if not line or line.startswith('#'): continue
            key,sep,value=line.partition('=')
            key=key.strip()
            if not sep or key in values: raise AgentError('CONFIG_INVALID',f'Invalid/duplicate .env line {i}')
            value=value.strip()
            if len(value)>1 and value[0]==value[-1] and value[0] in '\"\'': value=value[1:-1]
            values[key]=value
    def get(k,d=''): return os.environ.get(k,values.get(k,d))
    try:
        c=Config(get('LLM_BASE_URL').rstrip('/'),get('LLM_MODEL'),get('LLM_API_KEY'),float(get('LLM_TIMEOUT_SECONDS','60')),
                 float(get('TOOL_TIMEOUT_SECONDS','60')),int(get('LLM_MAX_CONCURRENCY','2')),int(get('VERIFY_MAX_CONCURRENCY','1')))
        c.cbmc_command=get('CBMC_COMMAND','cbmc')
        c.c2btor_data_model=get('C2BTOR_DATA_MODEL','LP64')
        if c.cbmc_command not in ('cbmc','c2btor'): raise ValueError()
        if c.c2btor_data_model not in ('ILP32','LP64'): raise ValueError()
        if not (0<c.llm_timeout<=3600 and 0<c.tool_timeout<=3600 and 1<=c.llm_max_concurrency<=16 and c.verify_max_concurrency==1):
            raise ValueError()
        return c
    except ValueError: raise AgentError('CONFIG_INVALID','Invalid tool/data-model/timeout/concurrency configuration; verification is serial')
