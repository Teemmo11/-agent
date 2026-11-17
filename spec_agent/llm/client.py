import json
import urllib.request
import urllib.error
from urllib.parse import urlsplit
from pathlib import Path
from ..errors import AgentError
from ..artifacts import write_json_atomic
from ..trace import redact

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs): return None

class OpenAIClient:
    mode='REAL'
    def __init__(self,config): self.config=config
    def complete(self,messages,directory,*,max_output_tokens=None,distinguish_timeout=False):
        c=self.config
        if c.llm_issues(): raise AgentError('LLM_CONFIG_MISSING',', '.join(c.llm_issues()))
        request_body={'model':c.model,'messages':messages}
        if max_output_tokens is not None:
            if type(max_output_tokens) is not int or not 1<=max_output_tokens<=65536:
                raise AgentError('LLM_CONFIG_INVALID','Invalid completion token limit')
            request_body['max_tokens']=max_output_tokens
        body=json.dumps(request_body).encode()
        if len(body)>2*1024*1024: raise AgentError('LLM_REQUEST_TOO_LARGE','Context exceeds 2 MiB')
        req=urllib.request.Request(c.base_url+'/chat/completions',data=body,headers={
            'Authorization':'Bearer '+c.api_key,'Content-Type':'application/json'},method='POST')
        handlers=[NoRedirect()]
        if urlsplit(c.base_url).hostname in ('localhost','127.0.0.1','::1'): handlers.append(urllib.request.ProxyHandler({}))
        opener=urllib.request.build_opener(*handlers)
        try:
            with opener.open(req,timeout=c.llm_timeout) as response: raw=response.read(4*1024*1024+1)
        except urllib.error.HTTPError as exc: raise AgentError('LLM_HTTP_ERROR',f'HTTP {exc.code}; response body omitted to protect secrets')
        except (OSError,urllib.error.URLError) as exc:
            if distinguish_timeout and isinstance(getattr(exc,'reason',exc),TimeoutError):
                raise AgentError('LLM_TIMEOUT','Model request exceeded its timeout') from None
            raise AgentError('LLM_CONNECTION_FAILED','Network request failed (details redacted)')
        if len(raw)>4*1024*1024: raise AgentError('LLM_RESPONSE_INVALID','Response too large')
        decoded=raw.decode('utf-8',errors='replace')
        try:
            data=json.loads(decoded)
        except (ValueError,RecursionError):
            # Invalid JSON cannot be safely decoded/redacted; omit payload entirely.
            write_json_atomic(Path(directory)/'response.raw.json',{'omitted':'MALFORMED_PROVIDER_JSON'})
            raise AgentError('LLM_RESPONSE_INVALID','Malformed Chat Completions response') from None
        data=redact(data,(c.api_key,))
        write_json_atomic(Path(directory)/'response.raw.json',data)
        try:
            choice=data['choices'][0]
            finish=choice.get('finish_reason')
            text=choice.get('message',{}).get('content')
            usage=data.get('usage')
            # Provider extensions may contain arbitrary text; only copy numeric counters.
            usage={k:v for k,v in usage.items() if k in ('prompt_tokens','completion_tokens','total_tokens')
                   and type(v) is int and v>=0} if isinstance(usage,dict) else None
            metadata={'model':data.get('model',c.model),'finish_reason':finish,
                      'usage':usage,'request_id':data.get('id')}
            write_json_atomic(Path(directory)/'response.metadata.json',redact(metadata,(c.api_key,)))
            if isinstance(text,str): (Path(directory)/'response.txt').write_text(text,encoding='utf-8')
            if finish not in (None,'stop') or not isinstance(text,str): raise ValueError()
        except (ValueError,KeyError,IndexError,TypeError,AttributeError):
            raise AgentError('LLM_RESPONSE_INVALID','Malformed or truncated Chat Completions response') from None
        return text

class FixtureClient:
    mode='FIXTURE_LLM'
    def __init__(self,path): self.data=json.loads(Path(path).read_text())
    def complete(self,messages,directory):
        context=json.loads(messages[-1]['content']); f=context['function']
        data=self.data.get(f['function_id'],self.data.get(f['name']))
        if data is None: raise AgentError('GENERATION_FAILED','No fixture for function '+f['name'])
        text=json.dumps(data)
        (Path(directory)/'response.txt').write_text(text,encoding='utf-8')
        write_json_atomic(Path(directory)/'response.metadata.json',{'mode':self.mode,'usage':None,'finish_reason':None})
        return text
