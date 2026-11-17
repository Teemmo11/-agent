"""Incremental event projection. Observation never manufactures proof verdicts."""
import hashlib
import json
import re
import time
from collections import deque
from datetime import datetime,timezone
from pathlib import Path,PurePosixPath,PureWindowsPath
from ..trace import redact

STAGES=[('INPUT_SNAPSHOTTED','输入快照'),('PREFLIGHT','工具预检'),('ANALYZING','程序分析'),
        ('GENERATING','规格生成'),('NORMALIZING','候选整理'),('FORMALIZING','规约形式化'),
        ('VERIFYING','模型验证'),('SUMMARIZING','结果汇总')]
TERMINAL={'COMPLETED','COMPLETED_WITH_ERRORS','FAILED','CANCELLED'}
MAX_READ=4*1024*1024
MAX_LINE=2*1024*1024


def safe_file(root,relative):
    parts=PurePosixPath(str(relative).replace('\\','/')).parts
    if not parts or any(p in ('..','.') or ':' in p for p in parts) or PurePosixPath(str(relative)).is_absolute():
        raise ValueError('Unsafe artifact path')
    path=root
    for part in parts:
        path=path/part
        if path.is_symlink():raise ValueError('Symlink artifacts are not served')
    if not path.resolve().is_relative_to(root):raise ValueError('Artifact escapes run')
    return path


def read_json(root,name,limit=8*1024*1024):
    try:
        path=safe_file(root,name)
        if path.stat().st_size>limit:return None
        value=json.loads(path.read_text(encoding='utf-8'))
        return value if isinstance(value,dict) else None
    except (OSError,ValueError,UnicodeError):return None


def timestamp_age(value):
    try:return max(0,(datetime.now(timezone.utc)-datetime.fromisoformat(value.replace('Z','+00:00'))).total_seconds())
    except (ValueError,TypeError,AttributeError):return None


class RunView:
    def __init__(self,root,secrets=(),*,show_pq=False):
        self.root=Path(root).resolve();self.secrets=secrets;self.show_pq=show_pq;self.reset()

    def reset(self):
        self.offset=0;self.pending=b'';self.identity=None;self.bad_lines=0;self.partial=False
        self.events=deque(maxlen=160);self.tools={};self.properties={};self.functions={}
        self.stages={s:{'id':s,'label':label,'status':'PENDING'} for s,label in STAGES}
        self.current='CREATED';self.last=None;self.start=None;self.run_details={};self.terminal=None
        self.branches={b:{'status':'PENDING','candidates':0} for b in ('hoare','static')}
        self.observation=[];self.original=str(self.root).replace('\\','/')

    def artifact(self,value):
        if not isinstance(value,str):return None
        value=value.replace('\\','/')
        if value.startswith('/') or (len(value)>1 and value[1]==':'):
            prefix=self.original.rstrip('/')+'/'
            if not value.startswith(prefix):return None
            value=value[len(prefix):]
        try:
            path=safe_file(self.root,value);parts=PurePosixPath(value).parts
            if parts[0] not in ('verification','preflight','generation'):return None
            if not (path.name.endswith('.stdout.log') or path.name.endswith('.stderr.log')):return None
            return value
        except (ValueError,OSError):return None

    def property(self,pid,context):
        if pid not in self.properties:
            if len(self.properties)>=10000:return None
            self.properties[pid]={'id':pid,'status':'PENDING','stage':'PENDING','verdict':None,'raw_result':None,
                'kind':None,'function_id':context.get('function_id'),'spec_id':context.get('spec_id'),
                'branch':context.get('branch','hoare'),'gate':None}
        return self.properties[pid]

    def apply(self,event):
        name=event['event'];d=event['details'];ctx={**d,**event.get('context',{})}
        self.last=event
        if name=='run.started':self.run_details=d;self.start=event['timestamp']
        if name=='stage.changed':
            state=d.get('state');self.current=state
            if state in self.stages:self.stages[state]['status']='ACTIVE'
            if state=='FAILED':
                for row in self.stages.values():
                    if row['status']=='ACTIVE':row['status']='ERROR'
        if name=='stage.finished' and d.get('state') in self.stages:
            self.stages[d['state']].update(status='DONE',duration_ms=d.get('duration_ms'))
        if name=='analysis.function':
            fid=ctx.get('function_id')
            if fid:self.functions[fid]={'id':fid,'name':d.get('function',fid),'status':'PENDING'}
        fid=ctx.get('function_id')
        if fid and fid in self.functions:
            if name=='llm.request.started':self.functions[fid]['status']='LLM_RUNNING';self.branches['hoare']['status']='RUNNING'
            if name=='spec.accepted':
                self.functions[fid].update(status='GENERATED',spec_id=ctx.get('spec_id'))
                self.branches['hoare']['candidates']+=1
            if name in ('llm.generation.failed','formalization.rejected'):self.functions[fid]['status']='ERROR'
        if name=='static.discovery.started':self.branches['static']['status']='RUNNING'
        if name=='static.candidate':self.branches['static']['candidates']+=1
        if name=='static.discovery.finished':self.branches['static']['status']='ERROR' if d.get('failures') else 'DONE'
        if name=='generation.finished':
            if self.run_details.get('branch')!='static':self.branches['hoare']['status']='DONE'
        if name=='generation.branch_failed' and ctx.get('branch') in self.branches:self.branches[ctx['branch']]['status']='ERROR'
        if name=='tool.started':
            tid=d.get('command_id')
            if tid and len(self.tools)<3000:self.tools[tid]={'id':tid,'argv':d.get('argv',[]),'started_at':event['timestamp'],
                'elapsed_ms':event.get('elapsed_ms'),'timeout':d.get('timeout_seconds'),'status':'RUNNING',
                'property_id':ctx.get('property_id'),'branch':ctx.get('branch'),'stage':self.current}
            if tid in self.tools:self.tools[tid].update(stdout=self.artifact(tid+'.stdout.log'),stderr=self.artifact(tid+'.stderr.log'))
        if name in ('tool.finished','tool.failed'):
            tool=self.tools.get(d.get('command_id'))
            if tool:
                tool.update(status='TIMED_OUT' if d.get('timed_out') else 'ERROR' if name=='tool.failed' or d.get('spawn_error') or d.get('resource_limit') else 'DONE' if d.get('returncode')==0 else 'NONZERO_EXIT',
                    duration_seconds=d.get('duration_seconds'),returncode=d.get('returncode'),
                    error=d.get('spawn_error') or d.get('resource_limit') or d.get('error_type'),
                    stdout=self.artifact(d.get('stdout')),stderr=self.artifact(d.get('stderr')))
        pid=ctx.get('property_id')
        if pid and name.startswith(('verification.','harness.','precondition.')):
            prop=self.property(pid,ctx)
            if prop:
                if name=='harness.emitted':prop.update(kind=d.get('kind'),precondition=d.get('precondition'),assertion=d.get('assertion'))
                if name=='verification.started':prop.update(status='RUNNING',kind=d.get('kind'))
                if name=='verification.stage':prop['stage']=d.get('state')
                if name=='verification.finished':prop.update(status='DONE',verdict=d.get('verdict'),raw_result=d.get('raw_result'),
                    error=d.get('error'),gate=d.get('conclusion_gate'))
        if name=='precondition.classified':
            sid=ctx.get('spec_id')
            for prop in self.properties.values():
                if prop.get('spec_id')==sid and prop.get('kind')=='PRECONDITION_FEASIBILITY':prop['classification']=d.get('status')
        if name in ('run.finished','run.failed','run.cancelled'):
            self.terminal=d.get('status') or ('CANCELLED' if name=='run.cancelled' else 'FAILED' if name=='run.failed' else 'OBSERVING')
        # Events are observations; full raw content remains in the existing files.
        clipped=dict(event)
        if len(json.dumps(clipped,ensure_ascii=False))>24000:
            clipped['details']={'notice':'事件详情较大，请查看 process.log；界面未重复载入全文。'}
        self.events.append(clipped)

    def specifications(self, contracts):
        """Project the saved Phase 1 expressions without parsing C or running tools."""
        functions = {f.get('spec_id'): f['name'] for f in self.functions.values() if f.get('spec_id')}
        functions.update({c['spec_id']: c.get('function') for c in contracts if c.get('spec_id')})
        # The generator saves the semantic candidate before normalization copies it to specs/.
        candidates = {f.get('spec_id'): f['id'] for f in self.functions.values() if f.get('spec_id')}
        specs = []
        for spec_id, function in functions.items():
            if not re.fullmatch(r'[A-Za-z0-9_-]+', spec_id):
                continue
            formal = read_json(self.root, f'specs/formal/{spec_id}.json', limit=256*1024)
            if formal and formal.get('source_spec_id') == spec_id:
                p, clauses = formal.get('precondition_expr'), formal.get('ensures')
                expression, guard, source = 'expr', 'guard_expr', 'FORMAL'
            else:
                semantic = read_json(self.root, f'specs/semantic/{spec_id}.json', limit=256*1024)
                fid = candidates.get(spec_id)
                if not semantic and isinstance(fid, str) and re.fullmatch(r'[A-Za-z0-9_-]+', fid):
                    semantic = read_json(self.root, f'generation/llm/functions/{fid}/spec.json', limit=256*1024)
                if not semantic or semantic.get('spec_id') != spec_id:
                    continue
                spec = semantic.get('function_spec')
                if not isinstance(spec, dict) or not isinstance(spec.get('pre_condition'), dict):
                    continue
                p, clauses = spec['pre_condition'].get('formal_candidate'), spec.get('post_conditions')
                expression, guard, source = 'formal_candidate', 'guard', 'SEMANTIC'
            if not isinstance(p, str) or not isinstance(clauses, list):
                continue
            posts = [
                {'id': clause['clause_id'], 'expression': clause[expression], 'guard': clause.get(guard)}
                for clause in clauses
                if isinstance(clause, dict) and isinstance(clause.get('clause_id'), str)
                and isinstance(clause.get(expression), str)
            ]
            specs.append({'id': spec_id, 'function': function or spec_id, 'source': source,
                          'precondition': p, 'postconditions': posts})
        return specs

    def refresh(self):
        manifest=read_json(self.root,'run_manifest.json')
        if manifest:
            try:
                source=manifest['input']['sources'][0]['snapshot']
                self.original=str((PureWindowsPath(source) if '\\' in source else PurePosixPath(source)).parents[3]).replace('\\','/')
            except (KeyError,IndexError,TypeError):pass
        try:
            path=safe_file(self.root,'events.jsonl');stat=path.stat();identity=(stat.st_dev,stat.st_ino)
            if self.identity is not None and (identity!=self.identity or stat.st_size<self.offset):
                original=self.original;self.reset();self.original=original;self.observation.append('事件文件已替换或截短，已重新读取。')
            self.identity=identity
            with path.open('rb') as stream:
                stream.seek(self.offset);chunk=stream.read(MAX_READ);self.offset+=len(chunk)
            lines=(self.pending+chunk).split(b'\n');self.pending=lines.pop();self.partial=bool(self.pending)
            if len(self.pending)>MAX_LINE:
                self.pending=b'';self.bad_lines+=1
            for line in lines:
                try:
                    if len(line)>MAX_LINE:raise ValueError('Oversize event')
                    event=json.loads(line)
                    if (not isinstance(event,dict) or not isinstance(event.get('details'),dict) or
                        not isinstance(event.get('event'),str) or not isinstance(event.get('timestamp'),str) or
                        type(event.get('sequence')) is not int or event['sequence']<1 or not isinstance(event.get('context',{}),dict)):raise ValueError('Invalid event')
                    self.apply(redact(event,self.secrets))
                except (ValueError,TypeError,UnicodeError):self.bad_lines+=1
            catching_up=stat.st_size>self.offset
        except (OSError,ValueError):catching_up=False
        result=read_json(self.root,'result.json')
        checkpoint=read_json(self.root,'checkpoint.json') or {}
        if result:
            for contract in result.get('contracts',[]):
                p=contract.get('precondition',{})
                for row in ([p['result']] if p.get('result') else [])+contract.get('properties',[]):
                    prop=self.property(row['property_id'],{'spec_id':contract.get('spec_id'),'branch':'hoare'})
                    if prop:
                        prop.update(status='DONE',kind=row.get('kind'),verdict=row.get('verdict'),raw_result=row.get('raw_result'),
                            gate=row.get('conclusion_gate'),error=row.get('error'),function=contract.get('function'))
                        if row.get('kind')=='PRECONDITION_FEASIBILITY':prop['classification']=p.get('status')
            for row in result.get('static_properties',[]):
                pid=row.get('property_id',row.get('cbmc_property_id',row.get('spec_id')))
                prop=self.property(pid,{'branch':'static','spec_id':row.get('spec_id')}) if pid else None
                if prop:prop.update(status='DONE' if row.get('verdict') else 'GENERATED',kind='CBMC_STATIC_PROPERTY',
                    verdict=row.get('verdict'),raw_result=row.get('raw_result'),gate=row.get('conclusion_gate'),error=row.get('error'))
        status=(result or {}).get('status') or self.terminal or 'OBSERVING'
        # A checkpoint is a progress record, never proof of completion/resume authority.
        current=self.current if self.last else checkpoint.get('state','CREATED')
        if status in TERMINAL:
            for row in self.stages.values():
                if row['status']=='ACTIVE':row['status']='ERROR' if status in ('FAILED','CANCELLED') else 'DONE'
        props=list(self.properties.values())
        for prop in props:
            if prop.get('kind')=='PRECONDITION_FEASIBILITY' and not prop.get('classification'):
                prop['classification']={'VIOLATED':'FEASIBLE','HOLDS':'INFEASIBLE'}.get(prop.get('verdict')) if (prop.get('gate') or {}).get('allowed') else None
            if prop.get('kind')=='PRECONDITION_FEASIBILITY':prop['interpretation']='P 探针使用 assume(P); assert(0)。SAT 表示前提可行；它不调用被测函数。'
        tools=list(self.tools.values())
        for tool in tools:
            tool['age_seconds']=timestamp_age(tool.get('started_at'))
        contracts=[{'function':c.get('function'),'spec_id':c.get('spec_id'),'precondition':c.get('precondition',{}).get('status'),
                    'verdict':c.get('verification',{}).get('verdict')} for c in (result or {}).get('contracts',[])]
        branch=self.run_details.get('branch',(result or {}).get('generation',{}).get('branch','both'))
        for key,row in self.branches.items():
            if branch!='both' and key!=branch:row['status']='SKIPPED'
        if branch=='static':self.stages['FORMALIZING']['status']='SKIPPED'
        if self.run_details.get('generate_only'):
            for stage in ('FORMALIZING','VERIFYING'):self.stages[stage]['status']='SKIPPED'
        warnings=list(self.observation)
        if self.bad_lines:warnings.append(f'{self.bad_lines} 条事件损坏或超出界面读取上限；观测可能不完整。')
        if self.partial:warnings.append('事件尾行尚未写完，等待后续内容。')
        logging=(result or {}).get('logging',{})
        if logging.get('status')=='DEGRADED':warnings.append('运行日志已降级，界面可能缺少事件。')
        if status not in TERMINAL and self.last and (timestamp_age(self.last['timestamp']) or 0)>20:
            warnings.append('近期没有新事件；可能在等待模型或工具。仅凭日志无法确认进程是否仍存活。')
        return redact({'run_id':(manifest or {}).get('run_id',self.root.name),'directory':str(self.root),
            'status':status,'mode':(result or {}).get('mode') or ('MOCK_ALL' if self.run_details.get('tool_mode')=='MOCK' else 'FIXTURE_LLM_REAL_TOOLS' if self.run_details.get('llm_mode')=='FIXTURE_LLM' else self.run_details.get('tool_mode','UNKNOWN')),
            'branch':branch,'generate_only':self.run_details.get('generate_only',False),'stage':current,
            'started_at':self.start,'last_event_at':self.last['timestamp'] if self.last else None,
            'elapsed_ms':self.last.get('elapsed_ms') if self.last else None,'stages':list(self.stages.values()),
            'branches':self.branches,'functions':list(self.functions.values()),'properties':props,'contracts':contracts,
            'tools':tools[-120:],'events':list(self.events),'warnings':warnings,'catching_up':catching_up,
            'logging':logging.get('status','OBSERVING'),'failures':(result or {}).get('failures',[]),
            'source_names':[Path(r['original'].replace('\\','/')).name for r in (manifest or {}).get('input',{}).get('sources',[])],
            'evaluation':'NOT_RUN',
            **({'specifications': self.specifications(contracts)} if self.show_pq else {})},self.secrets)


class RunRegistry:
    def __init__(self,root,*,single=False,secrets=(),show_pq=False):
        self.root=Path(root).resolve();self.single=single;self.secrets=secrets
        self.show_pq=show_pq
        self.views={};self.paths={};self.selected=None;self.last_scan=0;self.scan_limited=False
        self.focused=False;self.scan_queue=deque([self.root]);self.scan_count=0
        if single:self.selected=self.add(self.root)

    def attach(self,root):
        root=Path(root).resolve()
        if not root.is_relative_to(self.root):raise ValueError('Attached run outside monitor root')
        key=self.add(root);self.selected=key;return key

    def add(self,path):
        key=hashlib.sha256(str(path.relative_to(self.root)).encode()).hexdigest()[:20]
        self.paths[key]=path;return key

    def catalog(self):
        if not self.focused:
            if not self.scan_queue and time.monotonic()-self.last_scan>5:
                self.scan_queue=deque([self.root]);self.scan_count=0
            queue=self.scan_queue;count=0
            skip={'input','verification','preflight','analysis','specs','generation','queries','context','fixtures'}
            while queue and count<128 and self.scan_count<5000:
                path=queue.popleft();count+=1;self.scan_count+=1
                if path.is_symlink():continue
                if (path/'events.jsonl').is_file() and (path/'run_manifest.json').is_file():
                    self.add(path);continue
                if self.single:continue
                try:
                    queue.extend(sorted((p for p in path.iterdir() if p.is_dir() and not p.is_symlink()
                        and not p.name.startswith('.') and p.name not in skip),key=lambda p:p.name,reverse=True))
                except OSError:pass
            self.scan_limited=bool(queue)
            if self.scan_count>=5000:queue.clear()
            if not queue:self.last_scan=time.monotonic()
        rows=[]
        for key,path in sorted(self.paths.items(),key=lambda item:item[1].name,reverse=True)[:150]:
            result=read_json(path,'result.json') or {};manifest=read_json(path,'run_manifest.json') or {}
            rows.append({'key':key,'run_id':manifest.get('run_id',path.name),'status':result.get('status','OBSERVING'),
                         'mode':result.get('mode','UNKNOWN'),'relative':str(path.relative_to(self.root))})
        return {'runs':rows,'selected':self.selected,'scan_limited':self.scan_limited}

    def snapshot(self,key):
        if key not in self.paths:raise KeyError(key)
        if key not in self.views and len(self.views)>=8:self.views.pop(next(iter(self.views)))
        if key not in self.views:self.views[key]=RunView(self.paths[key],self.secrets,show_pq=self.show_pq)
        return self.views[key].refresh()

    def artifact_text(self,key,relative):
        if key not in self.views:raise KeyError(key)
        view=self.views[key];allowed={t.get(k) for t in view.tools.values() for k in ('stdout','stderr')}
        if relative not in allowed or relative is None:raise ValueError('Artifact is not an observed tool log')
        path=safe_file(view.root,relative)
        with path.open('rb') as stream:
            size=path.stat().st_size;stream.seek(max(0,size-32768));data=stream.read(32768)
        return {'path':relative,'truncated':size>32768,'text':redact(data.decode('utf-8',errors='replace'),self.secrets)}
