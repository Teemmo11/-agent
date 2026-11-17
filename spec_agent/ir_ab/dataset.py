"""Authored synthetic references. Only this module defines the benchmark semantics."""
from copy import deepcopy

from .semantics import PROFILE, canon, digest, expand, join, symbols


def eq(x,y): return ['eq',x,y]
def le(x,y): return ['le',x,y]
def ge(x,y): return ['ge',x,y]
def AND(*xs): return join('and',xs)
def OR(*xs): return join('or',xs)
def NOT(x): return ['not',x]
def REF(x): return ['ref',x]


def policy(name,family,params,guards,rules,default,*,risk,edit=None):
    """Ordered cases: effective guard is current condition minus all earlier cases.

    Each active branch promises a point or interval, not a particular implementation.
    The priority exclusion is inside the guard, not a restriction on P.
    """
    used=set(); definitions=dict(guards); obligations=[]; requirements=[]
    pre=AND(*(ge(p,0) for p in params),*(le(p,9) for p in params))
    requirements.append({'id':'R0','text':'各输入都是 0–9 的整数编码。'})
    obligations.append({'id':'S0','role':'requires','expr':pre,'requirement_refs':['R0']})
    earlier=[]
    for i,(text,condition,(lo,hi)) in enumerate([*rules,('未命中任何规则时',True,default)],1):
        guard=f'branch{i}'; definitions[guard]=AND(condition,*(NOT(x) for x in earlier)); earlier.append(condition)
        req=f'R{i}'; sid=f'S{i}'; used.add(guard)
        desc=f'返回 {lo}' if lo==hi else f'返回 {lo} 至 {hi}（含两端）的整数'
        requirements.append({'id':req,'text':f'按顺序匹配，第 {i} 条：{text}；{desc}。'})
        expr=eq('result',lo) if lo==hi else AND(ge('result',lo),le('result',hi))
        obligations.append({'id':sid,'role':'ensures','expr':expr,'guard':guard,'requirement_refs':[req]})
    case={'id':name,'family':family,'stratum':'edit' if edit else 'complex','params':list(params),
          'profile':PROFILE,'R':requirements,'S':obligations,'definitions':definitions,'risk':risk,
          'reference_origin':'authored synthetic policy; formal preflight separate; no independent human-review claim'}
    if edit:
        kind,target,change,expected,message=edit
        case['edit']={'kind':kind,'target':target,'change':change,'expected_affected_sources':expected,'request':message}
    return case


def simple(name,family,params,p,q,text):
    return {'id':name,'family':family,'stratum':'simple','params':params,'profile':PROFILE,
            'R':[{'id':'R1','text':text}], 'S':[
                {'id':'S1','role':'requires','expr':p,'requirement_refs':['R1']},
                {'id':'S2','role':'ensures','expr':q,'requirement_refs':['R1']}],
            'definitions':{},'risk':'basic positive control',
            'reference_origin':'authored synthetic control; no independent human-review claim'}


def build():
    a,b,c,d='level','zone','lock','override'
    access=lambda name,rules,defs=(),edit=None:policy(name,'access',[a,b,c,d],defs,rules,(0,1),risk='例外、重叠优先级和共享权限守卫',edit=edit)
    x,y,z,w='heat','load','sensor','mode'
    device=lambda name,rules,defs=(),edit=None:policy(name,'device',[x,y,z,w],defs,rules,(1,2),risk='嵌套信号、并列边界和回退',edit=edit)
    s,e,f,m='state','event','flag','mode'
    protocol=lambda name,rules,defs=(),edit=None:policy(name,'protocol',[s,e,f,m],defs,rules,(0,1),risk='状态分支和复合事件',edit=edit)
    u,v,t,h='first','second','slot','quota'
    schedule=lambda name,rules,defs=(),edit=None:policy(name,'schedule',[u,v,t,h],defs,rules,(0,2),risk='排序、并列、预算和优先级',edit=edit)
    return [
        simple('control_interval','device',['low','high'],le('low','high'),AND(ge('result','low'),le('result','high')),'上下界有序时，返回值位于闭区间。'),
        simple('control_permission','access',['locked'],OR(eq('locked',0),eq('locked',1)),AND(['implies',eq('locked',0),eq('result',1)],['implies',eq('locked',1),eq('result',0)]),'锁编码为 0 或 1；未锁返回 1，锁定返回 0。'),
        simple('control_state','protocol',['state'],AND(ge('state',0),le('state',3)),eq('result','state'),'输入状态在 0–3；返回同一状态。'),
        simple('control_choice','schedule',['a','b'],True,OR(eq('result','a'),eq('result','b')),'可以返回任一个输入。'),
        access('access_vault',[
            ('锁≥7且覆盖不足2',AND(ge(c,7),le(d,1)),(90,91)),('高等级例外',AND(ge(a,8),ge(d,7)),(30,31)),
            ('授权且区域≥6',AND(REF('trusted'),ge(b,6)),(40,44)),('授权且区域≤5',AND(REF('trusted'),le(b,5)),(50,54))],
            [('trusted',AND(ge(a,4),OR(AND(le(c,3),ge(d,2)),AND(ge(c,4),ge(d,5)))))]),
        access('access_export',[
            ('外部区且覆盖为0',AND(eq(b,9),eq(d,0)),(2,3)),('区7且锁为0',AND(eq(b,7),eq(c,0)),(11,12)),
            ('可读且等级至少6',AND(REF('readable'),ge(a,6)),(21,24)),('可读且等级低于6',AND(REF('readable'),le(a,5)),(31,35))],
            [('readable',OR(AND(le(b,4),le(c,2)),AND(ge(d,3),eq(b,5))))]),
        access('access_delegation',[
            ('覆盖8、锁不超过3或等级9且区域0',OR(AND(eq(d,8),le(c,3)),AND(eq(a,9),eq(b,0))),(63,66)),
            ('委派且资源级别高',AND(REF('delegate'),ge(b,5)),(50,55)),('委派且资源级别低',AND(REF('delegate'),le(b,4)),(41,44)),
            ('入口被锁且无覆盖',AND(ge(c,5),eq(d,0)),(4,6))],[('delegate',AND(ge(a,3),OR(ge(d,4),le(c,1))))]),
        device('device_thermal',[
            ('过热且满载',AND(ge(x,8),ge(y,8)),(70,72)),('低温且传感器为零',AND(le(x,2),eq(z,0)),(5,7)),
            ('运行窗口且模式高',AND(REF('window'),ge(w,5)),(30,39)),('运行窗口且模式低',AND(REF('window'),le(w,4)),(40,49))],
            [('window',AND(ge(x,3),OR(AND(ge(z,2),le(y,6)),AND(eq(z,1),le(y,3)))))]),
        device('device_sensor_fallback',[
            ('传感器为9，或模式0且负载9',OR(eq(z,9),AND(eq(w,0),eq(y,9))),(81,84)),('处于校准且负载大',AND(REF('cal'),ge(y,5)),(60,64)),
            ('处于校准且负载小',AND(REF('cal'),le(y,4)),(50,54)),('高温且人工模式',AND(ge(x,7),eq(w,8)),(21,24))],
            [('cal',OR(AND(le(x,5),ge(z,3)),AND(eq(w,6),le(z,2))))]),
        device('device_pump',[
            ('模式9但读数1',AND(eq(w,9),eq(z,1)),(91,93)),('压力高且温度高',AND(ge(y,8),ge(x,7)),(70,75)),
            ('泵可用且热',AND(REF('ready'),ge(x,5)),(40,44)),('泵可用且冷',AND(REF('ready'),le(x,4)),(30,34))],
            [('ready',AND(ge(z,2),OR(AND(eq(w,4),le(y,4)),AND(ge(w,5),ge(y,4)))))]),
        protocol('protocol_reconnect',[
            ('事件9且尚未完成',AND(eq(e,9),le(s,6)),(70,72)),('已连接且超时标志',AND(eq(s,4),eq(f,8)),(3,5)),
            ('允许握手且模式2',AND(REF('hello'),eq(m,2)),(31,33)),('允许握手且模式非2',AND(REF('hello'),NOT(eq(m,2))),(41,43))],
            [('hello',OR(AND(eq(s,1),eq(e,3)),AND(eq(s,2),ge(f,3))))]),
        protocol('protocol_commit',[
            ('事件8且待提交',AND(eq(e,8),eq(s,3)),(70,72)),('状态为9且模式非0',AND(eq(s,9),ge(m,1)),(10,14)),
            ('事务活跃且标志不小于5',AND(REF('active'),ge(f,5)),(30,32)),('事务活跃且标志小于5',AND(REF('active'),le(f,4)),(40,42))],
            [('active',AND(ge(s,2),OR(AND(le(e,3),ge(m,3)),AND(eq(e,4),le(m,1)))))]),
        protocol('protocol_channel',[
            ('状态 0 且事件 0',AND(eq(s,0),eq(e,0)),(11,12)),('管理事件且锁定',AND(ge(e,7),eq(f,9)),(61,63)),
            ('通道打开且事件7以上',AND(REF('open'),ge(e,7)),(31,34)),('通道打开且事件6以下',AND(REF('open'),le(e,6)),(41,44))],
            [('open',OR(AND(eq(s,2),ge(m,1)),AND(eq(s,3),le(f,4))))]),
        schedule('schedule_fair',[
            ('并列且有预算且奇特槽位2',AND(eq(u,v),ge(h,1),eq(t,2)),(30,32)),('第一优先且可以调度',AND(REF('ok'),['gt',u,v]),(10,13)),
            ('第二优先且可以调度',AND(REF('ok'),['lt',u,v]),(20,23)),('可调度且并列',AND(REF('ok'),eq(u,v)),(40,44))],
            [('ok',OR(AND(ge(h,3),le(t,7)),AND(eq(h,2),eq(t,1))))]),
        schedule('schedule_emergency',[
            ('槽位9且任一队列达到9',AND(eq(t,9),OR(eq(u,9),eq(v,9))),(70,71)),('预算为0且槽位非9',AND(eq(h,0),le(t,8)),(5,7)),
            ('可用窗口且第一队列不小于第二',AND(REF('avail'),ge(u,v)),(21,24)),('可用窗口且第一队列更小',AND(REF('avail'),['lt',u,v]),(31,34))],
            [('avail',AND(ge(h,1),OR(AND(le(t,4),ge(u,2)),AND(ge(t,5),ge(v,2)))))]),
        schedule('schedule_timeslice',[
            ('预算9且槽位0',AND(eq(h,9),eq(t,0)),(81,83)),('空队列',AND(eq(u,0),eq(v,0)),(5,6)),
            ('窗口且预算高',AND(REF('slice'),ge(h,5)),(41,44)),('窗口且预算低',AND(REF('slice'),le(h,4)),(31,34))],
            [('slice',OR(AND(ge(t,4),ge(u,2)),AND(le(t,3),ge(v,3))))]),
        access('edit_shared_access',[
            ('严重锁定',ge(c,8),(81,84)),('授权且区域高',AND(REF('trust'),ge(b,5)),(30,34)),
            ('授权且区域低',AND(REF('trust'),le(b,4)),(40,44)),('低区无覆盖',AND(eq(b,0),eq(d,0)),(13,14))],
            [('trust',AND(ge(a,4),ge(d,2)))],('definition','trust',AND(ge(a,5),ge(d,2)),['S2','S3','S4','S5'],'授权等级下限从4改为5；其他规则含顺序保持。')),
        device('edit_local_heat',[
            ('热保护',ge(x,8),(70,72)),('低负载运转',AND(REF('valid'),le(y,4)),(31,33)),
            ('高负载运转',AND(REF('valid'),ge(y,5)),(41,44)),('维护窗口',eq(w,9),(50,54))],
            [('valid',AND(ge(z,2),le(x,7)))],('leaf','S2',AND(ge('result',31),le('result',34)),['S2'],'只把低负载运转的返回上限从33改为34。')),
        protocol('edit_common_channel',[
            ('紧急关闭',eq(e,9),(90,92)),('正常打开且事件低',AND(REF('channel'),le(e,4)),(20,24)),
            ('备用打开且事件高',AND(REF('backup'),ge(e,5)),(30,34)),('维护事件',eq(m,8),(41,43))],
            [('base',ge(f,2)),('channel',AND(REF('base'),eq(s,2))),('backup',AND(REF('base'),eq(s,3)))],
            ('definition','base',ge(f,3),['S2','S3','S4','S5'],'共同允许标志由至少2改为至少3，影响正常和备用打开。')),
        schedule('edit_input_budget',[
            ('双方并列',eq(u,v),(70,72)),('可调度且第一优先',AND(REF('ok'),['gt',u,v]),(30,34)),
            ('可调度且第二优先',AND(REF('ok'),['lt',u,v]),(40,44)),('槽位7',eq(t,7),(51,54))],
            [('ok',ge(h,2))],('pre','S0',AND(*(ge(p,0) for p in (u,v,t,h)),le(u,9),le(v,9),le(t,9),le(h,8)),
            ['S0','S1','S2','S3','S4','S5'],'只把输入预算编码的合法上限由9改为8；保持所有分支。')),
        access('edit_add_obligation',[
            ('锁定',ge(c,8),(80,84)),('范围授权且区高',AND(REF('enabled'),ge(b,6)),(40,46)),
            ('范围授权且区低',AND(REF('enabled'),le(b,5)),(30,34)),('维护标志',eq(d,9),(21,25))],
            [('enabled',AND(ge(a,4),le(c,6)))],('add','S6',{'guard':'branch2','expr':NOT(eq('result',43))},['S6'],'对第2分支新增返回值不得为43，保留所有原有范围。')),
        device('edit_unrelated_window',[
            ('紧急模式',eq(w,9),(88,91)),('校准且冷',AND(REF('stable'),le(x,4)),(11,15)),
            ('校准且热',AND(REF('stable'),ge(x,5)),(21,25)),('负载9且温度9',AND(eq(y,9),eq(x,9)),(35,38))],
            [('stable',AND(le(y,6),ge(z,2)))],('leaf','S4',AND(ge('result',36),le('result',38)),['S4'],'仅第4条返回下限由35改为36，与校准组无关。')),
        protocol('edit_branch_priority',[
            ('撤销信号',AND(eq(e,8),ge(f,1)),(70,72)),('双因素握手且模式低',AND(REF('handshake'),le(m,3)),(10,14)),
            ('双因素握手且模式高',AND(REF('handshake'),ge(m,4)),(20,24)),('保活事件',eq(e,5),(30,33))],
            [('handshake',OR(AND(eq(s,1),ge(f,3)),AND(eq(s,2),eq(e,1))))],
            ('definition','handshake',OR(AND(eq(s,1),ge(f,4)),AND(eq(s,2),eq(e,1))),['S2','S3','S4','S5'],'第一种握手标志门槛从3升到4；仍按原顺序判定。')),
        schedule('edit_idle_fallback',[
            ('急件有预算',AND(eq(t,9),ge(h,1)),(70,74)),('仲裁开放且第一不小于第二',AND(REF('arb'),ge(u,v)),(40,45)),
            ('仲裁开放且第一小于第二',AND(REF('arb'),['lt',u,v]),(50,54)),('槽位2且预算0',AND(eq(t,2),eq(h,0)),(31,34))],
            [('arb',AND(ge(h,3),OR(ge(u,2),ge(v,2))))],('leaf','S5',AND(ge('result',1),le('result',3)),['S5'],'仅最终回退区间从0–2改为1–3。')),
    ]


def edited(case):
    next_case=deepcopy(case); e=next_case.pop('edit'); k,t,v=e['kind'],e['target'],e['change']
    next_case['R'].append({'id':'R_EDIT','text':e['request']})
    if k=='definition': next_case['definitions'][t]=v
    elif k=='add': next_case['S'].append({'id':t,'role':'ensures',**v,'requirement_refs':['R_EDIT']})
    else:
        node=next(s for s in next_case['S'] if s['id']==t)
        node['expr']=v; node['requirement_refs'].append('R_EDIT')
    return next_case


def definitions(case):
    done={}; visiting=set()
    def read(name):
        from .semantics import Invalid
        if name not in case['definitions']: raise Invalid('UNKNOWN_SOURCE_GUARD',name)
        if name in visiting: raise Invalid('SOURCE_GUARD_CYCLE',name)
        if name not in done:
            visiting.add(name); done[name]=expand(case['definitions'][name],symbols(case),'requires',read); visiting.remove(name)
        return done[name]
    for n in case['definitions']: read(n)
    return done


def reference(case):
    defs=definitions(case); names=symbols(case); out=[]
    for s in case['S']:
        expr=expand(s['expr'],names,s['role'])
        if 'guard' in s: expr=['implies',defs[s['guard']],expr]
        out.append({'id':s['id'],'role':s['role'],'expr':expr})
    return out


def metrics(case):
    from collections import Counter
    def depth(x): return 1+max(map(depth,x[1:]),default=0) if isinstance(x,list) else 0
    def refs(x):
        if isinstance(x,list):
            if x[0]=='ref': yield x[1]
            else:
                for t in x[1:]: yield from refs(t)
    uses=Counter([s['guard'] for s in case['S'] if 'guard' in s]+[r for e in case['definitions'].values() for r in refs(e)])
    return {'source_obligations':len(case['S']), 'atomic_post_obligations':sum(len(s['expr'])-1 if isinstance(s['expr'],list) and s['expr'][0]=='and' else 1 for s in case['S'] if s['role']=='ensures'),
            'guard_definitions':len(case['definitions']),'shared_guard_definitions':sum(v>1 for v in uses.values()),
            'max_guard_references':max(uses.values(),default=0),'ast_depth':max(depth(s['expr']) for s in reference(case)),
            'reference_sha256':digest(case)}
