'use strict';
const $=id=>document.getElementById(id);
// All run-provided strings are assigned as text; never interpreted as markup.
const labels={PENDING:'等待',ACTIVE:'进行中',RUNNING:'执行中',DONE:'已结束',GENERATED:'已生成',LLM_RUNNING:'等待模型响应',ERROR:'错误',TIMED_OUT:'超时',SKIPPED:'未启用',HOLDS:'成立',VIOLATED:'违反',UNKNOWN:'未决',VACUOUS:'空真',FEASIBLE:'前提可行',INFEASIBLE:'前提不可行',NOT_RUN:'未运行',OBSERVING:'尚无结束记录',COMPLETED:'流程已完成',COMPLETED_WITH_ERRORS:'完成但有错误',FAILED:'运行失败',CANCELLED:'已取消'};
const stages={CREATED:'准备运行',INPUT_SNAPSHOTTED:'输入快照',PREFLIGHT:'工具预检',ANALYZING:'程序分析',GENERATING:'规格生成',NORMALIZING:'候选整理',FORMALIZING:'规约形式化',VERIFYING:'模型验证',SUMMARIZING:'结果汇总',FINISHED:'流程已结束',PENDING:'等待',HARNESS_READY:'验证程序就绪',MODEL_BUILDING:'C2Btor 建模',MODEL_CONTRACT_CHECKING:'检查模型契约',MODEL_VALIDATING:'catbtor 校验',MODEL_BOUNDARY_VERIFYING:'验证模型边界',CONCLUSION_GATE:'结论证据检查',DONE:'已结束'};
const eventNames={'run.started':'运行开始','input.snapshotted':'输入快照已保存','analysis.partitioned':'完成函数与调用关系分析','llm.request.started':'向 LLM 请求规格','llm.response.received':'收到 LLM 响应','spec.accepted':'规格候选通过结构校验','llm.generation.failed':'规格生成失败','formalization.accepted':'规约形式化完成','formalization.rejected':'规约形式化被拒绝','formalization.skipped':'仅生成，跳过形式化','harness.emitted':'生成独立验证程序','static.discovery.started':'开始发现静态属性','static.discovery.finished':'静态属性发现结束','verification.started':'开始验证属性','verification.attributed':'目标 bad 归属已确认','verification.finished':'属性验证结束','precondition.classified':'P 可行性已分类','contract.concluded':'函数契约结论已汇总','run.finished':'流程结束','run.failed':'运行失败','run.cancelled':'运行已取消','tool.started':'工具开始执行','tool.finished':'工具执行结束','tool.failed':'工具执行异常','generation.finished':'规格生成结束','expectation.propagated':'向被调用函数传递期望'};
let selected=null,snapshot=null,paused=false,lastSignature='',catalogSignature='',disconnected=false;
function node(tag,text='',cls=''){const e=document.createElement(tag);if(text!==null)e.textContent=text;if(cls)e.className=cls;return e;}
labels.NONZERO_EXIT='非零退出';
function tone(v){return ['HOLDS','FEASIBLE','DONE','GENERATED','COMPLETED'].includes(v)?'good':['VIOLATED','ERROR','FAILED','COMPLETED_WITH_ERRORS','TIMED_OUT'].includes(v)?'error':['INFEASIBLE','VACUOUS','UNKNOWN','CANCELLED','NONZERO_EXIT'].includes(v)?'warning':['RUNNING','ACTIVE','LLM_RUNNING'].includes(v)?'active':'';}
function badge(value,text){return node('span',text||labels[value]||value||'等待','badge '+tone(value));}
function duration(seconds){if(!Number.isFinite(seconds))return '—';seconds=Math.max(0,Math.floor(seconds));return (seconds>=3600?String(Math.floor(seconds/3600)).padStart(2,'0')+':':'')+String(Math.floor(seconds/60)%60).padStart(2,'0')+':'+String(seconds%60).padStart(2,'0');}
function activeTool(){return snapshot?.status==='OBSERVING'?snapshot.tools.filter(t=>t.status==='RUNNING').at(-1):null;}
function toolName(t){let argv=t.argv||[],name=String(argv[0]||'工具').replaceAll('\\','/').split('/').at(-1);return name==='cbmc'?'CBMC / C2Btor':name==='c2btor'?'C2Btor':name==='catbtor'?'catbtor':name==='ric3'?'rIC3':name;}
function showDetail(title,value,tools=[]){$('detail-title').textContent=title;const body=$('detail-body');body.replaceChildren();if(tools.length){const actions=node('div',null,'detail-tools');for(const tool of tools){for(const side of ['stdout','stderr'])if(tool[side]){const b=node('button',toolName(tool)+' '+side);b.type='button';b.addEventListener('click',()=>showLog(tool[side]));actions.append(b);}}body.append(actions);}body.append(node('pre',typeof value==='string'?value:JSON.stringify(value,null,2)));if(!$('detail-dialog').open)$('detail-dialog').showModal();}
async function showLog(path){try{const value=await request('/api/run/'+selected+'/log?path='+encodeURIComponent(path));showDetail((value.truncated?'末尾 32 KiB · ':'')+value.path,value.text||'（工具没有输出）');}catch(e){showDetail('日志不可用',e.message);}}
async function request(path){const r=await fetch(path,{cache:'no-store'});if(!r.ok)throw new Error('无法读取观测数据（HTTP '+r.status+'）');return r.json();}
function choose(key){selected=key;lastSignature='';location.hash='run='+key;$('run-select').value=key;}
function renderCatalog(data){const signature=JSON.stringify(data.runs);if(signature!==catalogSignature){catalogSignature=signature;const list=$('run-list'),select=$('run-select');list.replaceChildren();select.replaceChildren();if(!data.runs.length)select.append(new Option('等待新的第一阶段运行…',''));for(const row of data.runs){select.append(new Option(row.run_id,row.key));if(list.children.length<10){const b=node('button',row.run_id,'run-button'+(row.key===selected?' active':''));b.type='button';b.dataset.run=row.key;b.append(node('small',labels[row.status]||row.status));b.addEventListener('click',()=>choose(row.key));list.append(b);}}}if(!selected){const hash=new URLSearchParams(location.hash.slice(1)).get('run');selected=data.runs.some(r=>r.key===hash)?hash:data.selected||data.runs[0]?.key||null;}if(selected)$('run-select').value=selected;for(const b of $('run-list').querySelectorAll('button'))b.classList.toggle('active',b.dataset.run===selected);}
function renderTasks(){if(!snapshot)return;const list=$('tasks');list.replaceChildren();const filter=$('branch-filter').value,search=$('task-search').value.toLowerCase();const props=snapshot.properties.filter(p=>(filter==='all'||p.branch===filter)&&(p.id+' '+(p.function||p.function_id||'')).toLowerCase().includes(search));for(const p of props){const row=node('div',null,'task-row');row.setAttribute('role','row');const name=node('div',p.kind==='PRECONDITION_FEASIBILITY'?'P · 前提可行性':p.kind==='CBMC_STATIC_PROPERTY'?'静态 · '+p.id:(p.id.split('.').at(-1)||p.id),'task-name');name.append(node('small',(p.function||snapshot.functions.find(f=>f.id===p.function_id)?.name||p.spec_id||'')+' · '+p.id));row.append(name,node('span',stages[p.stage]||p.stage||labels[p.status]||p.status,'task-stage'),node('span',p.raw_result||'—','task-raw mono'));const verdict=node('div',null,'task-verdict');verdict.append(badge(p.kind==='PRECONDITION_FEASIBILITY'?(p.classification||p.verdict):(p.verdict||p.status)));row.append(verdict);const more=node('button','↗','icon-button task-more');more.type='button';more.setAttribute('aria-label','查看 '+p.id+' 的验证详情');more.addEventListener('click',()=>showDetail(p.id,p,snapshot.tools.filter(t=>t.property_id===p.id)));row.append(more);list.append(row);}if(!props.length)list.append(node('div',snapshot.generate_only?'仅生成候选；本次不执行 P/Q 验证。':'尚无匹配任务。验证程序生成后，P、各条 Q 与静态属性会在此独立显示。','empty'));}

const loopStepByStage = {
  PENDING: 0, HARNESS_READY: 0,
  MODEL_BUILDING: 1,
  MODEL_CONTRACT_CHECKING: 2, MODEL_VALIDATING: 2,
  VERIFYING: 3, MODEL_BOUNDARY_VERIFYING: 3,
  CONCLUSION_GATE: 4, DONE: 4,
};

function renderLoop(run) {
  const rounds = run.generate_only ? [] : run.properties;
  const names = new Map(run.functions.map(f => [f.id, f.name]));
  const label = property => {
    if (property.branch === 'static') return '静态检查 · ' + property.id;
    const name = property.function || names.get(property.function_id) || '';
    const clause = property.kind === 'PRECONDITION_FEASIBILITY' ? 'P' : property.id.split('.').at(-1);
    return [name, clause].filter(Boolean).join(' · ');
  };

  const live = run.status === 'OBSERVING' && run.stage === 'VERIFYING' && !run.generate_only;
  const current = live ? rounds.findLast(p => p.status === 'RUNNING' || p.status === 'PENDING') : null;
  const step = current ? loopStepByStage[current.stage] : undefined;
  const completed = rounds.filter(p => p.status === 'DONE').length;
  $('loop-count').textContent = run.generate_only ? '仅生成规格' : `已记录 ${completed} 轮结论`;

  let caption = '规格准备好后进入验证循环';
  if (run.generate_only) caption = '本次仅生成规格，跳过验证循环';
  else if (current) caption = `第 ${rounds.indexOf(current) + 1} 轮 · ${label(current)} · 进行中`;
  else if (live) caption = '等待下一条属性或结果汇总';
  else if (run.status !== 'OBSERVING') caption = rounds.length ? labels[run.status] : '本次没有验证轮次记录';
  else if (run.stage === 'SUMMARIZING') caption = '验证循环已结束，正在汇总结果';
  const currentLabel = $('loop-current');
  if (currentLabel.textContent !== caption) {
    currentLabel.textContent = caption;
    if (current) animateAdvance(currentLabel);
  }

  [...$('loop-steps').children].forEach((item, index) => {
    const active = index === step;
    const changed = active && item.getAttribute('aria-current') !== 'step';
    if (active) item.setAttribute('aria-current', 'step');
    else item.removeAttribute('aria-current');
    item.classList.toggle('passed', step !== undefined && index < step);
    if (changed) animateAdvance(item.querySelector('.loop-step-number'));
  });

  const list = $('loop-rounds');
  list.replaceChildren();
  list.hidden = rounds.length === 0;
  const start = Math.max(0, rounds.length - 8);
  if (start) list.append(node('li', `前 ${start} 轮见下方属性列表`, 'muted'));
  rounds.slice(start).forEach((property, index) => {
    const active = property === current;
    const row = node('li', null, active ? 'loop-round active' : 'loop-round');
    let outcome = property.verdict;
    if (property.kind === 'PRECONDITION_FEASIBILITY' && ['HOLDS', 'VIOLATED'].includes(outcome)) {
      outcome = property.classification;
    }
    const state = active ? 'RUNNING' : outcome || property.status;
    const missingEnd = !live && property.status === 'RUNNING';
    row.append(
      node('span', `第 ${start + index + 1} 轮`, 'loop-round-number'),
      node('strong', label(property)),
      badge(state, missingEnd ? '缺少结束记录' : undefined),
    );
    list.append(row);
  });
}

function renderWorkflow(run) {
  const pipeline = $('pipeline');
  const stageIds = run.stages.map(stage => stage.id).join(',');
  if (pipeline.dataset.stages !== stageIds) {
    pipeline.dataset.stages = stageIds;
    pipeline.replaceChildren(...run.stages.map((stage, index) => {
      const item = node('li', null, 'stage');
      item.append(node('span', String(index + 1), 'stage-icon'),
        node('span', stage.label, 'stage-label'), node('small', '', 'stage-status'));
      return item;
    }));
  }
  let finished = 0;
  run.stages.forEach((stage, index) => {
    const item = pipeline.children[index];
    const previous = item.dataset.state;
    const caption = stage.status === 'SKIPPED' ? '无需执行' : labels[stage.status] || stage.status;
    item.dataset.state = stage.status;
    if (stage.status === 'ACTIVE') item.setAttribute('aria-current', 'step');
    else item.removeAttribute('aria-current');
    item.querySelector('.stage-icon').textContent = {DONE: '✓', ERROR: '!', SKIPPED: '–'}[stage.status] || String(index + 1);
    item.querySelector('.stage-status').textContent = caption;
    if (stage.status === 'DONE' || stage.status === 'SKIPPED') finished++;
    if (previous && previous !== stage.status && stage.status === 'ACTIVE') animateAdvance(item.querySelector('.stage-icon'));
  });
  $('flow-count').textContent = `${finished} / ${run.stages.length} 个阶段已处理`;
}

function animateAdvance(element) {
  if (paused || matchMedia('(prefers-reduced-motion: reduce)').matches) return;
  element.getAnimations().forEach(animation => animation.cancel());
  element.animate(
    [{opacity: 0.55, transform: 'translateY(5px)'}, {opacity: 1, transform: 'translateY(0)'}],
    {duration: 300, easing: 'ease-out'},
  );
}

function renderConditions(run) {
  const specs = run.specifications;
  const panel = $('pq-heading').closest('section');
  panel.hidden = !specs;
  $('pq-nav').hidden = !specs;
  if (!specs) return;

  const select = $('pq-select');
  const choices = JSON.stringify(specs.map(spec => [spec.id, spec.function]));
  if (select.dataset.choices !== choices) {
    const previous = select.value;
    select.replaceChildren(...specs.map(spec => new Option(spec.function, spec.id)));
    if (specs.some(spec => spec.id === previous)) select.value = previous;
    select.dataset.choices = choices;
  }
  select.hidden = specs.length < 2;
  const spec = specs.find(item => item.id === select.value);
  const content = $('pq-conditions');
  content.replaceChildren();
  if (!spec) {
    $('pq-source').textContent = '';
    content.append(node('p', run.branch === 'static' ? '本次运行仅包含静态安全属性。'
      : run.status === 'OBSERVING' ? '等待 Hoare 规格生成。' : '本次运行没有可读取的 Hoare 规格。', 'pq-empty'));
    return;
  }
  $('pq-source').textContent = `${spec.function} · ${spec.source === 'FORMAL' ? '形式化规格' : '语义候选'}`;
  const conditions = [
    {id: 'P', expression: spec.precondition, label: '前置条件'},
    ...spec.postconditions.map(clause => ({...clause, label: '后置条件'})),
  ];
  for (const condition of conditions) {
    const item = node('div', null, 'condition');
    const heading = node('div', null, 'condition-heading');
    heading.append(node('span', condition.id, 'condition-id'), node('span', condition.label));
    const expression = node('div', null, 'condition-expression');
    expression.append(node('code', condition.expression));
    if (condition.guard) {
      const guard = node('small', '适用条件 ');
      guard.append(node('code', condition.guard));
      expression.append(guard);
    }
    item.append(heading, expression);
    content.append(item);
  }
}

function renderBranches(run) {
  for (const key of ['hoare', 'static']) {
    const branch = run.branches[key];
    $(key + '-status').replaceWith(Object.assign(badge(branch.status), {id: key + '-status'}));
    $(key + '-detail').textContent = branch.status === 'SKIPPED' ? '本次未启用此分支。'
      : key === 'hoare' ? `已生成 ${branch.candidates} 份函数规格候选。`
      : `已发现 ${branch.candidates} 个静态安全属性。`;
  }
  const functions = $('functions');
  const contracts = $('contracts');
  const safety = $('safety-properties');
  functions.replaceChildren();
  contracts.replaceChildren();
  safety.replaceChildren();
  const chip = (name, status) => {
    const item = node('span', null, 'function-chip');
    item.append(node('span', name), badge(status));
    return item;
  };
  if (run.branches.hoare.status !== 'SKIPPED') {
    for (const f of run.functions) functions.append(chip(f.name, f.status));
  }
  for (const c of run.contracts) contracts.append(chip(c.function + ' 契约', c.verdict));
  if (!run.contracts.length && run.branches.hoare.status !== 'SKIPPED') {
    contracts.append(node('span', '契约结论将在 P 与各条 Q 检查后汇总。', 'muted'));
  }
  for (const p of run.properties.filter(property => property.branch === 'static')) {
    safety.append(chip(p.id, p.verdict || p.status));
  }
}

function renderTools(run) {
  const tools = $('tools');
  tools.replaceChildren();
  const running = run.tools.filter(tool => tool.status === 'RUNNING');
  $('tool-count').textContent = (run.status === 'OBSERVING' ? running.length : 0) + ' 个进行中';
  for (const tool of [...run.tools].reverse().slice(0, 10)) {
    const row = node('div', null, 'tool-row');
    const hasEnded = run.status !== 'OBSERVING';
    row.append(node('strong', toolName(tool)), badge(tool.status,
      tool.status === 'RUNNING' && hasEnded ? '缺少结束事件' : undefined));
    row.append(node('small', tool.property_id || tool.branch || '工具预检'));
    const actions = node('div', null, 'tool-actions');
    const timer = node('small', duration(tool.duration_seconds ?? (hasEnded ? null : tool.age_seconds)), 'mono');
    if (tool.status === 'RUNNING' && !hasEnded) {
      timer.dataset.toolTime = tool.started_at;
      timer.dataset.timeout = tool.timeout || '';
    }
    actions.append(timer);
    for (const side of ['stdout', 'stderr']) {
      if (!tool[side]) continue;
      const button = node('button', side);
      button.type = 'button';
      button.addEventListener('click', () => showLog(tool[side]));
      actions.append(button);
    }
    row.append(actions);
    tools.append(row);
  }
  if (!run.tools.length) tools.append(node('div', '等待工具执行记录。', 'empty'));
}

function renderEvents(run) {
  const events = $('events');
  events.replaceChildren();
  for (const event of [...run.events].reverse().slice(0, 70)) {
    const item = node('li');
    const name = eventNames[event.event] || event.event;
    const button = node('button', null, 'event-button');
    const summary = node('div');
    summary.append(node('strong', name), node('small',
      event.context?.property_id || event.context?.function_id || event.details?.state || event.event));
    button.type = 'button';
    const time = new Date(event.timestamp).toLocaleTimeString('zh-CN', {hour12: false});
    const tone = {ERROR: 'error', WARNING: 'warning'}[event.level] || '';
    button.append(node('time', time), summary, node('span', null, 'event-dot ' + tone));
    button.addEventListener('click', () => showDetail(name, event));
    item.append(button);
    events.append(item);
  }
  if (!run.events.length) events.append(node('li', '等待结构化事件。', 'empty'));
}

function render(run) {
  snapshot = run;
  $('run-title').textContent = run.source_names.join(' · ') || run.run_id;
  $('run-subtitle').textContent = run.run_id;
  $('run-subtitle').title = run.directory;
  const mode = {REAL: '真实模式', FIXTURE_LLM_REAL_TOOLS: '固定规格 / 真实工具', MOCK_ALL: '模拟工具（非证明）'};
  $('run-badges').replaceChildren(badge(run.status,
    run.status === 'OBSERVING' && run.started_at ? '正在观测' : undefined), badge(run.mode, mode[run.mode]));
  const warnings = [...run.warnings];
  if (run.catching_up) warnings.unshift('正在增量读取历史事件…');
  $('notice').hidden = !warnings.length;
  $('notice').textContent = warnings.join('\n');
  $('task-count').textContent = run.properties.filter(p => p.status === 'DONE').length + ' / ' + run.properties.length;
  const qs = run.properties.filter(p => p.kind !== 'PRECONDITION_FEASIBILITY');
  $('verdict-count').textContent = `成立 ${qs.filter(p => p.verdict === 'HOLDS').length} · 违反 ${qs.filter(p => p.verdict === 'VIOLATED').length} · 未决/错误 ${qs.filter(p => ['UNKNOWN', 'ERROR'].includes(p.verdict)).length}`;
  renderWorkflow(run);
  renderLoop(run);
  renderConditions(run);
  renderBranches(run);
  renderTasks();
  renderTools(run);
  renderEvents(run);
  const announcement = (labels[run.status] || run.status) + '，当前阶段 ' + (stages[run.stage] || run.stage);
  if ($('announcer').textContent !== announcement) $('announcer').textContent = announcement;
  tick();
}
function tick(){
if(!snapshot||paused)return;
const s=snapshot,t=activeTool(),running=s.status==='OBSERVING';
$('current-step').textContent=t?toolName(t)+' 执行中':running?(stages[s.stage]||s.stage):(labels[s.status]||s.status);
$('current-detail').textContent=t?(t.property_id||t.branch||'预检')+' · 以工具完成事件为准':s.generate_only?'仅生成候选，不执行正式属性验证。':running?'等待新的阶段或工具事件':'各项验证结论见任务与函数契约。';
const elapsed=running&&s.started_at?(Date.now()-Date.parse(s.started_at))/1000:(s.elapsed_ms||0)/1000;$('elapsed').textContent=duration(elapsed);
const age=s.last_event_at?Math.max(0,Math.floor((Date.now()-Date.parse(s.last_event_at))/1000)):null;
$('last-activity').textContent=age===null?'尚无事件':!running?'结束于 '+new Date(s.last_event_at).toLocaleTimeString('zh-CN',{hour12:false}):age<2?'刚刚收到事件':`最近事件 ${age} 秒前`;
$('tools').querySelectorAll('[data-tool-time]').forEach(e=>{const seconds=(Date.now()-Date.parse(e.dataset.toolTime))/1000;e.textContent=duration(seconds)+(e.dataset.timeout?' / '+e.dataset.timeout+'s 上限':'');});
}
async function poll() {
  try {
    if (paused) return;
    const catalog = await request('/api/runs');
    if (paused) return;
    renderCatalog(catalog);
    const key = selected;
    if (key) {
      const run = await request('/api/run/' + key);
      if (paused || key !== selected) return;
      const signature = JSON.stringify([key, run.last_event_at, run.status, run.warnings, run.properties.length,
        run.logging, run.catching_up, run.specifications]);
      if (signature !== lastSignature || disconnected) {
        lastSignature = signature;
        render(run);
      }
    }
    $('connection').textContent = '本地连接正常';
    $('connection').className = 'connection online';
    disconnected = false;
  } catch (error) {
    if (paused) return;
    $('connection').textContent = '连接已断开';
    $('connection').className = 'connection offline';
    $('notice').hidden = false;
    $('notice').textContent = '监控服务连接中断。页面保留最后一次收到的进度。';
    disconnected = true;
  } finally {
    setTimeout(poll, 1000);
  }
}

$('run-select').addEventListener('change', event => {
  if (event.target.value) choose(event.target.value);
});
$('pq-select').addEventListener('change', () => {
  if (snapshot) renderConditions(snapshot);
});
$('branch-filter').addEventListener('change', renderTasks);
$('task-search').addEventListener('input', renderTasks);
$('pause').addEventListener('click', () => {
  paused = !paused;
  document.body.classList.toggle('is-paused', paused);
  $('pause').textContent = paused ? '继续刷新' : '暂停刷新';
  $('pause').setAttribute('aria-pressed', String(paused));
  $('connection').textContent = paused ? '刷新已暂停' : '正在连接';
  $('connection').className = 'connection';
});
$('close-detail').addEventListener('click', () => $('detail-dialog').close());
setInterval(tick, 500);
poll();
