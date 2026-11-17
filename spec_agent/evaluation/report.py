"""Readable report with evidence level and limitations beside each claim."""


def markdown(report):
    if report['assessment_mode'].get('profile')=='strength':
        return strength_markdown(report)
    lines=['# 规约评估报告','',f"评估编号：{report['evaluation_id']}",
           f"执行状态：{report['execution_status']}；停止原因：{report['stop_reason']}",'',
           '验证结论与规约质量分别记录；本报告不修改第一阶段的验证结果。','',
           '## 评估维度','', '| 维度 | 状态 |','| --- | --- |']
    for name,value in report['dimensions'].items():lines.append(f"| {name} | {value['status']} |")
    lines.extend(['','## 问题及证据',''])
    if not report['findings']:lines.append('已执行检查没有产生问题；未执行或未决维度见上表。')
    for f in report['findings']:
        # Preserve untrusted strings as single escaped lines, not Markdown commands.
        explain=f['explanation'].replace('\n',' ').replace('<','&lt;').replace('>','&gt;')
        lines.extend([f"- {f['severity']} · {f['code']} · {f['spec_id']} · {f['evidence_kind']}/{f['claim_status']}",
                      f"  {explain}",f"  证据：{', '.join(f['evidence_ids'])}"])
    lines.extend(['','## 限制','', '- 自然语言对齐、覆盖与可用性判断不属于形式证明。',
                  '- 存在满足赋值不等于每个输入都有合法输出。',
                  '- 未提供经校验的反例轨迹时，不生成具体输入见证。',
                  '- 静态安全检查与业务需求覆盖分别记录。','',
                  '## 错误及未完成项',''])
    for err in report['errors']:lines.append('- '+str(err).replace('\n',' '))
    return '\n'.join(lines)+'\n'


def strength_markdown(report):
    lines = ['# 规约表达力评估', '', f"评估编号 {report['evaluation_id']}",
             f"执行状态 `{report['execution_status']}` · `{report['stop_reason']}`", '',
             'PreComp 衡量 P 排除已标注域外输入的比例。PostComp 衡量契约排除已标注错误输出的比例。',
             '比例以各指标已判定的样例数为分母。样例标签来自输入文件，结论适用于这组样例。', '']
    if 'strength' in report:
        strength = report['strength']
        if 'PreCorr' in strength['metrics']:
            lines += ['PreCorr 衡量生成的 P 保留已标注合法输入的比例。', '']
        lines += ['| 指标 | 计数 / 已判定 | 未决 | 分数 | 状态 |', '| --- | --- | --- | --- | --- |']
        for metric, row in strength['metrics'].items():
            score = '—' if row['score'] is None else f"{row['score']:.1%}"
            count, label = (row['retained'], '保留') if metric == 'PreCorr' else (row['rejected'], '排除')
            lines.append(f"| {metric} | {label} {count} / {row['decided']} | {row['undecided']} | {score} | {row['status']} |")
        for function in strength['functions']:
            lines += ['', f"## {function['function']}", '',
                      '| 样例 | 需求 | 指标 | 结果 | 查询 |', '| --- | --- | --- | --- | --- |']
            for case in function['cases']:
                query = case['query_id'] or function['feasibility_query']
                link = f'[{query}](queries/{query}/query.json)' if query else '—'
                req = str(case['requirement']).replace('|', '\\|').replace('\n', ' ').replace('<', '&lt;')
                lines.append(f"| {case['id']} | {req} | {case['metric']} | {case['outcome']} | {link} |")
    if report['errors']:
        lines += ['', '## 执行错误', '']
        lines.extend('- ' + str(error).replace('\n', ' ').replace('<', '&lt;') for error in report['errors'])
    return '\n'.join(lines)+'\n'
