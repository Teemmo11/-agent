# 三层调用的风扇控制

`fan_command` 根据模式决定关闭、正常运转或加速。正常模式把原始请求交给
`target_speed`。加速模式把限速值用作请求和上限。`target_speed` 再调用
`limit_speed`，它根据路径传入固定最低转速 20 或原始请求。

调用图包含三个函数和四处直接调用点。同一个被调用函数接收不同实参，
且每处调用有自己的分支条件。规格生成按调用者到被调用者的顺序处理，
保存每处调用的条件、实参和传递的期望。调用条件来自源码的词法结构。

## 复现

在 WSL 的项目目录运行以下命令。固定规格保留每处调用点的期望，验证使用真实工具。

```bash
python -m spec_agent run \
  --source ./examples/nested_fan/program.c \
  --requirements ./examples/nested_fan/requirements.md \
  --llm-fixture ./examples/nested_fan/llm_fixture.json \
  --branch hoare --output ./runs/nested-fan \
  --ui --show-pq --ui-no-open
```

打开终端打印的监控地址观察三个函数的 P 和 Q。验证结束后按 Ctrl+C
关闭监控。将终端 `Result:` 指向的 `result.json` 的所在目录填入以下命令。
第一阶段出现未决属性时也可评估，只要父运行的工件通过完整性检查。

```bash
RUN_DIR=./runs/nested-fan/实际运行目录名
python -m spec_agent evaluate --run "$RUN_DIR" \
  --strength-cases ./examples/nested_fan/strength_cases.json \
  --output ./evaluations/nested-fan
```

样例集从需求独立构造，包含 6 个合法输入、6 个域外输入和 11 个错误输出。
第一阶段的证据目录可查看 `analysis/callsites.json`、`analysis/functions_with_expectations.json`、
`specs/formal/` 和逐属性模型。第二阶段报告按函数列出全部样例及其查询。
`FIXTURE_LLM_REAL_TOOLS` 的记录提供任务编排和模型检查证据。

## 在线生成与上下文核对

```bash
python -m spec_agent run \
  --source ./examples/nested_fan/program.c \
  --requirements ./examples/nested_fan/requirements.md \
  --branch hoare --require-real --output ./runs/nested-fan-live
```

控制器先从源码抽取调用点、实参和词法条件。模型生成当前函数的契约和每个调用点的期望，
后续函数的请求携带这些期望。按序查看 `events.jsonl` 中的 `expectation.propagated`
和下一次 `llm.request.started`，以相同 `expectation_id` 核对传递链。
同次运行的 `generation/llm/functions/<函数ID>/prompt.json` 保存发送给该函数的上下文，
`specs/semantic/` 保存通过结构和引用检查的模型输出。完整的在线结果可用同一个
`strength_cases.json` 评估，评估命令可加 `--require-real`。

故障对照可将加速分支的 `target_speed(limit, limit)` 改成
`target_speed(requested, limit)`。保持源码文件名 `program.c` 与调用点行列，
便于复用同一份固定规约。此时输入 `requested=0, limit=12, mode=2` 会返回 0，
违反入口函数的加速后置条件。下层两个函数的行为保持原样。
