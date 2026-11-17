# SpecAgent · C 程序规约生成与验证

SpecAgent 从 C 源码和自然语言需求生成函数级 Hoare 规约 `{P} f {Q}`，并对程序执行独立的静态安全检查。控制器负责调度、表达式校验、工具调用和证据归档。LLM 负责提出语义规约和调用点期望，验证结论由模型检查与证据校验产生。

## Agent 框架

```mermaid
flowchart TD
    IN["C 源码与自然语言需求"] --> PRE["工具预检与输入快照"]
    PRE --> AST["AST 分析：函数、调用关系、实参与分支条件"]
    AST --> H["Hoare 分支：LLM 逐函数生成 P 和 Q"]
    AST --> S["静态分支：选定源码入口"]
    H --> L["把调用点期望传给后续函数"]
    L -->|还有函数| H
    L -->|生成完成| F["校验表达式，生成 P 与每条 Q 的 harness"]
    S --> G["C2Btor 解析源码并自动插入安全断言"]
    F --> V["C2Btor 生成 BTOR2 模型与源码映射"]
    G --> V
    V --> M["catbtor 校验，按源码映射定位唯一 bad"]
    M --> R["rIC3 检查 bad 可达性"]
    R --> J["记录属性结论与证据"]
    J -->|下一条属性| V
    J -->|任务结束| O["第一阶段结果与日志"]
    O -->|显式执行 evaluate| E["第二阶段：规约质量评估与独立报告"]
    O -.-> UI["浏览器监控：流程、验证循环、P/Q、工具事件"]
```

- **Hoare 分支**按调用者到被调函数的顺序生成规约。P 是允许的输入条件，Q 是在这些条件下函数正常返回时需要满足的性质。P 的可行性独立检查。P 不可行时，契约结论为 `VACUOUS`，即使各条 Q 的失败节点都不可达。
- **静态分支**由 C2Btor 按内置规则插入数组边界、指针、除零和有符号溢出等安全断言。Agent 的 AST 结果可帮助选择入口，插桩使用 C2Btor 自己的带类型程序表示。
- **结果判定**中，P 的探针返回 SAT 表示存在满足 P 的输入。Q 或安全断言的 `bad` 返回 SAT 表示存在违反条件的可达路径，UNSAT 表示该失败状态在当前模型中不可达。工具故障或证据缺失时保留错误或未决状态。
- **规约评估**由 `evaluate` 单独启动，以同一运行的快照为依据写入独立目录。强度模式检查合法输入保留率（PreCorr）、域外输入排除率（PreComp）、错误输出排除率（PostComp）。样例标签独立提供，错误输出查询使用独立返回值，未决项单独报告。

## 复现环境

建议在 Linux 或 Ubuntu WSL 中运行下列 Bash 命令。Agent 需要 Python 3.11+ 和 [pycparser](https://github.com/eliben/pycparser)。前端原生 HTML、CSS、JavaScript 随 Python 包安装，由标准库提供本地 HTTP 服务。

```bash
git clone https://github.com/Teemmo11/-agent.git spec-agent
cd spec-agent
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
cp .env.example .env
```

Ubuntu 的 Python 环境可安装 `python3` 和 `python3-venv`。按下表的公开文档在仓库外安装验证工具。源码构建通常需要 C/C++ 编译工具链，C2Btor 还需要 CMake、Flex、Bison、Perl 和 patch，rIC3 需要 Rust/Cargo 及其上游说明列出的构建依赖。

| 工具 | 公开源码与构建说明 | 集成要求 |
| --- | --- | --- |
| C2Btor | [westtide/C2Btor](https://github.com/westtide/c2btor) · [验收使用的公开提交](https://github.com/westtide/c2btor/commit/51053087c6ec963e9218ecb67af48aec4fd5e9cf) | `c2btor` 支持 BTOR2 导出、源码映射和安全检查开关 |
| catbtor | [hwmcc/btor2tools](https://github.com/hwmcc/btor2tools#build) | 构建后将 `build/bin` 加入 PATH |
| rIC3 | [gipsyh/rIC3](https://github.com/gipsyh/rIC3#install-from-source) | PATH 中的 `ric3` 支持 `ric3 check MODEL portfolio` |

也支持明确选择带 BTOR2 导出扩展的 `cbmc`。使用表中的独立 C2Btor 时，在 `.env` 中设置 `CBMC_COMMAND=c2btor` 和 `C2BTOR_DATA_MODEL=LP64`。先检查 PATH 并运行实际工具探针。

```bash
command -v c2btor catbtor ric3
python -m spec_agent doctor --probe-tools
```

在线生成需要自行向兼容 OpenAI Chat Completions API 的提供方取得凭据，并仅在本机 `.env` 或环境变量中设置 `LLM_BASE_URL`（包含提供方要求的 API 路径）、`LLM_MODEL` 与 `LLM_API_KEY`。开启在线生成时，源码和需求上下文会发给配置的模型服务。可用 `python -m spec_agent doctor --probe-tools --check-llm` 主动发送一次 API 探测。

## 运行样例

### 三层调用与图形界面

`fan_command → target_speed → limit_speed` 包含三层函数和四处调用点，适合观察调用上下文逐层传递。打开终端打印的本地地址，查看实时进度、逐属性验证循环和 P/Q。运行结束后监控仍可浏览，按 Ctrl+C 关闭。

```bash
python -m spec_agent run \
  --source examples/nested_fan/program.c \
  --requirements examples/nested_fan/requirements.md \
  --branch hoare --require-real --output runs/nested-fan \
  --ui --show-pq --ui-no-open
```

使用样例附带的固定规格时，把 `--require-real` 换成 `--llm-fixture examples/nested_fan/llm_fixture.json`。该命令运行真实验证工具，运行模式为 `FIXTURE_LLM_REAL_TOOLS`。完整样例见[风扇样例说明](examples/nested_fan/README.md)。

### 静态数组边界

```bash
python scripts/real_validation.py --case array --output runs/static-array
```

这个样例读取 `a[2]`（数组长度为 2），预期下界 `HOLDS`、上界 `VIOLATED`。验收脚本检出预期的越界且证据审计通过时，摘要为 `PASSED`。静态分支使用真实工具，无需模型凭据。其他样例见[示例索引](examples/README.md)。

### 独立评估与历史监控

把 `RUN_DIR` 设为运行结束时打印的 `result.json` 的**所在目录**。以下命令使用风扇样例的独立标签做 P/Q 强度检查，然后打开历史运行。

```bash
read -r -p 'Run directory: ' RUN_DIR
python -m spec_agent audit --run "$RUN_DIR"
python -m spec_agent evaluate --run "$RUN_DIR" \
  --strength-cases examples/nested_fan/strength_cases.json \
  --output evaluations/nested-fan
python -m spec_agent monitor --run "$RUN_DIR" --show-pq --port 8765
```

第一阶段结果见 `result.json`，流程与错误定位见 `process.log` 和 `events.jsonl`。Hoare 规约见 `specs/formal/`，逐属性模型、源码映射与工具输出见 `verification/`。评估报告见独立评估目录的 `report.md`。

## 源码结构

| 目录 | 用途 |
| --- | --- |
| `spec_agent/` | 控制器、AST 分析、规约生成与形式化、工具适配、证据审计、评估和精化 |
| `spec_agent/monitor/` | 只读监控服务及前端 HTML、CSS、JavaScript |
| `spec_agent/schemas/`、`spec_agent/prompts/` | 随包安装的结构定义和提示词 |
| `examples/` | 可复现的 C 样例、需求、固定规格与评估数据 |
| `scripts/`、`tests/` | 验收命令与回归测试 |

```bash
python -m unittest discover -s tests -v
```

测试使用模拟工具检查编排，真实验证另走验收命令。完整测试还可使用 GCC（harness 语法检查）、`jsonschema`（结构检查）和系统 Z3 共享库（独立的 `t3t4`、`nacsl` 子命令测试）。

Hoare 证明覆盖当前模型和前提下的部分正确性。**未知样例仍可能触发 rIC3 崩溃或超时。** 本地验证时使用过修订版 rIC3，复现入口以上游公开版本及工具探针为准。
