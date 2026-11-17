# 已通过的样例与复现命令

以下五例均有本机 REAL 验收记录，真实 Hoare 规格由 LLM 生成；静态数组检查
不请求 LLM。**验收 PASSED 表示符合该样例的预期，不等于程序都没有 bug。**

| case | 源文件 / 需求 | 预期 P | 预期属性 / Contract |
| --- | --- | --- | --- |
| clamp | `clamp/program.c` / `clamp/requirements.md` | FEASIBLE | Q1、Q2 HOLDS / HOLDS |
| buggy | `clamp/buggy.c` / 同上 | FEASIBLE | Q1 HOLDS、Q2 VIOLATED / VIOLATED |
| infeasible | `clamp/program.c` / `clamp/infeasible_requirements.md` | INFEASIBLE | 真空 Q，不是有效证明 / VACUOUS |
| array | `array_bug/program.c` / `array_bug/requirements.md` | 不适用，静态分支 | 下界 HOLDS、上界 VIOLATED |
| sum | `array_sum/program.c` / `array_sum/requirements.md` | FEASIBLE，P=`1` | Q1=`result == 45` HOLDS / HOLDS |

先在 WSL 激活虚拟环境、配置兼容工具和实际 .env，再按顺序运行：

```bash
python -m spec_agent doctor --probe-tools
python scripts/real_validation.py --case clamp --output ./runs/live-clamp
echo "exit=$?"
python scripts/real_validation.py --case buggy --output ./runs/live-buggy
echo "exit=$?"
python scripts/real_validation.py --case infeasible --output ./runs/live-infeasible
echo "exit=$?"
python scripts/real_validation.py --case array --output ./runs/live-array
echo "exit=$?"
python scripts/real_validation.py --case sum --output ./runs/live-array-sum
echo "exit=$?"
```

验收脚本预期全部 exit=0，summary/audit=PASSED；因为 buggy/array/infeasible
本来就期望负向或真空结果。通用 `python -m spec_agent run` 则会对 VIOLATED
返回 1、ERROR 返回 2、UNKNOWN/VACUOUS 返回 3，两种退出码不要混淆。
`echo` 应紧接命令，否则 `$?` 会指向中间命令。

原四例可用 `--case all` 顺序运行；sum 单独运行。固定基准中 Q 的数量被明确
约束以发现遗漏，通用生成仍按需求拆分独立子句。不能把数组的十个元素当成十条 Q。

不调用 LLM、隔离工具问题的六例回归：

```bash
python scripts/tool_regression.py --output ./runs/tool-regression
echo "exit=$?"
```

它额外检查 `array_sum/buggy.c`（循环 `i < 9`，返回 36，Q1 必须 VIOLATED）。
Hoare 输入使用 fixture，输出始终标注 FIXTURE_LLM_REAL_TOOLS，不能算 live 验收。

每次运行从输出目录生成证据、工具清单和模型哈希。可在新环境重新运行验收，
通过各次 `toolchain_manifest.json` 核对工具版本。

**在未知样例中可能存在导致 rIC3 崩溃的问题。** 遇到 panic/timeout/UNKNOWN
不得宣称 HOLDS；保存模型、source-map、原始 stderr/stdout 与 execution.json
后独立排障。当前表达式/参数支持范围和 partial correctness 边界仍适用。
