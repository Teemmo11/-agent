# 固定数组循环求和

`sum_array(void)` 在函数内部初始化 `a[10] = {0, 1, ..., 9}`，通过循环访问
`a[0]` 至 `a[9]`，返回总和。期望契约为 `{1} sum_array() {result == 45}`。
这里验证的是固定数组，不是任意数组参数或量化求和表达式。

在项目根目录的 WSL 虚拟环境执行真实 LLM + 真实工具链验收：

```bash
python scripts/real_validation.py --case sum --output ./runs/live-array-sum
```

该命令使用 `.env` 中的真实 LLM 配置，要求唯一的 Q1、JSON null guard，
并检查规格内容、P 可行性、Q 的工具结果和证据审计。预期 `summary.json`
为 PASSED，`result.json` 中 P=FEASIBLE、Q1=HOLDS、contract=HOLDS，
`audit.json` 为 PASSED。所有 evaluation 字段仍为 NOT_RUN。
`--case all` 保持原来四个场景的顺序，不自动加入 sum。

不请求 LLM API，仅用固定规格检查真实工具链：

```bash
python -m spec_agent run --branch hoare \
  --source ./examples/array_sum/program.c \
  --requirements ./examples/array_sum/requirements.md \
  --llm-fixture ./examples/array_sum/llm_fixture.json \
  --output ./runs/fixture-array-sum
```

此模式明确标记为 FIXTURE_LLM_REAL_TOOLS，不能算作真实 LLM 验收。
没有执行输入 C 程序，CBMC/C2Btor 建模后交给 catbtor/rIC3 检查；循环保持
在模型中，不通过固定展开次数代替原始循环。Hoare 结果不替代独立静态安全验证。

此样例曾在 rIC3 中触发内部 panic，随后用本地修订版完成了真实验收。
复现时以当前工具探针和逐属性结果为准。若工具报错，可从 `verification/`
查看 BTOR2 模型、源码映射和 rIC3 的原始错误输出。

生成与检查记录见每次 run 的 `process.log`、`events.jsonl`、
`generation/llm/functions/` 和 `verification/`；不要把 API key 贴进日志。
