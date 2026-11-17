# 第二阶段可复现样例：通过验证不等于规约充分

这是手工标注的合成测试，默认不调用在线 LLM，不属于 live LLM 验收。
输入 C 只经过模型转换，不会编译执行。需要现有兼容转换器、catbtor、rIC3 在 PATH 中。

## 1. 对比弱规约与正确返回值规约

```bash
python scripts/evaluation_validation.py --case weak-sum --output ./runs/phase2-weak-sum
echo "exit=$?"
python scripts/evaluation_validation.py --case correct-sum --output ./runs/phase2-correct-sum
echo "exit=$?"
```

两例需求都明确要求返回 45。候选分别是 `result >= 0` 和 `result == 45`。
前者应报告 `CANDIDATE_DOES_NOT_ENTAIL_REFERENCE`，后者不应报告此问题或恒真条款。
参考由测试作者提供，只能证明相对参考的形式关系，不能冒充自动证明自然语言全文。
这里的测试需求只约束返回值；原 `array_sum` 需求还包含初始化/遍历过程，不能仅凭返回 45 宣称全文覆盖。

每次脚本输出独立 `summary.json`；其 `cases[].evaluation` 定位质量报告。
同一顶层目录的 `cases/<name>/` 保留程序、需求、生成 fixture、参考及完整第一阶段父运行；
`evaluations/<name>/<id>/` 保留问题、上下文、原始逻辑工具证据和审计。
验收脚本的 exit=0 表示诊断符合标签，不表示被测规约没有问题。

## 2. 受控修订与实现错误分别保留

```bash
python scripts/refinement_validation.py --case improve --output ./runs/phase2-improve
echo "exit=$?"
python scripts/refinement_validation.py --case expose-bug --output ./runs/phase2-expose-bug
echo "exit=$?"
python scripts/refinement_validation.py --case weakening --output ./runs/phase2-block-weakening
echo "exit=$?"
python scripts/refinement_validation.py --case budget --output ./runs/phase2-budget
echo "exit=$?"
```

- improve：把非负结果加强为等于 45，候选 ACCEPTED，程序 HOLDS。
- expose-bug：程序实际返回 0；同样改进规约后候选 ACCEPTED，但程序保持 VIOLATED。
- weakening：补齐引用同时把等于 x 弱化为大于等于 x，必须 NEEDS_REVIEW，且不能进入实现重验证。
- budget：调用预算为零，必须在提案前停止，输出 INCONCLUSIVE。

`refinement.json` 中每轮记录原/新条款、覆盖变化、问题变化和原/新验证结论。
`selected_candidate` 只指向新目录，不覆盖原始需求、源码、规约或证明。

## 3. 其他边界

```bash
python scripts/evaluation_validation.py --suite design --output ./runs/phase2-design
python scripts/evaluation_validation.py --suite heldout --output ./runs/phase2-heldout
```

设计集含 15 例；保留集含 `_Bool`、`long/old`、`signed char` 三例。
它们检查形式诊断与类型范围，不提供在线模型准确率或通用可靠性保证。
UNKNOWN、崩溃、超时和预算耗尽不得算作命题证明。完整参数见
[第二阶段使用说明](../../README.md#独立评估与历史监控)。
