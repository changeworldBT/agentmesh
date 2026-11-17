---
name: memory-read
description: 按 task_type 与工具清单检索错误账本命中预防规则并汇总记忆库上下文，Planner 拆解后与 Worker 启动前强制调用。
when:
  - Planner 完成任务拆解后填充 brief 前
  - Worker 启动执行前注入系统提示前
  - Reviewer 交叉验证前检索相似历史失败
roles: [planner, worker, reviewer]
credential_groups: []
timeout_s: 30
retries: 1
idempotent: true
risk_level: low
inputs:
  - {name: task_type, type: string, required: true, desc: 任务类型，如 deploy / research / email_send}
  - {name: tool_list, type: 'list[string]', required: true, desc: 预计使用的工具名清单}
  - {name: keywords, type: 'list[string]', required: false, desc: 额外检索关键词，缺省为空}
outputs: |
  {memory_block: str, hits: [{rule_id, rule_text, risk_level, occurred_at}]}
version: 1.0
---

# memory-read

强制检索记忆库 + 错误账本的唯一读入口，输出标准化注入块（`memory_block`）供 Planner
填充 brief 与 Worker/Reviewer 注入系统提示。只读，无任何写路径。

## 执行步骤

1. 由调用角色（planner / worker / reviewer）按 front-matter `inputs` 传参，调用
   `scripts/memory_read.py`：容器内
   `docker exec agentmesh-core python3 /opt/agentmesh/skills/memory-read/scripts/memory_read.py --task-type <task_type> --tools <逗号分隔> [--keywords <逗号分隔>]`；
   脚本以 `AGENTMESH_ROOT`（缺省 /opt/agentmesh）为导入基准，连
   `AGENTMESH_DATA_DIR`（缺省 /opt/agentmesh/data）下的 `agentmesh.db`。
2. 检索算法（skills-config §3.1，确定性、无 LLM）：关键词合并
   `[task_type, *tool_list, *keywords]`，全空直接返回空块（不检索全量）；
   经 `app.engine.ledger.search_rules`（SQL 内置 status='active' 过滤）与
   `app.engine.ledger.search_errors` 检索，关键词列表以 `keyword_operator='OR'`
   承载文档版 FTS MATCH 的 OR 语义。
3. 结果按 `occurred_at` 降序、按规则 id / error_signature 去重，截前 10 条，
   渲染为 `memory_block` 注入块；出参只以单个 ```json 块打印到 stdout
   （skills-config §1.3 出参纪律）。

## 验收证据

- 退出码 0，stdout 恰一个 ```json 块，结构 = front-matter `outputs`：
  `memory_block` 非空字符串 + `hits` 列表（每条含 rule_id / rule_text /
  risk_level / occurred_at）。
- `scripts/test_memory_read.py` 通过（seed 一条 active 预防规则与一条错误记录后
  检索命中、去重与截断 10 条判据、空关键词返回空块）——对应 rules-config §4.2
  acceptance_template 的 behavior 型判据：「执行命令后期望观察」。
- 只读性证据：运行前后 SQLite 文件 mtime 不变（脚本不建表不写行）。

## 必须先询问的情况

- 输入超出 `when` 声明范围（非 Planner/Worker/Reviewer 角色调用、
  task_type 缺失）——按 skills-config §2.4 Fail Branch 以 AUTHZ_DENY 登记错误账本，
  不静默放行。
- 检索结果将作为「必须先询问」场景的证据引用到审批门材料时，须在引用处
  附 `hits` 原文与 occurred_at，不得转述省略。
- 本技能 `risk_level=low` 不触发审批门；若调用方拟把 `memory_block` 内容
  外发（email/message），外发动作本身按 global.yaml irreversible tier 走审批门，
  与本技能无关，不得借读路径绕行。
