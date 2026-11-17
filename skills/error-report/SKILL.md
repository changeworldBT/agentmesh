---
name: error-report
description: 把执行异常或验收缺陷规范化为 error_signature 并结构化登记错误账本，返回登记 id，任何组件捕获错误时必须调用。
when:
  - Worker 执行中捕获异常
  - Reviewer 发现质量缺陷或矛盾结论
  - 技能加载或授权校验失败
roles: [planner, worker, reviewer, orchestrator, approval_gate]
credential_groups: []
timeout_s: 30
retries: 0
idempotent: false
risk_level: low
inputs:
  - {name: raw_error, type: string, required: true, desc: 异常原文或缺陷描述}
  - {name: phase, type: string, required: true, desc: 发生阶段 ∈ planning/running/reviewing/rework/paused_for_approval（sys-arch §3.1 非终态）}
  - {name: context, type: dict, required: false, desc: 上下文（component/task_type/task_id/params/root_cause/fix_applied）}
outputs: |
  {status: registered, entry_id: int, error_signature: str}
version: 1.0
---

# error-report

错误账本的唯一写入口。`retries:0 + idempotent:false` 的理由：同一异常登记两次会污染
滑窗计数（memory-design 沉淀阈值「同签名 ≥2 次」），宁可失败人工重报，不做自动重试。

## 执行步骤

1. 捕获异常或发现缺陷的组件（worker / reviewer / orchestrator / approval_gate /
   planner）按 front-matter `inputs` 传参，调用 `scripts/error_report.py`：
   容器内
   `docker exec agentmesh-core python3 /opt/agentmesh/skills/error-report/scripts/error_report.py --raw-error "<异常原文>" --phase running --context '{"component":"worker","task_type":"deploy"}'`；
   脚本以 `AGENTMESH_ROOT`（缺省 /opt/agentmesh）为导入基准，写
   `AGENTMESH_DATA_DIR`（缺省 /opt/agentmesh/data）下的 `agentmesh.db`。
2. 签名规范化算法（skills-config §4.1，无 LLM，同输入必同签名）：
   ① 错误类型归一（HTTP 状态→`http_<code>`；Python 异常名保留小写；其余取首个
   冒号前短句去标点截 32）→ ② 模块归一（`context.component` 优先，缺省 phase，
   截 24）→ ③ 参数模式归一（路径/UUID/邮箱/URL host/字符串/数字依次替换为
   `<PATH>/<ID>/<EMAIL>/<HOST>/<STR>/<N>`，截 48）→ ④ 拼接
   `error_type|module|param_pattern` 全小写截 120。
3. 登记走内核账本单一写入口 `app.engine.ledger.ledger_write`（memory-design §2.4）：
   write_guard 脱敏 → raw_error 截断 → 账本侧签名/指纹计算（不被技能绕过）→
   INSERT + error_registered 事件；返回 entry_id。
4. 出参只以单个 ```json 块打印到 stdout：`{status: registered, entry_id, error_signature}`
   （skills-config §1.3 出参纪律；不打印凭证值与临时路径）。

## 验收证据

- 退出码 0，stdout 恰一个 ```json 块，结构 = front-matter `outputs`；
  `entry_id` 为正整数（可在 error_ledger 表按 id 回查该行）。
- 同因异参不变式（skills-config §4.1 实测口径）：`task_id=8f14e45f…` 与
  `task_id=deadbeef…`、`after 30s` 与 `after 45s` 两组变体产出相同签名——
  由 `scripts/test_error_report.py` 固化为断言。
- phase 越界（如 `done`，终态不在 sys-arch §3.1 非终态集）必须以非 0 退出拒绝，
  不落库。

## 必须先询问的情况

- `raw_error` 中疑似包含凭证/令牌形态字符串（`sk-` 前缀、Bearer 头、
  AGE-SECRET-KEY）：先脱敏再登记——账本 write_guard 会整字段拒绝或脱敏
  （memory-design §8.1），调用方不得为「让登记成功」而自行删除字段内容掩盖来源。
- 同一签名一小时内登记 ≥3 次（滑窗计数激增）：停止继续登记，先升级人工排查
  是否同一根因被重复执行——避免污染沉淀阈值计数。
- 涉及凭证组配置错误（credential-request 拒绝、AUTHZ_DENY 链路）的登记，
  登记后必须同步通知审批门/凭证管理角色，不得只落账本不通知。
