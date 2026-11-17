"""planner.py — 规划器：自然语言目标 → 任务树 + 分组 + 自包含 brief（含 tools/预算/风险预标）
+ 错误账本强制检索注入（读时机一）；输出经 schema 校验，失败重试 1 次。

设计文档出处（模块顶部注记，按 ask 要求）：
- sys-arch（ARCH-ROOT-01）§2.4：规划器组件；§3.2 T2：规划器产出任务树 + 分组 + 自包含
  brief + 风险分级，落库成功 → running；§4.1：三层模型（主任务-分组-子任务）、组间依赖
  构成 DAG、组内无序或批量并行；§4.2：自包含 brief 规范（假设读者对主对话零了解；主对话
  原文永不进入 brief）、prevention_rules 由规划器拆解后强制检索注入（读时机之一）、brief
  版本化落库；§4.4：批量拆分适用边界（≥10 项且项间无依赖）；§5.1：规划器预标风险分级
  （brief_spec 权威字段 risk_tier_hint）；§7.1：规划产出事件化落库；§8.1：规划器全权
  拆解；§9.1 时序（O→E 强制检索→P 规划→落任务树 transitions T2）。
- memory-design（MEM-ERR-01）§4 矩阵第 1 行（planning / Planner 读（强制））：任务树拆解
  完成后 search_rules(task_type, brief_keywords, limit=5) + search_errors(limit=5)，命中的
  生效规则与相似错误注入各子任务 brief 的 prevention_rules 字段；失败降级：返回空 + brief
  标 degraded:true + memory_degraded 事件，不阻塞拆解。
- rules-config（RULES-01）§4.1：brief_spec 权威字段集（task_id/task_type/objective/
  self_contained_context/acceptance_criteria/allowed_tools/risk_tier_hint/budget_usd/
  max_iterations/deliverable_path 必填，prevention_rules/memory_refs 可选）；
  max_iterations 取值域 1..15（roles.yaml 校验域同源）。
- interface-contracts（ICON-01）§2：event_type 词表——`ledger_lookup`（task_type、命中
  规则 ID 列表）、`plan_produced`（任务树摘要、分组数、批量项数、risk_tier_hint、预算）、
  `memory_degraded`；§5.4：brief 渲染面字段。
- deployment-ops §5.1：briefs 表归编排引擎（brief 版本化），首个 brief 版本写入前按需
  建表——由本模块 _ensure_briefs_table() 落实。

偏离与取舍（如实声明）：
- schema 校验为标准库手写校验器（拒绝依赖第三方 jsonschema——sys-arch §10.2 内核依赖
  面仅标准库+PyYAML+uvicorn/fastapi）；失败重试 1 次（本 ask 指定），两次失败 →
  PlanValidationError + 错误账本登记（error_type=plan_schema_violation），T10/T2 超时
  兜底归编排引擎。
- 允许工具集以 executor.TOOL_ALLOWLIST（http_get/file_write）为双闸门中的 brief 白名单
  一侧（§6.2 角色授权闸门归工具接入层后续交付物）；计划中出现未知工具按校验错误处理
  （从严——缺字段/越权工具拒绝派发，ARCH §4.2「缺字段拒绝派发」）。
- depends_on 依赖环检测（Kahn 拓扑）为 MVP 增补的 T2 落库合法性检查（设计未明说，环会
  死锁后续派发）。
- 计划内 ID（g1/g1-1 展示形）落库时命名空间化为 `<计划 ID>@<task_id>`：kernel 的
  groups/subtasks id 是全局 PRIMARY KEY，而 LLM 按任务树局部产出 ID，跨任务同名必然
  冲突（多任务同库实测踩中 UNIQUE 冲突）；@ 前段保留展示形可还原（ICON §5.3 示例的
  g1-1 即 @ 前段）。
- STUB/真实网关的响应均经同一校验器；LLM 输出包裹 ```json 围栏时剥离后解析。
- deliverable_path 由 workspace 策略（executor.task_workspace，默认
  /data/agentmesh/workspaces/<task_id>/，AGENTMESH_WORKSPACE_ROOT 可覆盖）计算为
  <task_id>/<subtask_id>.json——executor 的 file_write 硬限制与之同源。
"""

from __future__ import annotations

import json
import re
from typing import Any

from app.engine import ledger, state
from app.engine.db import Database, emit_event, json_dumps, utc_now_iso
from app.engine.executor import TOOL_ALLOWLIST, retrieval_keywords, task_workspace
from app.engine.llm import LLMRequest
from app.engine.state import TaskStatus, transition_task

PLAN_MAX_ATTEMPTS = 2  # 初次 + 重试 1 次（本 ask 指定「失败重试 1 次」）
BRIEF_VERSION_INITIAL = 1

_PLAN_SCHEMA_PROMPT = """你是任务规划器。把用户的自然语言目标拆解为任务树，只输出一个 JSON 对象（无多余文本），结构如下：
{
  "task_type": "字符串，任务类型",
  "budget_usd": 数字或 null，主任务预算（USD 估算）,
  "groups": [{"id": "g1", "name": "分组名", "depends_on": ["其他分组 id"],
              "batch_mode": false, "batch_total_items": null, "partial_ok": false}],
  "subtasks": [{"id": "g1-1", "group_id": "g1", "objective": "一句话可判定成败的目标",
                "task_type": "子任务类型", "self_contained_context": "背景必要摘录（读者对主对话零了解）",
                "acceptance_criteria": ["机器可核对判据"], "allowed_tools": ["http_get", "file_write"],
                "risk_tier_hint": "irreversible|reversible_costly|reversible",
                "budget_usd": 数字, "max_iterations": 1..15 的整数}]
}
约束：group id 与 subtask id 全局唯一；subtask.group_id 必须存在；depends_on 不得成环；
allowed_tools 只能取内核白名单内的工具名；批量并行拆分仅在项间无数据依赖且规模 ≥10 项时使用（sys-arch §4.4）。"""

_PREVENTION_PROMPT_HEADER = "【错误账本强制检索命中（写入每个 brief 的 prevention_rules，执行时必须遵守）】"


class PlanValidationError(ValueError):
    """规划输出未通过 schema 校验（重试 1 次后仍失败）。"""

    def __init__(self, errors: list[str], plan: Any = None) -> None:
        super().__init__("plan schema validation failed: " + "; ".join(errors[:10]))
        self.errors = errors
        self.plan = plan


# ---------------------------------------------------------------------------
# briefs 表（deployment-ops §5.1：编排引擎 brief 版本化，首写前按需建表）
# ---------------------------------------------------------------------------

_BRIEFS_TABLE_STATEMENTS: tuple[str, ...] = (
    """
    CREATE TABLE IF NOT EXISTS briefs (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      task_id    TEXT NOT NULL,
      subtask_id TEXT NOT NULL,
      version    INTEGER NOT NULL,
      brief      TEXT NOT NULL,
      created_at TEXT NOT NULL,
      UNIQUE(subtask_id, version)
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_briefs_subtask ON briefs(subtask_id, version)",
)


def _ensure_briefs_table(conn: Any) -> None:
    for stmt in _BRIEFS_TABLE_STATEMENTS:
        conn.execute(stmt)


# ---------------------------------------------------------------------------
# 强制检索注入（读时机之一，memory-design §4 矩阵第 1 行）
# ---------------------------------------------------------------------------

def fetch_prevention_context(database: Database, keywords: list[str], task_type: str) -> dict[str, Any]:
    """planning 强制读：search_rules(limit=5) + search_errors(limit=5)（MEM §4）。

    检索接口内部失败已返回空 + memory_degraded 事件（MEM §6.1 末段封装）；本函数外层再
    兜底任意异常，同样降级不阻塞拆解——「检索接口永不抛异常」的强制作实（MEM §4）。
    """
    try:
        # OR 语义（任一关键词命中即候选，limit/rank 截断）——注入场景要召回面；
        # 等值/全词命中（AND）语义保留给沉淀回放校验（ledger §6.1 默认不变）
        rules = ledger.search_rules(database, keywords, task_type=task_type, limit=5,
                                    keyword_operator="OR")
        errors = ledger.search_errors(database, keywords, limit=5, keyword_operator="OR")
        return {"rules": rules, "errors": errors, "degraded": False}
    except Exception as exc:  # noqa: BLE001 - 强制读永不抛（MEM §4）
        try:
            with database.transaction() as conn:
                emit_event(conn, component="planner", event_type="memory_degraded",
                           payload={"surface": "planner_retrieval", "detail": [str(exc)[:120]]})
        except Exception:
            pass
        return {"rules": [], "errors": [], "degraded": True}


def _prevention_entries(context: dict[str, Any]) -> list[dict[str, Any]]:
    """把命中规则与相似错误折叠进 brief.prevention_rules（ICON §5.4 形态：规则带 rule_id/
    rule_text/source=ledger_lookup，错误带 error_id/error_signature/source=ledger_error）。"""
    entries: list[dict[str, Any]] = []
    for rule in context.get("rules") or []:
        entries.append({"rule_id": int(rule["id"]), "rule_text": str(rule["rule_text"]),
                        "risk_level": str(rule.get("risk_level") or ""), "source": "ledger_lookup"})
    for err in context.get("errors") or []:
        entries.append({"error_id": int(err["id"]), "error_signature": str(err["error_signature"]),
                        "source": "ledger_error"})
    return entries


def _prevention_prompt_block(context: dict[str, Any]) -> str:
    lines: list[str] = []
    for rule in context.get("rules") or []:
        lines.append(f"- [生效规则 {rule['id']}] {rule['rule_text']}")
    for err in context.get("errors") or []:
        lines.append(f"- [相似历史错误 {err['id']}] {err['error_signature']}：根因={err['root_cause'] or '未填'}")
    if not lines:
        return ""
    return _PREVENTION_PROMPT_HEADER + "\n" + "\n".join(lines) + "\n规划时把上述条目纳入对应子任务的拆解与风险预标。\n"


# ---------------------------------------------------------------------------
# 计划 schema 校验（标准库手写；失败重试 1 次的判定面）
# ---------------------------------------------------------------------------

def _is_num(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def validate_plan(plan: Any, *, allowlist: tuple[str, ...] = TOOL_ALLOWLIST) -> list[str]:
    """校验 LLM 计划输出；返回错误清单（空 = 通过）。"""
    errors: list[str] = []
    if not isinstance(plan, dict):
        return ["plan must be a JSON object"]
    task_type = plan.get("task_type")
    if not isinstance(task_type, str) or not task_type.strip():
        errors.append("task_type must be a non-empty string")
    budget = plan.get("budget_usd")
    if budget is not None and (not _is_num(budget) or budget < 0):
        errors.append("budget_usd must be a non-negative number or null")
    groups = plan.get("groups")
    if not isinstance(groups, list) or not groups:
        errors.append("groups must be a non-empty list")
        groups = []
    group_ids: set[str] = set()
    edges: dict[str, list[str]] = {}
    for group in groups:
        if not isinstance(group, dict):
            errors.append("each group must be an object")
            continue
        gid = group.get("id")
        if not isinstance(gid, str) or not gid.strip():
            errors.append(f"group id must be a non-empty string: {gid!r}")
        elif gid in group_ids:
            errors.append(f"duplicate group id: {gid}")
        else:
            group_ids.add(gid)
        if not isinstance(group.get("name"), str) or not str(group.get("name")).strip():
            errors.append(f"group {gid!r} name must be a non-empty string")
        depends = group.get("depends_on")
        if not isinstance(depends, list) or not all(isinstance(d, str) for d in depends):
            errors.append(f"group {gid!r} depends_on must be a list of group ids")
        else:
            edges[str(gid)] = [str(d) for d in depends]
        if not isinstance(group.get("batch_mode"), bool):
            errors.append(f"group {gid!r} batch_mode must be boolean")
        items = group.get("batch_total_items")
        if items is not None and (not isinstance(items, int) or isinstance(items, bool) or items < 0):
            errors.append(f"group {gid!r} batch_total_items must be a non-negative integer or null")
        if not isinstance(group.get("partial_ok"), bool):
            errors.append(f"group {gid!r} partial_ok must be boolean")
    for gid, deps in edges.items():
        for dep in deps:
            if dep not in group_ids:
                errors.append(f"group {gid!r} depends on unknown group {dep!r}")
    # 组间 DAG 无环（Kahn 拓扑；环会死锁后续派发，MVP 增补合法性检查）
    indegree = {gid: 0 for gid in group_ids}
    for deps in edges.values():
        for dep in deps:
            if dep in indegree:
                indegree[dep] += 1
    queue = [gid for gid, deg in indegree.items() if deg == 0]
    seen = 0
    while queue:
        node = queue.pop()
        seen += 1
        for gid, deps in edges.items():
            if node in deps and gid != node:
                indegree[gid] -= 1
                if indegree[gid] == 0:
                    queue.append(gid)
    if group_ids and seen != len(group_ids):
        errors.append("groups depends_on contains a cycle")
    subtasks = plan.get("subtasks")
    if not isinstance(subtasks, list) or not subtasks:
        errors.append("subtasks must be a non-empty list")
        subtasks = []
    sub_ids: set[str] = set()
    for sub in subtasks:
        if not isinstance(sub, dict):
            errors.append("each subtask must be an object")
            continue
        sid = sub.get("id")
        if not isinstance(sid, str) or not sid.strip():
            errors.append(f"subtask id must be a non-empty string: {sid!r}")
        elif sid in sub_ids:
            errors.append(f"duplicate subtask id: {sid}")
        else:
            sub_ids.add(sid)
        if sub.get("group_id") not in group_ids:
            errors.append(f"subtask {sid!r} group_id unknown: {sub.get('group_id')!r}")
        if not isinstance(sub.get("objective"), str) or not str(sub.get("objective")).strip():
            errors.append(f"subtask {sid!r} objective must be a non-empty string")
        if sub.get("risk_tier_hint") not in ("irreversible", "reversible_costly", "reversible"):
            errors.append(f"subtask {sid!r} risk_tier_hint must be one of irreversible/reversible_costly/reversible")
        tools = sub.get("allowed_tools")
        if not isinstance(tools, list) or not all(isinstance(t, str) for t in tools):
            errors.append(f"subtask {sid!r} allowed_tools must be a list of strings")
        else:
            unknown = [t for t in tools if t not in allowlist]
            if unknown:
                errors.append(f"subtask {sid!r} allowed_tools beyond kernel allowlist: {unknown}")
        if not _is_num(sub.get("budget_usd")) or sub.get("budget_usd") < 0:
            errors.append(f"subtask {sid!r} budget_usd must be a non-negative number")
        iters = sub.get("max_iterations")
        if not isinstance(iters, int) or isinstance(iters, bool) or not (1 <= iters <= 15):
            errors.append(f"subtask {sid!r} max_iterations must be an integer in 1..15 (rules-config roles 校验域)")
        criteria = sub.get("acceptance_criteria")
        if (not isinstance(criteria, list) or not criteria
                or not all(isinstance(c, str) and c.strip() for c in criteria)):
            errors.append(f"subtask {sid!r} acceptance_criteria must be a non-empty list of strings")
        ctx = sub.get("self_contained_context")
        if not isinstance(ctx, str) or not ctx.strip():
            errors.append(f"subtask {sid!r} self_contained_context must be a non-empty string (brief 自包含)")
    return errors


def _strip_json_fences(text: str) -> str:
    t = str(text or "").strip()
    if t.startswith("```"):
        t = re.sub(r"^```[A-Za-z0-9_+\-]*\s*", "", t)
        t = re.sub(r"\s*```$", "", t)
    return t.strip()


# ---------------------------------------------------------------------------
# 规划主流程
# ---------------------------------------------------------------------------

def plan_task(
    database: Database,
    llm: Any,
    task_id: str,
    *,
    goal: str | None = None,
    task_type: str = "generic",
    allowlist: tuple[str, ...] = TOOL_ALLOWLIST,
    workspace_root_override: str | Any = None,
    now: str | None = None,
) -> dict[str, Any]:
    """规划一个处于 planning 状态的主任务：拆解 → 校验（失败重试 1 次）→ 落任务树 + briefs → T2。

    返回 {"task_id", "groups", "subtasks", "degraded", "prevention_rules_injected"}；
    两次校验失败 → PlanValidationError（账本已登记 plan_schema_violation，T2 超时兜底归引擎）。
    """
    now_ts = now or utc_now_iso()
    task_row = database.query_one("SELECT * FROM tasks WHERE id = ?", (task_id,))
    if task_row is None:
        raise KeyError(f"task not found: {task_id}")
    if TaskStatus(task_row["status"]) is not TaskStatus.PLANNING:
        raise ValueError(f"task {task_id} must be in planning to plan (got {task_row['status']})")
    goal_text = str(goal if goal is not None else task_row["goal"])

    # —— 读时机一：错误账本强制检索（MEM §4 矩阵第 1 行；ICON §2 ledger_lookup）——
    keywords = retrieval_keywords(goal_text, task_type)
    try:
        context = fetch_prevention_context(database, keywords, task_type)
    except Exception:  # noqa: BLE001 - 强制读永不抛（MEM §4）；检索助手自身异常同样降级并落事件
        try:
            with database.transaction() as conn:
                emit_event(conn, component="planner", event_type="memory_degraded",
                           payload={"surface": "planner_retrieval",
                                    "detail": ["fetch_prevention_context raised"]})
        except Exception:
            pass
        context = {"rules": [], "errors": [], "degraded": True}
    prevention_entries = _prevention_entries(context)
    with database.transaction() as conn:
        emit_event(conn, task_id=task_id, component="planner", event_type="ledger_lookup",
                   payload={"task_type": task_type, "keywords": keywords,
                            "rule_ids": [e["rule_id"] for e in prevention_entries if "rule_id" in e],
                            "error_ids": [e["error_id"] for e in prevention_entries if "error_id" in e],
                            "degraded": bool(context.get("degraded"))})

    messages: list[dict[str, Any]] = [
        {"role": "system",
         "content": _PLAN_SCHEMA_PROMPT + ("\n\n" + _prevention_prompt_block(context)
                                           if context.get("rules") or context.get("errors") else "")},
        {"role": "user", "content": json_dumps({"goal": goal_text, "task_type": task_type})},
    ]
    plan: dict[str, Any] | None = None
    errors: list[str] = ["plan not produced"]
    for attempt in range(1, PLAN_MAX_ATTEMPTS + 1):
        with database.transaction() as conn:
            emit_event(conn, task_id=task_id, component="planner", event_type="plan_requested",
                       payload={"attempt": attempt, "task_type": task_type,
                                "prevention_hits": len(prevention_entries)})
        response = llm.chat(LLMRequest(
            messages=[dict(m) for m in messages], json_mode=True, kind="plan",
            stub_payload={"goal": goal_text, "task_type": task_type},
            task_id=task_id, component="planner",
        ))
        candidate: Any = None
        parse_error: str | None = None
        try:
            candidate = json.loads(_strip_json_fences(str(response.content or "")))
        except ValueError as exc:
            parse_error = f"response is not valid JSON: {exc}"
        if candidate is not None:
            errors = validate_plan(candidate, allowlist=allowlist)
            if not errors:
                plan = candidate
                break
        else:
            errors = [parse_error or "empty response"]
        with database.transaction() as conn:
            emit_event(conn, task_id=task_id, component="planner", event_type="plan_rejected",
                       payload={"attempt": attempt, "errors": errors[:10]})
        if attempt < PLAN_MAX_ATTEMPTS:
            # 重试 1 次：附上一次坏输出与校验错误清单，要求修正
            messages.append({"role": "assistant", "content": str(response.content or "")})
            messages.append({"role": "user", "content": "上次输出未通过 schema 校验，错误清单：\n"
                             + "\n".join(f"- {e}" for e in errors)
                             + "\n请修正后重新只输出符合 schema 的 JSON 对象。"})
    if plan is None:
        try:
            ledger.ledger_write(database, "plan_schema_violation", "planner",
                                {"task_type": task_type},
                                "plan schema validation failed after retry: "
                                + "; ".join(errors[:10]), task_id, "planner")
        except Exception:
            pass  # 账本写失败不掩盖校验失败本身（MEM §4 降级）
        raise PlanValidationError(errors, plan)

    return _persist_plan(database, task_id, plan, prevention_entries,
                         degraded=bool(context.get("degraded")), goal_text=goal_text,
                         task_type=task_type, allowlist=allowlist,
                         workspace_root_override=workspace_root_override, now=now_ts)


def _persist_plan(database: Database, task_id: str, plan: dict[str, Any],
                  prevention_entries: list[dict[str, Any]], *, degraded: bool,
                  goal_text: str, task_type: str, allowlist: tuple[str, ...],
                  workspace_root_override: str | Any, now: str) -> dict[str, Any]:
    """落任务树（groups/subtasks）+ briefs 表（首写前按需建表）+ plan_produced 事件 → T2 → running。

    计划内 ID 是任务树局部的（LLM 惯于产出 g1/g1-1 这类展示形 ID）；kernel 的 groups/
    subtasks id 是全局 PRIMARY KEY，落库时统一命名空间化：`<计划 ID>@<task_id>`——
    跨任务同名计划 ID 不再冲突（多任务同库实测踩中 UNIQUE 冲突），@ 前段保留展示形可还原。
    """
    workspace = task_workspace(workspace_root_override, task_id)

    def namespaced(plan_id: str) -> str:
        return f"{plan_id}@{task_id}"

    gid_map = {str(g.get("id")): namespaced(str(g.get("id"))) for g in (plan.get("groups") or [])}
    group_rows: list[dict[str, Any]] = []
    created_subtasks: list[dict[str, Any]] = []
    briefs: list[tuple[str, dict[str, Any]]] = []
    if plan.get("budget_usd") is not None:
        with database.transaction() as conn:
            conn.execute("UPDATE tasks SET budget_usd = ?, updated_at = ? WHERE id = ?",
                         (float(plan["budget_usd"]), now, task_id))
    for group in plan.get("groups") or []:
        gid = state.create_group(
            database, task_id, name=str(group.get("name") or ""),
            group_id=namespaced(str(group.get("id"))),
            depends_on=[gid_map[d] for d in (group.get("depends_on") or []) if str(d) in gid_map],
            batch_mode=bool(group.get("batch_mode")),
            batch_total_items=group.get("batch_total_items"),
            partial_ok=bool(group.get("partial_ok")), now=now,
        )
        group_rows.append({"group_id": gid, "name": group.get("name"),
                           "depends_on": [gid_map[d] for d in (group.get("depends_on") or [])
                                          if str(d) in gid_map],
                           "batch_mode": bool(group.get("batch_mode")),
                           "batch_total_items": group.get("batch_total_items"),
                           "partial_ok": bool(group.get("partial_ok"))})
    for sub in plan.get("subtasks") or []:
        sid = namespaced(str(sub.get("id")))
        deliverable = str(workspace / f"{sid}.json")
        state.create_subtask(
            database, task_id, gid_map[str(sub.get("group_id"))],
            objective=str(sub.get("objective") or ""),
            subtask_id=sid, status="planning", risk_tier_hint=sub.get("risk_tier_hint"),
            brief_version=BRIEF_VERSION_INITIAL, deliverable_path=deliverable, now=now,
        )
        brief = _build_brief(task_id, sid, sub, prevention_entries, degraded, goal_text,
                             task_type, allowlist, deliverable)
        briefs.append((sid, brief))
        created_subtasks.append({"subtask_id": sid, "group_id": gid_map[str(sub.get("group_id"))],
                                 "brief_version": BRIEF_VERSION_INITIAL,
                                 "risk_tier_hint": brief["risk_tier_hint"]})
    with database.transaction() as conn:
        _ensure_briefs_table(conn)  # deployment-ops §5.1：首个 brief 版本写入前按需建表
        for sid, brief in briefs:
            conn.execute(
                "INSERT INTO briefs (task_id, subtask_id, version, brief, created_at)"
                " VALUES (?, ?, ?, ?, ?)",
                (task_id, sid, BRIEF_VERSION_INITIAL, json_dumps(brief), now),
            )
    batch_count = sum(1 for g in group_rows if g["batch_mode"])
    with database.transaction() as conn:
        emit_event(conn, task_id=task_id, component="planner", event_type="plan_produced",
                   payload={"groups": len(group_rows), "subtasks": len(created_subtasks),
                            "batch_groups": batch_count,
                            "budget_usd": plan.get("budget_usd"),
                            "risk_tier_hints": sorted({c["risk_tier_hint"] for c in created_subtasks}),
                            "degraded": degraded,
                            "prevention_rules_injected": len(prevention_entries),
                            "task_type": task_type})
    transition_task(database, task_id, TaskStatus.RUNNING, component="planner",
                    reason="T2: plan validated and persisted (groups+briefs)",
                    event_payload={"groups": len(group_rows), "subtasks": len(created_subtasks)},
                    now=now)
    return {"task_id": task_id, "groups": group_rows, "subtasks": created_subtasks,
            "degraded": degraded, "prevention_rules_injected": len(prevention_entries)}


def _build_brief(task_id: str, subtask_id: str, sub: dict[str, Any],
                 prevention_entries: list[dict[str, Any]], degraded: bool, goal_text: str,
                 task_type: str, allowlist: tuple[str, ...], deliverable: str) -> dict[str, Any]:
    """组装自包含 brief（rules-config §4.1 brief_spec 权威字段 + MEM §4 注入项）。

    主对话原文永不进入 brief（sys-arch §9.3 不变量 1）：self_contained_context 只取
    LLM 计划给出的必要摘录，兜底为主任务目标一句话摘录（非对话原文）。
    """
    _ = task_id  # 预留：brief 反向引用主任务 ID（replay 关联用），当前形态保持 brief_spec 最小集
    return {
        "task_id": subtask_id,
        "task_type": str(sub.get("task_type") or task_type),
        "objective": str(sub.get("objective") or ""),
        "self_contained_context": str(sub.get("self_contained_context")
                                      or f"主任务目标（必要摘录）: {goal_text[:200]}"),
        "acceptance_criteria": [str(c) for c in (sub.get("acceptance_criteria") or [])],
        "allowed_tools": [t for t in (sub.get("allowed_tools") or []) if t in allowlist],
        "prevention_rules": prevention_entries,  # 读时机一注入（MEM §4）；brief_spec 可选字段
        "risk_tier_hint": str(sub.get("risk_tier_hint")),
        "budget_usd": float(sub.get("budget_usd") or 0.0),
        "max_iterations": int(sub.get("max_iterations") or 3),
        "memory_refs": [],
        "deliverable_path": deliverable,
        "degraded": degraded,                 # MEM §4 降级标记
        "on_failure": "register_and_stop",    # sys-arch §4.2 失败处置
        "brief_version": BRIEF_VERSION_INITIAL,
    }
