"""state.py — 任务状态机：九态枚举、T1–T10 转移守卫、T11 done 回调、超时兜底统一扫描、T3/T4 审批落点。

设计文档出处（模块顶部注记，按本 ask 要求）：
- sys-arch（ARCH-ROOT-01）§3.1 状态集合（九态，含 pending）；§3.2 状态转移表 T1–T11
  （含超时兜底列）；§3.3 状态机实现约定（单一驱动者 / 转移原子性 / 超时兜底统一实现 /
  崩溃恢复）；§5.2–§5.3 审批门三按钮、默认等待期与超时兜底分支；§7.1 每步动作事件化落库。
- interface-contracts（ICON-01）§5.3（status_detail 挂起原因快照：waiting_approval_id /
  返工指令摘要）、§5.5（T9 中止时运行中子任务定点取消）、§6.1–§6.3（approvals 字段与
  三按钮裁决校验）、§13.1（超时参数默认值：PLANNING/REVIEW/REWORK=10m/15m/10m、
  SUBTASK_RUNNING_TIMEOUT=60m、MAX_RETRIES=2、APPROVAL_DEFAULT_WAIT=24h）。
- deployment-ops §5.1：task_transitions 表归属编排引擎状态机模块、按需建表（首次 T1
  转移写入前）——由本模块 _ensure_transition_table() 落实。

偏离与取舍（如实声明）：
- 本 ask 的状态机清单列举 8 态（planning/running/reviewing/rework/done/failed/aborted/
  paused_for_approval），未列 pending——但 sys-arch §3.2 的 T1（pending→planning）以其
  为起点、§3.1 九态含 pending，故按设计文档实现九态。
- T9 的 from-集合严格按 §3.2 实现为 running/reviewing/rework（不含 paused_for_approval /
  planning / pending）：设计未给这三态的中止路径，属设计缺口，如实保留不擅自扩边。
- 子任务状态集按 §3.2 各行 (sub) 层级归纳为 8 态（无 reviewing——T5/T6/T7 均 (top)）；
  子任务 running→done 是 T5 收敛前提（§3.2 T5「全部子任务到达自身终态」），归入
  SUBTASK_TRANSITIONS（id=T5）；T9 对子任务落地为「定点取消」（ICON §5.5），
  running/paused_for_approval → aborted。
- T6/T7 的领域性触发条件（无矛盾结论、抽检合格、缺陷为零）属验收器组件语义，MVP 内核
  部分的守卫为转移表合法性 + 可库内验证的条件（T5 的子任务终态收敛检查）；领域条件由
  组件经 transition_request 请求（§3.3 单一驱动者），引擎只校验转移合法性。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from app.engine.db import (
    Database,
    emit_event,
    iso_shift,
    json_dumps,
    new_ulid,
    utc_now_iso,
)

# ---------------------------------------------------------------------------
# 超时与重试常量（sys-arch §3.2 超时兜底列；interface-contracts §13.1；单位：秒）
# ---------------------------------------------------------------------------

TASK_PENDING_TIMEOUT = 5 * 60          # T1 兜底：pending 停留 > 5m 且引擎健康 → 强制领取
PLANNING_TIMEOUT = 10 * 60             # T2 兜底：planning > 10m 重试 1 次；再超时 → failed（签名 planning_timeout）
REVIEW_TIMEOUT = 15 * 60               # T6 兜底：reviewing > 15m 重试 1 次；再超时 → 人工升级事件 + 保持 reviewing
REWORK_TIMEOUT = 10 * 60               # T8 兜底：rework > 10m 未领取 → 重复派发；3 次派发失败 → failed
SUBTASK_RUNNING_TIMEOUT = 60 * 60      # T5 兜底：子任务 running > 60m → 定点取消重派（计入重试）
APPROVAL_DEFAULT_WAIT = 24 * 60 * 60   # T4/§5.3：审批默认等待期 24h，到期走超时兜底分支
MAX_RETRIES = 2                        # T5：重试超 2 → 子任务 failed 并连带分组决策（ICON §13.1）
PLANNING_MAX_RETRIES = 1               # T2：重试 1 次
REWORK_MAX_REDISPATCH = 3              # T8：3 次派发失败 → failed


# ---------------------------------------------------------------------------
# 状态集合（sys-arch §3.1）
# ---------------------------------------------------------------------------

class TaskStatus(str, Enum):
    """主任务九态（sys-arch §3.1 状态集合）。"""

    PENDING = "pending"
    PLANNING = "planning"
    PAUSED_FOR_APPROVAL = "paused_for_approval"
    RUNNING = "running"
    REVIEWING = "reviewing"
    REWORK = "rework"
    DONE = "done"
    FAILED = "failed"
    ABORTED = "aborted"


TASK_TERMINAL_STATES = frozenset({TaskStatus.DONE, TaskStatus.FAILED, TaskStatus.ABORTED})


class SubtaskStatus(str, Enum):
    """子任务状态集：sys-arch §3.2 各行 (sub) 层级的归纳（无 reviewing——T5/T6/T7 均 (top)）。

    规划器产出任务树落库（§9.1「落任务树（transitions T2）」）时子任务初始态为 planning；
    pending 留给「仅登记、尚未拆解」的占位形态。
    """

    PENDING = "pending"
    PLANNING = "planning"
    RUNNING = "running"
    PAUSED_FOR_APPROVAL = "paused_for_approval"
    REWORK = "rework"
    DONE = "done"
    FAILED = "failed"
    ABORTED = "aborted"


SUBTASK_TERMINAL_STATES = frozenset({SubtaskStatus.DONE, SubtaskStatus.FAILED, SubtaskStatus.ABORTED})


# ---------------------------------------------------------------------------
# 转移表（sys-arch §3.2）
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Transition:
    """一条状态转移的定义（sys-arch §3.2 一行）。"""

    tid: str
    from_states: frozenset[TaskStatus]
    to_states: frozenset[TaskStatus]
    layer: str
    description: str

    def allows(self, current: TaskStatus, target: TaskStatus) -> bool:
        return current in self.from_states and target in self.to_states


TRANSITIONS: dict[str, Transition] = {
    "T1": Transition(
        "T1", frozenset({TaskStatus.PENDING}), frozenset({TaskStatus.PLANNING}), "top",
        "编排引擎领取任务：存在且无依赖阻塞；先强制检索错误账本，命中规则注入规划上下文"
        "（兜底：pending > TASK_PENDING_TIMEOUT 且引擎健康 → 强制领取）"),
    "T2": Transition(
        "T2", frozenset({TaskStatus.PLANNING}), frozenset({TaskStatus.RUNNING}), "top+sub",
        "规划器产出任务树 + 分组 + 自包含 brief + 风险分级，落库成功"
        "（兜底：planning > PLANNING_TIMEOUT 重试 1 次；再超时 → failed，签名 planning_timeout）"),
    "T3": Transition(
        "T3", frozenset({TaskStatus.RUNNING}), frozenset({TaskStatus.PAUSED_FOR_APPROVAL}), "top+sub",
        "执行路径命中风险动作（§5.1 分级表）：暂停所在任务链，渲染草稿表单，启动默认等待期"),
    "T4": Transition(
        "T4", frozenset({TaskStatus.PAUSED_FOR_APPROVAL}), frozenset({TaskStatus.RUNNING, TaskStatus.DONE}), "top+sub",
        "用户裁决：批准 → 按原计划继续；采用编辑版 → 以编辑后载荷继续；重生成 → 回动作生成步"
        "局部回退；done = 拒绝链。兜底：APPROVAL_DEFAULT_WAIT 到期走超时兜底分支（§5.3）"),
    "T5": Transition(
        "T5", frozenset({TaskStatus.RUNNING}), frozenset({TaskStatus.REVIEWING}), "top",
        "该任务全部子任务到达自身终态（done/failed 按分组策略收敛）"
        "（兜底：子任务卡 running > SUBTASK_RUNNING_TIMEOUT → 定点干预取消重派）"),
    "T6": Transition(
        "T6", frozenset({TaskStatus.REVIEWING}), frozenset({TaskStatus.DONE}), "top",
        "验收器交叉验证通过：无矛盾结论、抽检合格、质量缺陷为零（或已修复复验）"
        "（兜底：reviewing > REVIEW_TIMEOUT 重试 1 次；再超时 → 人工升级事件 + 保持 reviewing）"),
    "T7": Transition(
        "T7", frozenset({TaskStatus.REVIEWING}), frozenset({TaskStatus.REWORK}), "top",
        "验收发现可修复缺陷：生成定点返工指令，缺陷同步登记错误账本"
        "（兜底：返工指令生成失败 → 直接 failed 并登记）"),
    "T8": Transition(
        "T8", frozenset({TaskStatus.REWORK}), frozenset({TaskStatus.RUNNING}), "top+sub",
        "编排引擎按返工指令拆出/唤醒对应子任务，携带返工 brief 重新入列"
        "（兜底：rework > REWORK_TIMEOUT 未被领取 → 重复派发；3 次派发失败 → failed）"),
    "T9": Transition(
        "T9", frozenset({TaskStatus.RUNNING, TaskStatus.REVIEWING, TaskStatus.REWORK}), frozenset({TaskStatus.ABORTED}), "top",
        "用户主动中止；或可观测台预算熔断（§7.4）触发系统级中止。"
        "注意：§3.2 未给 paused_for_approval/planning/pending 的中止路径（设计缺口，如实保留）"),
    "T10": Transition(
        "T10", frozenset(s for s in TaskStatus if s not in TASK_TERMINAL_STATES), frozenset({TaskStatus.FAILED}), "top+sub",
        "不可恢复错误：LLM 网关持续不可用、组件崩溃退出被 compose 重启 3 次内未自愈、SQLite 损坏"),
}

SUBTASK_TRANSITIONS: dict[str, Transition] = {
    "T2": Transition(
        "T2", frozenset({SubtaskStatus.PLANNING}), frozenset({SubtaskStatus.RUNNING}), "sub",
        "子任务随规划落库后派发执行（sys-arch §3.2 T2 的 (sub) 层级）"),
    "T3": Transition(
        "T3", frozenset({SubtaskStatus.RUNNING}), frozenset({SubtaskStatus.PAUSED_FOR_APPROVAL}), "sub",
        "子任务执行路径命中风险动作（sys-arch §3.2 T3 的 (sub) 层级）"),
    "T4": Transition(
        "T4", frozenset({SubtaskStatus.PAUSED_FOR_APPROVAL}), frozenset({SubtaskStatus.RUNNING}), "sub",
        "审批裁决后按原计划/编辑版继续或局部回退（sys-arch §3.2 T4 的 (sub) 层级）"),
    "T5": Transition(
        "T5", frozenset({SubtaskStatus.RUNNING}), frozenset({SubtaskStatus.DONE}), "sub",
        "子任务到达自身终态 done——sys-arch §3.2 T5「全部子任务到达自身终态」收敛的前提"),
    "T8": Transition(
        "T8", frozenset({SubtaskStatus.REWORK}), frozenset({SubtaskStatus.RUNNING}), "sub",
        "返工指令定点唤醒子任务，携带返工 brief 重新入列（sys-arch §3.2 T8 的 (sub) 层级）"),
    "T9": Transition(
        "T9", frozenset({SubtaskStatus.RUNNING, SubtaskStatus.PAUSED_FOR_APPROVAL}), frozenset({SubtaskStatus.ABORTED}), "sub",
        "主任务 T9 中止时对运行中子任务的定点取消（interface-contracts §5.5）"),
    "T10": Transition(
        "T10", frozenset(s for s in SubtaskStatus if s not in SUBTASK_TERMINAL_STATES), frozenset({SubtaskStatus.FAILED}), "sub",
        "不可恢复错误（sys-arch §3.2 T10 的 (sub) 层级）"),
}


class InvalidTransitionError(ValueError):
    """违反 sys-arch §3.2 转移表的转移请求（守卫拒绝）。"""


def _coerce_task_status(status: TaskStatus | str) -> TaskStatus:
    if isinstance(status, TaskStatus):
        return status
    try:
        return TaskStatus(str(status))
    except ValueError as exc:
        valid = ",".join(s.value for s in TaskStatus)
        raise InvalidTransitionError(f"unknown task status {status!r}; valid: {valid}") from exc


def _coerce_subtask_status(status: SubtaskStatus | str) -> SubtaskStatus:
    if isinstance(status, SubtaskStatus):
        return status
    try:
        return SubtaskStatus(str(status))
    except ValueError as exc:
        valid = ",".join(s.value for s in SubtaskStatus)
        raise InvalidTransitionError(f"unknown subtask status {status!r}; valid: {valid}") from exc


def find_transition(current: TaskStatus, target: TaskStatus) -> Transition:
    """在主任务转移表中查找 (current → target) 的转移定义；无则守卫拒绝。"""
    for transition in TRANSITIONS.values():
        if transition.allows(current, target):
            return transition
    raise InvalidTransitionError(
        f"no transition {current.value} -> {target.value} (sys-arch §3.2)"
    )


def find_subtask_transition(current: SubtaskStatus, target: SubtaskStatus) -> Transition:
    for transition in SUBTASK_TRANSITIONS.values():
        if transition.allows(current, target):
            return transition
    raise InvalidTransitionError(
        f"no subtask transition {current.value} -> {target.value} (sys-arch §3.2 (sub) rows)"
    )


# ---------------------------------------------------------------------------
# task_transitions 表（sys-arch §3.2；deployment-ops §5.1：状态机模块按需建表，
# 时机 = 首次转移写入前）
# ---------------------------------------------------------------------------

_TRANSITION_TABLE_STATEMENTS: tuple[str, ...] = (
    """
    CREATE TABLE IF NOT EXISTS task_transitions (
      id           INTEGER PRIMARY KEY AUTOINCREMENT,
      ts           TEXT NOT NULL,
      task_id      TEXT NOT NULL,
      subtask_id   TEXT,
      transition   TEXT NOT NULL,
      from_status  TEXT NOT NULL,
      to_status    TEXT NOT NULL,
      layer        TEXT NOT NULL,
      reason       TEXT,
      component    TEXT NOT NULL,
      event_id     TEXT NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_task_transitions_task ON task_transitions(task_id, ts)",
)


def _ensure_transition_table(conn: Any) -> None:
    for stmt in _TRANSITION_TABLE_STATEMENTS:
        conn.execute(stmt)


# ---------------------------------------------------------------------------
# 任务树创建（编排引擎 intake / 规划器落库；sys-arch §9.1「写 tasks(pending) + 事件」）
# ---------------------------------------------------------------------------

def create_task(
    database: Database,
    *,
    title: str,
    goal: str,
    correlation_id: str | None = None,
    risk_level: str = "medium",
    source: str = "user",
    budget_usd: float | None = None,
    task_id: str | None = None,
    now: str | None = None,
) -> str:
    """建立任务记录（pending）并落 task_created 事件（sys-arch §9.1 第一步）。"""
    if not title.strip() or not goal.strip():
        raise ValueError("title and goal must be non-empty (ICON §5.1 GOAL_EMPTY)")
    now_ts = now or utc_now_iso()
    tid = task_id or "task-" + new_ulid()
    corr = correlation_id or new_ulid()
    with database.transaction() as conn:
        conn.execute(
            "INSERT INTO tasks (id, title, goal, status, correlation_id, risk_level, source,"
            " budget_usd, status_changed_at, created_at, updated_at)"
            " VALUES (?, ?, ?, 'pending', ?, ?, ?, ?, ?, ?, ?)",
            (tid, title, goal, corr, risk_level, source, budget_usd, now_ts, now_ts, now_ts),
        )
        emit_event(conn, task_id=tid, component="orchestrator", event_type="task_created",
                   correlation_id=corr,
                   payload={"title": title, "source": source, "risk_level": risk_level})
    return tid


def create_group(
    database: Database,
    task_id: str,
    *,
    name: str,
    group_id: str | None = None,
    depends_on: list[str] | None = None,
    batch_mode: bool = False,
    batch_total_items: int | None = None,
    partial_ok: bool = False,
    now: str | None = None,
) -> str:
    """建立分组（sys-arch §4.1：规划器按阶段/依赖划分的执行单元，组间依赖构成 DAG）。"""
    now_ts = now or utc_now_iso()
    gid = group_id or "g-" + new_ulid()
    with database.transaction() as conn:
        row = conn.execute("SELECT correlation_id FROM tasks WHERE id = ?", (task_id,)).fetchone()
        if row is None:
            raise KeyError(f"task not found: {task_id}")
        conn.execute(
            "INSERT INTO groups (id, task_id, name, depends_on, batch_mode, batch_total_items,"
            " partial_ok, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (gid, task_id, name, json_dumps(list(depends_on or [])), int(batch_mode),
             batch_total_items, int(partial_ok), now_ts, now_ts),
        )
        emit_event(conn, task_id=task_id, component="planner", event_type="group_created",
                   correlation_id=row["correlation_id"],
                   payload={"group_id": gid, "name": name, "depends_on": list(depends_on or []),
                            "batch_mode": batch_mode, "partial_ok": partial_ok})
    return gid


def create_subtask(
    database: Database,
    task_id: str,
    group_id: str,
    *,
    objective: str,
    subtask_id: str | None = None,
    status: SubtaskStatus | str = SubtaskStatus.PLANNING,
    risk_tier_hint: str | None = None,
    brief_version: int = 1,
    deliverable_path: str | None = None,
    now: str | None = None,
) -> str:
    """建立子任务（sys-arch §4.1 最小执行单元；规划落库后初始态 planning，派发走 T2）。"""
    now_ts = now or utc_now_iso()
    sid = subtask_id or "sub-" + new_ulid()
    status_value = _coerce_subtask_status(status).value
    with database.transaction() as conn:
        row = conn.execute("SELECT correlation_id FROM tasks WHERE id = ?", (task_id,)).fetchone()
        if row is None:
            raise KeyError(f"task not found: {task_id}")
        conn.execute(
            "INSERT INTO subtasks (id, task_id, group_id, objective, status, brief_version,"
            " risk_tier_hint, deliverable_path, status_changed_at, created_at, updated_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (sid, task_id, group_id, objective, status_value, brief_version, risk_tier_hint,
             deliverable_path, now_ts, now_ts, now_ts),
        )
        emit_event(conn, task_id=task_id, component="planner", event_type="subtask_created",
                   correlation_id=row["correlation_id"],
                   payload={"subtask_id": sid, "group_id": group_id, "objective": objective,
                            "status": status_value})
    return sid


# ---------------------------------------------------------------------------
# 状态转移执行（sys-arch §3.3：单一驱动者 + 转移原子性）
# ---------------------------------------------------------------------------

def transition_task(
    database: Database,
    task_id: str,
    target: TaskStatus | str,
    *,
    component: str,
    reason: str = "",
    status_detail: dict[str, Any] | None = None,
    event_payload: dict[str, Any] | None = None,
    now: str | None = None,
) -> str:
    """执行主任务状态转移，返回关联 event_id。

    - 守卫：sys-arch §3.2 转移表合法性；终态锁定；T5 追加「全部子任务到达自身终态」
      库内可验证条件；
    - 原子性：状态变更 + task_transitions 行 + state_transition 事件在同一 SQLite
      事务内（sys-arch §3.3）；
    - 单一驱动者：非引擎组件应以 request_transition() 发 transition_request 事件，
      由引擎校验后调用本函数执行。
    """
    target_status = _coerce_task_status(target)
    now_ts = now or utc_now_iso()
    with database.transaction() as conn:
        row = conn.execute(
            "SELECT id, status, correlation_id, status_detail FROM tasks WHERE id = ?", (task_id,)
        ).fetchone()
        if row is None:
            raise KeyError(f"task not found: {task_id}")
        current = _coerce_task_status(row["status"])
        if current in TASK_TERMINAL_STATES and target_status is not current:
            raise InvalidTransitionError(
                f"task {task_id} already terminal ({current.value}); no exit from terminal states"
            )
        transition = find_transition(current, target_status)
        if transition.tid == "T5":
            non_terminal = conn.execute(
                "SELECT COUNT(*) AS n FROM subtasks WHERE task_id = ?"
                " AND status NOT IN ('done','failed','aborted')",
                (task_id,),
            ).fetchone()["n"]
            if int(non_terminal):
                raise InvalidTransitionError(
                    f"T5 guard: task {task_id} has {int(non_terminal)} non-terminal subtask(s)"
                    " (sys-arch §3.2 T5: 全部子任务到达自身终态)"
                )
        event_id = emit_event(
            conn, task_id=task_id, component=component, event_type="state_transition",
            correlation_id=row["correlation_id"],
            payload={"transition": transition.tid, "layer": "top",
                     "from": current.value, "to": target_status.value,
                     "reason": reason, **(event_payload or {})},
        )
        conn.execute(
            "UPDATE tasks SET status = ?, status_detail = ?, status_changed_at = ?, updated_at = ?"
            " WHERE id = ?",
            (target_status.value,
             json_dumps(status_detail) if status_detail is not None else None,
             now_ts, now_ts, task_id),
        )
        _ensure_transition_table(conn)
        conn.execute(
            "INSERT INTO task_transitions (ts, task_id, subtask_id, transition, from_status,"
            " to_status, layer, reason, component, event_id) VALUES (?, ?, NULL, ?, ?, ?, ?, ?, ?, ?)",
            (now_ts, task_id, transition.tid, current.value, target_status.value,
             transition.layer, reason or None, component, event_id),
        )
    return event_id


def transition_subtask(
    database: Database,
    subtask_id: str,
    target: SubtaskStatus | str,
    *,
    component: str,
    reason: str = "",
    status_detail: dict[str, Any] | None = None,
    event_payload: dict[str, Any] | None = None,
    now: str | None = None,
) -> str:
    """执行子任务状态转移（(sub) 层级转移表；同样满足转移原子性）。"""
    target_status = _coerce_subtask_status(target)
    now_ts = now or utc_now_iso()
    with database.transaction() as conn:
        row = conn.execute("SELECT id, task_id, status FROM subtasks WHERE id = ?", (subtask_id,)).fetchone()
        if row is None:
            raise KeyError(f"subtask not found: {subtask_id}")
        current = _coerce_subtask_status(row["status"])
        if current in SUBTASK_TERMINAL_STATES and target_status is not current:
            raise InvalidTransitionError(
                f"subtask {subtask_id} already terminal ({current.value})"
            )
        transition = find_subtask_transition(current, target_status)
        event_id = emit_event(
            conn, task_id=row["task_id"], component=component, event_type="state_transition",
            payload={"transition": transition.tid, "layer": "sub", "subtask_id": subtask_id,
                     "from": current.value, "to": target_status.value,
                     "reason": reason, **(event_payload or {})},
        )
        conn.execute(
            "UPDATE subtasks SET status = ?, status_detail = ?, status_changed_at = ?, updated_at = ?"
            " WHERE id = ?",
            (target_status.value,
             json_dumps(status_detail) if status_detail is not None else None,
             now_ts, now_ts, subtask_id),
        )
        _ensure_transition_table(conn)
        conn.execute(
            "INSERT INTO task_transitions (ts, task_id, subtask_id, transition, from_status,"
            " to_status, layer, reason, component, event_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (now_ts, row["task_id"], subtask_id, transition.tid, current.value,
             target_status.value, transition.layer, reason or None, component, event_id),
        )
    return event_id


def request_transition(
    database: Database,
    task_id: str,
    target: TaskStatus | str,
    *,
    component: str,
    reason: str = "",
    now: str | None = None,
) -> str:
    """非引擎组件的状态变更请求（sys-arch §3.3 单一驱动者：只发 transition_request 事件，
    由引擎校验合法性后执行；本函数同时预校验转移合法性，让非法请求尽早暴露）。"""
    now_ts = now or utc_now_iso()
    with database.transaction() as conn:
        row = conn.execute("SELECT status, correlation_id FROM tasks WHERE id = ?", (task_id,)).fetchone()
        if row is None:
            raise KeyError(f"task not found: {task_id}")
        find_transition(_coerce_task_status(row["status"]), _coerce_task_status(target))
        event_id = emit_event(
            conn, task_id=task_id, component=component, event_type="transition_request",
            correlation_id=row["correlation_id"],
            payload={"to": _coerce_task_status(target).value, "reason": reason},
        )
    return event_id


# ---------------------------------------------------------------------------
# T11 done 终态回调（sys-arch §3.2 T11）
# ---------------------------------------------------------------------------

def done_callback(database: Database, task_id: str, *, now: str | None = None) -> str:
    """done 终态回调：触发错误账本规则沉淀检查事件（沉淀执行在 ledger.consolidation_check）。

    成本账固化 task_metrics 归可观测台计量面（sys-arch §7.3），不在本 ask 范围。
    """
    now_ts = now or utc_now_iso()
    with database.transaction() as conn:
        row = conn.execute("SELECT status, correlation_id FROM tasks WHERE id = ?", (task_id,)).fetchone()
        if row is None:
            raise KeyError(f"task not found: {task_id}")
        if _coerce_task_status(row["status"]) is not TaskStatus.DONE:
            raise InvalidTransitionError(f"T11 callback requires status=done, got {row['status']}")
        event_id = emit_event(
            conn, task_id=task_id, component="orchestrator",
            event_type="ledger_consolidation_check", correlation_id=row["correlation_id"],
            ts=now_ts,
            payload={"note": "T11: 同签名滑窗 ≥2 次 → 候选规则 → 人工审核位（memory-design §5）"},
        )
    return event_id


# ---------------------------------------------------------------------------
# 审批域 T3/T4 落点（sys-arch §5.2/§5.3；ICON §6.1–§6.3）
# ---------------------------------------------------------------------------

def open_approval(
    database: Database,
    task_id: str,
    *,
    action_type: str,
    risk_tier: str,
    summary: str,
    payload: dict[str, Any] | None = None,
    evidence: dict[str, Any] | None = None,
    subtask_id: str | None = None,
    timeout_fallback: str = "skip_and_continue",
    wait_seconds: int = APPROVAL_DEFAULT_WAIT,
    component: str = "approval_gate",
    now: str | None = None,
) -> str:
    """R2（及 R1 联动升级）动作拦截：approval 行 + 主任务 T3 → paused_for_approval（同一事务）。

    付款类动作的超时兜底为 skip_strict（sys-arch §5.3：不降级执行也不换路径，直接跳过）；
    付款类判定规则归审批门/global.yaml（rules-config §2.1），本层以 timeout_fallback
    显式传参承接，不擅自发明 action_type 判定。
    """
    if risk_tier not in ("irreversible", "reversible_costly", "reversible"):
        raise ValueError(f"risk_tier must be one of irreversible/reversible_costly/reversible, got {risk_tier!r}")
    if timeout_fallback not in ("skip_and_continue", "skip_strict"):
        raise ValueError(f"timeout_fallback must be skip_and_continue/skip_strict, got {timeout_fallback!r}")
    now_ts = now or utc_now_iso()
    approval_id = "apr-" + new_ulid()
    # 审批行 + T3 转移 + 事件在同一事务内（sys-arch §3.3 转移原子性；嵌套事务并入外层）
    with database.transaction() as conn:
        row = conn.execute("SELECT correlation_id FROM tasks WHERE id = ?", (task_id,)).fetchone()
        if row is None:
            raise KeyError(f"task not found: {task_id}")
        conn.execute(
            "INSERT INTO approvals (id, task_id, subtask_id, correlation_id, status, action_type,"
            " risk_tier, summary, payload, evidence, wait_expires_at, timeout_fallback,"
            " created_at, updated_at) VALUES (?, ?, ?, ?, 'waiting', ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (approval_id, task_id, subtask_id, row["correlation_id"], action_type, risk_tier,
             summary, json_dumps(payload or {}), json_dumps(evidence or {}),
             iso_shift(now_ts, wait_seconds), timeout_fallback, now_ts, now_ts),
        )
        emit_event(conn, task_id=task_id, component=component, event_type="approval_requested",
                   correlation_id=row["correlation_id"],
                   payload={"approval_id": approval_id, "action_type": action_type,
                            "risk_tier": risk_tier, "summary": summary,
                            "timeout_fallback": timeout_fallback,
                            "wait_expires_at": iso_shift(now_ts, wait_seconds)})
        transition_task(
            database, task_id, TaskStatus.PAUSED_FOR_APPROVAL,
            component=component, reason=f"approval {approval_id} ({action_type})",
            status_detail={"waiting_approval_id": approval_id},
            event_payload={"approval_id": approval_id, "action_type": action_type},
            now=now_ts,
        )
    return approval_id


def decide_approval(
    database: Database,
    approval_id: str,
    action: str,
    *,
    edited_payload: dict[str, Any] | None = None,
    comment: str | None = None,
    decided_by: str | None = None,
    now: str | None = None,
) -> dict[str, Any]:
    """T4 三按钮裁决（sys-arch §5.2；ICON §6.3 必填校验）。

    approve / use_edited → 按载荷继续（任务 T4 → running）；regenerate → 携批注退回
    动作生成步（T4 → running，running 内局部回退，status_detail 记录回退标记）。
    T4 的 done（拒绝链）去向不在三按钮内，未实现（如实保留）。
    """
    if action not in ("approve", "use_edited", "regenerate"):
        raise ValueError(f"action must be approve/use_edited/regenerate, got {action!r}")
    if action == "use_edited" and not edited_payload:
        raise ValueError("edited_payload required for use_edited (ICON §6.3 EDITED_PAYLOAD_REQUIRED)")
    if action == "regenerate" and not (comment or "").strip():
        raise ValueError("comment required for regenerate (ICON §6.3 COMMENT_REQUIRED)")
    now_ts = now or utc_now_iso()
    with database.transaction() as conn:
        row = conn.execute("SELECT * FROM approvals WHERE id = ?", (approval_id,)).fetchone()
        if row is None:
            raise KeyError(f"approval not found: {approval_id}")
        if row["status"] != "waiting":
            raise InvalidTransitionError(f"approval {approval_id} not waiting (status={row['status']})")
        conn.execute(
            "UPDATE approvals SET status = 'decided', decision = ?, decision_comment = ?,"
            " edited_payload = ?, decided_by = ?, decided_at = ?, updated_at = ? WHERE id = ?",
            (action, comment, json_dumps(edited_payload) if edited_payload is not None else None,
             decided_by, now_ts, now_ts, approval_id),
        )
        decision_event_id = emit_event(
            conn, task_id=row["task_id"], component="approval_gate",
            event_type="approval_decision", correlation_id=row["correlation_id"],
            payload={"approval_id": approval_id, "decision": action,
                     "action_type": row["action_type"], "risk_tier": row["risk_tier"],
                     "has_edited_payload": edited_payload is not None,
                     "comment": comment, "decided_by": decided_by})
        task_id = row["task_id"]
    status_detail = (
        {"resolved_approval_id": approval_id, "decision": action, "regenerated": True}
        if action == "regenerate" else None
    )
    transition_task(
        database, task_id, TaskStatus.RUNNING,
        component="approval_gate", reason=f"approval {approval_id} decided: {action}",
        status_detail=status_detail,
        event_payload={"approval_id": approval_id, "decision": action},
        now=now_ts,
    )
    new_approval_id = None
    if action == "regenerate":
        # ICON §6.3：草稿重出后产生新的 approval_id（旧 ID 永不复用）——
        # MVP 重出 = 同载荷新行回到 waiting（重出内容由规划器接线后续项）
        new_approval_id = _clone_approval_for_regeneration(database, approval_id, now_ts)
    return {"approval_id": approval_id, "decision": action, "task_id": task_id,
            "task_status": TaskStatus.RUNNING.value,
            "decision_recorded_event_id": decision_event_id,
            "new_approval_id": new_approval_id}


def _clone_approval_for_regeneration(database: Database, old_approval_id: str,
                                      now_ts: str) -> str:
    """regenerate 的草稿重出落点：按旧行克隆一条新 waiting 审批（载荷原样、旧 id 永不复用）。"""
    with database.transaction() as conn:
        old = conn.execute("SELECT * FROM approvals WHERE id = ?", (old_approval_id,)).fetchone()
        new_id = "apr-" + new_ulid()
        conn.execute(
            "INSERT INTO approvals (id, task_id, subtask_id, correlation_id, status,"
            " action_type, risk_tier, summary, payload, evidence, wait_expires_at,"
            " timeout_fallback, created_at, updated_at)"
            " VALUES (?, ?, ?, ?, 'waiting', ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (new_id, old["task_id"], old["subtask_id"], old["correlation_id"],
             old["action_type"], old["risk_tier"], old["summary"] + "（重出草稿）",
             old["payload"], old["evidence"],
             iso_shift(now_ts, APPROVAL_DEFAULT_WAIT), old["timeout_fallback"],
             now_ts, now_ts),
        )
        emit_event(conn, task_id=old["task_id"], component="approval_gate",
                   event_type="approval_requested",
                   correlation_id=old["correlation_id"],
                   payload={"approval_id": new_id, "action_type": old["action_type"],
                            "risk_tier": old["risk_tier"], "summary": old["summary"],
                            "regenerated_from": old_approval_id,
                            "wait_expires_at": iso_shift(now_ts, APPROVAL_DEFAULT_WAIT)})
    return new_id


# ---------------------------------------------------------------------------
# 超时兜底统一扫描（sys-arch §3.3：引擎内一个定时扫描器按 §3.2 超时列逐一核对）
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class TimeoutAction:
    """一次超时兜底动作提案（扫描只读，执行经 apply_timeout_action 落库且动作本身落事件）。"""

    kind: str
    ref_id: str
    transition: str | None
    event_type: str
    payload: dict[str, Any] = field(default_factory=dict)
    description: str = ""


def _count_events(conn: Any, task_id: str, event_type: str) -> int:
    return int(conn.execute(
        "SELECT COUNT(*) AS n FROM events WHERE task_id = ? AND event_type = ?",
        (task_id, event_type),
    ).fetchone()["n"])


def scan_timeouts(database: Database, now: str | None = None) -> list[TimeoutAction]:
    """按 sys-arch §3.2 超时兜底列逐一核对（只读；返回动作清单，不直接改状态）。"""
    now_ts = now or utc_now_iso()
    actions: list[TimeoutAction] = []

    def cutoff(seconds: float) -> str:
        return iso_shift(now_ts, -seconds)

    with database.transaction() as conn:
        # T1 兜底：pending 停留超时且引擎健康 → 强制领取
        for row in conn.execute(
            "SELECT id FROM tasks WHERE status = 'pending' AND status_changed_at < ?",
            (cutoff(TASK_PENDING_TIMEOUT),),
        ).fetchall():
            actions.append(TimeoutAction(
                "pending_force_claim", row["id"], "T1", "state_transition",
                {"transition": "T1", "fallback": "pending_timeout_force_claim"},
                "T1 兜底：pending 超时强制领取（引擎健康分支）"))
        # T2 兜底：planning 超时 → 重试 1 次；再超时 → failed + 错误登记（签名 planning_timeout）
        for row in conn.execute(
            "SELECT id FROM tasks WHERE status = 'planning' AND status_changed_at < ?",
            (cutoff(PLANNING_TIMEOUT),),
        ).fetchall():
            retries = _count_events(conn, row["id"], "planning_timeout")
            if retries < PLANNING_MAX_RETRIES:
                actions.append(TimeoutAction(
                    "planning_timeout_retry", row["id"], None, "planning_timeout", {},
                    "T2 兜底：planning 超时，重试 1 次（重置计时）"))
            else:
                actions.append(TimeoutAction(
                    "planning_timeout_failed", row["id"], "T10", "planning_timeout", {},
                    "T2 兜底：重试后再超时 → failed，错误登记错误账本（签名 planning_timeout）"))
        # T6 兜底：reviewing 超时 → 重试 1 次；再超时 → 人工升级事件 + 保持 reviewing（防误杀）
        for row in conn.execute(
            "SELECT id FROM tasks WHERE status = 'reviewing' AND status_changed_at < ?",
            (cutoff(REVIEW_TIMEOUT),),
        ).fetchall():
            if _count_events(conn, row["id"], "review_timeout") < 1:
                actions.append(TimeoutAction(
                    "review_timeout_retry", row["id"], None, "review_timeout", {},
                    "T6 兜底：reviewing 超时，重试 1 次（重置计时）"))
            elif _count_events(conn, row["id"], "review_timeout_escalate") == 0:
                actions.append(TimeoutAction(
                    "review_timeout_escalate", row["id"], None, "review_timeout_escalate",
                    {"needs_human": True},
                    "T6 兜底：再超时 → 人工升级事件（needs_human 标记）+ 保持 reviewing"))
        # T8 兜底：rework 超时未领取 → 重复派发；3 次派发失败 → failed
        for row in conn.execute(
            "SELECT id FROM tasks WHERE status = 'rework' AND status_changed_at < ?",
            (cutoff(REWORK_TIMEOUT),),
        ).fetchall():
            dispatches = _count_events(conn, row["id"], "rework_redispatch")
            if dispatches < REWORK_MAX_REDISPATCH:
                actions.append(TimeoutAction(
                    "rework_redispatch", row["id"], None, "rework_redispatch", {},
                    "T8 兜底：rework 超时未领取，重复派发（重置计时）"))
            else:
                actions.append(TimeoutAction(
                    "rework_failed", row["id"], "T10", "rework_timeout", {},
                    "T8 兜底：3 次派发失败 → failed"))
        # T5 兜底：子任务卡 running 超时 → 定点取消重派（计入重试）；重试超 MAX_RETRIES → failed
        for row in conn.execute(
            "SELECT id, task_id, attempts FROM subtasks WHERE status = 'running'"
            " AND status_changed_at < ?",
            (cutoff(SUBTASK_RUNNING_TIMEOUT),),
        ).fetchall():
            payload = {"subtask_id": row["id"], "task_id": row["task_id"], "attempts": int(row["attempts"])}
            if int(row["attempts"]) < MAX_RETRIES:
                actions.append(TimeoutAction(
                    "subtask_redispatch", row["id"], None, "subtask_redispatch", payload,
                    "T5 兜底：子任务 running 超时，定点取消重派（计入重试）"))
            else:
                actions.append(TimeoutAction(
                    "subtask_failed", row["id"], "T10", "subtask_timeout", payload,
                    "T5 兜底：重试超 MAX_RETRIES → 子任务 failed 并连带分组决策"))
        # T4 兜底：审批默认等待期到期无响应 → 动作不执行（skip），任务链继续推进非风险部分
        for row in conn.execute(
            "SELECT id, task_id, action_type, timeout_fallback FROM approvals"
            " WHERE status = 'waiting' AND wait_expires_at < ?",
            (now_ts,),
        ).fetchall():
            actions.append(TimeoutAction(
                "approval_expired", row["id"], "T4", "approval_timeout_skip",
                {"task_id": row["task_id"], "action_type": row["action_type"],
                 "timeout_fallback": row["timeout_fallback"]},
                "T4 兜底：等待期到期无响应，该动作不执行（§5.3 超时兜底分支）"))
    return actions


def _emit_task_event(database: Database, task_id: str, event_type: str,
                     payload: dict[str, Any], component: str = "orchestrator") -> str:
    with database.transaction() as conn:
        return emit_event(conn, task_id=task_id, component=component,
                          event_type=event_type, payload=payload)


def _reset_state_clock(database: Database, table: str, row_id: str, now_ts: str) -> None:
    if table not in ("tasks", "subtasks"):
        raise ValueError(f"unexpected table for state clock reset: {table}")
    with database.transaction() as conn:
        conn.execute(
            f"UPDATE {table} SET status_changed_at = ?, updated_at = ? WHERE id = ?",
            (now_ts, now_ts, row_id),
        )


def apply_timeout_action(database: Database, action: TimeoutAction, *, now: str | None = None) -> dict[str, Any]:
    """执行一条超时兜底动作（所有超时动作本身落事件，可 replay——sys-arch §3.3）。"""
    now_ts = now or utc_now_iso()
    kind = action.kind

    if kind == "pending_force_claim":
        transition_task(database, action.ref_id, TaskStatus.PLANNING, component="orchestrator",
                        reason="T1 fallback: pending timeout force claim",
                        event_payload={"fallback": kind, **action.payload}, now=now_ts)
        return {"kind": kind, "ref_id": action.ref_id, "status": TaskStatus.PLANNING.value}

    if kind == "planning_timeout_retry":
        _emit_task_event(database, action.ref_id, "planning_timeout",
                         {"fallback": kind, "action": "retry_planning"})
        _reset_state_clock(database, "tasks", action.ref_id, now_ts)
        return {"kind": kind, "ref_id": action.ref_id, "status": TaskStatus.PLANNING.value}

    if kind == "planning_timeout_failed":
        _emit_task_event(database, action.ref_id, "planning_timeout",
                         {"fallback": kind, "action": "give_up"})
        transition_task(database, action.ref_id, TaskStatus.FAILED, component="orchestrator",
                        reason="T2 fallback: planning timeout after retry exhausted",
                        event_payload={"fallback": kind}, now=now_ts)
        # T2 兜底：错误登记错误账本（签名 planning_timeout）——写失败按 memory-design §4 降级，不影响已落状态
        from app.engine import ledger  # 局部导入避免模块环
        entry_id = ledger.ledger_write(
            database, "planning_timeout", "orchestrator", {},
            f"planning exceeded PLANNING_TIMEOUT={PLANNING_TIMEOUT}s after "
            f"{PLANNING_MAX_RETRIES} retry(ies); task failed by T2 fallback",
            action.ref_id, "orchestrator",
        )
        return {"kind": kind, "ref_id": action.ref_id, "status": TaskStatus.FAILED.value,
                "ledger_entry_id": entry_id}

    if kind == "review_timeout_retry":
        _emit_task_event(database, action.ref_id, "review_timeout",
                         {"fallback": kind, "action": "retry_review"})
        _reset_state_clock(database, "tasks", action.ref_id, now_ts)
        return {"kind": kind, "ref_id": action.ref_id, "status": TaskStatus.REVIEWING.value}

    if kind == "review_timeout_escalate":
        _emit_task_event(database, action.ref_id, "review_timeout_escalate",
                         {"fallback": kind, "needs_human": True})
        with database.transaction() as conn:
            conn.execute(
                "UPDATE tasks SET status_detail = ?, updated_at = ? WHERE id = ?",
                (json_dumps({"needs_human": True}), now_ts, action.ref_id),
            )
        return {"kind": kind, "ref_id": action.ref_id, "status": TaskStatus.REVIEWING.value,
                "needs_human": True}

    if kind == "rework_redispatch":
        _emit_task_event(database, action.ref_id, "rework_redispatch",
                         {"fallback": kind, "action": "redispatch_rework"})
        _reset_state_clock(database, "tasks", action.ref_id, now_ts)
        return {"kind": kind, "ref_id": action.ref_id, "status": TaskStatus.REWORK.value}

    if kind == "rework_failed":
        _emit_task_event(database, action.ref_id, "rework_timeout",
                         {"fallback": kind, "action": "give_up"})
        transition_task(database, action.ref_id, TaskStatus.FAILED, component="orchestrator",
                        reason="T8 fallback: rework redispatch failed 3 times",
                        event_payload={"fallback": kind}, now=now_ts)
        return {"kind": kind, "ref_id": action.ref_id, "status": TaskStatus.FAILED.value}

    if kind == "subtask_redispatch":
        with database.transaction() as conn:
            conn.execute(
                "UPDATE subtasks SET attempts = attempts + 1, status_changed_at = ?, updated_at = ?"
                " WHERE id = ?",
                (now_ts, now_ts, action.ref_id),
            )
        _emit_task_event(database, action.payload["task_id"], "subtask_redispatch",
                         {"fallback": kind, "subtask_id": action.ref_id,
                          "attempts": int(action.payload["attempts"]) + 1})
        return {"kind": kind, "ref_id": action.ref_id, "attempts": int(action.payload["attempts"]) + 1}

    if kind == "subtask_failed":
        _emit_task_event(database, action.payload["task_id"], "subtask_timeout",
                         {"fallback": kind, "subtask_id": action.ref_id,
                          "note": "重试超 MAX_RETRIES，子任务 failed 并连带分组决策"})
        transition_subtask(database, action.ref_id, SubtaskStatus.FAILED, component="orchestrator",
                           reason="T5 fallback: subtask running timeout after retries exhausted",
                           event_payload={"fallback": kind}, now=now_ts)
        return {"kind": kind, "ref_id": action.ref_id, "status": SubtaskStatus.FAILED.value}

    if kind == "approval_expired":
        with database.transaction() as conn:
            row = conn.execute(
                "SELECT task_id, action_type, timeout_fallback, correlation_id FROM approvals WHERE id = ?",
                (action.ref_id,),
            ).fetchone()
            if row is None:
                raise KeyError(f"approval not found: {action.ref_id}")
            conn.execute(
                "UPDATE approvals SET status = 'expired', updated_at = ? WHERE id = ?",
                (now_ts, action.ref_id),
            )
            emit_event(conn, task_id=row["task_id"], component="approval_gate",
                       event_type="approval_timeout_skip", correlation_id=row["correlation_id"],
                       payload={"approval_id": action.ref_id, "action_type": row["action_type"],
                                "timeout_fallback": row["timeout_fallback"],
                                "note": "该动作不执行（付款类 skip_strict 同样直接跳过），"
                                        "任务链跳过该动作继续推进可自主推进的部分（sys-arch §5.3）"})
            task_id = row["task_id"]
        transition_task(database, task_id, TaskStatus.RUNNING, component="orchestrator",
                        reason=f"T4 fallback: approval {action.ref_id} expired, action skipped",
                        event_payload={"fallback": kind, "approval_id": action.ref_id}, now=now_ts)
        return {"kind": kind, "ref_id": action.ref_id, "status": TaskStatus.RUNNING.value,
                "task_id": task_id}

    raise ValueError(f"unknown timeout action kind: {kind!r}")


# ---------------------------------------------------------------------------
# 崩溃恢复视图（sys-arch §3.3：进程重启后以库内状态为准重建调度视图）
# ---------------------------------------------------------------------------

def recovery_view(database: Database) -> dict[str, list[dict[str, str]]]:
    """重建调度视图：planning/running/reviewing 幂等续跑；paused_for_approval 原样保留等待用户。"""
    resume: list[dict[str, str]] = []
    waiting_user: list[dict[str, str]] = []
    for row in database.query(
        "SELECT id, status, correlation_id FROM tasks"
        " WHERE status IN ('planning','running','reviewing','paused_for_approval') ORDER BY created_at"
    ):
        item = {"task_id": row["id"], "status": row["status"], "correlation_id": row["correlation_id"]}
        if row["status"] == "paused_for_approval":
            waiting_user.append(item)
        else:
            resume.append(item)
    return {"resume": resume, "waiting_user": waiting_user}
