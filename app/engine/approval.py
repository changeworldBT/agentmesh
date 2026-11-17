"""approval.py — 审批门：risk_flags 分级路由 / pending 审批存储 / 批准·驳回·编辑草稿三动作。

设计文档出处（模块顶部注记，按 ask 要求）：
- sys-arch（ARCH-ROOT-01）§5.1：风险分级表（R2/R1/R0 = irreversible/reversible_costly/
  reversible，权威在 rules global.yaml；规划器预标与审批门实时分级不一致时从严；
  R2 三类默认审批不可被完全关闭——hard_floor；R1 默认自主推进落审计，同签名错误 ≥2 次
  升级审批，参数名 escalate_after_occurrences）；§5.2：可编辑草稿表单 + 三按钮路由
  （批准/采用编辑版/重生成）；§5.3：默认等待期 APPROVAL_DEFAULT_WAIT 与超时兜底分支
  （动作不执行，任务链跳过继续推进非风险部分）；§7.1：审批行为事件化落库可 replay。
- rules-config（RULES-01）§2.1：审批分级匹配表（actions 按工具名+参数模式 `action:*`
  匹配；unclassified_default_tier 安全默认 reversible_costly；irreversible hard_floor
  不得降级；reversible_costly escalate_after_occurrences: 2）。
- interface-contracts（ICON-01）§2：event_type 词表——`approval_requested`、
  `approval_decision`、`approval_timeout_skip`；§6.1–§6.3：approvals 字段、三按钮与
  必填校验（use_edited 必填 edited_payload；regenerate 必填 comment）。
- memory-design §4 矩阵末行：人工审核/裁决动作直接报错给人，无静默降级（人工操作不许
  假成功）。
- state.py：T3（running→paused_for_approval）与 T4（paused→running/done）的转移执行位
  （open_approval/decide_approval 在编排引擎状态机模块）。

偏离与取舍（如实声明）：
- global.yaml 尚未装载（规则装载器属后续交付物）：分级匹配表以 DEFAULT_ACTION_TIERS
  内置常量逐条对齐 rules-config §2.1 的 actions 清单（`pattern:*` 前缀匹配语义），
  overrides 参数预留 global.yaml 热加载接线位；unclassified 默认 reversible_costly
  （rules-config §2.1 安全默认）。
- 驳回（reject）与编辑草稿别名（edit_draft→use_edited）已作为正式契约增补写回
  ICON §6.3（2026-11-17 评审批次）：reject 语义取 sys-arch §5.3 超时兜底分支的人工
  即时版——动作不执行、登记 approval_decision（decision=reject）事件、任务链跳过该
  动作回到 running 继续推进非风险部分。approvals.decision CHECK 相应从 v1 扩容
  （db.py v1→v2 迁移），'regenerate'/'use_edited'（ICON 三按钮名）继续可用。
- 编辑草稿（edit_draft）即 ICON §6.3 的 use_edited（以编辑后载荷为实际执行载荷，§5.2）。
- pending 审批存储复用 ask-1 的 approvals 常驻表（sys-arch §5.3 原名 approval_events
  的归属注记见 db.py docstring）；裁决审计同时落 approval_decision 事件（§7.1）。
"""

from __future__ import annotations

import json
from typing import Any

from app.engine import ledger, state
from app.engine.db import Database, emit_event, utc_now_iso
from app.engine.state import InvalidTransitionError, TaskStatus

# rules-config §2.1 审批分级匹配表（actions 按工具名+参数模式匹配；`pattern:*` → 前缀匹配）
DEFAULT_ACTION_TIERS: tuple[tuple[str, str], ...] = (
    ("email.send", "irreversible"),
    ("payment.pay", "irreversible"),
    ("message.send", "irreversible"),
    ("credential.rotate", "irreversible"),
    ("data.delete_permanent", "irreversible"),
    ("dns.update", "irreversible"),
    ("file.write_outside_workspace", "reversible_costly"),
    ("vps.config_change", "reversible_costly"),
    ("db.migration", "reversible_costly"),
    ("data.delete_bulk", "reversible_costly"),
    ("content.draft_publishable", "reversible_costly"),
    ("file.write_in_workspace", "reversible"),
    ("http.get", "reversible"),
    ("db.read", "reversible"),
    ("memory.write", "reversible"),
    ("ledger.write", "reversible"),
)
UNCLASSIFIED_DEFAULT_TIER = "reversible_costly"  # rules-config §2.1：安全默认
TIER_STRICTNESS = {"reversible": 0, "reversible_costly": 1, "irreversible": 2}
VALID_TIERS = ("irreversible", "reversible_costly", "reversible")


def strictest(a: str, b: str) -> str:
    """两档取严（sys-arch §5.1：预标与实时分级不一致时从严）。"""
    if a not in TIER_STRICTNESS or b not in TIER_STRICTNESS:
        raise ValueError(f"unknown risk tier: {a!r}/{b!r}")
    return a if TIER_STRICTNESS[a] >= TIER_STRICTNESS[b] else b


def resolve_risk_tier(action_type: str, hint: str | None = None,
                      overrides: dict[str, str] | None = None) -> str:
    """解析动作风险档：内置表（+overrides 接线 global.yaml）匹配 `pattern:*` 前缀，
    未命中取安全默认 reversible_costly；与规划器预标 hint 不一致时从严。"""
    action = str(action_type or "").strip()
    if not action:
        raise ValueError("action_type must be non-empty")
    table: dict[str, str] = dict(overrides) if overrides else {}
    for pattern, tier in DEFAULT_ACTION_TIERS:
        table.setdefault(pattern, tier)
    tier: str | None = None
    for pattern, candidate in table.items():
        if candidate not in VALID_TIERS:
            raise ValueError(f"override tier invalid for {pattern!r}: {candidate!r}")
        base = pattern[:-2] if pattern.endswith(":*") else pattern
        if action == base or action.startswith(base + "."):
            if tier is None or TIER_STRICTNESS[candidate] > TIER_STRICTNESS[tier]:
                tier = candidate
    resolved = tier or UNCLASSIFIED_DEFAULT_TIER
    if hint is not None:
        resolved = strictest(resolved, str(hint))
    return resolved


# ---------------------------------------------------------------------------
# 分级路由（本 ask：risk_flags 分级路由）
# ---------------------------------------------------------------------------

def route_action(
    database: Database,
    action_type: str,
    *,
    task_id: str,
    summary: str,
    payload: dict[str, Any] | None = None,
    evidence: dict[str, Any] | None = None,
    subtask_id: str | None = None,
    hint: str | None = None,
    overrides: dict[str, str] | None = None,
    escalate_after_occurrences: int = 2,
    now: str | None = None,
) -> dict[str, Any]:
    """按风险档路由一个执行期动作：

    - irreversible（R2，hard_floor）：必经审批门 → open_approval（T3，paused_for_approval）；
    - reversible_costly（R1）：默认自主推进落审计；错误账本中同签名错误累计
      ≥ escalate_after_occurrences（rules-config §2.1，全时段计数）→ 升级为审批；
    - reversible（R0）：自主推进写事件流即可。

    签名口径：make_signature(action_type, module='approval_gate', params=payload)——
    动作失败登记账本时使用同一 (error_type, module, params) 三元组即可命中升级计数。
    """
    tier = resolve_risk_tier(action_type, hint=hint, overrides=overrides)
    if tier == "irreversible":
        approval_id = state.open_approval(
            database, task_id, action_type=action_type, risk_tier=tier, summary=summary,
            payload=payload, evidence=evidence, subtask_id=subtask_id, now=now,
        )
        return {"route": "approval", "approval_id": approval_id, "risk_tier": tier,
                "reason": "r2_default_gate"}
    params_norm = {str(k): str(v) for k, v in (payload or {}).items()}
    _, signature_hash = ledger.make_signature(action_type, "approval_gate", params_norm)
    occurrences = ledger.count_signature_occurrences(database, signature_hash,
                                                     window_hours=None, now=now)
    if tier == "reversible_costly" and occurrences >= escalate_after_occurrences:
        merged_evidence = dict(evidence or {})
        merged_evidence["escalation"] = {
            "reason": "same_signature_errors",
            "signature_hash": signature_hash,
            "occurrences": occurrences,
            "threshold": escalate_after_occurrences,
        }
        approval_id = state.open_approval(
            database, task_id, action_type=action_type, risk_tier=tier, summary=summary,
            payload=payload, evidence=merged_evidence, subtask_id=subtask_id, now=now,
        )
        return {"route": "approval", "approval_id": approval_id, "risk_tier": tier,
                "reason": "r1_escalated_after_same_signature_errors",
                "signature_occurrences": occurrences, "threshold": escalate_after_occurrences}
    # R0 与未升级 R1：默认自主推进，动作落审计（sys-arch §5.1；ICON §2 词表外增补事件）
    with database.transaction() as conn:
        emit_event(conn, task_id=task_id, component="approval_gate",
                   event_type="action_auto_proceeded",
                   payload={"action_type": action_type, "risk_tier": tier, "summary": summary,
                            "subtask_id": subtask_id, "payload": payload or {},
                            "signature_hash": signature_hash,
                            "signature_occurrences": occurrences})
    return {"route": "auto", "risk_tier": tier, "signature_hash": signature_hash,
            "signature_occurrences": occurrences}


# ---------------------------------------------------------------------------
# 裁决三动作（批准 / 驳回 / 编辑草稿）
# ---------------------------------------------------------------------------

def decide(
    database: Database,
    approval_id: str,
    action: str,
    *,
    edited_payload: dict[str, Any] | None = None,
    comment: str | None = None,
    decided_by: str | None = None,
    now: str | None = None,
) -> dict[str, Any]:
    """审批裁决路由（本 ask 三动作 + ICON §6.3 原生两按钮直通）：

    - approve：按当前草稿原文执行（T4 → running）；
    - edit_draft：以编辑后载荷执行（= ICON use_edited；edited_payload 必填）；
    - reject：动作不执行（§5.3 超时兜底分支的人工即时版），任务链跳过该动作回 running；
    - use_edited / regenerate：ICON §6.3 原生按钮直通 state.decide_approval。

    裁决动作直接报错给人，无静默降级（memory-design §4 末行：人工操作不许假成功）。
    """
    action = str(action)
    if action == "approve":
        return state.decide_approval(database, approval_id, "approve",
                                     decided_by=decided_by, now=now)
    if action == "edit_draft":
        if not edited_payload:
            raise ValueError("edited_payload required for edit_draft (ICON §6.3)")
        return state.decide_approval(database, approval_id, "use_edited",
                                     edited_payload=edited_payload, comment=comment,
                                     decided_by=decided_by, now=now)
    if action == "use_edited":
        return state.decide_approval(database, approval_id, "use_edited",
                                     edited_payload=edited_payload, comment=comment,
                                     decided_by=decided_by, now=now)
    if action == "regenerate":
        return state.decide_approval(database, approval_id, "regenerate", comment=comment,
                                     decided_by=decided_by, now=now)
    if action == "reject":
        return _reject(database, approval_id, comment=comment, decided_by=decided_by, now=now)
    raise ValueError(f"action must be approve/edit_draft/reject (or use_edited/regenerate), got {action!r}")


def _reject(database: Database, approval_id: str, *, comment: str | None,
            decided_by: str | None, now: str | None) -> dict[str, Any]:
    """驳回：动作不执行 + approval_decision(decision=reject) 事件 + T4 → running（跳过该动作继续推进非风险部分）。"""
    now_ts = now or utc_now_iso()
    with database.transaction() as conn:
        row = conn.execute("SELECT * FROM approvals WHERE id = ?", (approval_id,)).fetchone()
        if row is None:
            raise KeyError(f"approval not found: {approval_id}")
        if row["status"] != "waiting":
            raise InvalidTransitionError(
                f"approval {approval_id} not waiting (status={row['status']})")
        conn.execute(
            "UPDATE approvals SET status = 'decided', decision = 'reject', decision_comment = ?,"
            " decided_by = ?, decided_at = ?, updated_at = ? WHERE id = ?",
            (comment, decided_by, now_ts, now_ts, approval_id),
        )
        # ICON §2 词表内事件（decision=reject 为 ICON §6.3 正式增补动作，2026-11-17 已回写契约）
        emit_event(conn, task_id=row["task_id"], component="approval_gate",
                   event_type="approval_decision",
                   payload={"approval_id": approval_id, "decision": "reject",
                            "action_type": row["action_type"],
                            "risk_tier": row["risk_tier"], "decided_by": decided_by,
                            "comment": comment,
                            "note": "动作不执行，任务链跳过该动作继续推进非风险部分（sys-arch §5.3 兜底语义的人工即时版）"})
        task_id = row["task_id"]
        task_status = conn.execute("SELECT status FROM tasks WHERE id = ?", (task_id,)).fetchone()["status"]
    # 仅当任务确实停在 paused_for_approval 时才做 T4 → running（regenerate 后任务已在
    # running，此时 reject 只裁决审批行，任务状态不动——T4 无 running→running 自转移）
    if task_status == TaskStatus.PAUSED_FOR_APPROVAL.value:
        state.transition_task(database, task_id, TaskStatus.RUNNING, component="approval_gate",
                              reason=f"approval {approval_id} rejected: action skipped",
                              status_detail={"rejected_approval_id": approval_id, "action_skipped": True},
                              event_payload={"approval_id": approval_id, "decision": "reject"},
                              now=now_ts)
        final_status = TaskStatus.RUNNING.value  # T4：paused → running（跳过该动作继续推进）
    else:
        final_status = task_status  # regenerate 后已在 running：仅裁决审批行
    return {"approval_id": approval_id, "decision": "reject", "task_id": task_id,
            "task_status": final_status}


def pending_approvals(database: Database, *, task_id: str | None = None,
                      limit: int = 50) -> list[dict[str, Any]]:
    """待裁决审批列表（ICON §6.1 B1 的数据面：status=waiting）。"""
    if task_id is None:
        rows = database.query(
            "SELECT * FROM approvals WHERE status = 'waiting' ORDER BY created_at LIMIT ?",
            (limit,),
        )
    else:
        rows = database.query(
            "SELECT * FROM approvals WHERE status = 'waiting' AND task_id = ? ORDER BY created_at LIMIT ?",
            (task_id, limit),
        )
    items = []
    for row in rows:
        item = dict(row)
        for key in ("payload", "evidence"):
            item[key] = json.loads(str(item[key] or "{}"))
        items.append(item)
    return items
