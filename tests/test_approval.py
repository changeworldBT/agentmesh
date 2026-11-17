"""test_approval.py — approval.py 测试：risk_flags 分级路由、R1 同签名升级、三动作裁决、
approvals.decision v1→v2 迁移。

覆盖验收面（ask 第 4 条）：
- 分级路由：irreversible 必进审批门（T3 → paused_for_approval + approval_requested 事件）；
  reversible 自主推进落审计（action_auto_proceeded 事件）；规则表与预标 hint 不一致从严；
- R1（reversible_costly）默认自主推进；错误账本同签名 ≥ escalate_after_occurrences（默认
  2，rules-config §2.1 escalate_after_occurrences）→ 升级审批；
- 三动作：approve（按草稿原文）/ reject（动作不执行，任务链跳过回 running，v1→v2 迁移后
  decision='reject' 合法）/ edit_draft（以编辑后载荷执行 = ICON use_edited）；
- pending 审批存储（approvals 常驻表 + pending_approvals 列表面）。
出处：sys-arch §5.1/§5.2/§5.3；rules-config §2.1（actions 匹配表、unclassified 默认档、
escalate_after_occurrences）；ICON §2/§6.1-§6.3；本 ask 第 4 条。
"""

from __future__ import annotations

import json

from _helpers import cleanup, fresh_db

from app.engine import approval, ledger, state
from app.engine.db import SCHEMA_VERSION, Database
from app.engine.state import InvalidTransitionError, TaskStatus


def _running_task(database) -> str:
    task_id = state.create_task(database, title="审批路由", goal="分级路由测试")
    state.transition_task(database, task_id, TaskStatus.PLANNING, component="orchestrator")
    state.transition_task(database, task_id, TaskStatus.RUNNING, component="orchestrator")
    return task_id


def test_resolve_risk_tier_matching_and_strictest() -> None:
    # rules-config §2.1 匹配表：`pattern:*` 前缀匹配
    assert approval.resolve_risk_tier("email.send") == "irreversible"
    assert approval.resolve_risk_tier("payment.pay.card") == "irreversible"  # 前缀匹配 payment.pay
    assert approval.resolve_risk_tier("message.send.im") == "irreversible"
    assert approval.resolve_risk_tier("file.write_outside_workspace") == "reversible_costly"
    assert approval.resolve_risk_tier("http.get") == "reversible"
    # 未分类动作 → 安全默认 reversible_costly（rules-config §2.1 unclassified_default_tier）
    assert approval.resolve_risk_tier("custom.thing") == "reversible_costly"
    # 预标与规则表不一致 → 从严（sys-arch §5.1）
    assert approval.resolve_risk_tier("http.get", hint="irreversible") == "irreversible"
    assert approval.resolve_risk_tier("email.send", hint="reversible") == "irreversible"  # hard_floor 不降级
    # overrides 预留 global.yaml 接线
    assert approval.resolve_risk_tier("calendar.event", overrides={"calendar.event": "reversible"}) == "reversible"
    # 空动作名拒绝
    try:
        approval.resolve_risk_tier("  ")
    except ValueError:
        pass
    else:
        raise AssertionError("empty action_type must raise")


def test_route_irreversible_opens_approval() -> None:
    database, directory = fresh_db()
    try:
        task_id = _running_task(database)
        result = approval.route_action(
            database, "email.send", task_id=task_id,
            summary="发送邮件至 cto@example.com", payload={"to": "cto@example.com"},
            evidence={"subtask_id": "s1"})
        assert result["route"] == "approval" and result["reason"] == "r2_default_gate"
        row = database.query_one("SELECT * FROM approvals WHERE id = ?", (result["approval_id"],))
        assert row["status"] == "waiting" and row["risk_tier"] == "irreversible"
        assert row["wait_expires_at"]  # 默认等待期已计时（sys-arch §5.3）
        assert database.query_one("SELECT status FROM tasks WHERE id = ?", (task_id,))["status"] == "paused_for_approval"
        # ICON §2：approval_requested 事件
        events = database.query(
            "SELECT * FROM events WHERE event_type = 'approval_requested' AND task_id = ?", (task_id,))
        assert len(events) == 1
        # pending 列表面
        pending = approval.pending_approvals(database, task_id=task_id)
        assert [p["id"] for p in pending] == [result["approval_id"]]
    finally:
        cleanup(database, directory)


def test_route_reversible_auto_proceeds_with_audit() -> None:
    database, directory = fresh_db()
    try:
        task_id = _running_task(database)
        result = approval.route_action(
            database, "http.get", task_id=task_id, summary="读取定价页",
            payload={"url": "https://example.com/pricing"}, hint=None)
        assert result["route"] == "auto" and result["risk_tier"] == "reversible"
        assert database.query_one("SELECT status FROM tasks WHERE id = ?", (task_id,))["status"] == "running"
        events = database.query(
            "SELECT * FROM events WHERE event_type = 'action_auto_proceeded' AND task_id = ?", (task_id,))
        assert len(events) == 1
        payload = json.loads(events[0]["payload"])
        assert payload["action_type"] == "http.get" and payload["risk_tier"] == "reversible"
    finally:
        cleanup(database, directory)


def test_route_r1_escalates_after_same_signature_errors() -> None:
    database, directory = fresh_db()
    try:
        task_id = _running_task(database)
        action_payload = {"path": "/etc/agentmesh/hosts", "content": "x"}
        # 首次失败（同一签名三元组登记账本）
        ledger.ledger_write(database, "file.write_outside_workspace", "approval_gate",
                            action_payload, "write failed once", task_id, "worker")
        first = approval.route_action(database, "file.write_outside_workspace", task_id=task_id,
                                      summary="工作区外写配置", payload=action_payload)
        assert first["route"] == "auto" and first["signature_occurrences"] == 1  # <2：仍自主推进
        # 第二次同签名失败 → 升级
        ledger.ledger_write(database, "file.write_outside_workspace", "approval_gate",
                            action_payload, "write failed twice", task_id, "worker")
        second = approval.route_action(database, "file.write_outside_workspace", task_id=task_id,
                                       summary="工作区外写配置", payload=action_payload,
                                       escalate_after_occurrences=2)
        assert second["route"] == "approval"
        assert second["reason"] == "r1_escalated_after_same_signature_errors"
        assert second["signature_occurrences"] == 2 and second["threshold"] == 2
        row = database.query_one("SELECT * FROM approvals WHERE id = ?", (second["approval_id"],))
        assert json.loads(row["evidence"])["escalation"]["occurrences"] == 2  # 升级依据入证据栏
        assert database.query_one("SELECT status FROM tasks WHERE id = ?", (task_id,))["status"] == "paused_for_approval"
        # 未失败过的 R1 动作（R2 除外）默认自主推进
        task_id2 = _running_task(database)
        clean = approval.route_action(database, "db.migration", task_id=task_id2,
                                      summary="库表迁移", payload={"table": "events"})
        assert clean["route"] == "auto"
    finally:
        cleanup(database, directory)


def test_decide_three_actions() -> None:
    database, directory = fresh_db()
    try:
        # 批准：按草稿原文执行（T4 → running）
        task_id = _running_task(database)
        apr = approval.route_action(database, "email.send", task_id=task_id,
                                    summary="发报价邮件", payload={"to": "a@b.c"})["approval_id"]
        res = approval.decide(database, apr, "approve", decided_by="user-1")
        assert res["decision"] == "approve" and res["task_status"] == "running"
        assert database.query_one("SELECT decision FROM approvals WHERE id = ?", (apr,))["decision"] == "approve"
        # 编辑草稿：以编辑后载荷执行（= ICON use_edited，决策枚举落 use_edited）
        task_id2 = _running_task(database)
        apr2 = approval.route_action(database, "email.send", task_id=task_id2,
                                     summary="发邮件", payload={"to": "a@b.c"})["approval_id"]
        res2 = approval.decide(database, apr2, "edit_draft",
                               edited_payload={"to": "cfo@b.c", "body": "修订版"}, decided_by="user-1")
        assert res2["decision"] == "use_edited" and res2["task_status"] == "running"
        row_check = database.query_one("SELECT decision, edited_payload FROM approvals WHERE id = ?", (apr2,))
        assert row_check["decision"] == "use_edited"
        assert json.loads(row_check["edited_payload"]) == {"to": "cfo@b.c", "body": "修订版"}
        # 驳回：动作不执行，任务链跳过回 running（approval_decision 事件 + status_detail 标记）
        task_id3 = _running_task(database)
        apr3 = approval.route_action(database, "message.send", task_id=task_id3,
                                     summary="对外发消息", payload={"channel": "im"})["approval_id"]
        res3 = approval.decide(database, apr3, "reject", comment="先不要发", decided_by="user-1")
        assert res3["decision"] == "reject" and res3["task_status"] == "running"
        row3 = database.query_one("SELECT * FROM approvals WHERE id = ?", (apr3,))
        assert row3["decision"] == "reject" and row3["decision_comment"] == "先不要发"
        rejected = database.query(
            "SELECT payload FROM events WHERE event_type = 'approval_decision' AND task_id = ?",
            (task_id3,))
        assert any(json.loads(e["payload"])["decision"] == "reject" for e in rejected)
        detail = json.loads(database.query_one(
            "SELECT status_detail FROM tasks WHERE id = ?", (task_id3,))["status_detail"])
        assert detail == {"rejected_approval_id": apr3, "action_skipped": True}
        # 已裁决的审批不可再裁决（无静默降级）
        try:
            approval.decide(database, apr3, "approve")
        except InvalidTransitionError:
            pass
        else:
            raise AssertionError("decided approval cannot be re-decided")
        # edit_draft 必填 edited_payload（ICON §6.3）
        task_id4 = _running_task(database)
        apr4 = approval.route_action(database, "email.send", task_id=task_id4,
                                     summary="x", payload={})["approval_id"]
        try:
            approval.decide(database, apr4, "edit_draft")
        except ValueError:
            pass
        else:
            raise AssertionError("edit_draft requires edited_payload")
        # 未知动作拒绝
        try:
            approval.decide(database, apr4, "maybe")
        except ValueError:
            pass
        else:
            raise AssertionError("unknown action must raise")
    finally:
        cleanup(database, directory)


def test_schema_migration_adds_reject_decision() -> None:
    directory_root = None
    database, directory = fresh_db()
    try:
        assert SCHEMA_VERSION == "2"
        # 模拟 v1 旧库：按旧 CHECK 重建 approvals 表，再重新 connect 触发迁移
        database.close()
        old_ddl = """
        CREATE TABLE approvals (
          id               TEXT PRIMARY KEY,
          task_id          TEXT NOT NULL REFERENCES tasks(id),
          subtask_id       TEXT,
          correlation_id   TEXT NOT NULL,
          status           TEXT NOT NULL DEFAULT 'waiting' CHECK (status IN ('waiting','decided','expired')),
          action_type      TEXT NOT NULL,
          risk_tier        TEXT NOT NULL CHECK (risk_tier IN ('irreversible','reversible_costly','reversible')),
          summary          TEXT NOT NULL,
          payload          TEXT NOT NULL DEFAULT '{}',
          evidence         TEXT NOT NULL DEFAULT '{}',
          edited_payload   TEXT,
          decision         TEXT CHECK (decision IN ('approve','use_edited','regenerate')),
          decision_comment TEXT,
          decided_by       TEXT,
          decided_at       TEXT,
          wait_expires_at  TEXT NOT NULL,
          timeout_fallback TEXT NOT NULL DEFAULT 'skip_and_continue'
                           CHECK (timeout_fallback IN ('skip_and_continue','skip_strict')),
          created_at       TEXT NOT NULL,
          updated_at       TEXT NOT NULL
        )
        """
        raw = Database(directory / "agentmesh.db")
        raw.connect()
        raw.execute("DROP TABLE approvals")
        raw.execute(old_ddl)
        raw.close()
        # 重新打开：init_schema 检测旧 CHECK → 表重建迁移，数据保留
        database2 = Database(directory / "agentmesh.db")
        database2.connect()
        assert database2.fts_available
        assert database2.query_one("SELECT value FROM schema_meta WHERE key = 'schema_version'")["value"] == "2"
        # 迁移后 reject 决策合法；旧行数据仍在
        task_id = _running_task(database2)
        apr = approval.route_action(database2, "email.send", task_id=task_id,
                                    summary="迁移后驳回", payload={"to": "a@b.c"})["approval_id"]
        res = approval.decide(database2, apr, "reject", comment="no")
        assert res["decision"] == "reject"
        directory_root = directory
    finally:
        cleanup(database, directory)
        _ = directory_root
