"""test_review_fixes.py — 评审问题回归测试（P1/P2/P4/P5/P7）。

出处：评审清单——P1 A4 契约 URL 形态（ICON §3/§5.4）；P2 引擎主循环全链与审批超时兜底
（ARCH §3.2/§3.3、ICON §1.7/§6.1/§6.3/§13.1）；P4 webhook JSON 解析失败 400
INVALID_WEBHOOK_BODY（ICON §7.6 错误码表）；P5 credential_audit DDL 对齐 CRED §6.1；
P7 regenerate 新 approval_id（ICON §6.3）与 reject 落 approval_decision（ICON §2）。
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import time
from pathlib import Path

from _helpers import cleanup, fresh_db, temp_workspace_root
from test_api_server import TOKEN, _boot, _json_of, _request

from app.engine import state
from app.engine.db import Database, iso_shift, json_dumps, utc_now_iso
from app.engine.planner import _ensure_briefs_table


def test_a4_briefs_contract_url_shape() -> None:
    """P1 回归：A4 契约 URL 形态（7 段）必须命中，且两级隶属校验生效。"""
    tmp = Path(__file__).parent / "_tmp_rev1"
    database, rules, api, server, base = _boot(tmp)
    try:
        task_id = state.create_task(database, title="A4", goal="brief 列表")
        gid = state.create_group(database, task_id, name="G")
        sid = state.create_subtask(database, task_id, gid, objective="抓取定价页")
        with database.transaction() as conn:
            _ensure_briefs_table(conn)
            conn.execute("INSERT INTO briefs (task_id, subtask_id, version, brief, created_at)"
                         " VALUES (?, ?, 1, ?, ?)",
                         (task_id, sid, json_dumps({"objective": "o"}), utc_now_iso()))
        status, payload, _ = _request("GET", base,
                                      f"/api/v1/tasks/{task_id}/subtasks/{sid}/briefs")
        assert status == 200
        items = _json_of(payload)["items"]
        assert len(items) == 1 and items[0]["brief"]["objective"] == "o"
        # task_id 与 subtask 不隶属 → 404 SUBTASK_NOT_FOUND
        other_task = state.create_task(database, title="别的任务", goal="g")
        status, payload, _ = _request("GET", base,
                                      f"/api/v1/tasks/{other_task}/subtasks/{sid}/briefs")
        assert status == 404 and _json_of(payload)["error"]["code"] == "SUBTASK_NOT_FOUND"
    finally:
        import test_api_server as _t
        _t._stop(server, api)
        cleanup(database, tmp)


def test_webhook_invalid_json_returns_400() -> None:
    """P4 回归：JSON 解析失败 → 400 INVALID_WEBHOOK_BODY（ICON §7.6 错误码表逐字）。"""
    tmp = Path(__file__).parent / "_tmp_rev2"
    database, rules, api, server, base = _boot(tmp)
    try:
        status, payload, _ = _request("POST", base, "/api/v1/triggers",
                                      body={"type": "webhook",
                                            "goal_template": "处理 {{payload.event}}"})
        hook = _json_of(payload)
        token = hook["ingest_path"].rsplit("/", 1)[-1]
        body = b"this is not json"
        ts = str(int(time.time()))
        sig = "sha256=" + hmac.new(hook["secret_once"].encode(),
                                   f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
        status, payload, _ = _request("POST", base, f"/api/v1/triggers/webhook/{token}",
                                      raw_body=body, token=None,
                                      headers={"X-Agentmesh-Timestamp": ts,
                                               "X-Agentmesh-Signature": sig})
        assert status == 400 and _json_of(payload)["error"]["code"] == "INVALID_WEBHOOK_BODY"
        assert not database.query("SELECT id FROM tasks WHERE source = 'webhook'")
    finally:
        import test_api_server as _t
        _t._stop(server, api)
        cleanup(database, tmp)


def test_credential_audit_ddl_matches_cred() -> None:
    """P5 回归：credential_audit 按 CRED §6.1 逐字对齐（created_at/NOT NULL/两索引），
    旧 ts 形态库自动迁移。"""
    tmp = Path(__file__).parent / "_tmp_rev3"
    database, rules, api, server, base = _boot(tmp)
    try:
        database.execute("""
            CREATE TABLE credential_audit (
              id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, role TEXT,
              task_id TEXT, key_name TEXT NOT NULL, action TEXT NOT NULL, detail TEXT)
        """)
        database.execute("INSERT INTO credential_audit (ts, role, task_id, key_name, action,"
                         " detail) VALUES ('2026-01-01T00:00:00.000Z', 'worker', 'g1-1', 'k',"
                         " 'deny', 'group_not_authorized')")
        status, payload, _ = _request("GET", base, "/api/v1/credentials/k/audit")
        assert status == 200
        items = _json_of(payload)["items"]
        assert len(items) == 1 and items[0]["created_at"] == "2026-01-01T00:00:00.000Z"
        assert "ts" not in items[0]  # 契约字段名 created_at（ICON §11.3）
        ddl = database.query_one(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='credential_audit'")["sql"]
        assert "created_at" in ddl and "NOT NULL" in ddl
        idx = {r["name"] for r in database.query(
            "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='credential_audit'")}
        assert {"idx_credential_audit_role_time", "idx_credential_audit_key_time"} <= idx
    finally:
        import test_api_server as _t
        _t._stop(server, api)
        cleanup(database, tmp)


def test_regenerate_new_approval_and_reject_event() -> None:
    """P7 回归：regenerate 产出新 approval_id（旧 ID 永不复用，ICON §6.3）；
    reject 落 approval_decision 事件（decision_recorded_event_id 非 null，ICON §2）。"""
    tmp = Path(__file__).parent / "_tmp_rev4"
    database, rules, api, server, base = _boot(tmp)
    try:
        task_id = state.create_task(database, title="重出", goal="三按钮")
        state.transition_task(database, task_id, state.TaskStatus.PLANNING, component="orchestrator")
        state.transition_task(database, task_id, state.TaskStatus.RUNNING, component="orchestrator")
        apr = state.open_approval(database, task_id, action_type="email.send",
                                  risk_tier="irreversible", summary="发邮件",
                                  payload={"to": "a@b.c"})
        status, payload, _ = _request("POST", base, f"/api/v1/approvals/{apr}/decision",
                                      body={"action": "regenerate", "comment": "改语气"})
        result = _json_of(payload)
        assert status == 200 and result["decision"] == "regenerate"
        new_apr = result["new_approval_id"]
        assert new_apr and new_apr != apr and new_apr.startswith("apr-")
        row = database.query_one("SELECT status FROM approvals WHERE id = ?", (new_apr,))
        assert row["status"] == "waiting"  # 重出草稿回到等待裁决
        status, payload, _ = _request("POST", base, f"/api/v1/approvals/{new_apr}/decision",
                                      body={"action": "reject", "comment": "先不发"})
        rejected = _json_of(payload)
        assert status == 200 and rejected["decision_recorded_event_id"]
        event_row = database.query_one(
            "SELECT event_type, payload FROM events WHERE event_id = ?",
            (rejected["decision_recorded_event_id"],))
        assert event_row["event_type"] == "approval_decision"
        assert json.loads(event_row["payload"])["decision"] == "reject"
        # ICON §6.3：reject 未带 comment → 400 COMMENT_REQUIRED（增补按钮的必填校验）
        apr2 = state.open_approval(database, task_id, action_type="email.send",
                                   risk_tier="irreversible", summary="发邮件2",
                                   payload={"to": "a@b.c"})
        status, payload, _ = _request("POST", base, f"/api/v1/approvals/{apr2}/decision",
                                      body={"action": "reject"})
        assert status == 400 and _json_of(payload)["error"]["code"] == "COMMENT_REQUIRED"
    finally:
        import test_api_server as _t
        _t._stop(server, api)
        cleanup(database, tmp)


def test_engine_loop_full_lifecycle_and_approval_expiry() -> None:
    """P2 回归：引擎 tick 完成 T1→plan→execute→T5/T6→T11 全链（STUB 无 key 全跑）；
    审批到期被 scan 置 expired 并回 running（B3 之后返回 410，ICON §13.1）。"""
    tmp = Path(__file__).parent / "_tmp_rev5"
    database, rules, api, server, base = _boot(tmp)
    try:
        from app.engine.llm import StubClient
        from app.main import EngineLoop
        engine = EngineLoop(database, StubClient(database=database))
        task_id = state.create_task(database, title="全链", goal="STUB 推进到 done")
        with temp_workspace_root():
            result = engine.tick()
        assert any(c["task_id"] == task_id and c.get("stage") == "done"
                   for c in result["claimed"])
        status, payload, _ = _request("GET", base, f"/api/v1/tasks/{task_id}")
        assert _json_of(payload)["status"] == "done"
        subs = database.query("SELECT status FROM subtasks WHERE task_id = ?", (task_id,))
        assert subs and all(s["status"] == "done" for s in subs)
        assert database.query_one(
            "SELECT event_id FROM events WHERE event_type = 'ledger_consolidation_check' AND task_id = ?",
            (task_id,)) is not None
        # done 非 pending：引擎不重复领取
        assert engine.tick()["claimed"] == []
        # 审批超时兜底（ICON §6.1 列表转 expired / §13.1 410 行为）
        running_id = state.create_task(database, title="审批超时", goal="T4 兜底")
        state.transition_task(database, running_id, state.TaskStatus.PLANNING, component="orchestrator")
        state.transition_task(database, running_id, state.TaskStatus.RUNNING, component="orchestrator")
        apr = state.open_approval(database, running_id, action_type="email.send",
                                  risk_tier="irreversible", summary="付款", wait_seconds=0)
        engine.tick(now=iso_shift(utc_now_iso(), 5))
        assert database.query_one("SELECT status FROM approvals WHERE id = ?", (apr,))["status"] == "expired"
        assert database.query_one("SELECT status FROM tasks WHERE id = ?", (running_id,))["status"] == "running"
        status, payload, _ = _request("POST", base, f"/api/v1/approvals/{apr}/decision",
                                      body={"action": "approve"})
        assert status == 410 and _json_of(payload)["error"]["code"] == "APPROVAL_TIMEOUT_APPLIED"
    finally:
        import test_api_server as _t
        _t._stop(server, api)
        cleanup(database, tmp)


def test_deploy_artifacts_credential_channel_no_plaintext() -> None:
    """P-cred 回归：部署产物走 age 密文库（CRED §3A'/§10.2），磁盘无明文令牌文件、
    .env 无 key 槽、compose 挂密文与 age_key secret。"""
    deploy = Path(__file__).resolve().parent.parent / "deploy"
    compose_text = (deploy / "compose.yaml").read_text(encoding="utf-8")
    install_text = (deploy / "install.sh").read_text(encoding="utf-8")
    # .env 不入库（.gitignore），由 install.sh 步骤 4 的 heredoc 生成——校验其生成模板
    env_match = re.search(r'cat > "\$ENV_FILE" <<EOF\n(.*?)\nEOF\n', install_text, re.S)
    assert env_match, "install.sh must generate .env via heredoc"
    env_text = env_match.group(1)
    # .env：只有路径指针，无任何 *KEY=/TOKEN= 明文槽
    assert "AGENTMESH_CREDENTIALS_FILE=" in env_text
    assert "AGENTMESH_AGE_KEY_FILE=" in env_text
    for forbidden in ("LLM_API_KEY=", "AGENTMESH_API_TOKEN=", "LLM_API_KEY_FILE="):
        assert forbidden not in env_text, forbidden
    # compose：密文只读挂载 + age_key file 型 secret + 内核 env 指针
    assert "/opt/agentmesh/credentials:/opt/agentmesh/credentials:ro" in compose_text
    assert "age_key:" in compose_text and "/etc/agentmesh/age-key.txt" in compose_text
    assert "AGENTMESH_CREDENTIALS_FILE: /opt/agentmesh/credentials/credentials.enc" in compose_text
    assert "AGENTMESH_AGE_KEY_FILE: /run/secrets/age_key" in compose_text
    # install.sh：建 age keypair + 加密建库 + 解密自检；不再生成明文 api_token 文件
    assert "age-keygen" in install_text and "credentials.enc" in install_text
    assert "age -d -i" in install_text
    assert "secrets/api_token" not in install_text
    assert "secrets/llm_key" not in install_text
    # llm.py：env 明文兜底已删除（ARCH §10.1）
    llm_text = (Path(__file__).resolve().parent.parent / "app" / "engine" / "llm.py"
                ).read_text(encoding="utf-8")
    assert "api_key = str(env.get(\"LLM_API_KEY\"))" not in llm_text
    assert "env.get(\"LLM_API_KEY\")" in llm_text  # 仅诊断提示位（不读值注入）


def test_use_edited_field_whitelist() -> None:
    """评审遗留项回归：ICON §6.3 edited_payload 白名单——不可编辑字段（系统注入的
    evidence 上下文项）→ 400 FIELD_NOT_EDITABLE；缺必填键 → 400 EDITED_PAYLOAD_REQUIRED；
    白名单内完整替换 → 200 use_edited。表单渲染侧同步标 editable=False。"""
    tmp = Path(__file__).parent / "_tmp_rev6"
    database, rules, api, server, base = _boot(tmp)
    try:
        task_id = state.create_task(database, title="白名单", goal="edit 载荷字段校验")
        state.transition_task(database, task_id, state.TaskStatus.PLANNING, component="orchestrator")
        state.transition_task(database, task_id, state.TaskStatus.RUNNING, component="orchestrator")
        apr = state.open_approval(database, task_id, action_type="email.send",
                                  risk_tier="irreversible", summary="发邮件",
                                  payload={"to": "a@b.c", "subject": "s"},
                                  evidence={"subtask_id": "s1"})
        status, payload, _ = _request("GET", base, f"/api/v1/approvals/{apr}")
        assert status == 200
        fields = {f["name"]: f["editable"] for f in _json_of(payload)["form"]["fields"]}
        assert fields == {"to": True, "subject": True, "subtask_id": False}
        # 敲不可编辑字段 → 400 FIELD_NOT_EDITABLE
        status, payload, _ = _request("POST", base, f"/api/v1/approvals/{apr}/decision",
                                      body={"action": "use_edited",
                                            "edited_payload": {"to": "x@b.c", "subject": "s2",
                                                               "subtask_id": "s1"}})
        assert status == 400 and _json_of(payload)["error"]["code"] == "FIELD_NOT_EDITABLE"
        # 缺必填键 → 400 EDITED_PAYLOAD_REQUIRED
        status, payload, _ = _request("POST", base, f"/api/v1/approvals/{apr}/decision",
                                      body={"action": "use_edited",
                                            "edited_payload": {"to": "x@b.c"}})
        assert status == 400 and _json_of(payload)["error"]["code"] == "EDITED_PAYLOAD_REQUIRED"
        # 白名单内完整替换 → 200
        status, payload, _ = _request("POST", base, f"/api/v1/approvals/{apr}/decision",
                                      body={"action": "use_edited",
                                            "edited_payload": {"to": "x@b.c", "subject": "s2"}})
        result = _json_of(payload)
        assert status == 200 and result["decision"] == "use_edited"
        assert result["effective_payload"] == "edited"
    finally:
        import test_api_server as _t
        _t._stop(server, api)
        cleanup(database, tmp)
