"""test_api_server.py — app/api/server.py 测试：端点全表（A/B/C/D/E/F/G/H 域）、SSE 事件流、
静态托管、鉴权与错误包络（ICON-01；ask 第 1 条，stdlib 实现零第三方依赖）。

每个用例自建临时内核（db + 最小 rules/skills/web 目录），起 127.0.0.1 随机端口服务，
urllib 直连验收。
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from _helpers import cleanup, fresh_db

from app.api.server import KernelAPI, serve
from app.engine import approval, ledger, state
from app.engine.db import Database, emit_event, json_dumps, utc_now_iso
from app.engine.skills.registry import SkillRegistry

TOKEN = "test-token-123"

RULE_GLOBAL = """meta: {version: v1}
concurrency: {max_global_concurrency: 4}
approval_risk_tiers:
  tiers:
    - {tier: irreversible, hard_floor: true}
locale: {timezone: Asia/Shanghai}
"""
RULE_ROLES = """roles:
  worker: {tools: [memory-read], credential_groups: [accounts]}
  planner: {tools: [], credential_groups: []}
"""
RULE_COLLAB = "brief_spec: {}\n"
RULE_LESSONS = "rules: []\n"

SKILL_MD = """---
name: memory-read
description: 读取记忆库与错误账本检索
when: [需要历史错误参考]
roles: [worker]
credential_groups: []
timeout_s: 60
retries: 0
idempotent: true
risk_level: low
inputs: [{name: query, type: string, required: true, desc: 检索关键词}]
outputs: JSON hits
version: 1.0
---
# memory-read
"""


def _write_rules(tmp: Path, *, global_yaml: str = RULE_GLOBAL) -> Path:
    rules = tmp / "rules"
    rules.mkdir(parents=True, exist_ok=True)
    (rules / "global.yaml").write_text(global_yaml, encoding="utf-8")
    (rules / "roles.yaml").write_text(RULE_ROLES, encoding="utf-8")
    (rules / "collab.yaml").write_text(RULE_COLLAB, encoding="utf-8")
    (rules / "lessons.yaml").write_text(RULE_LESSONS, encoding="utf-8")
    return rules


def _write_skills(tmp: Path) -> Path:
    skills = tmp / "skills" / "memory-read"
    skills.mkdir(parents=True, exist_ok=True)
    (skills / "SKILL.md").write_text(SKILL_MD, encoding="utf-8")
    return tmp / "skills"


def _write_web(tmp: Path) -> Path:
    web = tmp / "web"
    web.mkdir(parents=True, exist_ok=True)
    (web / "index.html").write_text("<h1>agentmesh</h1>", encoding="utf-8")
    return web


def _boot(tmp: Path, *, token: str | None = TOKEN,
          credential_manager: Any | None = None) -> tuple[Database, Path, KernelAPI, Any, str]:
    database = Database(tmp / "agentmesh.db")
    database.connect()
    rules = _write_rules(tmp)
    import yaml
    rules_cfg = {k.removesuffix(".yaml"): yaml.safe_load((rules / k).read_text(encoding="utf-8"))
                 for k in ("global.yaml", "roles.yaml", "collab.yaml", "lessons.yaml")}
    skills_root = _write_skills(tmp)
    registry = SkillRegistry(database=database)
    failures = registry.load_all(skills_root, rules_cfg["roles"])
    assert failures == [], failures
    api = KernelAPI(database, skills_registry=registry, rules_cfg=rules_cfg,
                    web_dir=_write_web(tmp), api_token=token, budget_global_daily=10.0,
                    tz_name="UTC", sse_poll_interval=0.05,
                    credential_manager=credential_manager)
    server = serve(api, host="127.0.0.1", port=0)
    base = f"http://127.0.0.1:{server.server_address[1]}"
    return database, rules, api, server, base


def _stop(server, api) -> None:
    api.shutdown_flag.set()
    server.shutdown()
    server.server_close()


def _request(method: str, base: str, path: str, *, token: str | None = TOKEN,
             body: dict | None = None, headers: dict[str, str] | None = None,
             raw_body: bytes | None = None) -> tuple[int, dict | bytes, dict[str, str]]:
    url = base + path
    data = raw_body if raw_body is not None else (
        json.dumps(body, ensure_ascii=False).encode("utf-8") if body is not None else None)
    req_headers = {"X-Request-Id": "req-test-1"}
    if token is not None:
        req_headers["Authorization"] = f"Bearer {token}"
    if data is not None:
        req_headers["Content-Type"] = "application/json"
    req_headers.update(headers or {})
    request = urllib.request.Request(url, data=data, headers=req_headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=10) as resp:
            payload = resp.read()
            return resp.status, payload, dict(resp.headers)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(), dict(exc.headers)


def _json_of(payload: dict | bytes) -> dict:
    return json.loads(payload.decode("utf-8")) if isinstance(payload, bytes) else payload


def test_healthz_and_auth() -> None:
    database, rules, api, server, base = _boot(Path(__file__).parent / "_tmp_api1")
    try:
        status, payload, _ = _request("GET", base, "/healthz", token=None)
        assert status == 200
        body = _json_of(payload)
        assert body["status"] == "ok" and body["db_mode"] == "wal"
        # 无令牌 → 401 AUTH_REQUIRED（错误包络）
        status, payload, _ = _request("GET", base, "/api/v1/tasks", token=None)
        assert status == 401
        err = _json_of(payload)["error"]
        assert err["code"] == "AUTH_REQUIRED"
        # 错误令牌 → 401 AUTH_INVALID_TOKEN
        status, payload, _ = _request("GET", base, "/api/v1/tasks", token="wrong")
        assert status == 401 and _json_of(payload)["error"]["code"] == "AUTH_INVALID_TOKEN"
        # X-Request-Id 回传（ICON §1.3）
        status, _, headers = _request("GET", base, "/api/v1/tasks")
        assert status == 200 and headers.get("X-Request-Id") == "req-test-1"
    finally:
        _stop(server, api)
        cleanup(database, Path(__file__).parent / "_tmp_api1")


def test_task_domain_a1_a5() -> None:
    tmp = Path(__file__).parent / "_tmp_api2"
    database, rules, api, server, base = _boot(tmp)
    try:
        # A1 提交：202 + Location + links
        status, payload, headers = _request("POST", base, "/api/v1/tasks",
                                            body={"goal": "调研两个定价页"})
        assert status == 202 and headers.get("Location", "").startswith("/api/v1/tasks/")
        submit = _json_of(payload)
        assert submit["status"] == "pending" and submit["source"] == "user"
        assert submit["links"]["stream"].endswith(f"task_id={submit['task_id']}")
        task_id = submit["task_id"]
        # 画布字段 → 契约级否决
        status, payload, _ = _request("POST", base, "/api/v1/tasks",
                                      body={"goal": "x", "nodes": [], "edges": []})
        assert status == 400 and _json_of(payload)["error"]["code"] == "CANVAS_FIELDS_REJECTED"
        # goal 校验
        status, payload, _ = _request("POST", base, "/api/v1/tasks", body={"goal": "  "})
        assert status == 400 and _json_of(payload)["error"]["code"] == "GOAL_EMPTY"
        status, payload, _ = _request("POST", base, "/api/v1/tasks",
                                      body={"goal": "x" * 8001})
        assert status == 400 and _json_of(payload)["error"]["code"] == "GOAL_TOO_LONG"
        status, payload, _ = _request("POST", base, "/api/v1/tasks",
                                      body={"goal": "x", "source": "cron"})
        assert status == 400 and _json_of(payload)["error"]["code"] == "SOURCE_FORBIDDEN"
        # A2 列表
        status, payload, _ = _request("GET", base, "/api/v1/tasks?status=pending")
        items = _json_of(payload)["items"]
        assert len(items) == 1 and items[0]["task_id"] == task_id
        assert items[0]["risk_tier_max"] == "reversible_costly"  # medium → R1 映射
        # A3 任务树
        status, payload, _ = _request("GET", base, f"/api/v1/tasks/{task_id}")
        assert status == 200 and _json_of(payload)["status"] == "pending"
        status, payload, _ = _request("GET", base, "/api/v1/tasks/task-missing")
        assert status == 404 and _json_of(payload)["error"]["code"] == "TASK_NOT_FOUND"
        # A5 中止：pending → aborted 不合法（T9 from 集合不含 pending）→ 409? 先推进到 running
        state.transition_task(database, task_id, state.TaskStatus.PLANNING, component="orchestrator")
        state.transition_task(database, task_id, state.TaskStatus.RUNNING, component="orchestrator")
        status, payload, _ = _request("POST", base, f"/api/v1/tasks/{task_id}/abort",
                                      body={"reason": "方向不对"})
        assert status == 200
        body_obj = _json_of(payload)
        assert body_obj["status"] == "aborted" and body_obj["transition"] == "T9"
        # 再中止 → 409 ALREADY_TERMINAL
        status, payload, _ = _request("POST", base, f"/api/v1/tasks/{task_id}/abort", body={})
        assert status == 409 and _json_of(payload)["error"]["code"] == "ALREADY_TERMINAL"
        # task_aborted 事件（ICON §2）
        events = database.query("SELECT * FROM events WHERE event_type = 'task_aborted'")
        assert len(events) == 1
    finally:
        _stop(server, api)
        cleanup(database, tmp)


def test_idempotency_and_413() -> None:
    tmp = Path(__file__).parent / "_tmp_api3"
    database, rules, api, server, base = _boot(tmp)
    try:
        headers = {"Idempotency-Key": "idem-1"}
        status1, payload1, _ = _request("POST", base, "/api/v1/tasks",
                                        body={"goal": "幂等目标"}, headers=headers)
        assert status1 == 202
        status2, payload2, _ = _request("POST", base, "/api/v1/tasks",
                                        body={"goal": "幂等目标"}, headers=headers)
        assert status2 == 200  # ICON §1.3：同键 24h 内返回既有任务
        assert _json_of(payload1)["task_id"] == _json_of(payload2)["task_id"]
        # 413：正文 >1MB
        big = "x" * (1024 * 1024 + 100)
        status, payload, _ = _request("POST", base, "/api/v1/tasks",
                                      raw_body=json.dumps({"goal": big}).encode())
        assert status == 413 and _json_of(payload)["error"]["code"] == "PAYLOAD_TOO_LARGE"
    finally:
        _stop(server, api)
        cleanup(database, tmp)


def test_approval_domain_b1_b3() -> None:
    tmp = Path(__file__).parent / "_tmp_api4"
    database, rules, api, server, base = _boot(tmp)
    try:
        task_id = state.create_task(database, title="审批", goal="R2")
        state.transition_task(database, task_id, state.TaskStatus.PLANNING, component="orchestrator")
        state.transition_task(database, task_id, state.TaskStatus.RUNNING, component="orchestrator")
        apr = state.open_approval(database, task_id, action_type="email.send",
                                  risk_tier="irreversible", summary="发报价邮件",
                                  payload={"to": "cto@example.com", "body": "草稿全文"})
        # B1 列表（waiting）
        status, payload, _ = _request("GET", base, "/api/v1/approvals?status=waiting")
        items = _json_of(payload)["items"]
        assert [i["approval_id"] for i in items] == [apr]
        # B2 渲染数据（可编辑字段 + 三按钮 + timeout_fallback）
        status, payload, _ = _request("GET", base, f"/api/v1/approvals/{apr}")
        assert status == 200
        render = _json_of(payload)
        assert render["risk_tier"] == "irreversible"
        assert render["buttons"] == ["approve", "use_edited", "regenerate"]
        assert {f["name"] for f in render["form"]["fields"]} == {"to", "body"}
        # B3 批准 → effective as_draft + T4 → running
        status, payload, _ = _request("POST", base, f"/api/v1/approvals/{apr}/decision",
                                      body={"action": "approve"})
        assert status == 200
        decided = _json_of(payload)
        assert decided["effective_payload"] == "as_draft"
        assert decided["task_status"] == "running" and decided["transition"] == "T4"
        assert decided["decision_recorded_event_id"]
        # 重复裁决 → 409
        status, payload, _ = _request("POST", base, f"/api/v1/approvals/{apr}/decision",
                                      body={"action": "approve"})
        assert status == 409 and _json_of(payload)["error"]["code"] == "APPROVAL_ALREADY_DECIDED"
        # expired → 410
        apr2 = state.open_approval(database, task_id, action_type="payment.pay",
                                   risk_tier="irreversible", summary="付款", wait_seconds=0)
        database.execute("UPDATE approvals SET status = 'expired' WHERE id = ?", (apr2,))
        status, payload, _ = _request("POST", base, f"/api/v1/approvals/{apr2}/decision",
                                      body={"action": "approve"})
        assert status == 410 and _json_of(payload)["error"]["code"] == "APPROVAL_TIMEOUT_APPLIED"
        # message.send 路由后任务已 paused，再走一个 running 动作需要先把任务拉回 running
        database.execute("UPDATE tasks SET status = 'running' WHERE id = ?", (task_id,))
        apr4 = state.open_approval(database, task_id, action_type="im.post",
                                   risk_tier="irreversible", summary="发消息")
        status, payload, _ = _request("POST", base, f"/api/v1/approvals/{apr4}/decision",
                                      body={"action": "reject", "comment": "先不发"})
        assert status == 200 and _json_of(payload)["effective_payload"] == "skipped"
        detail = json.loads(database.query_one(
            "SELECT status_detail FROM tasks WHERE id = ?", (task_id,))["status_detail"])
        assert detail["action_skipped"] is True
    finally:
        _stop(server, api)
        cleanup(database, tmp)


def test_events_c1_and_sse_c2() -> None:
    tmp = Path(__file__).parent / "_tmp_api5"
    database, rules, api, server, base = _boot(tmp)
    try:
        task_id = state.create_task(database, title="事件", goal="C1/C2")
        with database.transaction() as conn:
            for i in range(3):
                emit_event(conn, task_id=task_id, component="orchestrator",
                           event_type="state_transition",
                           payload={"from": "pending", "to": "planning", "seq": i})
        # C1 历史查询 + types 过滤
        status, payload, _ = _request("GET", base, "/api/v1/events?task_id=" + task_id)
        assert status == 200
        items = _json_of(payload)["items"]
        assert len(items) >= 4  # task_created + 3 state_transition
        assert all(item["event_type"] in ("state_transition", "task_created") for item in items)
        status, payload, _ = _request("GET", base,
                                      "/api/v1/events?task_id=" + task_id + "&types=state_transition")
        assert len(_json_of(payload)["items"]) == 3
        # C2 SSE：订阅线程读帧；主线程注入新事件
        stream_url = f"{base}/api/v1/events/stream?task_id={task_id}&types=state_transition"
        frames: list[bytes] = []
        ready = threading.Event()

        def reader() -> None:
            request = urllib.request.Request(
                stream_url, headers={"Authorization": f"Bearer {TOKEN}"})
            with urllib.request.urlopen(request, timeout=10) as resp:
                ready.set()
                deadline = time.time() + 8
                while time.time() < deadline:
                    line = resp.readline()
                    if line:
                        frames.append(line)
                    joined = b"".join(frames)
                    if b'"transition": "T2"' in joined and b"event: state_transition" in joined:
                        break

        thread = threading.Thread(target=reader, daemon=True)
        thread.start()
        assert ready.wait(5)
        time.sleep(0.3)  # 等订阅端进入轮询循环
        with database.transaction() as conn:
            emit_event(conn, task_id=task_id, component="orchestrator",
                       event_type="state_transition",
                       payload={"from": "planning", "to": "running", "transition": "T2"})
        thread.join(timeout=10)
        text = b"".join(frames).decode("utf-8")
        assert "retry: 3000" in text
        assert "event: state_transition" in text
        assert '"transition": "T2"' in text
        # Last-Event-ID 未知 → stream_resync 帧（ICON §4.2 第 2 条）
        text2 = _read_sse_snapshot(f"{base}/api/v1/events/stream?task_id={task_id}",
                                   last_event_id="01JZZZZZZZZZZZZZZZZZZZZZZZ")
        assert "event: stream_resync" in text2 and "cursor_expired" in text2
        # FILTER_CONFLICT
        status, payload, _ = _request(
            "GET", base,
            f"/api/v1/events/stream?task_id={task_id}&correlation_id=abc", token=TOKEN)
        assert status == 400 and _json_of(payload)["error"]["code"] == "FILTER_CONFLICT"
        # since 格式错 → INVALID_SINCE_FORMAT
        status, payload, _ = _request("GET", base,
                                      "/api/v1/events/stream?since=not-a-date", token=TOKEN)
        assert status == 400 and _json_of(payload)["error"]["code"] == "INVALID_SINCE_FORMAT"
    finally:
        _stop(server, api)
        cleanup(database, tmp)


def _read_sse_snapshot(url: str, *, last_event_id: str) -> str:
    """打开 SSE，读到 stream_resync 帧后立即断开（快照式读取）。"""
    request = urllib.request.Request(url, headers={"Authorization": f"Bearer {TOKEN}",
                                                   "Last-Event-ID": last_event_id})
    chunks: list[bytes] = []
    with urllib.request.urlopen(request, timeout=10) as resp:
        deadline = time.time() + 5
        while time.time() < deadline:
            line = resp.readline()
            if line:
                chunks.append(line)
            if b"cursor_expired" in b"".join(chunks):
                break
    return b"".join(chunks).decode("utf-8")


def test_executions_d1_d2_d3() -> None:
    tmp = Path(__file__).parent / "_tmp_api6"
    database, rules, api, server, base = _boot(tmp)
    try:
        task_id = state.create_task(database, title="执行记录", goal="D 域")
        corr = database.query_one("SELECT correlation_id FROM tasks WHERE id = ?", (task_id,))["correlation_id"]
        state.transition_task(database, task_id, state.TaskStatus.PLANNING, component="orchestrator")
        ledger.ledger_write(database, "TypeError", "http_client", {}, "boom", task_id, "worker")
        # D1 按日期分组
        status, payload, _ = _request("GET", base, "/api/v1/executions")
        assert status == 200
        items = _json_of(payload)["items"]
        assert len(items) == 1 and items[0]["correlation_id"] == corr
        assert items[0]["event_count_day"] >= 3
        assert items[0]["errors_day"] == 1
        assert f"/executions/{corr}/timeline?date=" in items[0]["timeline"]
        # D2 时间线（types 过滤 + INVALID_TYPES + 404）
        status, payload, _ = _request(
            "GET", base, f"/api/v1/executions/{corr}/timeline?types=state_transition")
        assert status == 200
        timeline = _json_of(payload)["items"]
        assert timeline[0]["ts"] <= timeline[-1]["ts"]  # 正序
        assert all(item["event_type"] == "state_transition" for item in timeline)
        status, payload, _ = _request(
            "GET", base, f"/api/v1/executions/{corr}/timeline?types=bogus_type")
        assert status == 400 and _json_of(payload)["error"]["code"] == "INVALID_TYPES"
        status, payload, _ = _request("GET", base, "/api/v1/executions/nope/timeline")
        assert status == 404 and _json_of(payload)["error"]["code"] == "CORRELATION_NOT_FOUND"
        # D3 replay（无副作用 + 每步 digest）
        status, payload, _ = _request("GET", base, f"/api/v1/executions/{corr}/replay")
        replay = _json_of(payload)
        assert replay["side_effects"] == "none"
        assert replay["steps"][0]["event_type"] == "task_created"
        assert any("状态" in s["digest"] for s in replay["steps"] if s["event_type"] == "state_transition")
        assert replay["terminal_status"] is None  # 任务未到终态
    finally:
        _stop(server, api)
        cleanup(database, tmp)


def test_costs_budget_runtime_e1_e4() -> None:
    tmp = Path(__file__).parent / "_tmp_api7"
    database, rules, api, server, base = _boot(tmp)
    try:
        task_id = state.create_task(database, title="成本", goal="E 域")
        gid = state.create_group(database, task_id, name="G")
        sid = state.create_subtask(database, task_id, gid, objective="o")
        from app.engine.planner import _ensure_briefs_table
        with database.transaction() as conn:
            _ensure_briefs_table(conn)  # briefs 由 planner 首写建表；测试直建等价面
            conn.execute("INSERT INTO briefs (task_id, subtask_id, version, brief, created_at)"
                         " VALUES (?, ?, 1, ?, ?)",
                         (task_id, sid, json_dumps({"max_iterations": 5}), utc_now_iso()))
            for _ in range(2):
                emit_event(conn, task_id=task_id, component="worker_runtime",
                           event_type="llm_call",
                           payload={"model": "m", "tokens_in": 100, "tokens_out": 30,
                                    "subtask_id": sid, "cost_usd_est": None, "kind": "execute"})
        # E1 全局汇总
        status, payload, _ = _request("GET", base, "/api/v1/costs/summary")
        summary = _json_of(payload)
        assert summary["llm"]["calls"] == 2
        assert summary["llm"]["tokens_in"] == 200 and summary["llm"]["tokens_out"] == 60
        assert summary["budget_global_daily_usd"] == 10.0
        assert summary["remaining_usd_est"] == 10.0
        assert "token" in summary["metering_disclaimer"]
        # E2 任务成本明细（brief.max_llm_calls 回填）
        status, payload, _ = _request("GET", base, f"/api/v1/tasks/{task_id}/costs")
        costs = _json_of(payload)
        assert costs["subtasks"][0]["subtask_id"] == sid
        assert costs["subtasks"][0]["llm_calls"] == 2
        assert costs["subtasks"][0]["tokens_total"] == 260
        assert costs["subtasks"][0]["max_llm_calls"] == 5
        # E3 预算状态
        status, payload, _ = _request("GET", base, "/api/v1/budget")
        assert status == 200
        budget = _json_of(payload)
        assert budget["global"]["daily_limit_usd"] == 10.0
        assert "metering_disclaimer" in budget
        # E4 运行时
        status, payload, _ = _request("GET", base, "/api/v1/runtime/metrics")
        metrics = _json_of(payload)
        assert metrics["max_concurrency"] == 4 and metrics["active_tasks"] == 1
        assert metrics["queue_depth"] >= 1  # planning 子任务入队
    finally:
        _stop(server, api)
        cleanup(database, tmp)


def test_errors_domain_f1_f5() -> None:
    tmp = Path(__file__).parent / "_tmp_api8"
    database, rules, api, server, base = _boot(tmp)
    try:
        task_id = state.create_task(database, title="账本", goal="F 域")
        e1 = ledger.ledger_write(database, "TypeError", "http_client",
                                 {"url": "https://a.com", "retry": "3"}, "boom one", task_id, "worker")
        e2 = ledger.ledger_write(database, "TypeError", "http_client",
                                 {"url": "https://b.com", "retry": "3"}, "boom two", task_id, "worker")
        # F1 列表（同签名累计计数）
        status, payload, _ = _request("GET", base, f"/api/v1/errors?task_id={task_id}")
        items = _json_of(payload)["items"]
        assert len(items) == 2
        assert items[0]["occurrence_count_same_signature"] == 2
        assert items[0]["raw_error_truncated"] is False
        assert "raw_error" not in items[0]  # 列表不内嵌全文（ICON §9.1）
        # F2 详情（含 raw_error）
        status, payload, _ = _request("GET", base, f"/api/v1/errors/{e1}")
        assert status == 200 and _json_of(payload)["raw_error"] == "boom one"
        status, payload, _ = _request("GET", base, "/api/v1/errors/9999")
        assert status == 404 and _json_of(payload)["error"]["code"] == "ERROR_NOT_FOUND"
        # F3 FTS 检索（连字符/关键词服务端加引号）
        status, payload, _ = _request("GET", base, "/api/v1/errors/search?q=http_client%20boom")
        assert status == 200 and _json_of(payload)["matched_by"] == "fts"
        assert len(_json_of(payload)["items"]) == 2
        status, payload, _ = _request("GET", base, "/api/v1/errors/search?q=")
        assert status == 400 and _json_of(payload)["error"]["code"] == "EMPTY_QUERY"
        # F4 规则列表 + 状态过滤
        with database.transaction() as conn:
            conn.execute(
                "INSERT INTO prevention_rules (rule_text, match_keywords, status, risk_level)"
                " VALUES ('超时规则', 'timeout', 'candidate', 'high')")
        rule_id = int(database.query_one("SELECT id FROM prevention_rules")["id"])
        status, payload, _ = _request("GET", base, "/api/v1/errors/rules?status=candidate")
        assert [i["id"] for i in _json_of(payload)["items"]] == [rule_id]
        status, payload, _ = _request("GET", base, "/api/v1/errors/rules?status=bogus")
        assert status == 400 and _json_of(payload)["error"]["code"] == "INVALID_RULE_STATUS"
        # F5 审核：candidate retire → INVALID_TRANSITION（ICON §9.5）
        status, payload, _ = _request("POST", base, f"/api/v1/errors/rules/{rule_id}/review",
                                      body={"action": "retire", "reason": "x", "reviewer": "ops"})
        assert status == 400 and _json_of(payload)["error"]["code"] == "INVALID_TRANSITION"
        status, payload, _ = _request("POST", base, f"/api/v1/errors/rules/{rule_id}/review",
                                      body={"action": "approve", "reviewer": "ops-user"})
        assert status == 200 and _json_of(payload)["status"] == "active"
        # retire 缺 reason → 400；active retire → retired
        status, payload, _ = _request("POST", base, f"/api/v1/errors/rules/{rule_id}/review",
                                      body={"action": "retire", "reviewer": "ops-user"})
        assert status == 400 and _json_of(payload)["error"]["code"] == "RETIRE_REASON_REQUIRED"
        status, payload, _ = _request("POST", base, f"/api/v1/errors/rules/{rule_id}/review",
                                      body={"action": "retire", "reason": "过时", "reviewer": "ops"})
        assert status == 200 and _json_of(payload)["status"] == "retired"
        # reviewer 缺失 → 400 REVIEWER_REQUIRED
        status, payload, _ = _request("POST", base, f"/api/v1/errors/rules/{rule_id}/review",
                                      body={"action": "approve"})
        assert status == 400 and _json_of(payload)["error"]["code"] == "REVIEWER_REQUIRED"
        status, payload, _ = _request("POST", base, "/api/v1/errors/rules/999/review",
                                      body={"action": "approve", "reviewer": "x"})
        assert status == 404 and _json_of(payload)["error"]["code"] == "RULE_NOT_FOUND"
    finally:
        _stop(server, api)
        cleanup(database, tmp)


def test_triggers_domain_g1_g6() -> None:
    tmp = Path(__file__).parent / "_tmp_api9"
    database, rules, api, server, base = _boot(tmp)
    try:
        # G1 创建 cron
        status, payload, _ = _request("POST", base, "/api/v1/triggers",
                                      body={"type": "cron", "schedule": "0 9 * * *",
                                            "timezone": "UTC", "goal_template": "每日汇总"})
        assert status == 201
        cron = _json_of(payload)
        assert cron["next_fire_at"] and cron["ingest_path"] is None
        # G1 非法 schedule → 400 INVALID_SCHEDULE
        status, payload, _ = _request("POST", base, "/api/v1/triggers",
                                      body={"type": "cron", "schedule": "bad",
                                            "goal_template": "x"})
        assert status == 400 and _json_of(payload)["error"]["code"] == "INVALID_SCHEDULE"
        # G1 webhook → secret_once 只此一次
        status, payload, _ = _request("POST", base, "/api/v1/triggers",
                                      body={"type": "webhook", "goal_template": "处理 {{payload.event}}"})
        hook = _json_of(payload)
        assert hook["secret_mode"] == "generated" and hook["secret_once"].startswith("whsec_")
        status, payload, _ = _request("GET", base, f"/api/v1/triggers/{hook['trigger_id']}")
        detail = _json_of(payload)
        assert "secret_once" not in detail and "secret" not in detail  # 键级断言（secret_mode 含子串）
        # G2 列表
        status, payload, _ = _request("GET", base, "/api/v1/triggers")
        assert len(_json_of(payload)["items"]) == 2
        # G4 PATCH：cron 上 rotate → 400 ROTATE_ON_CRON
        status, payload, _ = _request("PATCH", base, f"/api/v1/triggers/{cron['trigger_id']}",
                                      body={"rotate_secret": True})
        assert status == 400 and _json_of(payload)["error"]["code"] == "ROTATE_ON_CRON"
        status, payload, _ = _request("PATCH", base, f"/api/v1/triggers/{cron['trigger_id']}",
                                      body={"enabled": False})
        assert status == 200 and _json_of(payload)["enabled"] is False
        # G6 webhook 摄入（HTTP 面 HMAC）
        token = hook["ingest_path"].rsplit("/", 1)[-1]
        body = json.dumps({"event": "push"}).encode()
        ts = str(int(time.time()))
        sig = "sha256=" + hmac.new(hook["secret_once"].encode(), f"{ts}.".encode() + body,
                                   hashlib.sha256).hexdigest()
        status, payload, _ = _request("POST", base, f"/api/v1/triggers/webhook/{token}",
                                      raw_body=body, token=None,
                                      headers={"X-Agentmesh-Timestamp": ts,
                                               "X-Agentmesh-Signature": sig})
        assert status == 202
        ingest = _json_of(payload)
        assert ingest["source"] == "webhook" and ingest["task_id"]
        # 幂等重放 → 200
        status, payload, _ = _request("POST", base, f"/api/v1/triggers/webhook/{token}",
                                      raw_body=body, token=None,
                                      headers={"X-Agentmesh-Timestamp": ts,
                                               "X-Agentmesh-Signature": sig,
                                               "Idempotency-Key": "gh-1"})
        assert status == 202
        idem_task_id = _json_of(payload)["task_id"]
        status, payload, _ = _request("POST", base, f"/api/v1/triggers/webhook/{token}",
                                      raw_body=body, token=None,
                                      headers={"X-Agentmesh-Timestamp": ts,
                                               "X-Agentmesh-Signature": sig,
                                               "Idempotency-Key": "gh-1"})
        assert status == 200 and _json_of(payload)["task_id"] == idem_task_id
        # 错误签名 → 401 WEBHOOK_SIGNATURE_INVALID（防枚举，不区分细节）
        status, payload, _ = _request("POST", base, f"/api/v1/triggers/webhook/{token}",
                                      raw_body=body, token=None,
                                      headers={"X-Agentmesh-Timestamp": ts,
                                               "X-Agentmesh-Signature": "sha256=" + "0" * 64})
        assert status == 401 and _json_of(payload)["error"]["code"] == "WEBHOOK_SIGNATURE_INVALID"
        # 未知 token → 404
        status, payload, _ = _request("POST", base, "/api/v1/triggers/webhook/whk_none",
                                      raw_body=body, token=None)
        assert status == 404 and _json_of(payload)["error"]["code"] == "TRIGGER_NOT_FOUND"
        # G5 删除 → 204，再查 404
        status, _, _ = _request("DELETE", base, f"/api/v1/triggers/{hook['trigger_id']}")
        assert status == 204
        status, payload, _ = _request("GET", base, f"/api/v1/triggers/{hook['trigger_id']}")
        assert status == 404 and _json_of(payload)["error"]["code"] == "TRIGGER_NOT_FOUND"
    finally:
        _stop(server, api)
        cleanup(database, tmp)


def test_credentials_domain_h_degraded() -> None:
    tmp = Path(__file__).parent / "_tmp_api10"
    database, rules, api, server, base = _boot(tmp)
    try:
        # 凭证管理器未接线 → H1 降级空列表（MEM §4：HTTP 200 + degraded）
        status, payload, _ = _request("GET", base, "/api/v1/credentials")
        body = _json_of(payload)
        assert status == 200 and body["items"] == [] and body["degraded"] is True
        # H2 键名层 404
        status, payload, _ = _request("GET", base, "/api/v1/credentials/nope")
        assert status == 404 and _json_of(payload)["error"]["code"] == "KEY_NOT_FOUND"
        # H3 审计（表按需建 + 动作过滤校验）
        status, payload, _ = _request("GET", base, "/api/v1/credentials/k/audit?action=bogus")
        assert status == 400 and _json_of(payload)["error"]["code"] == "INVALID_ACTION_FILTER"
        status, payload, _ = _request("GET", base, "/api/v1/credentials/k/audit")
        assert status == 200 and _json_of(payload)["items"] == []
        # H4 预检：roles.yaml 装载面生效（ROLE_UNKNOWN / group_authorized 闸门）
        status, payload, _ = _request("POST", base, "/api/v1/credentials/check",
                                      body={"role": "nope", "key_name": "k", "inject_path": "env"})
        assert status == 400 and _json_of(payload)["error"]["code"] == "ROLE_UNKNOWN"
        status, payload, _ = _request("POST", base, "/api/v1/credentials/check",
                                      body={"role": "worker", "key_name": "smtp_notify",
                                            "inject_path": "env"})
        check = _json_of(payload)
        # 凭证通道未接线：key 的组未知 → 组闸门为 null（roles.yaml 只给角色侧授权面）
        assert check["gates"]["group_authorized"] is None
        assert check["gates"]["key_exists"] is None  # 凭证通道未接线（null 闸门）
        assert check["allowed"] is False and check["denial"]["reason"] == "key_not_found"
        status, payload, _ = _request("POST", base, "/api/v1/credentials/check",
                                      body={"role": "worker", "key_name": "k",
                                            "inject_path": " sideways"})
        assert status == 400 and _json_of(payload)["error"]["code"] == "INVALID_INJECT_PATH"
        # H5 到期报告（降级空）
        status, payload, _ = _request("GET", base, "/api/v1/credentials/expiring?within_days=30")
        assert status == 200 and _json_of(payload)["expiring"] == []
        status, payload, _ = _request("GET", base, "/api/v1/credentials/expiring?within_days=0")
        assert status == 400 and _json_of(payload)["error"]["code"] == "INVALID_WITHIN_DAYS"
    finally:
        _stop(server, api)
        cleanup(database, tmp)


def test_credentials_manifest_mode() -> None:
    tmp = Path(__file__).parent / "_tmp_api11"
    database, rules, api, server, base = _boot(tmp)
    try:
        manifest = {"groups": {"api_keys": {"groq_api_key": {
            "env": None, "header": "X-Api-Key", "rotate_at": "2020-01-01", "notes": ""}}}}
        manifest_path = tmp / "creds_manifest.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        old = dict(os.environ)
        os.environ["AGENTMESH_CREDENTIALS_MANIFEST"] = str(manifest_path)
        try:
            status, payload, _ = _request("GET", base, "/api/v1/credentials")
            items = _json_of(payload)["items"]
            assert len(items) == 1 and items[0]["key_name"] == "groq_api_key"
            assert "value" not in json.dumps(items)  # 明文禁令（CRED §7）
            status, payload, _ = _request("GET", base, "/api/v1/credentials/groq_api_key")
            assert status == 200
            status, payload, _ = _request("GET", base,
                                          "/api/v1/credentials/expiring?within_days=30")
            expiring = _json_of(payload)["expiring"]
            assert expiring and expiring[0]["state"] == "due_now"  # rotate_at 2020 已过期
        finally:
            os.environ.clear()
            os.environ.update(old)
    finally:
        _stop(server, api)
        cleanup(database, tmp)


def test_static_hosting_and_traversal() -> None:
    tmp = Path(__file__).parent / "_tmp_api12"
    database, rules, api, server, base = _boot(tmp)
    try:
        status, payload, _ = _request("GET", base, "/", token=None)
        assert status == 200 and b"agentmesh" in payload
        # 未知静态文件 → 404
        status, payload, _ = _request("GET", base, "/missing.css", token=None)
        assert status == 404
        # 路径越界 → 拒绝（绝不越出 web/ 根）
        secret = tmp / "secret.txt"
        secret.write_text("top", encoding="utf-8")
        status, payload, _ = _request("GET", base, "/../secret.txt", token=None)
        assert status == 404
        status, payload, _ = _request("GET", base, "/%2e%2e/secret.txt", token=None)
        assert status == 404
        # 非 GET 方法 → 405
        status, payload, _ = _request("POST", base, "/", body={"x": 1}, token=None)
        assert status == 405
    finally:
        _stop(server, api)
        cleanup(database, tmp)


from typing import Any  # noqa: E402 - _boot 返回注解使用（置底避免顶部循环导入观感）
