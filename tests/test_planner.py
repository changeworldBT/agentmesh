"""test_planner.py — planner.py 测试：任务树拆解、brief 自包含字段、账本强制检索注入、
schema 校验与失败重试 1 次、T2 落库、briefs 按需建表。

覆盖验收面（ask 第 2 条）：
- 自然语言目标 → 任务树 + 分组 + 自包含 brief（含 tools/预算/风险预标）→ T2 → running；
- 读时机一（memory-design §4 矩阵第 1 行）：search_rules(5)+search_errors(5) 注入
  brief.prevention_rules（ledger_lookup 事件记录命中）；
- 输出 schema 校验：非法 JSON/缺字段/未知工具/依赖环 → 拒绝；失败重试 1 次；两次失败 →
  PlanValidationError + 错误账本登记 plan_schema_violation；
- degraded 降级面（强制读永不抛）；
- briefs 表按需建表（deployment-ops §5.1）与 deliverable_path 落在任务工作区内。
"""

from __future__ import annotations

import json

from _helpers import FakeLLM, cleanup, fresh_db, valid_plan

from app.engine import ledger, planner, state
from app.engine.db import json_dumps
from app.engine.llm import StubClient
from app.engine.planner import PlanValidationError


def _to_planning(database, task_id: str) -> None:
    state.transition_task(database, task_id, state.TaskStatus.PLANNING, component="orchestrator")


def test_planner_stub_happy_path_persists_tree_and_brief() -> None:
    database, directory = fresh_db()
    try:
        task_id = state.create_task(database, title="调研", goal="调研 20 个 SaaS 定价页并整理对比表")
        _to_planning(database, task_id)
        result = planner.plan_task(database, StubClient(database=database), task_id,
                                   task_type="web_research")
        # T2 落库：任务 running，分组/子任务/brief 落库
        assert state.TaskStatus(database.query_one(
            "SELECT status FROM tasks WHERE id = ?", (task_id,))["status"]) is state.TaskStatus.RUNNING
        assert len(result["groups"]) == 1 and len(result["subtasks"]) == 1
        group_row = database.query_one("SELECT * FROM groups WHERE task_id = ?", (task_id,))
        assert group_row["name"] == "执行组" and json.loads(group_row["depends_on"]) == []
        sub_row = database.query_one("SELECT * FROM subtasks WHERE task_id = ?", (task_id,))
        assert sub_row["risk_tier_hint"] == "reversible"
        assert sub_row["brief_version"] == 1 and sub_row["attempts"] == 0
        # 主任务预算按计划更新（sys-arch §7.4 主任务级预算；STUB 计划预算 1.0）
        task_row = database.query_one("SELECT budget_usd FROM tasks WHERE id = ?", (task_id,))
        assert task_row["budget_usd"] == 1.0
        # briefs 按需建表 + brief 字段齐备（rules-config §4.1 brief_spec）
        assert "briefs" in {r["name"] for r in database.query(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        brief_row = database.query_one(
            "SELECT * FROM briefs WHERE subtask_id = ?", (result["subtasks"][0]["subtask_id"],))
        brief = json.loads(str(brief_row["brief"]))
        for key in ("task_id", "task_type", "objective", "self_contained_context",
                    "acceptance_criteria", "allowed_tools", "risk_tier_hint", "budget_usd",
                    "max_iterations", "deliverable_path"):
            assert key in brief, key
        assert brief["allowed_tools"] == ["http_get", "file_write"]
        assert brief["max_iterations"] == 3 and brief["budget_usd"] == 0.5
        assert brief["on_failure"] == "register_and_stop"
        assert brief["degraded"] is False
        assert brief["self_contained_context"]  # 自包含：非空必要摘录
        # deliverable_path 落在任务工作区内（/data/agentmesh/workspaces/<task_id>/ 之下）
        assert brief["deliverable_path"].replace("\\", "/").endswith(f"/{task_id}/{sub_row['id']}.json")
        # ICON §2 词表：ledger_lookup / plan_requested / plan_produced / state_transition
        for event_type in ("ledger_lookup", "plan_requested", "plan_produced"):
            assert len(database.query(
                "SELECT * FROM events WHERE event_type = ? AND task_id = ?", (event_type, task_id))) >= 1
    finally:
        cleanup(database, directory)


def test_planner_injects_prevention_rules_from_ledger() -> None:
    database, directory = fresh_db()
    try:
        task_id = state.create_task(database, title="带规则", goal="调用 http 接口处理 timeout 重试")
        # 预置：一条 active 生效规则 + 一条相似历史错误（match_keywords 命中目标关键词）
        with database.transaction() as conn:
            conn.execute(
                "INSERT INTO prevention_rules (rule_text, match_keywords, task_types, status,"
                " source_error_ids, occurrences, risk_level)"
                " VALUES ('对外 http 调用必须显式设置超时', 'http timeout', '*', 'candidate', '[]', 2, 'high')")
        rule_id = int(database.query_one("SELECT id FROM prevention_rules")["id"])
        ledger.review_rule(database, rule_id, "alice")
        ledger.ledger_write(database, "TypeError", "http_client", {},
                            "http timeout during upstream call", task_id, "worker")
        _to_planning(database, task_id)
        result = planner.plan_task(database, StubClient(database=database), task_id,
                                   task_type="web_research")
        assert result["prevention_rules_injected"] == 2
        brief_row = database.query_one("SELECT * FROM briefs WHERE subtask_id = ?",
                                       (result["subtasks"][0]["subtask_id"],))
        brief = json.loads(str(brief_row["brief"]))
        sources = {entry["source"] for entry in brief["prevention_rules"]}
        assert sources == {"ledger_lookup", "ledger_error"}
        assert any(entry.get("rule_id") == rule_id for entry in brief["prevention_rules"])
        # ICON §2 ledger_lookup 事件记录命中 ID
        lookup = database.query(
            "SELECT payload FROM events WHERE event_type = 'ledger_lookup' AND task_id = ?",
            (task_id,))[0]
        payload = json.loads(lookup["payload"])
        assert rule_id in payload["rule_ids"] and len(payload["error_ids"]) == 1
    finally:
        cleanup(database, directory)


def test_planner_retry_once_on_invalid_then_valid() -> None:
    database, directory = fresh_db()
    try:
        task_id = state.create_task(database, title="重试", goal="修复解析")
        _to_planning(database, task_id)
        llm = FakeLLM(["这不是 JSON", json_dumps(valid_plan("修复解析并输出报告"))])
        result = planner.plan_task(database, llm, task_id, task_type="generic")
        assert len(result["subtasks"]) == 1
        assert len(llm.requests) == 2  # 失败重试 1 次（本 ask 指定）
        rejected = database.query(
            "SELECT payload FROM events WHERE event_type = 'plan_rejected' AND task_id = ?",
            (task_id,))
        assert len(rejected) == 1
        assert json.loads(rejected[0]["payload"])["attempt"] == 1
        # 重试请求带上错误清单（LLM 修复输入）
        assert "schema" in llm.requests[1].messages[-1]["content"]
    finally:
        cleanup(database, directory)


def test_planner_double_failure_raises_and_registers() -> None:
    database, directory = fresh_db()
    try:
        task_id = state.create_task(database, title="双败", goal="永远输出坏计划")
        _to_planning(database, task_id)
        llm = FakeLLM(["bad 1", "bad 2"])
        try:
            planner.plan_task(database, llm, task_id, task_type="generic")
        except PlanValidationError as exc:
            assert exc.errors
        else:
            raise AssertionError("double failure must raise PlanValidationError")
        assert len(llm.requests) == 2  # 初次 + 重试 1 次，无第三次
        entry = database.query_one(
            "SELECT * FROM error_ledger WHERE task_id = ? AND error_type = 'plan_schema_violation'",
            (task_id,))
        assert entry is not None and entry["role"] == "planner"
        # T2 兜底归编排引擎：任务保持 planning，不被 planner 擅自转 failed
        assert database.query_one("SELECT status FROM tasks WHERE id = ?", (task_id,))["status"] == "planning"
    finally:
        cleanup(database, directory)


def test_planner_validation_rejects_unknown_tools_and_cycles() -> None:
    plan = valid_plan()
    plan["subtasks"][0]["allowed_tools"] = ["shell_exec"]
    errors = planner.validate_plan(plan)
    assert any("allowed_tools" in e for e in errors)
    plan2 = valid_plan()
    plan2["groups"][0]["depends_on"] = ["g1"]  # 自环
    errors2 = planner.validate_plan(plan2)
    assert any("cycle" in e for e in errors2)
    plan3 = valid_plan()
    plan3["subtasks"][0]["max_iterations"] = 16  # rules-config roles 校验域 1..15
    errors3 = planner.validate_plan(plan3)
    assert any("max_iterations" in e for e in errors3)


def test_planner_degraded_retrieval_marks_brief() -> None:
    database, directory = fresh_db()
    try:
        task_id = state.create_task(database, title="降级", goal="账本检索降级")
        _to_planning(database, task_id)
        llm = FakeLLM([json_dumps(valid_plan("降级目标"))])
        # monkeypatch 强制读入口抛意外异常 → planner 兜底降级不阻塞拆解（MEM §4 强制读永不抛）
        original = planner.fetch_prevention_context
        planner.fetch_prevention_context = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("账本炸了"))
        try:
            result = planner.plan_task(database, llm, task_id, task_type="generic")
        finally:
            planner.fetch_prevention_context = original
        assert result["degraded"] is True and result["prevention_rules_injected"] == 0
        brief = json.loads(str(database.query_one(
            "SELECT brief FROM briefs WHERE subtask_id = ?",
            (result["subtasks"][0]["subtask_id"],))["brief"]))
        assert brief["degraded"] is True
        degraded = database.query(
            "SELECT payload FROM events WHERE event_type = 'memory_degraded'")
        assert any(json.loads(e["payload"])["surface"] == "planner_retrieval" for e in degraded)
    finally:
        cleanup(database, directory)


def test_planner_requires_planning_status() -> None:
    database, directory = fresh_db()
    try:
        task_id = state.create_task(database, title="守卫", goal="pending 不可直接规划")
        try:
            planner.plan_task(database, StubClient(), task_id, task_type="generic")
        except ValueError as exc:
            assert "planning" in str(exc)
        else:
            raise AssertionError("planner must require planning status")
        # 规划器全权拆解，但 T1 领取仍归编排引擎（sys-arch §3.2 T1）
    finally:
        cleanup(database, directory)
