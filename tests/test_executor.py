"""test_executor.py — executor.py 测试：brief 上下文组装、工具循环、file_write 路径硬限制、
http_get、tool_calls 审计、结果事件落库、on_failure register_and_stop。

覆盖验收面（ask 第 3 条）：
- 按 brief 组装上下文调 LLM（二次检索注入系统提示，与 brief 去重）；
- 内置工具 http_get/file_write：file_write 写路径硬限制在
  /data/agentmesh/workspaces/<task_id>/ 之下，越界即拒绝并登记错误账本（path_escape）；
- 结果事件落库（brief_dispatched/subtask_started/tool_call/subtask_stopped）；
- 失败路径：LLM 网关错误 / 迭代预算耗尽 / 结果非 JSON → 账本登记 + 子任务 failed
  （sys-arch §4.2 on_failure register_and_stop，不上报半成品为成功）；
- tool_calls 表按需建表（deployment-ops §5.1）。
"""

from __future__ import annotations

import json
from pathlib import Path

from _helpers import FakeLLM, cleanup, fresh_db, local_http_server, valid_plan

from app.engine import executor, ledger, planner, state
from app.engine.executor import (
    PathEscapeError,
    resolve_in_workspace,
    tool_file_write,
    tool_http_get,
)
from app.engine.llm import LLMRateLimitedError, StubClient


def _plan_and_get_sid(database, task_id: str, llm=None, workspace: Path | None = None) -> str:
    state.transition_task(database, task_id, state.TaskStatus.PLANNING, component="orchestrator")
    result = planner.plan_task(database, llm or StubClient(database=database), task_id,
                               task_type="web_research",
                               workspace_root_override=str(workspace) if workspace else None)
    return result["subtasks"][0]["subtask_id"]


def test_path_guard_rejects_escapes() -> None:
    root = Path(__file__).parent / "_tmp_ws_guard"
    try:
        # 合法：工作区内相对路径
        inside = resolve_in_workspace(root, "task-1", "out/result.json")
        assert str(inside).replace("\\", "/").endswith("task-1/out/result.json")
        # 越界：相对上跳
        for bad in ("../evil.txt", "a/../../evil.txt"):
            try:
                resolve_in_workspace(root, "task-1", bad)
            except PathEscapeError:
                pass
            else:
                raise AssertionError(f"must reject escape: {bad}")
        # 越界：绝对路径在工作区外
        try:
            resolve_in_workspace(root, "task-1", "C:/Windows/temp/evil.txt")
        except PathEscapeError:
            pass
        else:
            raise AssertionError("absolute outside path must be rejected")
        # task_id 注入防护
        try:
            executor.task_workspace(root, "../evil")
        except ValueError:
            pass
        else:
            raise AssertionError("unsafe task_id must be rejected")
        # 默认根（本 ask 指定 /data/agentmesh/workspaces）
        assert str(executor.workspace_root()).replace("\\", "/").endswith("/data/agentmesh/workspaces")
    finally:
        import shutil
        shutil.rmtree(root, ignore_errors=True)


def test_file_write_and_http_get_tools() -> None:
    database, directory = fresh_db()
    try:
        task_id = state.create_task(database, title="工具", goal="直接工具面")
        # file_write 成功
        root = directory / "ws"
        result = tool_file_write({"path": "notes/a.md", "content": "# hi"}, task_id=task_id, root=root)
        written = Path(result["path"])
        assert written.exists() and written.read_text(encoding="utf-8") == "# hi"
        assert result["bytes"] == 4
        assert str(written).replace("\\", "/").endswith(f"/{task_id}/notes/a.md")
        # file_write 越界 → PathEscapeError（error_type=path_escape）
        try:
            tool_file_write({"path": "../outside.txt", "content": "x"}, task_id=task_id, root=root)
        except PathEscapeError as exc:
            assert exc.error_type == "path_escape"
        else:
            raise AssertionError("escape must be rejected")
        # http_get 成功（本地服务）
        with local_http_server([(200, {"hello": "world"})]) as (base_url, captured):
            got = tool_http_get({"url": base_url + "/data"}, task_id=task_id)
        assert got["status"] == 200 and '"hello"' in got["body"] and got["truncated"] is False
        # http_get 404 → ToolError HTTP_404
        with local_http_server([(404, {"error": "nope"})]) as (base_url, _):
            try:
                tool_http_get({"url": base_url + "/missing"}, task_id=task_id)
            except executor.ToolError as exc:
                assert exc.error_type == "HTTP_404"
            else:
                raise AssertionError("404 must raise ToolError HTTP_404")
    finally:
        cleanup(database, directory)


def test_toolbox_audits_and_registers_errors() -> None:
    database, directory = fresh_db()
    try:
        task_id = state.create_task(database, title="审计", goal="tool_calls 表")
        box = executor.ToolBox(database, task_id, "s1", root=directory / "ws")
        # 成功调用：tool_calls 行 + tool_call 事件
        box.call("file_write", {"path": "a.txt", "content": "ok"})
        row = database.query_one("SELECT * FROM tool_calls WHERE tool_name = 'file_write'")
        assert row["status"] == "ok" and row["subtask_id"] == "s1"
        events = database.query("SELECT * FROM events WHERE event_type = 'tool_call'")
        assert len(events) == 1 and json.loads(events[0]["payload"])["tool"] == "file_write"
        # 越界调用：审计 error + 错误账本即时登记（本 ask：越界即拒绝并登记错误账本）
        try:
            box.call("file_write", {"path": "../../evil", "content": "x"})
        except PathEscapeError:
            pass
        else:
            raise AssertionError("toolbox must propagate escape")
        err_row = database.query_one(
            "SELECT * FROM tool_calls WHERE tool_name = 'file_write' AND status = 'error'")
        assert err_row is not None
        entry = database.query_one(
            "SELECT * FROM error_ledger WHERE task_id = ? AND error_type = 'path_escape'", (task_id,))
        assert entry is not None and entry["module"] == "file_write"
        # 未知工具
        try:
            box.call("shell_exec", {})
        except executor.ToolError as exc:
            assert exc.error_type == "unknown_tool"
        else:
            raise AssertionError("unknown tool must raise")
    finally:
        cleanup(database, directory)


def test_executor_stub_happy_path() -> None:
    database, directory = fresh_db()
    workspace = directory / "ws"
    try:
        task_id = state.create_task(database, title="执行", goal="STUB 全链")
        sid = _plan_and_get_sid(database, task_id, workspace=workspace)
        result = executor.execute_subtask(database, StubClient(database=database), sid,
                                          workspace_root_override=str(workspace))
        assert result["status"] == "done" and result["summary"].startswith("STUB completed:")
        assert state.SubtaskStatus(database.query_one(
            "SELECT status FROM subtasks WHERE id = ?", (sid,))["status"]) is state.SubtaskStatus.DONE
        # 结果事件落库（ICON §2：brief_dispatched/subtask_started/subtask_stopped）
        for event_type in ("brief_dispatched", "subtask_started", "subtask_stopped"):
            rows = database.query(
                "SELECT payload FROM events WHERE event_type = ? AND task_id = ?", (event_type, task_id))
            assert rows, event_type
        stopped = json.loads(database.query(
            "SELECT payload FROM events WHERE event_type = 'subtask_stopped' AND task_id = ?",
            (task_id,))[0]["payload"])
        assert stopped["status"] == "done" and stopped["summary"].startswith("STUB completed:")
        # llm_call 计量事件（规划 1 次 + 执行 2 次：STUB 先发 file_write，再给终答）
        llm_events = database.query("SELECT * FROM events WHERE event_type = 'llm_call'")
        assert len(llm_events) == 3
        # STUB 同样走真实工具路径：工作区内留下产物 + tool_calls 审计行
        assert result["tool_rounds"] == 1
        written = Path(result["deliverable_path"])
        assert written.exists() and written.stat().st_size > 0
        assert Path(result["deliverable_path"]).name == f"{sid}.json"
        audit = database.query_one("SELECT * FROM tool_calls WHERE tool_name = 'file_write'")
        assert audit["status"] == "ok" and audit["task_id"] == task_id
    finally:
        cleanup(database, directory)


def test_executor_tool_loop_writes_file_and_audits() -> None:
    database, directory = fresh_db()
    workspace = directory / "ws"
    try:
        task_id = state.create_task(database, title="工具循环", goal="LLM 两次往返")
        sid = _plan_and_get_sid(database, task_id, workspace=workspace)
        final = json.dumps({"summary": "已写好结果文件", "score": 3}, ensure_ascii=False)
        llm = FakeLLM([
            {"tool_calls": [{"id": "t1", "name": "file_write",
                             "arguments": {"path": "out/result.json", "content": final}}]},
            {"content": final},
        ])
        result = executor.execute_subtask(database, llm, sid, workspace_root_override=str(workspace))
        assert result["status"] == "done" and result["iterations"] == 2 and result["tool_rounds"] == 1
        written = workspace / task_id / "out" / "result.json"
        assert written.exists() and json.loads(written.read_text(encoding="utf-8"))["summary"] == "已写好结果文件"
        row = database.query_one("SELECT * FROM tool_calls WHERE tool_name = 'file_write'")
        assert row["status"] == "ok" and row["task_id"] == task_id
        digest = json.loads(row["params_digest"])  # 参数摘要脱敏后落库（sys-arch §6.1）
        assert digest["path"] == "out/result.json"
        # tool 回包进入对话（assistant tool_calls + tool role 消息）
        sent_messages = llm.requests[1].messages
        assert any(m.get("role") == "assistant" and m.get("tool_calls") for m in sent_messages)
        assert any(m.get("role") == "tool" and "result.json" in str(m.get("content")) for m in sent_messages)
    finally:
        cleanup(database, directory)


def test_executor_second_retrieval_injected_into_system_prompt() -> None:
    database, directory = fresh_db()
    workspace = directory / "ws"
    try:
        task_id = state.create_task(database, title="二次检索", goal="http timeout 处理")
        sid = _plan_and_get_sid(database, task_id, llm=StubClient(database=database),
                                workspace=workspace)
        # 规划完成后再沉淀一条匹配规则 → brief 里没有，二次检索应补进系统提示（读时机之二）
        with database.transaction() as conn:
            conn.execute(
                "INSERT INTO prevention_rules (rule_text, match_keywords, task_types, status,"
                " source_error_ids, occurrences, risk_level)"
                " VALUES ('外部请求必须先设 10s 超时再重试', 'http timeout', '*', 'candidate', '[]', 1, 'high')")
        rule_id = int(database.query_one("SELECT id FROM prevention_rules")["id"])
        ledger.review_rule(database, rule_id, "alice")
        final = json.dumps({"summary": "done"}, ensure_ascii=False)
        llm = FakeLLM([{"content": final}])
        executor.execute_subtask(database, llm, sid, workspace_root_override=str(workspace))
        system = llm.requests[0].messages[0]["content"]
        assert "外部请求必须先设 10s 超时再重试" in system
        assert "账本二次检索" in system
    finally:
        cleanup(database, directory)


def test_executor_failure_paths_register_and_stop() -> None:
    database, directory = fresh_db()
    workspace = directory / "ws"
    try:
        # 1) LLM 网关失败（429）→ 账本 llm_gateway_error + 子任务 failed
        task_id = state.create_task(database, title="网关失败", goal="g")
        sid = _plan_and_get_sid(database, task_id, workspace=workspace)
        llm = FakeLLM([LLMRateLimitedError("gateway 429")])
        result = executor.execute_subtask(database, llm, sid, workspace_root_override=str(workspace))
        assert result["status"] == "failed" and result["error_type"] == "llm_gateway_error"
        assert state.SubtaskStatus(database.query_one(
            "SELECT status FROM subtasks WHERE id = ?", (sid,))["status"]) is state.SubtaskStatus.FAILED
        assert database.query_one(
            "SELECT * FROM error_ledger WHERE task_id = ? AND error_type = 'llm_gateway_error'",
            (task_id,)) is not None
        stopped = json.loads(database.query(
            "SELECT payload FROM events WHERE event_type = 'subtask_stopped' AND task_id = ? ORDER BY ts DESC",
            (task_id,))[0]["payload"])
        assert stopped["status"] == "failed"  # 不上报半成品为成功
        # 2) 迭代预算耗尽（max_llm_calls=1，LLM 只回工具调用且工具成功）→ failed
        task_id2 = state.create_task(database, title="预算耗尽", goal="g2")
        sid2 = _plan_and_get_sid(database, task_id2, workspace=workspace)
        with local_http_server([(200, {"ok": True})]) as (base_url, _):
            llm2 = FakeLLM([{"tool_calls": [{"id": "t1", "name": "http_get",
                                              "arguments": {"url": base_url + "/x"}}]}])
            result2 = executor.execute_subtask(database, llm2, sid2,
                                               workspace_root_override=str(workspace), max_llm_calls=1)
        assert result2["status"] == "failed" and result2["error_type"] == "max_llm_calls_exceeded"
        assert database.query_one(
            "SELECT * FROM error_ledger WHERE task_id = ? AND error_type = 'max_llm_calls_exceeded'",
            (task_id2,)) is not None
        # 3) 终答非 JSON → result_schema_violation
        task_id3 = state.create_task(database, title="坏终答", goal="g3")
        sid3 = _plan_and_get_sid(database, task_id3, workspace=workspace)
        llm3 = FakeLLM([{"content": "抱歉我不会输出 JSON"}])
        result3 = executor.execute_subtask(database, llm3, sid3, workspace_root_override=str(workspace))
        assert result3["status"] == "failed" and result3["error_type"] == "result_schema_violation"
        # 4) LLM 调用未列工具（未列即禁用，§4.2）→ tool_not_allowed
        task_id4 = state.create_task(database, title="越权工具", goal="g4")
        sid4 = _plan_and_get_sid(database, task_id4, workspace=workspace)
        llm4 = FakeLLM([{"tool_calls": [{"id": "t9", "name": "shell_exec",
                                          "arguments": {"cmd": "rm"}}]}])
        result4 = executor.execute_subtask(database, llm4, sid4, workspace_root_override=str(workspace))
        assert result4["status"] == "failed" and result4["error_type"] == "tool_not_allowed"
        # 5) 工具执行失败（http 404）→ 账本 HTTP_404 + failed（ToolBox 已登记，executor 停止）
        task_id5 = state.create_task(database, title="工具失败", goal="g5")
        sid5 = _plan_and_get_sid(database, task_id5, workspace=workspace)
        with local_http_server([(404, {"e": 1})]) as (base_url, _):
            llm5 = FakeLLM([{"tool_calls": [{"id": "t2", "name": "http_get",
                                              "arguments": {"url": base_url + "/x"}}]},
                            {"content": json.dumps({"summary": "fallback"})}])
            result5 = executor.execute_subtask(database, llm5, sid5,
                                               workspace_root_override=str(workspace))
        assert result5["status"] == "failed" and result5["error_type"] == "HTTP_404"
        assert database.query_one(
            "SELECT * FROM error_ledger WHERE task_id = ? AND error_type = 'HTTP_404'",
            (task_id5,)) is not None
    finally:
        cleanup(database, directory)


def test_executor_requires_planning_status_and_brief() -> None:
    database, directory = fresh_db()
    try:
        task_id = state.create_task(database, title="守卫", goal="无 brief 不可执行")
        gid = state.create_group(database, task_id, name="G")
        sid = state.create_subtask(database, task_id, gid, objective="无 brief")
        try:
            executor.execute_subtask(database, StubClient(), sid,
                                     workspace_root_override=str(directory / "ws"))
        except ValueError as exc:
            assert "brief" in str(exc) or "planning" in str(exc)
        else:
            raise AssertionError("executor must require planning + brief")
    finally:
        cleanup(database, directory)
