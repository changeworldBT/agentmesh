"""_helpers.py — ask-2 测试共享替身（非 test_* 文件，run_all 不收集）。

提供：临时库句柄、FakeLLM（脚本化 LLMResponse 序列 + 请求捕获）、本地 HTTP 服务
（stdlib http.server，用于 OPENAI_COMPAT 适配器与 http_get 工具的真实 HTTP 往返）、
合规计划样例。
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from shutil import rmtree
from typing import Any, Iterator

from app.engine.db import Database
from app.engine.llm import LLMResponse


class TestSkipped(RuntimeError):
    """测试环境缺少必要能力时的诚实跳过信号（run_all 计 skip 不计 fail）。"""


def fresh_db(tmp: Path | None = None, *, name: str = "agentmesh.db",
             fts: str = "auto") -> tuple[Database, Path]:
    """建临时库并连接（调用方负责 close + 清理）。"""
    directory = Path(tempfile.mkdtemp(prefix="agentmesh-ask2-")) if tmp is None else tmp
    database = Database(directory / name, fts=fts)
    database.connect()
    return database, directory


def cleanup(database: Database, directory: Path) -> None:
    database.close()
    rmtree(directory, ignore_errors=True)


@contextmanager
def temp_workspace_root() -> Iterator[Path]:
    """临时设置 AGENTMESH_WORKSPACE_ROOT，使引擎全链测试不依赖可写的 /data（退出时还原）。"""
    root = Path(tempfile.mkdtemp(prefix="agentmesh-ws-"))
    previous = os.environ.get("AGENTMESH_WORKSPACE_ROOT")
    os.environ["AGENTMESH_WORKSPACE_ROOT"] = str(root)
    try:
        yield root
    finally:
        if previous is None:
            os.environ.pop("AGENTMESH_WORKSPACE_ROOT", None)
        else:
            os.environ["AGENTMESH_WORKSPACE_ROOT"] = previous
        rmtree(root, ignore_errors=True)


class FakeLLM:
    """脚本化 LLM 替身：按序出队响应（dict → LLMResponse；Exception → 抛出），记录全部请求。"""

    def __init__(self, responses: list[Any] | None = None,
                 *, model: str = "fake-model") -> None:
        self.responses = list(responses or [])
        self.requests: list[Any] = []
        self.model = model

    def chat(self, request: Any) -> LLMResponse:
        self.requests.append(request)
        if not self.responses:
            raise AssertionError("FakeLLM: no scripted response left")
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return make_response(item, model=self.model)


def make_response(item: dict[str, Any] | str, *, model: str = "fake-model") -> LLMResponse:
    """把脚本条目转成 LLMResponse；tool_calls 元素同步生成 raw 形态（多轮协议回传用）。"""
    if isinstance(item, str):
        item = {"content": item}
    tool_calls = [
        {"id": str(t.get("id") or f"c{i+1}"), "name": str(t.get("name") or ""),
         "arguments": t.get("arguments") if isinstance(t.get("arguments"), str)
         else json.dumps(t.get("arguments") or {}, ensure_ascii=False)}
        for i, t in enumerate(item.get("tool_calls") or [])
    ]
    raw_tool_calls = [
        {"id": t["id"], "type": "function",
         "function": {"name": t["name"], "arguments": t["arguments"]}}
        for t in tool_calls
    ]
    return LLMResponse(content=item.get("content"), tool_calls=tool_calls,
                       raw_tool_calls=raw_tool_calls, finish_reason=item.get("finish_reason") or "stop",
                       model=model, provider="fake",
                       usage={"prompt_tokens": 10, "completion_tokens": 5}, latency_ms=1)


class _ScriptedHandler(BaseHTTPRequestHandler):
    """按脚本出队 (status, payload) 的本地 HTTP 服务；捕获请求 path/headers/body。"""

    script: list[tuple[int, dict[str, Any]]] = []
    captured: list[dict[str, Any]] = []

    def _respond(self) -> None:
        status, payload = self.script.pop(0) if self.script else (200, {})
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler 约定
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        self.captured.append({"method": "POST", "path": self.path,
                              "headers": {k: v for k, v in self.headers.items()},
                              "body": json.loads(raw.decode("utf-8")) if raw else None})
        self._respond()

    def do_GET(self) -> None:  # noqa: N802
        self.captured.append({"method": "GET", "path": self.path,
                              "headers": {k: v for k, v in self.headers.items()}, "body": None})
        self._respond()

    def log_message(self, *args: Any) -> None:  # 静默
        pass


@contextmanager
def local_http_server(script: list[tuple[int, dict[str, Any]]]) -> Iterator[tuple[str, list[dict[str, Any]]]]:
    """起一个 127.0.0.1 随机端口 HTTP 服务，yield (base_url, captured)；退出时关闭。"""
    handler = type("Handler", (_ScriptedHandler,), {"script": list(script), "captured": []})
    server = HTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", handler.captured
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def valid_plan(goal: str = "调研两个 SaaS 的定价页", *, subtask_id: str = "g1-1") -> dict[str, Any]:
    """一份可通过 planner.validate_plan 的最小合规计划。"""
    return {
        "task_type": "web_research",
        "budget_usd": 1.5,
        "groups": [{"id": "g1", "name": "执行组", "depends_on": [],
                    "batch_mode": False, "batch_total_items": None, "partial_ok": False}],
        "subtasks": [{
            "id": subtask_id, "group_id": "g1", "objective": goal,
            "task_type": "web_research",
            "self_contained_context": f"主任务目标（必要摘录）: {goal}",
            "acceptance_criteria": ["结果为 JSON 且含非空 summary 字段"],
            "allowed_tools": ["http_get", "file_write", "agent_run"],
            "risk_tier_hint": "reversible",
            "budget_usd": 0.5,
            "max_iterations": 3,
        }],
    }


def chat_completion_body(content: str, *, finish_reason: str = "stop",
                         tool_calls: list[dict[str, Any]] | None = None,
                         prompt_tokens: int = 11, completion_tokens: int = 7,
                         model: str = "test-model") -> dict[str, Any]:
    """构造 OPENAI_COMPAT /chat/completions 响应体。"""
    message: dict[str, Any] = {"role": "assistant", "content": content}
    if tool_calls:
        message["tool_calls"] = tool_calls
    return {
        "choices": [{"message": message, "finish_reason": finish_reason}],
        "usage": {"prompt_tokens": prompt_tokens, "completion_tokens": completion_tokens},
        "model": model,
    }
