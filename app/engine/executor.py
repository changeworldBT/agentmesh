"""executor.py — 子任务执行器：按 brief 组装上下文调 LLM，内置工具 http_get/file_write，结果事件落库。

设计文档出处（模块顶部注记，按 ask 要求）：
- sys-arch（ARCH-ROOT-01）§2.4：子代理运行时（全局并发 ≤4 归引擎信号量，本模块为单子任务
  执行体）；§4.1：每个子任务由独立子代理运行时实例执行，不共享主对话；§4.2：brief 是
  子代理的全部世界（子代理启动时二次检索补充进系统提示——读时机之二）、on_failure
  register_and_stop（登记错误账本后停止，不上报半成品为成功）、brief 版本化；
  §6.1：每次工具调用落 tool_calls 表（错误自动登记错误账本）；§7.1：子代理起止/每次工具
  调用事件化落库；§9.1 时序（R→E→T→C 链）；§9.3 不变量 1（主对话原文不出现在任何
  brief/子代理提示中——本模块只组装 brief 自身字段）。
- interface-contracts（ICON-01）§2：event_type 词表——`brief_dispatched`（subtask_id、
  brief 版本号）、`subtask_started`/`subtask_stopped`（subtask_id、起止原因）、
  `tool_call`（工具名、参数摘要、结果状态）、`llm_call`；§5.4：brief 字段渲染面。
- memory-design（MEM-ERR-01）§4 矩阵：running（worker 启动）读（二次读）——
  search_rules(task_type, brief_keywords, limit=3) + search_errors(limit=3) 注入系统提示
  （与 brief 内容去重），失败降级系统提示照常生成仅缺记忆块；工具调用或任务体捕获异常
  写（即时）ledger_write。
- deployment-ops §5.1：tool_calls 表归工具接入层（MCP 客户端），首次工具调用审计写入前
  按需建表。
- real-vps-facts：重状态放 /data（数据盘 20G）——本 ask 指定工作区根
  /data/agentmesh/workspaces/<task_id>/。
- credentials-spec（CRED-01）§5.1 六步短寿命注入：工具参数里只出现
  `credential:<key_name>` 占位符（①），ToolBox 在调用瞬间向凭证管理器要 ②校验→③解密
  →④注入（header 型进本次 HTTP 请求头；env 型无 in-process 注入面→硬拒绝）→⑤消费
  →⑥调用返回即丢弃（局部 dict 不缓存）；deny 落 credential_audit（§4.3），明文永不进
  事件/账本/tool_calls 摘要。

偏离与取舍（如实声明）：
- 工作区根默认 /data/agentmesh/workspaces（本 ask 指定），另设 AGENTMESH_WORKSPACE_ROOT
  环境变量与函数参数覆盖位——本地非 Linux 环境跑验收必需的显式测试钩子，默认值不变。
- MVP 内置工具仅 http_get/file_write（本 ask 指定）；sys-arch §6.2 tool_registry/
  role_tool_grants（MCP 注册表与角色授权双闸门）归工具接入层 MCP 客户端后续交付物，
  本模块以 TOOL_ALLOWLIST 常量承接双闸门中的 brief 白名单一侧（未列即禁用，§4.2）。
- http_get 无出网 allowlist/SSRF 防护——设计未定义出口策略，MVP 如实保留（仅有超时与
  响应字节上限），列为后续加固项。
- env 型凭证在 http_get 内无注入面：CRED §5.1 ④ 的 env 通道语义是「子进程 env」，
  本内核工具均为 in-process 调用，故 env 型条目经 http_get 引用时硬拒绝
  （credential_inject_unsupported，登记账本），不伪造一条「注入成功」的假路径。
- 工具回包不落库全文，tool_calls 表存参数摘要（write_guard 脱敏）与状态（sys-arch §6.1
  「参数摘要脱敏」）。
"""

from __future__ import annotations

import json
import os
import re
import shutil
import sqlite3
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from app.engine import ledger
from app.engine.db import Database, emit_event, json_dumps, utc_now_iso
from app.engine.llm import LLMGatewayError, LLMRequest, LLMResponse
from app.engine.state import SubtaskStatus, transition_subtask

TOOL_ALLOWLIST: tuple[str, ...] = ("http_get", "file_write", "agent_run")
DEFAULT_WORKSPACE_ROOT = "/data/agentmesh/workspaces"  # 本 ask 指定；real-vps-facts：重状态落 /data
MAX_HTTP_BYTES = 262144          # http_get 响应字节上限（256KB，防大响应挤占内存）
DEFAULT_HTTP_TIMEOUT_S = 10.0
_TASK_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_\-]*$")


class ToolError(RuntimeError):
    """工具执行失败（error_type 用于错误账本签名）。"""

    def __init__(self, error_type: str, message: str, params: dict[str, str] | None = None) -> None:
        super().__init__(message)
        self.error_type = error_type
        self.params = params or {}


class PathEscapeError(ToolError):
    """file_write 路径越界（本 ask：越界即拒绝并登记错误账本）。"""

    def __init__(self, message: str, params: dict[str, str] | None = None) -> None:
        super().__init__("path_escape", message, params)


# ---------------------------------------------------------------------------
# 工作区路径策略（file_write 硬限制的唯一事实源；planner 计算 deliverable_path 复用）
# ---------------------------------------------------------------------------

def workspace_root(override: str | os.PathLike[str] | None = None) -> Path:
    """工作区根：参数 > AGENTMESH_WORKSPACE_ROOT 环境变量 > /data/agentmesh/workspaces（本 ask 默认）。"""
    if override is not None:
        return Path(os.fspath(override))
    env = os.environ.get("AGENTMESH_WORKSPACE_ROOT")
    if env:
        return Path(env)
    return Path(DEFAULT_WORKSPACE_ROOT)


def task_workspace(root: str | os.PathLike[str] | None, task_id: str) -> Path:
    """task 工作区目录 <root>/<task_id>/；task_id 必须是安全文件名段（防目录注入）。"""
    if not _TASK_ID_RE.match(task_id):
        raise ValueError(f"unsafe task_id for workspace path: {task_id!r}")
    return Path(os.fspath(root)) / task_id if root is not None else workspace_root() / task_id


def resolve_in_workspace(root: str | os.PathLike[str] | None, task_id: str, raw_path: str) -> Path:
    """把工具传入路径解析到任务工作区内；越界（相对上跳/绝对路径在外/符号链接逃逸）即拒绝。

    本 ask 硬限制：一切 file_write 落点必须在 /data/agentmesh/workspaces/<task_id>/ 之下。
    """
    if not isinstance(raw_path, str) or not raw_path.strip():
        raise PathEscapeError("empty path", {"path": str(raw_path)})
    task_root = task_workspace(root, task_id).resolve()
    candidate = Path(raw_path)
    if not candidate.is_absolute():
        candidate = task_root / candidate
    resolved = candidate.resolve()
    if resolved != task_root and task_root not in resolved.parents:
        raise PathEscapeError(
            f"path escapes task workspace: {raw_path!r} (workspace={task_root})",
            {"path": raw_path},
        )
    return resolved


# ---------------------------------------------------------------------------
# 内置工具实现（纯函数，审计与账本登记在 ToolBox）
# ---------------------------------------------------------------------------

def tool_http_get(params: dict[str, Any], *, task_id: str,
                  headers: dict[str, str] | None = None) -> dict[str, Any]:
    """内置 http_get：stdlib urllib GET，超时 + 响应字节上限。

    headers 仅供凭证注入通道使用（CRED §5.1 ④ header 型）：值只在本函数栈帧与本次
    请求头中存在，调用返回即随 request/session 丢弃（⑥）。
    """
    url = str((params or {}).get("url") or "").strip()
    if not url:
        raise ToolError("http_error", "http_get requires url", {"url": ""})
    timeout_s = float((params or {}).get("timeout_s") or DEFAULT_HTTP_TIMEOUT_S)
    request = urllib.request.Request(url, headers=dict(headers or {}), method="GET")
    try:
        with urllib.request.urlopen(request, timeout=timeout_s) as resp:  # noqa: S310 - MVP 无出网策略
            status = int(resp.status)
            body_bytes = resp.read(MAX_HTTP_BYTES + 1)
    except urllib.error.HTTPError as exc:
        raise ToolError(f"HTTP_{exc.code}", f"HTTP {exc.code}: {exc.reason} url={url}",
                        {"url": url}) from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise ToolError("http_error", f"http_get failed: {exc}", {"url": url}) from exc
    truncated = len(body_bytes) > MAX_HTTP_BYTES
    body = body_bytes[:MAX_HTTP_BYTES].decode("utf-8", errors="replace")
    return {"url": url, "status": status, "body": body, "truncated": truncated}


def tool_file_write(params: dict[str, Any], *, task_id: str, root: str | os.PathLike[str] | None = None) -> dict[str, Any]:
    """内置 file_write：写路径硬限制在任务工作区内，越界即拒绝（PathEscapeError → 账本）。"""
    path_raw = str((params or {}).get("path") or "")
    content = (params or {}).get("content")
    if content is None:
        content = ""
    target = resolve_in_workspace(root, task_id, path_raw)
    target.parent.mkdir(parents=True, exist_ok=True)
    data = str(content).encode("utf-8")
    target.write_bytes(data)
    return {"path": str(target), "bytes": len(data)}


# ---------------------------------------------------------------------------
# agent_run：经 herdr CLI 把子任务派给真实 coding agent（治理层⇄执行体对接位）。
# herdr 预置一个常驻 agent pane（herdr agent start ... --kind claude），内核以
# `herdr agent prompt <name> <text> --wait` 派活并等终态，再 `herdr agent read` 收尾答。
# 治理纪律：内核不直接 shell 任意命令——只经 herdr 一条受控通道；产物由 agent 写进
# 本任务工作区（brief.deliverable_path 落在 <root>/<task_id>/ 之下，file_write 硬限制同源）。
# ---------------------------------------------------------------------------

DEFAULT_HERDR_BIN = "herdr"
DEFAULT_HERDR_AGENT = "agentmesh-worker"
AGENT_RUN_TIMEOUT_S = 600.0          # 真实 agent 跑任务的兜底上限（10 分钟）
AGENT_RUN_MAX_OUTPUT = 8192          # 回读 tail 上限（防大输出挤占上下文）


class HerdrUnavailableError(ToolError):
    """herdr CLI/agent pane 不可用（治理通道未接线）。"""

    def __init__(self, message: str, params: dict[str, str] | None = None) -> None:
        super().__init__("herdr_unavailable", message, params)


def _herdr_bin() -> str:
    """herdr 二进制：AGENTMESH_HERDR_BIN 环境变量 > PATH 上的 herdr。"""
    override = os.environ.get("AGENTMESH_HERDR_BIN")
    if override and os.path.isfile(override):
        return override
    found = shutil.which(DEFAULT_HERDR_BIN)
    if not found:
        raise HerdrUnavailableError(
            "herdr CLI 不在 PATH（治理执行通道未接线）；安装后设 AGENTMESH_HERDR_BIN")
    return found


def _herdr_agent_name() -> str:
    return os.environ.get("AGENTMESH_HERDR_AGENT") or DEFAULT_HERDR_AGENT


def tool_agent_run(params: dict[str, Any], *, task_id: str,
                   root: str | os.PathLike[str] | None = None) -> dict[str, Any]:
    """把一段自包含任务文本派给 herdr 常驻 agent，阻塞等终态并回读末尾输出。

    params:
      - task: 必填，自包含任务文本（自然语言；agent 无主对话上下文）
      - workspace: 可选，相对任务工作区的子目录（agent 的工作落点提示，写进任务文本）
    返回 {agent,status,exit_hint,output_tail}；不搬运产物文件——产物由 agent 按 brief
    的 deliverable_path 直接写任务工作区（与 file_write 同一硬限制根，内核只回读文本）。
    """
    text = str((params or {}).get("task") or "").strip()
    if not text:
        raise ToolError("task_empty", "agent_run requires task", {"task": ""})
    sub = str((params or {}).get("workspace") or "").strip()
    bin_path = _herdr_bin()
    agent_name = _herdr_agent_name()
    prompt = text
    if sub:
        safe = re.sub(r"[^A-Za-z0-9._/-]", "_", sub).strip("/")
        if safe:
            ws = resolve_in_workspace(root, task_id, safe)
            ws.mkdir(parents=True, exist_ok=True)
            prompt = f"{text}\n（产物/工作文件请放在 {ws} 目录内）"

    def _herdr(args: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        try:
            return subprocess.run([bin_path, *args], capture_output=True, text=True,
                                  encoding="utf-8", errors="replace", timeout=timeout)
        except FileNotFoundError as exc:
            raise HerdrUnavailableError(f"herdr binary vanished: {bin_path}") from exc
        except subprocess.TimeoutExpired as exc:
            raise ToolError("agent_run_timeout",
                            f"herdr {args[0]} timed out after {timeout:.0f}s",
                            {"agent": agent_name}) from exc

    # ① 派活并等终态（--wait 阻塞到 agent 回 idle；失败即 ToolError，账本即时登记）
    prompt_run = _herdr(["agent", "prompt", agent_name, prompt, "--wait"], AGENT_RUN_TIMEOUT_S)
    if prompt_run.returncode != 0:
        raise ToolError("agent_prompt_failed",
                        (prompt_run.stderr or prompt_run.stdout or "").strip()[:400],
                        {"agent": agent_name, "exit_code": str(prompt_run.returncode)})
    # ② 回读终端末尾输出（最终答复/报错都在末尾；tail 上限防挤占）
    read_run = _herdr(["agent", "read", agent_name], 30.0)
    tail = (read_run.stdout or "").strip()[-AGENT_RUN_MAX_OUTPUT:]
    state = _herdr(["agent", "get", agent_name], 15.0)
    status = "idle"
    try:
        payload = json.loads(state.stdout or "{}")
        status = str(((payload.get("result") or {}).get("agent") or {}).get("agent_status") or "idle")
    except json.JSONDecodeError:
        pass
    return {"agent": agent_name, "status": status, "exit_hint": prompt_run.returncode,
            "output_tail": tail}


TOOL_SCHEMAS: list[dict[str, Any]] = [
    {
        "name": "http_get",
        "description": "HTTP GET 一个 URL，返回 {url,status,body,truncated}；超时 10s、响应上限 256KB",
        "parameters": {
            "type": "object",
            "properties": {"url": {"type": "string"}, "timeout_s": {"type": "number"}},
            "required": ["url"],
        },
    },
    {
        "name": "file_write",
        "description": "把文本写入任务工作区内路径（仅限 /data/agentmesh/workspaces/<task_id>/ 之下），返回 {path,bytes}",
        "parameters": {
            "type": "object",
            "properties": {"path": {"type": "string"}, "content": {"type": "string"}},
            "required": ["path", "content"],
        },
    },
    {
        "name": "agent_run",
        "description": "把一段自包含任务派给 herdr 常驻真实 coding agent（可读写文件/跑命令），阻塞等终态并回读输出末尾；产物请让 agent 写入任务工作区",
        "parameters": {
            "type": "object",
            "properties": {
                "task": {"type": "string", "description": "自包含任务文本（agent 无主对话上下文）"},
                "workspace": {"type": "string", "description": "任务工作区内子目录，agent 的产物落点"},
            },
            "required": ["task"],
        },
    },
]


# ---------------------------------------------------------------------------
# ToolBox：工具分发 + tool_calls 审计表 + tool_call 事件 + 错误账本即时登记
# ---------------------------------------------------------------------------

TOOL_CALLS_TABLE_STATEMENTS: tuple[str, ...] = (
    """
    CREATE TABLE IF NOT EXISTS tool_calls (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      ts            TEXT NOT NULL,
      task_id       TEXT,
      subtask_id    TEXT,
      tool_name     TEXT NOT NULL,
      params_digest TEXT NOT NULL,
      status        TEXT NOT NULL,
      duration_ms   INTEGER,
      error         TEXT,
      event_id      TEXT NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_tool_calls_task ON tool_calls(task_id, ts)",
)


def _params_digest(params: dict[str, Any] | None) -> str:
    """参数摘要（sys-arch §6.1：参数摘要脱敏；值经 normalize_param 归一化 + write_guard 脱敏）。"""
    normalized = {str(k): ledger.normalize_param(str(v)) for k, v in (params or {}).items()}
    return ledger.write_guard(json_dumps(normalized))


CREDENTIAL_PLACEHOLDER_RE = re.compile(r"credential:([A-Za-z0-9][A-Za-z0-9_.\-]*)")


def _strip_credential_placeholders(params: dict[str, Any]) -> dict[str, Any]:
    """剥离参数中的 `credential:<key_name>` 引用标记（key 名不发给外部服务；值是注入的，不做替换）。"""
    stripped: dict[str, Any] = {}
    for key, value in params.items():
        if isinstance(value, str):
            stripped[key] = CREDENTIAL_PLACEHOLDER_RE.sub("", value)
        else:
            stripped[key] = value
    return stripped


class ToolBox:
    """子代理的工具面：分发内置工具、审计（tool_calls 表 + tool_call 事件）、错误即时登记（MEM §4 写时机）、
    凭证占位符解析与短寿命注入（CRED §5.1 六步；评审收口项）。"""

    def __init__(self, database: Database, task_id: str, subtask_id: str,
                 *, root: str | os.PathLike[str] | None = None, role: str = "worker:executor",
                 credential_manager: Any | None = None) -> None:
        self.database = database
        self.task_id = task_id
        self.subtask_id = subtask_id
        self.root = root
        self.role = role
        self.credential_manager = credential_manager
        with database.transaction() as conn:
            for stmt in TOOL_CALLS_TABLE_STATEMENTS:  # deployment-ops §5.1：首写前按需建表
                conn.execute(stmt)

    def call(self, name: str, params: dict[str, Any] | None) -> dict[str, Any]:
        """执行一个工具调用；成功/失败都审计，失败即时登记错误账本后原样上抛（不吞错）。"""
        started = time.perf_counter()
        digest = _params_digest(params)
        try:
            call_params, headers = self._resolve_credentials(name, params or {})
            if name == "http_get":
                result = tool_http_get(call_params, task_id=self.task_id, headers=headers)
            elif name == "file_write":
                result = tool_file_write(call_params, task_id=self.task_id, root=self.root)
            elif name == "agent_run":
                result = tool_agent_run(call_params, task_id=self.task_id, root=self.root)
            else:
                raise ToolError("unknown_tool", f"unknown tool: {name!r}")
        except ToolError as exc:
            duration_ms = int((time.perf_counter() - started) * 1000)
            self._audit(name, digest, "error", duration_ms, str(exc))
            self._register_error(exc, name)
            raise
        duration_ms = int((time.perf_counter() - started) * 1000)
        self._audit(name, digest, "ok", duration_ms, None)
        return result

    # -- 凭证占位符 → 短寿命注入（CRED §5.1 ①→④；⑥ 由本函数返回即丢弃保证）----------

    def _resolve_credentials(self, tool_name: str, params: dict[str, Any]
                             ) -> tuple[dict[str, Any], dict[str, str]]:
        """扫描参数中的 `credential:<key_name>` 占位符（①），过管理器三闸门（②③），
        返回 (剥离占位符后的参数, 本次请求头)（④）。

        - 占位符是**引用标记**而非值：解析后从出参参数中剥离，绝不把 key 名发往外部服务；
        - header 型条目 → 注入本次 HTTP 请求头（值只存在于本栈帧与 request 对象，⑥）；
        - env 型条目 → 本内核工具无子进程 env 注入面，硬拒绝（credential_inject_unsupported）；
        - 非 http_get 工具携带占位符 → 同样硬拒绝（没有注入面就不伪造注入）。
        """
        found: list[str] = []
        for value in params.values():
            if isinstance(value, str):
                for match in CREDENTIAL_PLACEHOLDER_RE.finditer(value):
                    if match.group(1) not in found:
                        found.append(match.group(1))
        if not found:
            return params, {}
        if tool_name != "http_get":
            raise ToolError(
                "credential_inject_unsupported",
                f"tool {tool_name!r} has no credential injection surface (CRED §5.1 ④ 仅 env/header)",
                {"tool": tool_name, "key_name": ",".join(found)})
        manager = self.credential_manager
        if manager is None:
            raise ToolError("credential_channel_unavailable",
                            "凭证管理器未接线，无法解析 credential: 占位符",
                            {"key_name": ",".join(found)})
        role = self.role.split(":", 1)[0]
        headers: dict[str, str] = {}
        for key_name in found:
            resolution = manager.resolve(key_name, role, "header", task_id=self.task_id)
            if not resolution.get("allowed"):
                denial = resolution.get("denial") or {}
                reason = str(denial.get("reason") or "unknown")
                pair = manager.entry(key_name)
                if reason == "kind_mismatch" and pair and pair[1].get("env") is not None:
                    # 条目是 env 型：本内核工具无子进程 env 注入面（见模块 docstring 偏离声明）
                    raise ToolError(
                        "credential_inject_unsupported",
                        f"credential {key_name!r} is env-kind; no env injection surface "
                        f"in in-process tools (CRED §5.1 ④)",
                        {"key_name": key_name, "kind": "env"})
                raise ToolError("credential_denied",
                                f"credential denied: {reason} ({key_name})",
                                {"key_name": key_name, "reason": reason})
            header_name, header_value = resolution["inject"]["header"]
            headers[str(header_name)] = str(header_value)
        return _strip_credential_placeholders(params), headers

    def _audit(self, tool_name: str, digest: str, status: str, duration_ms: int,
               error: str | None) -> str:
        """sys-arch §6.1 调用审计：tool_calls 表行 + tool_call 事件（同一事务，可 replay）。"""
        with self.database.transaction() as conn:
            event_id = emit_event(conn, task_id=self.task_id, component="worker_runtime",
                                  event_type="tool_call",
                                  payload={"subtask_id": self.subtask_id, "tool": tool_name,
                                           "status": status, "duration_ms": duration_ms,
                                           "params_digest": digest, "error": error})
            conn.execute(
                "INSERT INTO tool_calls (ts, task_id, subtask_id, tool_name, params_digest,"
                " status, duration_ms, error, event_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (utc_now_iso(), self.task_id, self.subtask_id, tool_name, digest,
                 status, duration_ms, error, event_id),
            )
        return event_id

    def _register_error(self, exc: ToolError, tool_name: str) -> None:
        """memory-design §4 写时机（running 即时写）；签名经 make_signature 等值可累计。"""
        try:
            ledger.ledger_write(
                self.database, exc.error_type, tool_name, exc.params,
                str(exc), self.task_id, self.role,
            )
        except Exception:
            pass  # 账本写失败不掩盖原工具异常（MEM §4：异常本身仍按原路径上抛）


# ---------------------------------------------------------------------------
# 子任务执行主流程
# ---------------------------------------------------------------------------

def _strip_json_fences(text: str) -> str:
    t = str(text or "").strip()
    if t.startswith("```"):
        t = re.sub(r"^```[A-Za-z0-9_+\-]*\s*", "", t)
        t = re.sub(r"\s*```$", "", t)
    return t.strip()


def _latest_brief(database: Database, subtask_id: str) -> dict[str, Any]:
    try:
        rows = database.query(
            "SELECT brief FROM briefs WHERE subtask_id = ? ORDER BY version DESC LIMIT 1",
            (subtask_id,),
        )
    except sqlite3.OperationalError as exc:
        # briefs 表由 planner 首写时按需建（deployment-ops §5.1）；从未规划过的库视同无 brief
        raise ValueError(f"no brief found for subtask {subtask_id}: {exc}") from exc
    if not rows:
        raise ValueError(f"no brief found for subtask {subtask_id}; run planner first")
    return dict(json.loads(str(rows[0]["brief"])))


def _second_retrieval(database: Database, brief: dict[str, Any]) -> list[str]:
    """读时机之二（memory-design §4）：worker 启动二次检索 rules(3)/errors(3) 注入系统提示，
    与 brief 已注入项去重；失败返回空列表（系统提示照常生成，仅缺记忆块）。"""
    lines: list[str] = []
    known_rule_ids = {
        entry.get("rule_id") for entry in (brief.get("prevention_rules") or [])
        if isinstance(entry, dict)
    }
    keywords = retrieval_keywords(str(brief.get("objective") or ""), str(brief.get("task_type") or "generic"))
    if not keywords:
        return lines
    try:
        # OR 语义召回面（同 planner 读时机一；与 brief 已注入项按 rule_id 去重）
        for rule in ledger.search_rules(database, keywords,
                                        task_type=str(brief.get("task_type") or "generic"), limit=3,
                                        keyword_operator="OR"):
            if rule["id"] in known_rule_ids:
                continue  # 与 brief 内容去重（MEM §4 注入位置约定）
            lines.append(f"- [生效规则 {rule['id']}] {rule['rule_text']}")
        for err in ledger.search_errors(database, keywords, limit=3, keyword_operator="OR"):
            lines.append(f"- [相似历史错误 {err['id']}] {err['error_signature']}：根因={err['root_cause'] or '未填'}")
    except Exception:
        return lines  # 检索失败不阻塞启动（降级已由 search 层落 memory_degraded 事件）
    return lines


def retrieval_keywords(text: str, task_type: str, limit: int = 8) -> list[str]:
    """检索关键词：ASCII 词（≥3 字符）+ CJK 连续段（2-6 字），附 task_type，去重保序截断。"""
    tokens: list[str] = []
    for tok in re.findall(r"[A-Za-z][A-Za-z0-9_\-]{2,}|[\u4e00-\u9fff]{2,6}", str(text or "")):
        if tok not in tokens:
            tokens.append(tok)
    if task_type and task_type not in tokens:
        tokens.append(task_type)
    return tokens[:limit]


def execute_subtask(
    database: Database,
    llm: Any,
    subtask_id: str,
    *,
    workspace_root_override: str | os.PathLike[str] | None = None,
    max_llm_calls: int | None = None,
    now: str | None = None,
    credential_manager: Any | None = None,
) -> dict[str, Any]:
    """执行一个子任务（brief → 上下文组装 → LLM/工具循环 → 结果事件落库）。

    返回 {"status": "done"|"failed", ...}；失败路径遵循 brief.on_failure=register_and_stop
    （sys-arch §4.2）：错误登记错误账本后停止，子任务转 failed（T10 sub），不上报半成品。
    """
    now_ts = now or utc_now_iso()
    row = database.query_one("SELECT * FROM subtasks WHERE id = ?", (subtask_id,))
    if row is None:
        raise KeyError(f"subtask not found: {subtask_id}")
    task_id = str(row["task_id"])
    if SubtaskStatus(row["status"]) is not SubtaskStatus.PLANNING:
        raise ValueError(f"subtask {subtask_id} must be in planning to execute (got {row['status']})")
    brief = _latest_brief(database, subtask_id)
    allowed_tools = tuple(brief.get("allowed_tools") or [])
    unknown = [t for t in allowed_tools if t not in TOOL_ALLOWLIST]
    if unknown:
        raise ValueError(f"brief allowed_tools beyond kernel allowlist: {unknown}")

    transition_subtask(database, subtask_id, SubtaskStatus.RUNNING, component="worker_runtime",
                       reason="brief dispatch", now=now_ts)
    with database.transaction() as conn:
        emit_event(conn, task_id=task_id, component="worker_runtime", event_type="brief_dispatched",
                   payload={"subtask_id": subtask_id, "brief_version": int(row["brief_version"])})
        emit_event(conn, task_id=task_id, component="worker_runtime", event_type="subtask_started",
                   payload={"subtask_id": subtask_id, "objective": brief.get("objective")})

    toolbox = ToolBox(database, task_id, subtask_id, root=workspace_root_override,
                      credential_manager=credential_manager)
    max_calls = int(max_llm_calls or brief.get("max_iterations") or 3)

    system_prompt = (
        "你是子代理执行体。brief 是你的全部世界（主对话不可见）。"
        "可用工具：未在 brief.allowed_tools 列出的工具一律禁用。"
        "最终答复必须是 JSON 对象且含非空 summary 字段。\n"
        f"BRIEF:\n{json_dumps(brief)}\n"
    )
    supplement = _second_retrieval(database, brief)
    if supplement:
        system_prompt += "【账本二次检索（系统提示补充）】\n" + "\n".join(supplement) + "\n"
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": json_dumps({
            "objective": brief.get("objective"),
            "self_contained_context": brief.get("self_contained_context"),
            "acceptance_criteria": brief.get("acceptance_criteria") or [],
            "deliverable_path": brief.get("deliverable_path"),
        })},
    ]
    tools = [schema for schema in TOOL_SCHEMAS if schema["name"] in allowed_tools]

    iterations = 0
    tool_rounds = 0
    while iterations < max_calls:
        iterations += 1
        try:
            response: LLMResponse = llm.chat(LLMRequest(
                messages=messages, tools=tools if tools else None,
                kind="execute",
                stub_payload={"objective": brief.get("objective"),
                              "deliverable_path": brief.get("deliverable_path")},
                task_id=task_id, subtask_id=subtask_id, component="worker_runtime",
            ))
        except LLMGatewayError as exc:
            return _fail(database, subtask_id, task_id, "llm_gateway_error", "executor",
                         {}, f"LLM gateway error: {exc}", now_ts)
        if response.tool_calls:
            tool_rounds += len(response.tool_calls)
            messages.append({"role": "assistant", "content": response.content,
                             "tool_calls": response.raw_tool_calls})
            for tc in response.tool_calls:
                name = tc.get("name") or ""
                if name not in allowed_tools:
                    # sys-arch §4.2：未列即禁用——拒绝并登记后停止（register_and_stop）
                    return _fail(database, subtask_id, task_id, "tool_not_allowed", name,
                                 {}, f"tool {name!r} not in brief.allowed_tools", now_ts)
                try:
                    call_params = dict(json.loads(str(tc.get("arguments") or "{}")))
                except ValueError as exc:
                    return _fail(database, subtask_id, task_id, "bad_tool_arguments", name,
                                 {}, f"tool arguments not valid JSON: {exc}", now_ts)
                try:
                    result = toolbox.call(name, call_params)
                except ToolError as exc:  # ToolBox 已登记账本与审计，此处按 on_failure 停止
                    return _fail(database, subtask_id, task_id, exc.error_type, name,
                                 exc.params, str(exc), now_ts, already_registered=True)
                messages.append({"role": "tool", "tool_call_id": tc.get("id") or "",
                                 "content": json_dumps(result)})
            continue
        # 终答：必须为 JSON 且含非空 summary
        try:
            result = json.loads(_strip_json_fences(str(response.content or "")))
            if not isinstance(result, dict) or not str(result.get("summary") or "").strip():
                raise ValueError("result must be a JSON object with non-empty 'summary'")
        except ValueError as exc:
            return _fail(database, subtask_id, task_id, "result_schema_violation", "executor",
                         {}, f"final result invalid: {exc}; raw={str(response.content)[:200]!r}",
                         now_ts)
        with database.transaction() as conn:
            emit_event(conn, task_id=task_id, component="worker_runtime",
                       event_type="subtask_stopped",
                       payload={"subtask_id": subtask_id, "status": "done",
                                "summary": result.get("summary"), "result": result,
                                "iterations": iterations, "tool_rounds": tool_rounds})
        transition_subtask(database, subtask_id, SubtaskStatus.DONE, component="worker_runtime",
                           reason="execution finished", now=now_ts)
        return {"status": "done", "subtask_id": subtask_id, "task_id": task_id,
                "summary": result.get("summary"), "result": result,
                "iterations": iterations, "tool_rounds": tool_rounds,
                "deliverable_path": brief.get("deliverable_path")}
    # 迭代预算耗尽仍未终答（sys-arch §4.2 constraints 预算面，超限暂停→按 on_failure 停止）
    return _fail(database, subtask_id, task_id, "max_llm_calls_exceeded", "executor", {},
                 f"LLM call budget exhausted ({max_calls}) without a final JSON answer", now_ts)


def _fail(database: Database, subtask_id: str, task_id: str, error_type: str, module: str,
          params: dict[str, str], raw_error: str, now_ts: str, *,
          already_registered: bool = False) -> dict[str, Any]:
    """失败路径（on_failure=register_and_stop）：登记账本 → subtask_stopped 事件 → T10 sub → failed。"""
    entry_id: int | None = None
    if not already_registered:
        try:
            entry_id = ledger.ledger_write(database, error_type, module, params,
                                           raw_error, task_id, "worker:executor")
        except Exception:
            entry_id = None  # 账本写失败不阻断失败路径本身（MEM §4 降级）
    with database.transaction() as conn:
        emit_event(conn, task_id=task_id, component="worker_runtime",
                   event_type="subtask_stopped",
                   payload={"subtask_id": subtask_id, "status": "failed",
                            "error_type": error_type, "reason": raw_error[:500],
                            "ledger_entry_id": entry_id})
    transition_subtask(database, subtask_id, SubtaskStatus.FAILED, component="worker_runtime",
                       reason=f"on_failure register_and_stop: {error_type}", now=now_ts)
    return {"status": "failed", "subtask_id": subtask_id, "task_id": task_id,
            "error_type": error_type, "error": raw_error, "ledger_entry_id": entry_id}
