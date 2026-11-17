"""server.py — HTTP API：按 out/interface-contracts.md 实现端点全表 + SSE 事件流 + 静态托管。

设计文档出处（模块顶部注记，按 ask 要求）：
- interface-contracts（ICON-01）为本模块的规范源：§1 全局约定（Bearer 鉴权/错误包络/
  游标分页/X-Request-Id/Idempotency-Key 24h/时间与 ID 形态）；§2 事件词表；§3 端点全表
  （0 healthz、A1-A5 任务域、B1-B3 审批域、C1-C2 事件域、D1-D3 执行记录、E1-E4 成本预算、
  F1-F5 错误账本、G1-G6 触发器、H1-H5 凭证元数据）；§4.2 SSE（Last-Event-ID 断线续播、
  stream_resync、心跳 15s、并发流上限 8 → 429 STREAM_LIMIT_EXCEEDED、FILTER_CONFLICT、
  X-Accel-Buffering: no）；§5-§12 各端点请求/响应/错误码。
- sys-arch（ARCH-ROOT-01）§9.2「用户 ⇄ 内核」行：HTTP JSON API 是对外唯一入口；
  §10.1：对外唯一端口 8787（compose 映射 127.0.0.1:8787→8787，容器内监听 0.0.0.0）；
  §9.3 不变量 3/4：replay 无副作用、写路径经引擎单一驱动者（状态变更全部走 state.py
  转移函数，本模块不直接 UPDATE tasks.status）。
- deployment-ops §2.1/§2.2：容器内 uvicorn --host 0.0.0.0 --port 8787、healthz 探针。

偏离与取舍（如实声明）：
- 传输层用标准库 http.server（ThreadingHTTPServer）而非 fastapi/uvicorn：本 ask 允许
  「若引入 fastapi/uvicorn 保持延迟导入以便 stdlib 环境不炸」——直接零第三方依赖更简单
  且本机可全量验收；ICON 的 HTTP JSON/SSE 契约与传输库无关，部署形态换 ASGI 时路由表
  与数据面可原样复用（sys-arch §10.2 依赖清单中的 uvicorn/fastapi 届时再进 requirements）。
- SSE 采用「库内轮询游标推进」而非进程内推送队列：事件落库即真相（ARCH §7.1），轮询
  等价满足断线续播语义且天然无界队列问题（慢消费者表现为游标落后，重连即追平）——
  §4.2 第 3 条「有界队列 1024 帧」的实现位等价替换，如实声明。
- 日期过滤（A2/D1/E1）按 UTC 存储日期 + 容器本地时区换算（ICON §1.5 容器时区自然日）；
  容器时区取 AGENTMESH_TZ/TZ 环境变量（IANA 名，zoneinfo），不可用时回退 UTC 并在
  healthz degradations 标注。
- cost_usd_est 全部为 0.0（单价表为配置值归可观测台，sys-arch §7.4 计量精度声明；
  token 数计量已在 llm_call 事件落库），响应带 metering_disclaimer。
- H 域（凭证元数据）依赖凭证管理器解密面（credentials-spec，后续交付物）：元数据源为
  可选的 AGENTMESH_CREDENTIALS_MANIFEST（解密后元数据 JSON 的进程内只读快照路径）；
  未接线时 H1/H5 返回空 + degraded:true（MEM §4 统一降级），H2 404 KEY_NOT_FOUND，
  H4 的 key_exists/kind_match 闸门为 null（ICON §6.3 响应 B 允许 null 闸门）。
- F5 retire 仅允许 active→retired（ICON §9.5；candidate 废止能力保留在内核内部
  ledger.retire_rule，HTTP 面按契约从严）。
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import threading
import time
import urllib.parse
from datetime import UTC, datetime, timedelta, timezone as dt_timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from app.engine import approval as approval_mod
from app.engine import credentials as credentials_mod
from app.engine import executor as executor_mod
from app.engine import ledger as ledger_mod
from app.engine import state as state_mod
from app.engine import triggers as triggers_mod
from app.engine.db import (Database, emit_event, iso_shift, json_dumps, new_ulid,
                           utc_now_iso)
from app.engine.state import TASK_TERMINAL_STATES, TaskStatus

MAX_BODY_BYTES = 1024 * 1024          # ICON §5.1：正文 >1MB → 413
WEBHOOK_MAX_BODY_BYTES = 256 * 1024   # ICON §7.6：请求体 ≤256KB
DEFAULT_PAGE_LIMIT = 50
MAX_PAGE_LIMIT = 200                  # ICON §1.4
SSE_MAX_CONCURRENT = 8                # ICON §4.2 并发流上限
SSE_HEARTBEAT_S = 15.0                # ICON §4.2 心跳 15s
MAX_CONCURRENCY = 4                   # ARCH §2.1 原则 5（硬约束，只读展示于 E4）
ICON_EVENT_TYPES = frozenset({
    "task_submitted", "ledger_lookup", "plan_produced", "brief_dispatched",
    "subtask_started", "subtask_stopped", "llm_call", "tool_call",
    "state_transition", "approval_requested", "approval_decision",
    "approval_timeout_skip", "rework_instruction", "review_verdict",
    "error_registered", "rule_candidate", "budget_exceeded", "task_aborted",
    "trigger_fired", "trigger_missed", "credential_inject", "credential_deny",
    "memory_degraded",
})
METERING_DISCLAIMER = "金额为按配置单价表的估算，token 数为准（ARCH §7.4 计量精度声明）"
RISK_LEVEL_TO_TIER = {"low": "reversible", "medium": "reversible_costly", "high": "irreversible"}
STATIC_CONTENT_TYPES = {".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8",
                        ".js": "application/javascript; charset=utf-8", ".json": "application/json",
                        ".svg": "image/svg+xml", ".png": "image/png", ".ico": "image/x-icon",
                        ".txt": "text/plain; charset=utf-8"}


def _entries_to_groups(entries: list[dict[str, Any]]) -> dict[str, dict[str, dict[str, Any]]]:
    """把元数据条目列表折回 manifest 形态（{groups: {组: {key: 条目}}}）。"""
    groups: dict[str, dict[str, dict[str, Any]]] = {}
    for entry in entries:
        groups.setdefault(str(entry["group"]), {})[str(entry["key_name"])] = {
            k: v for k, v in entry.items() if k not in ("group", "key_name")}
    return groups


class ApiError(Exception):
    """ICON §1.6 统一错误包络。"""

    def __init__(self, status: int, code: str, message: str,
                 details: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.details = details


class KernelAPI:
    """内核 API 上下文：持有 db/规则/注册表/调度器/鉴权令牌/静态目录。"""

    def __init__(
        self,
        database: Database,
        *,
        skills_registry: Any | None = None,
        rules_cfg: dict[str, Any] | None = None,
        web_dir: str | os.PathLike[str] | None = None,
        api_token: str | None = None,
        budget_global_daily: float | None = None,
        tz_name: str | None = None,
        sse_poll_interval: float = 0.5,
        credential_manager: Any | None = None,
    ) -> None:
        self.database = database
        self.credential_manager = credential_manager
        self.skills_registry = skills_registry
        self.rules_cfg = rules_cfg or {}
        self.web_dir = Path(web_dir) if web_dir else None
        self.api_token = api_token
        self.budget_global_daily = budget_global_daily
        self.sse_poll_interval = sse_poll_interval
        self.started_at = time.time()
        with database.transaction() as conn:
            for stmt in executor_mod.TOOL_CALLS_TABLE_STATEMENTS:  # E1 读面首查前按需建（deployment-ops §5.1）
                conn.execute(stmt)
        self._sse_lock = threading.Lock()
        self._sse_count = 0
        self.shutdown_flag = threading.Event()
        self.tz_name = tz_name or os.environ.get("AGENTMESH_TZ") or os.environ.get("TZ") or "UTC"
        try:
            self.tz = ZoneInfo(self.tz_name)
            self.tz_degraded = False
        except (ZoneInfoNotFoundError, ValueError):
            self.tz = dt_timezone.utc
            self.tz_degraded = True

    # -- 鉴权（ICON §1.2：常量时间比较；token 永不出现在任何响应）----------------

    def check_auth(self, headers: Any) -> None:
        # headers 为 email.message.Message（get() 大小写不敏感）
        auth = str(headers.get("Authorization") or "")
        if not auth.startswith("Bearer ") or not auth[7:].strip():
            raise ApiError(401, "AUTH_REQUIRED", "缺少 Bearer 凭证或格式错误")
        if not self.api_token:
            raise ApiError(401, "AUTH_INVALID_TOKEN", "内核未配置 API 令牌（fail-closed）")
        if not hmac.compare_digest(auth[7:].strip().encode("utf-8"),
                                   self.api_token.encode("utf-8")):
            raise ApiError(401, "AUTH_INVALID_TOKEN", "令牌比对失败")

    # -- SSE 并发上限（ICON §4.2 第 4 条）----------------------------------------

    def sse_enter(self) -> None:
        with self._sse_lock:
            if self._sse_count >= SSE_MAX_CONCURRENT:
                raise ApiError(429, "STREAM_LIMIT_EXCEEDED",
                               f"并发 SSE 连接超上限 {SSE_MAX_CONCURRENT}")
            self._sse_count += 1

    def sse_exit(self) -> None:
        with self._sse_lock:
            self._sse_count = max(0, self._sse_count - 1)

    # -- 通用查询面 ---------------------------------------------------------------

    def events_query(self, *, task_id: str | None = None,
                     correlation_id: str | None = None,
                     types: list[str] | None = None,
                     date: str | None = None,
                     since: str | None = None,
                     after_ts: str | None = None, after_id: str | None = None,
                     limit: int = DEFAULT_PAGE_LIMIT,
                     ascending: bool = False) -> tuple[list[dict[str, Any]], bool]:
        """events 表过滤查询（C1/D2/D3/SSE 共用）；返回 (items, has_more)。"""
        clauses: list[str] = []
        params: list[Any] = []
        if task_id:
            clauses.append("(task_id = ? OR correlation_id = ?)")
            params.extend([task_id, task_id])
        if correlation_id:
            clauses.append("correlation_id = ?")
            params.append(correlation_id)
        if types:
            placeholders = ",".join("?" for _ in types)
            clauses.append(f"event_type IN ({placeholders})")
            params.extend(types)
        if date:
            start, end = self._utc_interval(date)
            clauses.append("(ts >= ? AND ts < ?)")
            params.extend([start, end])
        if since:
            clauses.append("ts >= ?")
            params.append(since)
        if after_ts:
            clauses.append("(ts > ? OR (ts = ? AND event_id > ?))")
            params.extend([after_ts, after_ts, after_id or ""])
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        order = "ASC" if ascending else "DESC"
        rows = self.database.query(
            f"SELECT * FROM events {where} ORDER BY ts {order}, event_id {order} LIMIT ?",
            (*params, limit + 1),
        )
        return [self._event_dict(r) for r in rows[:limit]], len(rows) > limit

    def _event_dict(self, row: Any) -> dict[str, Any]:
        data = {k: row[k] for k in row.keys()}
        try:
            data["payload"] = json.loads(str(data.get("payload") or "{}"))
        except ValueError:
            data["payload"] = {"raw": str(data.get("payload") or "")[:500]}
        return data

    def _utc_interval(self, local_date: str) -> tuple[str, str]:
        """容器时区自然日 [local 00:00, 次日 00:00) 对应的 UTC ISO 区间（左闭右开）。

        ts/created_at 以 UTC ISO 存储（db.utc_now_iso 形态），而 date= 参数语义是容器时区
        自然日（ICON §1.5；本模块顶部注记「按 UTC 存储日期 + 容器本地时区换算」）。
        此前用 substr(ts,1,10)=date 直接比对 UTC 前缀，容器 TZ≠UTC 时会把本地今日的事件
        划到 UTC 昨日 → D1/E1/A2 date 过滤错日。此处改为 UTC 区间比对（字符串比较与
        存储形态同构：毫秒精度 + Z 后缀）。
        """
        y, m, d = (int(x) for x in local_date.split("-"))
        fmt = "%Y-%m-%dT%H:%M:%S.%f"
        start_local = datetime(y, m, d, tzinfo=self.tz)
        end_local = start_local + timedelta(days=1)
        return (start_local.astimezone(dt_timezone.utc).strftime(fmt)[:-3] + "Z",
                end_local.astimezone(dt_timezone.utc).strftime(fmt)[:-3] + "Z")


def _encode_cursor(obj: dict[str, Any]) -> str | None:
    if not obj:
        return None
    return base64.urlsafe_b64encode(json_dumps(obj).encode("utf-8")).decode("ascii")


def _decode_cursor(cursor: str | None) -> dict[str, Any]:
    if not cursor:
        return {}
    try:
        return dict(json.loads(base64.urlsafe_b64decode(cursor.encode("ascii")).decode("utf-8")))
    except Exception as exc:
        raise ApiError(400, "INVALID_CURSOR", f"cursor 无法解析: {exc}") from exc


def _clamp_limit(raw: str | None) -> int:
    try:
        value = int(raw) if raw else DEFAULT_PAGE_LIMIT
    except ValueError as exc:
        raise ApiError(400, "INVALID_LIMIT", f"limit 必须是整数: {raw!r}") from exc
    return max(1, min(MAX_PAGE_LIMIT, value))


def _parse_iso(value: str) -> datetime:
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as exc:
        raise ApiError(400, "INVALID_SINCE_FORMAT", f"非 ISO8601 UTC 时间: {value!r}") from exc


# ---------------------------------------------------------------------------
# HTTP Handler
# ---------------------------------------------------------------------------

class ApiHandler(BaseHTTPRequestHandler):
    """路由分发 + 鉴权 + 错误包络 + SSE + 静态托管。协议版本 1.1 以支持长连接 SSE。"""

    protocol_version = "HTTP/1.1"
    server_version = "agentmesh-core/1"

    # -- 基础设施 ------------------------------------------------------------

    @property
    def api(self) -> KernelAPI:
        return self.server.api  # type: ignore[attr-defined]

    def log_message(self, fmt: str, *args: Any) -> None:
        pass  # 访问日志静默（审计面在 events 表；stdout 只留启动/调度日志）

    def _send(self, status: int, body: bytes, content_type: str,
              extra_headers: dict[str, str] | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Request-Id", getattr(self, "_rid", None) or new_ulid())  # ICON §1.3
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _json(self, status: int, obj: Any, extra_headers: dict[str, str] | None = None) -> None:
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self._send(status, body, "application/json; charset=utf-8", extra_headers)

    def _error(self, exc: ApiError) -> None:
        error: dict[str, Any] = {"code": exc.code, "message": str(exc)}
        if exc.details:
            error["details"] = exc.details
        self._json(exc.status, {"error": error})

    def _read_body(self, limit: int = MAX_BODY_BYTES) -> bytes:
        # 请求体已在 _dispatch 统一排空并缓存（keep-alive 帧干净：任何早退响应——
        # 405/404/413——发出前 socket 内不再残留未读字节，避免客户端 RST 收不到包络）
        length = int(self.headers.get("Content-Length") or 0)
        if length > limit:
            raise ApiError(413, "PAYLOAD_TOO_LARGE", f"正文超过 {limit} 字节上限")
        return getattr(self, "_raw_body", b"")

    def _drain_body(self) -> None:
        """排空并缓存请求体（上限 8MB，防恶意 Content-Length 撑爆内存）。"""
        length = int(self.headers.get("Content-Length") or 0)
        if length > 0:
            self._raw_body = self.rfile.read(min(length, 8 * 1024 * 1024))
        else:
            self._raw_body = b""

    def _parse_json(self, raw: bytes) -> dict[str, Any]:
        if not raw:
            return {}
        try:
            obj = json.loads(raw.decode("utf-8"))
        except ValueError as exc:
            raise ApiError(400, "INVALID_JSON", f"请求体不是合法 JSON: {exc}") from exc
        if not isinstance(obj, dict):
            raise ApiError(400, "INVALID_JSON", "请求体必须是 JSON 对象")
        return obj

    def _query(self) -> dict[str, str]:
        parsed = urllib.parse.urlparse(self.path)
        return {k: v[-1] for k, v in urllib.parse.parse_qs(parsed.query).items()}

    def _route_path(self) -> str:
        return urllib.parse.urlparse(self.path).path

    def _request_id(self) -> str:
        rid = self.headers.get("X-Request-Id") or new_ulid()  # ICON §1.3
        return str(rid)

    def _with_request_id(self, headers: dict[str, str]) -> dict[str, str]:
        headers["X-Request-Id"] = self.headers.get("X-Request-Id") or new_ulid()
        return headers

    # -- HTTP 方法入口 ---------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802
        self._dispatch("GET")

    def do_POST(self) -> None:  # noqa: N802
        self._dispatch("POST")

    def do_PATCH(self) -> None:  # noqa: N802
        self._dispatch("PATCH")

    def do_DELETE(self) -> None:  # noqa: N802
        self._dispatch("DELETE")

    def _dispatch(self, method: str) -> None:
        self._rid = self._request_id()
        try:
            path = self._route_path()
            self._drain_body()  # 先排空请求体：所有早退响应（405/404/healthz）帧干净
            if path == "/healthz":
                self._handle_healthz()
                return
            if path.startswith("/api/v1/"):
                self._handle_api(method, path, self._rid)
                return
            if method == "GET":
                self._handle_static(path)
                return
            raise ApiError(405, "METHOD_NOT_ALLOWED", f"{method} 不支持该路径")
        except ApiError as exc:
            try:
                self._error(exc)
            except OSError:
                pass  # 客户端已断开（含 Windows ConnectionAborted 10053）
        except OSError:
            pass  # 客户端断开（SSE 常态；BrokenPipe/Reset/Aborted 均为 OSError 子类）
        except Exception as exc:  # noqa: BLE001 - 统一 500 包络
            try:
                self._error(ApiError(500, "INTERNAL", f"内部错误: {type(exc).__name__}: {exc}"))
            except OSError:
                pass

    # -- healthz（ICON §12.1，无鉴权）--------------------------------------------

    def _handle_healthz(self) -> None:
        api = self.api
        try:
            mode = str(api.database.conn.execute("PRAGMA journal_mode").fetchone()[0])
            degradations: list[str] = []
        except Exception:
            self._json(503, {"status": "not_ready", "error": "KERNEL_NOT_READY",
                             "version": "v1"})
            return
        if api.tz_degraded:
            degradations.append("tz_fallback_utc")
        if not api.database.fts_available:
            degradations.append("fts_unavailable")  # 部署首验降级路径（MEM §1.4）
        self._json(200, {"status": "ok", "uptime_s": int(time.time() - api.started_at),
                         "db_mode": mode, "degradations": degradations, "version": "v1"})

    # -- /api/v1 路由表 -----------------------------------------------------------

    def _handle_api(self, method: str, path: str, request_id: str) -> None:
        # request_id = self._rid（ICON §1.3：响应头回传；任务事件内亦引用）
        api = self.api
        # webhook 入口不走 Bearer（ICON §1.2 第二行）
        if not path.startswith("/api/v1/triggers/webhook/"):
            api.check_auth(self.headers)
        query = self._query()
        parts = [p for p in path.split("/") if p]  # ['api','v1',...]
        body_bytes = self._read_body(MAX_BODY_BYTES) if method in ("POST", "PATCH") else b""

        # ---- 任务域 A1-A5 ----
        if path == "/api/v1/tasks" and method == "POST":
            return self._create_task(body_bytes, request_id)
        if path == "/api/v1/tasks" and method == "GET":
            return self._list_tasks(query)
        if (len(parts) == 4 and parts[2] == "tasks" and method == "GET"):
            return self._get_task(parts[3])
        if (len(parts) == 7 and parts[2] == "tasks" and parts[4] == "subtasks"
                and parts[6] == "briefs" and method == "GET"):
            return self._list_briefs(parts[3], parts[5])
        if (len(parts) == 5 and parts[2] == "tasks" and parts[4] == "abort" and method == "POST"):
            return self._abort_task(parts[3], body_bytes)
        if (len(parts) == 5 and parts[2] == "tasks" and parts[4] == "costs" and method == "GET"):
            return self._task_costs(parts[3])

        # ---- 审批域 B1-B3 ----
        if path == "/api/v1/approvals" and method == "GET":
            return self._list_approvals(query)
        if len(parts) == 4 and parts[2] == "approvals" and method == "GET":
            return self._get_approval(parts[3])
        if (len(parts) == 5 and parts[2] == "approvals" and parts[4] == "decision"
                and method == "POST"):
            return self._decide_approval(parts[3], body_bytes)

        # ---- 事件域 C1-C2 ----
        if path == "/api/v1/events" and method == "GET":
            return self._list_events(query)
        if path == "/api/v1/events/stream" and method == "GET":
            return self._sse_stream(query)

        # ---- 执行记录 D1-D3 ----
        if path == "/api/v1/executions" and method == "GET":
            return self._list_executions(query)
        if (len(parts) == 5 and parts[2] == "executions" and parts[4] == "timeline"
                and method == "GET"):
            return self._timeline(parts[3], query)
        if (len(parts) == 5 and parts[2] == "executions" and parts[4] == "replay"
                and method == "GET"):
            return self._replay(parts[3])

        # ---- 成本预算 E1/E3/E4 ----
        if path == "/api/v1/costs/summary" and method == "GET":
            return self._costs_summary(query)
        if path == "/api/v1/budget" and method == "GET":
            return self._budget()
        if path == "/api/v1/runtime/metrics" and method == "GET":
            return self._runtime_metrics()

        # ---- 错误账本 F1-F5 ----
        if path == "/api/v1/errors" and method == "GET":
            return self._list_errors(query)
        if (len(parts) == 4 and parts[2] == "errors" and parts[3] == "search" and method == "GET"):
            return self._search_errors(query)
        if (len(parts) == 4 and parts[2] == "errors" and parts[3] == "rules" and method == "GET"):
            return self._list_rules(query)
        if (len(parts) == 6 and parts[2] == "errors" and parts[3] == "rules"
                and parts[5] == "review" and method == "POST"):
            return self._review_rule(parts[4], body_bytes)
        if len(parts) == 4 and parts[2] == "errors" and method == "GET":
            return self._get_error(int(parts[3]) if parts[3].isdigit() else -1)

        # ---- 触发器 G1-G6 ----
        if path == "/api/v1/triggers" and method == "POST":
            return self._create_trigger(body_bytes)
        if path == "/api/v1/triggers" and method == "GET":
            return self._list_triggers()
        if (len(parts) == 4 and parts[2] == "triggers" and parts[3] != "webhook"):
            if method == "GET":
                return self._get_trigger(parts[3])
            if method == "PATCH":
                return self._patch_trigger(parts[3], body_bytes)
            if method == "DELETE":
                return self._delete_trigger(parts[3])
        if (len(parts) == 5 and parts[2] == "triggers" and parts[3] == "webhook"
                and method == "POST"):
            return self._webhook_ingest(parts[4], body_bytes)

        # ---- 凭证域 H1-H5 ----
        if path == "/api/v1/credentials" and method == "GET":
            return self._credentials_list()
        if (len(parts) == 4 and parts[2] == "credentials" and parts[3] == "expiring"
                and method == "GET"):
            return self._credentials_expiring(query)
        if (len(parts) == 4 and parts[2] == "credentials" and method == "GET"):
            return self._credential_detail(parts[3])
        if (len(parts) == 5 and parts[2] == "credentials" and parts[4] == "audit"
                and method == "GET"):
            return self._credential_audit(parts[3], query)
        if (path == "/api/v1/credentials/check" and method == "POST"):
            return self._credential_check(body_bytes)

        raise ApiError(404, "NOT_FOUND", f"未知端点: {method} {path}")

    # =========================================================================
    # 任务域 A1-A5
    # =========================================================================

    def _create_task(self, body_bytes: bytes, request_id: str) -> None:
        api = self.api
        body = self._parse_json(body_bytes)
        canvas_keys = {"tasks", "nodes", "edges", "workflow"} & set(body)
        if canvas_keys:  # ARCH §8.1 不做画布 → 契约级否决
            raise ApiError(400, "CANVAS_FIELDS_REJECTED",
                           f"请求体含画布式编排字段: {sorted(canvas_keys)}")
        goal = str(body.get("goal") or "")
        if not goal.strip():
            raise ApiError(400, "GOAL_EMPTY", "goal 不能为空白")
        if len(goal) > 8000:
            raise ApiError(400, "GOAL_TOO_LONG", "goal 超过 8000 字符上限")
        source = str(body.get("source") or "user")
        if source in ("cron", "webhook"):
            raise ApiError(400, "SOURCE_FORBIDDEN", "cron/webhook 入口由内核代填")
        if source != "user":
            raise ApiError(400, "SOURCE_FORBIDDEN", f"未知 source: {source!r}")
        client_ref = str(body.get("client_ref") or "")[:128]
        notes = str(body.get("notes") or "")[:2000]
        idem_key = self.headers.get("Idempotency-Key")
        if idem_key:
            existing = triggers_mod.lookup_idempotency(api.database, f"task:{idem_key}")
            if existing is not None:
                row = api.database.query_one("SELECT * FROM tasks WHERE id = ?", (existing["task_id"],))
                if row is not None:
                    return self._json(200, self._task_submit_body(row), {"Location": f"/api/v1/tasks/{row['id']}"})
        task_id = state_mod.create_task(api.database, title=goal[:80], goal=goal, source="user")
        with api.database.transaction() as conn:
            emit_event(conn, task_id=task_id, component="orchestrator",
                       event_type="task_submitted",
                       payload={"goal_summary": goal[:200], "source": source,
                                "client_ref": client_ref, "notes_present": bool(notes),
                                "request_id": request_id})
        if idem_key:
            triggers_mod.store_idempotency(api.database, f"task:{idem_key}", {"task_id": task_id})
        row = api.database.query_one("SELECT * FROM tasks WHERE id = ?", (task_id,))
        self._json(202, self._task_submit_body(row),
                   {"Location": f"/api/v1/tasks/{task_id}"})

    def _task_submit_body(self, row: Any) -> dict[str, Any]:
        return {"task_id": row["id"], "status": row["status"],
                "correlation_id": row["correlation_id"], "source": row["source"],
                "created_at": row["created_at"],
                "links": {"self": f"/api/v1/tasks/{row['id']}",
                          "stream": f"/api/v1/events/stream?task_id={row['id']}"}}

    def _list_tasks(self, query: dict[str, str]) -> None:
        api = self.api
        limit = _clamp_limit(query.get("limit"))
        cursor = _decode_cursor(query.get("cursor"))
        clauses: list[str] = []
        params: list[Any] = []
        status = query.get("status")
        if status:
            statuses = [s.strip() for s in status.split(",") if s.strip()]
            for s in statuses:
                if s not in {t.value for t in TaskStatus}:
                    raise ApiError(400, "INVALID_STATUS_FILTER", f"未知状态: {s!r}")
            placeholders = ",".join("?" for _ in statuses)
            clauses.append(f"status IN ({placeholders})")
            params.extend(statuses)
        if query.get("source"):
            clauses.append("source = ?")
            params.append(query["source"])
        if query.get("date"):
            start, end = api._utc_interval(query["date"])
            clauses.append("(created_at >= ? AND created_at < ?)")
            params.extend([start, end])
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        if cursor:
            cursor_clause = " AND (created_at < ? OR (created_at = ? AND id < ?))"
            cursor_params: list[Any] = [cursor.get("created_at", ""),
                                        cursor.get("created_at", ""),
                                        cursor.get("id", "")]
        else:
            cursor_clause = ""
            cursor_params = []
        rows = api.database.query(
            f"SELECT * FROM tasks {where}{cursor_clause}"
            " ORDER BY created_at DESC, id DESC LIMIT ?",
            (*params, *cursor_params, limit + 1),
        )
        has_more = len(rows) > limit
        items = [self._task_list_item(r) for r in rows[:limit]]
        next_cursor = _encode_cursor({"created_at": rows[limit - 1]["created_at"],
                                      "id": rows[limit - 1]["id"]}) if has_more and rows else None
        self._json(200, {"items": items, "next_cursor": next_cursor, "has_more": has_more})

    def _task_list_item(self, row: Any) -> dict[str, Any]:
        tier = RISK_LEVEL_TO_TIER.get(str(row["risk_level"]), str(row["risk_level"]))
        return {"task_id": row["id"], "correlation_id": row["correlation_id"],
                "goal_summary": str(row["goal"])[:80] + ("…" if len(str(row["goal"])) > 80 else ""),
                "status": row["status"], "source": row["source"], "risk_tier_max": tier,
                "cost_usd_est": 0.0, "created_at": row["created_at"], "updated_at": row["updated_at"]}

    def _get_task(self, task_id: str) -> None:
        api = self.api
        row = api.database.query_one("SELECT * FROM tasks WHERE id = ?", (task_id,))
        if row is None:
            raise ApiError(404, "TASK_NOT_FOUND", f"任务不存在: {task_id}")
        groups = api.database.query("SELECT * FROM groups WHERE task_id = ? ORDER BY created_at", (task_id,))
        group_items = []
        for group in groups:
            subtasks = api.database.query(
                "SELECT * FROM subtasks WHERE group_id = ? ORDER BY created_at", (group["id"],))
            group_items.append({
                "group_id": group["id"], "name": group["name"],
                "depends_on": json.loads(str(group["depends_on"] or "[]")),
                "batch": {"mode": bool(group["batch_mode"]),
                          "total_items": group["batch_total_items"],
                          "partial_ok": bool(group["partial_ok"])},
                "subtasks": [{
                    "subtask_id": s["id"], "status": s["status"], "objective": s["objective"],
                    "brief_version": int(s["brief_version"]), "risk_tier_hint": s["risk_tier_hint"],
                    "attempts": int(s["attempts"]), "cost_usd_est": float(s["cost_usd_est"] or 0),
                    "deliverable_path": s["deliverable_path"],
                } for s in subtasks],
            })
        detail = None
        if row["status_detail"]:
            try:
                detail = json.loads(str(row["status_detail"]))
            except ValueError:
                detail = {"raw": str(row["status_detail"])[:200]}
        self._json(200, {
            "task_id": row["id"], "correlation_id": row["correlation_id"],
            "goal_summary": str(row["goal"])[:80], "status": row["status"],
            "status_detail": detail, "budget_usd": row["budget_usd"], "cost_usd_est": 0.0,
            "groups": group_items, "updated_at": row["updated_at"],
        })

    def _list_briefs(self, task_id: str, subtask_id: str) -> None:
        """ICON §5.4：GET /api/v1/tasks/{task_id}/subtasks/{subtask_id}/briefs（两级校验）。"""
        api = self.api
        task = api.database.query_one("SELECT id FROM tasks WHERE id = ?", (task_id,))
        if task is None:
            raise ApiError(404, "TASK_NOT_FOUND", f"任务不存在: {task_id}")
        sub = api.database.query_one("SELECT * FROM subtasks WHERE id = ?", (subtask_id,))
        if sub is None or sub["task_id"] != task_id:
            raise ApiError(404, "SUBTASK_NOT_FOUND", f"子任务不存在: {subtask_id}")
        try:
            rows = api.database.query(
                "SELECT * FROM briefs WHERE subtask_id = ? ORDER BY version ASC", (subtask_id,))
        except sqlite3.OperationalError as exc:
            # briefs 由 planner 首写按需建（deployment-ops §5.1）；从未规划过的库视同无 brief
            raise ApiError(404, "SUBTASK_NOT_FOUND", f"no briefs for subtask {subtask_id}: {exc}") from exc
        items = []
        for r in rows:
            try:
                brief = json.loads(str(r["brief"]))
            except ValueError:
                brief = {"raw": str(r["brief"])[:500]}
            items.append({"version": int(r["version"]), "created_at": r["created_at"],
                          "brief": brief})
        self._json(200, {"items": items, "next_cursor": None, "has_more": False})

    def _abort_task(self, task_id: str, body_bytes: bytes) -> None:
        body = self._parse_json(body_bytes)
        reason = str(body.get("reason") or "用户主动中止")[:500]
        api = self.api
        row = api.database.query_one("SELECT * FROM tasks WHERE id = ?", (task_id,))
        if row is None:
            raise ApiError(404, "TASK_NOT_FOUND", f"任务不存在: {task_id}")
        if TaskStatus(row["status"]) in TASK_TERMINAL_STATES:
            raise ApiError(409, "ALREADY_TERMINAL", f"任务已在终态 {row['status']}")
        event_id = state_mod.transition_task(api.database, task_id, TaskStatus.ABORTED,
                                             component="orchestrator", reason=f"用户中止: {reason}")
        with api.database.transaction() as conn:
            emit_event(conn, task_id=task_id, component="orchestrator", event_type="task_aborted",
                       payload={"source": "user", "reason": reason})
        self._json(200, {"task_id": task_id, "status": "aborted", "transition": "T9",
                         "aborted_at": utc_now_iso(), "event_id": event_id})

    # =========================================================================
    # 审批域 B1-B3
    # =========================================================================

    def _approval_status_filter(self, query: dict[str, str]) -> str | None:
        status = query.get("status")
        if status and status not in ("waiting", "decided", "expired"):
            raise ApiError(400, "INVALID_STATUS_FILTER", f"status 取值 waiting/decided/expired: {status!r}")
        return status

    def _list_approvals(self, query: dict[str, str]) -> None:
        api = self.api
        limit = _clamp_limit(query.get("limit"))
        status = self._approval_status_filter(query)
        where = "WHERE status = ?" if status else ""
        params: tuple[Any, ...] = (status,) if status else ()
        rows = api.database.query(
            f"SELECT * FROM approvals {where} ORDER BY created_at DESC LIMIT ?", (*params, limit))
        items = []
        for row in rows:
            items.append({"approval_id": row["id"], "task_id": row["task_id"],
                          "correlation_id": row["correlation_id"], "status": row["status"],
                          "action_type": row["action_type"], "risk_tier": row["risk_tier"],
                          "summary": row["summary"], "wait_expires_at": row["wait_expires_at"],
                          "created_at": row["created_at"]})
        self._json(200, {"items": items, "next_cursor": None, "has_more": False})

    def _get_approval(self, approval_id: str) -> None:
        api = self.api
        row = api.database.query_one("SELECT * FROM approvals WHERE id = ?", (approval_id,))
        if row is None:
            raise ApiError(404, "APPROVAL_NOT_FOUND", f"审批不存在: {approval_id}")
        try:
            payload = json.loads(str(row["payload"] or "{}"))
            evidence = json.loads(str(row["evidence"] or "{}"))
        except ValueError:
            payload, evidence = {}, {}
        fields = [{"name": k, "label": k, "type": "string" if not isinstance(v, (dict, list)) else "json",
                   "value": v, "editable": True} for k, v in (payload or {}).items()]
        # ICON §6.2：不可编辑字段 = 系统注入的上下文项（evidence 面）；渲染出来但标 editable=False，
        # 与 §6.3 的 edited_payload 白名单校验同源（allowlist = payload 键集）。
        fields += [{"name": k, "label": k, "type": "string" if not isinstance(v, (dict, list)) else "json",
                    "value": v, "editable": False}
                   for k, v in (evidence or {}).items() if k not in (payload or {})]
        self._json(200, {
            "approval_id": row["id"], "task_id": row["task_id"],
            "correlation_id": row["correlation_id"], "status": row["status"],
            "action_type": row["action_type"], "risk_tier": row["risk_tier"],
            "title": row["summary"], "evidence": evidence,
            "form": {"fields": fields},
            "buttons": ["approve", "use_edited", "regenerate"],
            "button_semantics": {"approve": "按当前草稿原文执行",
                                 "use_edited": "按提交的 edited_payload 执行",
                                 "regenerate": "携带批注退回动作生成步重出草稿"},
            "wait_expires_at": row["wait_expires_at"],
            "timeout_fallback": row["timeout_fallback"], "created_at": row["created_at"],
        })

    def _decide_approval(self, approval_id: str, body_bytes: bytes) -> None:
        api = self.api
        body = self._parse_json(body_bytes)
        action = str(body.get("action") or "")
        edited = body.get("edited_payload")
        comment = body.get("comment")
        # 契约三按钮 = approve/use_edited/regenerate（ARCH §5.2 / ICON §6.3 请求表）；
        # reject/edit_draft 为 ICON §6.3 正式增补动作（2026-11-17 评审批次回写，含错误码表）
        if action not in ("approve", "use_edited", "regenerate", "reject", "edit_draft"):
            raise ApiError(400, "INVALID_DECISION_ACTION",
                           "action 取值 approve/use_edited/regenerate（ARCH §5.2 三按钮）"
                           " 或 reject/edit_draft（ICON §6.3 增补动作，2026-11-17 回写）")
        if action in ("use_edited", "edit_draft") and not isinstance(edited, dict):
            raise ApiError(400, "EDITED_PAYLOAD_REQUIRED", "use_edited 未带编辑载荷（须为对象）")
        if action in ("use_edited", "edit_draft") and not edited:
            raise ApiError(400, "EDITED_PAYLOAD_REQUIRED", "use_edited 未带编辑载荷")
        if action == "regenerate" and not str(comment or "").strip():
            raise ApiError(400, "COMMENT_REQUIRED", "regenerate 未带批注")
        if action == "reject" and not str(comment or "").strip():
            raise ApiError(400, "COMMENT_REQUIRED", "reject 未带批注（ICON §6.3）")
        row = api.database.query_one("SELECT * FROM approvals WHERE id = ?", (approval_id,))
        if row is None:
            raise ApiError(404, "APPROVAL_NOT_FOUND", f"审批不存在: {approval_id}")
        if row["status"] == "expired":
            raise ApiError(410, "APPROVAL_TIMEOUT_APPLIED",
                           "等待期已到且兜底已执行，动作已按 timeout_fallback 跳过",
                           details={"approval_id": approval_id})
        if row["status"] == "decided":
            raise ApiError(409, "APPROVAL_ALREADY_DECIDED", "该审批已被裁决，不可重复提交",
                           details={"approval_id": approval_id, "decided_at": row["decided_at"]})
        if action in ("use_edited", "edit_draft"):
            # ICON §6.3：edited_payload 的键必须 ⊆ 表单 editable:true 字段集合（= 草稿 payload 键集）；
            # 触碰不可编辑字段（系统注入的 evidence 上下文项 / 未知键）→ 400 FIELD_NOT_EDITABLE；
            # 缺必填键（草稿字段被静默丢弃会让执行载荷不完整）→ 400 EDITED_PAYLOAD_REQUIRED。
            try:
                draft = json.loads(str(row["payload"] or "{}"))
            except ValueError:
                draft = {}
            editable = set(draft.keys()) if isinstance(draft, dict) else set()
            unknown = sorted(str(k) for k in edited.keys() if k not in editable)
            if unknown:
                raise ApiError(400, "FIELD_NOT_EDITABLE",
                               f"edited_payload 含不可编辑字段: {', '.join(unknown)}",
                               details={"fields": unknown, "editable": sorted(editable)})
            missing = sorted(editable - set(str(k) for k in edited.keys()))
            if missing:
                raise ApiError(400, "EDITED_PAYLOAD_REQUIRED",
                               f"edited_payload 缺必填键: {', '.join(missing)}",
                               details={"missing": missing})
        result = approval_mod.decide(api.database, approval_id, action,
                                     edited_payload=edited, comment=comment,
                                     decided_by="user")
        decision_value = result["decision"]
        effective = {"approve": "as_draft", "use_edited": "edited",
                     "edit_draft": "edited", "regenerate": "regenerated",
                     "reject": "skipped"}[decision_value]
        event = api.database.query_one(
            "SELECT event_id FROM events WHERE event_type = 'approval_decision' AND payload LIKE ?"
            " ORDER BY ts DESC LIMIT 1", (f'%{approval_id}%',))
        self._json(200, {"approval_id": approval_id, "decision": decision_value,
                         "effective_payload": effective,
                         "decision_recorded_event_id": event["event_id"] if event else None,
                         "task_id": result["task_id"], "task_status": result["task_status"],
                         "transition": "T4",
                         **({"new_approval_id": result["new_approval_id"]}
                            if result.get("new_approval_id") else {})})

    # =========================================================================
    # 事件域 C1-C2
    # =========================================================================

    def _list_events(self, query: dict[str, str]) -> None:
        api = self.api
        limit = _clamp_limit(query.get("limit"))
        cursor = _decode_cursor(query.get("cursor"))
        types = [t.strip() for t in (query.get("types") or "").split(",") if t.strip()]
        items, has_more = api.events_query(
            task_id=query.get("task_id"), correlation_id=query.get("correlation_id"),
            types=types or None, date=query.get("date"), since=query.get("since"),
            after_ts=cursor.get("ts"), after_id=cursor.get("event_id"),
            limit=limit, ascending=False)
        next_cursor = (_encode_cursor({"ts": items[-1]["ts"], "event_id": items[-1]["event_id"]})
                       if has_more and items else None)
        self._json(200, {"items": items, "next_cursor": next_cursor, "has_more": has_more})

    def _sse_stream(self, query: dict[str, str]) -> None:
        api = self.api
        task_id = query.get("task_id")
        correlation_id = query.get("correlation_id")
        if task_id and correlation_id:
            raise ApiError(400, "FILTER_CONFLICT", "task_id 与 correlation_id 互斥")
        since = query.get("since")
        if since:
            _parse_iso(since)  # INVALID_SINCE_FORMAT
        types = [t.strip() for t in (query.get("types") or "").split(",") if t.strip()]
        api.sse_enter()
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("X-Accel-Buffering", "no")
            self.send_header("X-Request-Id", self._request_id())
            self.end_headers()
            self.wfile.write(b"retry: 3000\n\n")
            self.wfile.flush()
            cursor_ts: str | None = None
            cursor_id: str | None = None
            last_event_header = self.headers.get("Last-Event-ID")
            if last_event_header:
                anchor = api.database.query_one(
                    "SELECT ts FROM events WHERE event_id = ?", (last_event_header,))
                if anchor is None:
                    head = api.database.query_one(
                        "SELECT ts, event_id FROM events ORDER BY ts DESC, event_id DESC LIMIT 1")
                    resync = {"reason": "cursor_expired",
                              "head": head["event_id"] if head else None}
                    self._write_frame("stream_resync", None, resync)
                    self.wfile.flush()
                    if head is not None:
                        # ICON §4.2 第 2 条：不回放，从当前头部开始实时推送
                        cursor_ts, cursor_id = head["ts"], head["event_id"]
                else:
                    cursor_ts = anchor["ts"]
                    cursor_id = last_event_header
            elif since:
                cursor_ts = _parse_iso(since).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
                cursor_id = ""
            last_beat = time.time()
            while not api.shutdown_flag.is_set():
                items, _ = api.events_query(
                    task_id=task_id, correlation_id=correlation_id,
                    types=types or None, since=since,
                    after_ts=cursor_ts, after_id=cursor_id,
                    limit=200, ascending=True)
                for item in items:
                    self._write_frame(item["event_type"], item["event_id"], item)
                    cursor_ts, cursor_id = item["ts"], item["event_id"]
                    last_beat = time.time()
                if items:
                    self.wfile.flush()
                if time.time() - last_beat >= SSE_HEARTBEAT_S:
                    self.wfile.write(b": ping\n\n")  # 心跳注释帧，不推进游标
                    self.wfile.flush()
                    last_beat = time.time()
                if api.shutdown_flag.wait(api.sse_poll_interval):
                    break
        finally:
            api.sse_exit()

    def _write_frame(self, event_type: str, event_id: str | None, data: Any) -> None:
        lines = []
        if event_id:
            lines.append(f"id: {event_id}")
        lines.append(f"event: {event_type}")
        lines.append(f"data: {json.dumps(data, ensure_ascii=False)}")
        self.wfile.write(("\n".join(lines) + "\n\n").encode("utf-8"))

    # =========================================================================
    # 执行记录 D1-D3
    # =========================================================================

    def _local_date(self, ts: str) -> str:
        """ICON §1.5：日期参数取容器时区自然日（ts 为 UTC 存储）。"""
        dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00")).astimezone(self.api.tz)
        return dt.strftime("%Y-%m-%d")

    def _list_executions(self, query: dict[str, str]) -> None:
        api = self.api
        date = query.get("date") or datetime.now(api.tz).strftime("%Y-%m-%d")
        limit = _clamp_limit(query.get("limit"))
        start, end = api._utc_interval(date)
        rows = api.database.query(
            "SELECT * FROM events WHERE (ts >= ? AND ts < ?) ORDER BY ts ASC", (start, end))
        grouped: dict[str, list[Any]] = {}
        for row in rows:
            corr = row["correlation_id"]
            if not corr:
                continue
            grouped.setdefault(str(corr), []).append(row)
        items = []
        for corr, evs in grouped.items():
            task = api.database.query_one("SELECT * FROM tasks WHERE correlation_id = ?", (corr,))
            state_changes = sum(1 for e in evs if e["event_type"] == "state_transition")
            items.append({
                "task_id": task["id"] if task else None,
                "correlation_id": corr,
                "goal_summary": (str(task["goal"])[:80] if task else ""),
                "status_now": task["status"] if task else None,
                "first_event_at": evs[0]["ts"], "last_event_at": evs[-1]["ts"],
                "event_count_day": len(evs), "state_changes_day": state_changes,
                "errors_day": sum(1 for e in evs if e["event_type"] == "error_registered"),
                "approvals_day": sum(1 for e in evs
                                     if e["event_type"] in ("approval_requested", "approval_decision")),
                "timeline": f"/api/v1/executions/{corr}/timeline?date={date}",
            })
        items.sort(key=lambda x: str(x["last_event_at"]), reverse=True)
        self._json(200, {"date": date, "items": items[:limit],
                         "next_cursor": None, "has_more": len(items) > limit})

    def _timeline(self, correlation_id: str, query: dict[str, str]) -> None:
        api = self.api
        limit = _clamp_limit(query.get("limit"))
        types = [t.strip() for t in (query.get("types") or "").split(",") if t.strip()]
        for t in types:
            if t not in ICON_EVENT_TYPES:
                raise ApiError(400, "INVALID_TYPES", f"未知 event_type（ICON §2 词表）: {t!r}")
        exists = api.database.query_one(
            "SELECT event_id FROM events WHERE correlation_id = ? LIMIT 1", (correlation_id,))
        if exists is None:
            raise ApiError(404, "CORRELATION_NOT_FOUND", f"correlation_id 不存在: {correlation_id}")
        cursor = _decode_cursor(query.get("cursor"))
        items, has_more = api.events_query(
            correlation_id=correlation_id, types=types or None,
            date=query.get("date"), after_ts=cursor.get("ts"), after_id=cursor.get("event_id"),
            limit=limit, ascending=True)
        next_cursor = (_encode_cursor({"ts": items[-1]["ts"], "event_id": items[-1]["event_id"]})
                       if has_more and items else None)
        self._json(200, {"items": items, "next_cursor": next_cursor, "has_more": has_more})

    def _replay(self, correlation_id: str) -> None:
        api = self.api
        rows = api.database.query(
            "SELECT * FROM events WHERE correlation_id = ? ORDER BY ts ASC, event_id ASC",
            (correlation_id,))
        if not rows:
            raise ApiError(404, "CORRELATION_NOT_FOUND",
                           f"correlation_id 不存在: {correlation_id}")
        task = api.database.query_one("SELECT * FROM tasks WHERE correlation_id = ?",
                                      (correlation_id,))
        steps = []
        for seq, row in enumerate(rows, start=1):
            data = api._event_dict(row)
            steps.append({"seq": seq, "event_id": data["event_id"], "ts": data["ts"],
                          "component": data["component"],
                          "event_type": data["event_type"],
                          "digest": self._digest(data)})
        status_now = task["status"] if task else None
        terminal = status_now if status_now in {t.value for t in TASK_TERMINAL_STATES} else None
        self._json(200, {
            "correlation_id": correlation_id,
            "goal_summary": str(task["goal"])[:80] if task else "",
            "span": {"from": rows[0]["ts"], "to": rows[-1]["ts"]},
            "terminal_status": terminal,
            "side_effects": "none",  # ARCH §7.2：replay 是审计视图，不是重新执行
            "steps": steps, "next_cursor": None, "has_more": False,
        })

    def _digest(self, event: dict[str, Any]) -> str:
        """D3 steps[].digest：每步一行人类可读摘要（ARCH §7.2）。"""
        etype = event["event_type"]
        payload = event.get("payload") or {}
        if etype == "task_submitted":
            return f"goal 提交（source={payload.get('source', 'user')}）"
        if etype == "ledger_lookup":
            return f"强制检索命中 {len(payload.get('rule_ids') or [])} 条生效规则"
        if etype == "state_transition":
            return f"状态 {payload.get('from')}→{payload.get('to')}（{payload.get('transition')}）"
        if etype == "approval_requested":
            return (f"R2 动作 {payload.get('action_type')} 拦截，等待裁决"
                    f"（approval_id={payload.get('approval_id')}）")
        if etype == "approval_decision":
            return f"审批裁决 {payload.get('decision')}（{payload.get('approval_id')}）"
        if etype == "tool_call":
            return f"工具 {payload.get('tool')} 调用 {payload.get('status')}"
        if etype == "llm_call":
            return (f"LLM 调用 {payload.get('model')} tokens_in={payload.get('tokens_in')}"
                    f" tokens_out={payload.get('tokens_out')}")
        if etype == "subtask_started":
            return f"子任务启动 {payload.get('subtask_id')}"
        if etype == "subtask_stopped":
            return f"子任务结束 {payload.get('subtask_id')}（{payload.get('status')}）"
        if etype == "error_registered":
            return f"错误登记 {payload.get('error_signature')}"
        if etype == "trigger_fired":
            return f"触发器 {payload.get('trigger_id')} 触发（{payload.get('type')}）"
        if etype == "plan_produced":
            return f"规划产出 {payload.get('groups')} 组 {payload.get('subtasks')} 子任务"
        return etype

    # =========================================================================
    # 成本预算 E1/E2/E3/E4
    # =========================================================================

    def _costs_summary(self, query: dict[str, str]) -> None:
        api = self.api
        date = query.get("date") or datetime.now(api.tz).strftime("%Y-%m-%d")
        start, end = api._utc_interval(date)
        rows = api.database.query(
            "SELECT payload FROM events WHERE event_type = 'llm_call' AND (ts >= ? AND ts < ?)",
            (start, end))
        calls = 0
        tokens_in = 0
        tokens_out = 0
        for row in rows:
            try:
                payload = json.loads(str(row["payload"]))
            except ValueError:
                continue
            calls += 1
            tokens_in += int(payload.get("tokens_in") or 0)
            tokens_out += int(payload.get("tokens_out") or 0)
        tool_rows = api.database.query(
            "SELECT COUNT(*) AS n FROM tool_calls WHERE (ts >= ? AND ts < ?)", (start, end))
        tool_calls_n = int(tool_rows[0]["n"]) if tool_rows else 0
        total = 0.0  # 单价表为配置值归可观测台（sys-arch §7.4）；token 计量已在事件面
        budget = api.budget_global_daily
        state_value = "exceeded_paused" if (budget is not None and total > budget) else "normal"
        self._json(200, {
            "date": date,
            "llm": {"calls": calls, "tokens_in": tokens_in, "tokens_out": tokens_out,
                    "cost_usd_est": 0.0},
            "tools": {"calls": tool_calls_n, "billed_cost_usd_est": 0.0},
            "total_cost_usd_est": total,
            "budget_global_daily_usd": budget,
            "remaining_usd_est": (budget - total) if budget is not None else None,
            "state": state_value,
            "metering_disclaimer": METERING_DISCLAIMER,
        })

    def _task_costs(self, task_id: str) -> None:
        api = self.api
        task = api.database.query_one("SELECT * FROM tasks WHERE id = ?", (task_id,))
        if task is None:
            raise ApiError(404, "TASK_NOT_FOUND", f"任务不存在: {task_id}")
        # ARCH §7.3 任务级聚合是主任务/子任务两级：子任务级 llm_call 事件按 §4.2 帧形态
        # task_id=树路径码 + correlation_id=父值，故按主任务 id OR correlation_id 归集。
        corr = task["correlation_id"]
        rows = api.database.query(
            "SELECT payload FROM events WHERE event_type = 'llm_call'"
            " AND (task_id = ? OR correlation_id = ?)", (task_id, corr))
        per_sub: dict[str, dict[str, int]] = {}
        total_tokens = 0
        for row in rows:
            try:
                payload = json.loads(str(row["payload"]))
            except ValueError:
                continue
            sid = str(payload.get("subtask_id") or "unassigned")
            bucket = per_sub.setdefault(sid, {"llm_calls": 0, "tokens_total": 0})
            bucket["llm_calls"] += 1
            bucket["tokens_total"] += (int(payload.get("tokens_in") or 0)
                                       + int(payload.get("tokens_out") or 0))
            total_tokens += bucket["tokens_total"] and (int(payload.get("tokens_in") or 0)
                                                        + int(payload.get("tokens_out") or 0))
        subtasks = api.database.query("SELECT id FROM subtasks WHERE task_id = ?", (task_id,))
        items = []
        for sub in subtasks:
            bucket = per_sub.get(str(sub["id"]), {"llm_calls": 0, "tokens_total": 0})
            brief_row = api.database.query_one(
                "SELECT brief FROM briefs WHERE subtask_id = ? ORDER BY version DESC LIMIT 1",
                (sub["id"],))
            max_calls = None
            if brief_row is not None:
                try:
                    max_calls = json.loads(str(brief_row["brief"])).get("max_iterations")
                except ValueError:
                    max_calls = None
            items.append({"subtask_id": sub["id"], "llm_calls": bucket["llm_calls"],
                          "tokens_total": bucket["tokens_total"], "cost_usd_est": 0.0,
                          "max_llm_calls": max_calls})
        self._json(200, {"task_id": task_id, "finalized": task["status"] == "done",
                         "task_cost_usd_est": 0.0, "budget_usd": task["budget_usd"],
                         "subtasks": items, "updated_at": task["updated_at"],
                         "metering_disclaimer": METERING_DISCLAIMER})

    def _budget(self) -> None:
        api = self.api
        rows = api.database.query(
            "SELECT id, budget_usd, status FROM tasks WHERE budget_usd IS NOT NULL"
            " AND status IN ('running','planning','reviewing','rework')")
        tasks_at_risk = []
        for row in rows:
            budget = float(row["budget_usd"] or 0)
            spent = 0.0  # 无单价表，金额恒 0（token 数见 llm_call 事件）
            if budget > 0 and spent >= 0.8 * budget:
                tasks_at_risk.append({"task_id": row["id"], "budget_usd": budget,
                                      "spent_usd_est": spent, "state": "near_limit"})
        paused = api.database.query(
            "SELECT id FROM tasks WHERE status = 'paused_for_approval'")
        self._json(200, {
            "global": {"daily_limit_usd": api.budget_global_daily, "spent_today_usd_est": 0.0,
                       "state": "normal"},
            "tasks_at_risk": tasks_at_risk,
            "paused_by_budget": [r["id"] for r in paused],  # 可见性面；熔断执行归可观测台/引擎
            "updated_at": utc_now_iso(),
            "metering_disclaimer": METERING_DISCLAIMER,
        })

    def _runtime_metrics(self) -> None:
        api = self.api
        running = int(api.database.query_one(
            "SELECT COUNT(*) AS n FROM subtasks WHERE status = 'running'")["n"])
        queued = int(api.database.query_one(
            "SELECT COUNT(*) AS n FROM subtasks WHERE status IN ('pending','planning')")["n"])
        active = int(api.database.query_one(
            "SELECT COUNT(*) AS n FROM tasks WHERE status IN"
            " ('pending','planning','running','reviewing','rework','paused_for_approval')")["n"])
        self._json(200, {"running_subagents": running, "max_concurrency": MAX_CONCURRENCY,
                         "queue_depth": queued, "active_tasks": active,
                         "updated_at": utc_now_iso()})

    # =========================================================================
    # 错误账本 F1-F5
    # =========================================================================

    def _error_item(self, row: Any, *, with_raw: bool) -> dict[str, Any]:
        raw = str(row["raw_error"])
        return {
            "id": int(row["id"]), "error_signature": row["error_signature"],
            "signature_hash": row["signature_hash"], "error_type": row["error_type"],
            "module": row["module"], "param_pattern": row["param_pattern"],
            "raw_error_truncated": len(raw) >= ledger_mod.RAW_ERROR_MAX_CHARS,
            "root_cause": row["root_cause"], "fix_applied": row["fix_applied"],
            "prevention_suggestion": row["prevention_suggestion"],
            "task_id": row["task_id"], "role": row["role"],
            "occurred_at": row["occurred_at"],
            "occurrence_count_same_signature": int(ledger_mod.count_signature_occurrences(
                self.api.database, str(row["signature_hash"]), window_hours=None)),
            **({"raw_error": raw} if with_raw else {}),
        }

    def _list_errors(self, query: dict[str, str]) -> None:
        api = self.api
        limit = _clamp_limit(query.get("limit"))
        cursor = _decode_cursor(query.get("cursor"))
        clauses: list[str] = []
        params: list[Any] = []
        if query.get("signature_hash"):
            clauses.append("signature_hash = ?")
            params.append(query["signature_hash"])
        if query.get("task_id"):
            clauses.append("task_id = ?")
            params.append(query["task_id"])
        if query.get("error_type"):
            clauses.append("error_type = ?")
            params.append(query["error_type"])
        if query.get("date"):
            start, end = api._utc_interval(query["date"])
            clauses.append("(occurred_at >= ? AND occurred_at < ?)")
            params.extend([start, end])
        if cursor:
            cursor_clause = " AND (occurred_at < ? OR (occurred_at = ? AND id < ?))"
            cursor_params: list[Any] = [cursor.get("occurred_at", ""),
                                        cursor.get("occurred_at", ""),
                                        int(cursor.get("id") or 0)]
        else:
            cursor_clause = ""
            cursor_params = []
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        rows = api.database.query(
            f"SELECT * FROM error_ledger {where}{cursor_clause}"
            " ORDER BY occurred_at DESC, id DESC LIMIT ?",
            (*params, *cursor_params, limit + 1),
        )
        has_more = len(rows) > limit
        items = [self._error_item(r, with_raw=False) for r in rows[:limit]]
        next_cursor = (_encode_cursor({"occurred_at": rows[limit - 1]["occurred_at"],
                                       "id": int(rows[limit - 1]["id"])})
                       if has_more and rows else None)
        self._json(200, {"items": items, "next_cursor": next_cursor, "has_more": has_more})

    def _get_error(self, error_id: int) -> None:
        row = self.api.database.query_one("SELECT * FROM error_ledger WHERE id = ?", (error_id,))
        if row is None:
            raise ApiError(404, "ERROR_NOT_FOUND", f"错误不存在: {error_id}")
        self._json(200, self._error_item(row, with_raw=True))

    def _search_errors(self, query: dict[str, str]) -> None:
        api = self.api
        q = str(query.get("q") or "").strip()
        if not q:
            raise ApiError(400, "EMPTY_QUERY", "q 不能为空（空格分隔关键词）")
        tokens = q.split()
        limit = _clamp_limit(query.get("limit"))
        hits = ledger_mod.search_errors(api.database, tokens, limit=limit)  # token 双引号在 ledger 内处理
        items = []
        for hit in hits:
            row = api.database.query_one("SELECT * FROM error_ledger WHERE id = ?", (hit["id"],))
            if row is not None:
                items.append(self._error_item(row, with_raw=False))
        self._json(200, {"items": items, "next_cursor": None, "has_more": False,
                         "matched_by": "fts", "degraded": False})

    def _list_rules(self, query: dict[str, str]) -> None:
        status = query.get("status")
        if status and status not in ("candidate", "active", "retired"):
            raise ApiError(400, "INVALID_RULE_STATUS",
                           f"status 取值 candidate/active/retired: {status!r}")
        rows = self.api.database.query(
            "SELECT * FROM prevention_rules WHERE (? IS NULL OR status = ?) ORDER BY id"
            " LIMIT ?",
            (status, status, _clamp_limit(query.get("limit"))))
        items = []
        for row in rows:
            try:
                source_ids = json.loads(str(row["source_error_ids"] or "[]"))
            except ValueError:
                source_ids = []
            items.append({"id": int(row["id"]), "rule_text": row["rule_text"],
                          "match_keywords": row["match_keywords"],
                          "task_types": row["task_types"], "status": row["status"],
                          "source_error_ids": source_ids,
                          "occurrences": int(row["occurrences"]),
                          "risk_level": row["risk_level"], "reviewed_by": row["reviewed_by"],
                          "auto_activated": bool(row["auto_activated"]),
                          "created_at": None})  # MEM §3.1 DDL 无 created_at 列（如实 null）
        self._json(200, {"items": items, "next_cursor": None, "has_more": False})

    def _review_rule(self, rule_id_raw: str, body_bytes: bytes) -> None:
        api = self.api
        body = self._parse_json(body_bytes)
        action = str(body.get("action") or "")
        reviewer = str(body.get("reviewer") or "").strip()
        reason = body.get("reason")
        if action not in ("approve", "retire"):
            raise ApiError(400, "INVALID_TRANSITION",
                           f"action 取值 approve/retire: {action!r}")
        if not reviewer:
            raise ApiError(400, "REVIEWER_REQUIRED", "reviewer 必填（人工审核位）")
        if action == "retire" and not str(reason or "").strip():
            raise ApiError(400, "RETIRE_REASON_REQUIRED", "retire_reason 必填（MEM §3.1）")
        rule_id = int(rule_id_raw) if rule_id_raw.isdigit() else -1
        row = api.database.query_one("SELECT status FROM prevention_rules WHERE id = ?", (rule_id,))
        if row is None:
            raise ApiError(404, "RULE_NOT_FOUND", f"规则不存在: {rule_id_raw}")
        if action == "retire" and row["status"] != "active":
            raise ApiError(400, "INVALID_TRANSITION",
                           f"retire 仅允许 active→retired（当前 {row['status']}）")
        if action == "approve":
            result = ledger_mod.review_rule(api.database, rule_id, reviewer)
        else:
            result = ledger_mod.retire_rule(api.database, rule_id, str(reason), reviewer)
        self._json(200, {"rule_id": result["rule_id"], "status": result["status"],
                         "reviewed_by": reviewer,
                         "reviewed_at": result.get("reviewed_at") or result.get("retired_at"),
                         "export_note": "active 规则将在下一次 done 沉淀检查时导出重写"
                                        " /opt/agentmesh/rules/lessons.yaml（MEM §3.3 单一权威源）"})

    # =========================================================================
    # 触发器 G1-G6
    # =========================================================================

    def _create_trigger(self, body_bytes: bytes) -> None:
        api = self.api
        body = self._parse_json(body_bytes)
        try:
            result = triggers_mod.create_trigger(
                api.database, trigger_type=str(body.get("type") or ""),
                goal_template=str(body.get("goal_template") or ""),
                schedule=body.get("schedule"),
                timezone_name=body.get("timezone"),
                enabled=bool(body.get("enabled", True)),
                secret_ref=body.get("secret_ref"),
                default_tz=api.tz_name,
                idempotency_key=self.headers.get("Idempotency-Key"),
                credential_store=api.credential_manager)
        except triggers_mod.TriggerError as exc:
            status = 409 if exc.code == "SECRET_REF_IMMUTABLE" else 400
            raise ApiError(status, exc.code, str(exc)) from exc
        status_code = 200 if not result.get("created", True) else 201
        self._json(status_code, {k: v for k, v in result.items() if k != "created"})

    def _list_triggers(self) -> None:
        items = triggers_mod.list_triggers(self.api.database)
        self._json(200, {"items": items, "next_cursor": None, "has_more": False})

    def _get_trigger(self, trigger_id: str) -> None:
        result = triggers_mod.get_trigger(self.api.database, trigger_id)
        if result is None:
            raise ApiError(404, "TRIGGER_NOT_FOUND", f"触发器不存在: {trigger_id}")
        self._json(200, result)

    def _patch_trigger(self, trigger_id: str, body_bytes: bytes) -> None:
        body = self._parse_json(body_bytes)
        try:
            result = triggers_mod.update_trigger(
                self.api.database, trigger_id,
                enabled=body.get("enabled") if "enabled" in body else None,
                goal_template=body.get("goal_template"),
                schedule=body.get("schedule"),
                rotate_secret=bool(body.get("rotate_secret")),
                default_tz=self.api.tz_name)
        except triggers_mod.TriggerError as exc:
            status = 409 if exc.code == "SECRET_REF_IMMUTABLE" else 400
            raise ApiError(status, exc.code, str(exc)) from exc
        if not result:
            raise ApiError(404, "TRIGGER_NOT_FOUND", f"触发器不存在: {trigger_id}")
        self._json(200, result)

    def _delete_trigger(self, trigger_id: str) -> None:
        if not triggers_mod.delete_trigger(self.api.database, trigger_id):
            raise ApiError(404, "TRIGGER_NOT_FOUND", f"触发器不存在: {trigger_id}")
        self._send(204, b"", "application/json")

    def _webhook_ingest(self, token: str, body_bytes: bytes) -> None:
        api = self.api
        if len(body_bytes) > WEBHOOK_MAX_BODY_BYTES:
            raise ApiError(413, "PAYLOAD_TOO_LARGE", "webhook 请求体超过 256KB")
        try:
            result, error_code = triggers_mod.ingest_webhook(
                api.database, token, body_bytes,
                signature=self.headers.get("X-Agentmesh-Signature"),
                timestamp=self.headers.get("X-Agentmesh-Timestamp"),
                idempotency_key=self.headers.get("Idempotency-Key"),
                credential_store=api.credential_manager)
        except triggers_mod.TriggerError as exc:
            raise ApiError(400, exc.code, str(exc)) from exc
        if error_code == "TRIGGER_NOT_FOUND" or error_code == "TRIGGER_DISABLED":
            raise ApiError(404, error_code, f"触发器不可用: {token}")
        if error_code in ("WEBHOOK_SIGNATURE_INVALID", "WEBHOOK_TIMESTAMP_SKEW"):
            raise ApiError(401, error_code, "webhook 鉴权失败（防枚举：不区分细节）")
        if error_code == "INVALID_WEBHOOK_BODY":
            raise ApiError(400, error_code, "请求体 JSON 解析失败")
        if error_code == "PAYLOAD_TOO_LARGE":
            raise ApiError(413, error_code, "请求体超过 256KB")
        if error_code == "KERNEL_NOT_READY":
            raise ApiError(503, error_code, "secret_ref 凭证通道未接线")
        body = result or {}
        replayed = bool(body.get("replayed"))
        body.pop("replayed", None)
        self._json(200 if replayed else 202, body)

    # =========================================================================
    # 凭证域 H1-H5（元数据/审计只读面；永不返回明文）
    # =========================================================================

    def _credentials_manifest(self) -> dict[str, Any] | None:
        """凭证元数据源（优先级）：① 凭证管理器（age 解密 credentials.enc；CRED §3A'/§10.2，
        生产主路径，build_runtime 接线）→ ② AGENTMESH_CREDENTIALS_MANIFEST env 快照
        （仅本地验收/离线排查的显式测试钩子，部署 .env 不含该项）→ None（降级）。"""
        manager = self.api.credential_manager
        if manager is not None and manager.available():
            return {"groups": _entries_to_groups(manager.metadata_entries())}
        path = os.environ.get("AGENTMESH_CREDENTIALS_MANIFEST")
        if not path or not Path(path).exists():
            return None
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else None
        except (ValueError, OSError):
            return None

    def _manifest_entries(self) -> list[dict[str, Any]]:
        manifest = self._credentials_manifest()
        if not manifest:
            return []
        entries: list[dict[str, Any]] = []
        for group, items in (manifest.get("groups") or {}).items():
            for key_name, meta in (items or {}).items():
                entries.append({"group": group, "key_name": key_name, **(meta or {})})
        self._enrich_with_audit(entries)
        return entries

    def _enrich_with_audit(self, entries: list[dict[str, Any]]) -> None:
        """ICON §11.1：days_to_rotate / last_inject_at / inject_count_7d 聚合自 credential_audit
        （CRED §6.1；只读审计表，无明文）。"""
        if not entries:
            return
        try:
            self._ensure_credential_audit_table()
            today = datetime.now(UTC).date()
            for entry in entries:
                rotate_at = str(entry.get("rotate_at") or "")
                entry["days_to_rotate"] = None
                if rotate_at:
                    try:
                        entry["days_to_rotate"] = (
                            datetime.strptime(rotate_at, "%Y-%m-%d").date() - today).days
                    except ValueError:
                        entry["days_to_rotate"] = None
                row = self.api.database.query_one(
                    "SELECT MAX(created_at) AS last_at,"
                    " SUM(CASE WHEN action = 'inject' AND created_at >= ? THEN 1 ELSE 0 END) AS cnt"
                    " FROM credential_audit WHERE key_name = ?",
                    (iso_shift(utc_now_iso(), -7 * 24 * 3600), entry["key_name"]))
                entry["last_inject_at"] = None
                entry["inject_count_7d"] = 0
                if row is not None:
                    entry["inject_count_7d"] = int(row["cnt"] or 0)
                    inject_row = self.api.database.query_one(
                        "SELECT MAX(created_at) AS last_at FROM credential_audit"
                        " WHERE key_name = ? AND action = 'inject'", (entry["key_name"],))
                    if inject_row is not None:
                        entry["last_inject_at"] = inject_row["last_at"]
        except Exception:  # 审计聚合失败不阻断元数据面（降级为 null/0）
            for entry in entries:
                entry.setdefault("days_to_rotate", None)
                entry.setdefault("last_inject_at", None)
                entry.setdefault("inject_count_7d", 0)

    def _credentials_list(self) -> None:
        entries = self._manifest_entries()
        self._json(200, {"items": entries, "next_cursor": None, "has_more": False,
                         "degraded": not entries,
                         "note": None if entries else
                         "凭证管理器未接线（age 密文/私钥缺失或解密失败）：元数据面降级为空"
                         "——按 CRED §3A'/§10.1 完成 credentials.enc 建库后恢复"})

    def _credential_detail(self, key_name: str) -> None:
        entries = [e for e in self._manifest_entries() if e["key_name"] == key_name]
        if not entries:
            raise ApiError(404, "KEY_NOT_FOUND", f"key_name 不存在: {key_name}")  # 仅键名层 404
        entry = dict(entries[0])
        entry["recent_audit"] = self._audit_rows(key_name=key_name, limit=20)
        self._json(200, entry)


    def _ensure_credential_audit_table(self) -> None:
        """CRED §6.1 DDL 逐字落地（含 created_at 默认值与 role/key 两索引）；
        旧 ts 形态的表重建迁移（SQLite 不能 ALTER 列名→拷贝映射 ts→created_at）。"""
        conn = self.api.database.conn
        row = conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='credential_audit'").fetchone()
        if row is not None and "created_at" not in str(row["sql"]):
            with self.api.database.transaction() as c:
                c.execute("ALTER TABLE credential_audit RENAME TO credential_audit_old_ts")
                c.execute(credentials_mod.CREDENTIAL_AUDIT_DDL)
                c.execute(
                    "INSERT INTO credential_audit (role, task_id, key_name, action, detail,"
                    " created_at) SELECT role,"
                    " COALESCE(task_id, 'system'), key_name, action, detail, ts"
                    " FROM credential_audit_old_ts")
                c.execute("DROP TABLE credential_audit_old_ts")
                for stmt in credentials_mod.CREDENTIAL_AUDIT_INDEXES:
                    c.execute(stmt)
            return
        with self.api.database.transaction() as c:
            c.execute(credentials_mod.CREDENTIAL_AUDIT_DDL)
            for stmt in credentials_mod.CREDENTIAL_AUDIT_INDEXES:
                c.execute(stmt)

    def _audit_rows(self, *, key_name: str | None = None, action: str | None = None,
                    role: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
        self._ensure_credential_audit_table()  # deployment-ops §5.1：首查前按需建表
        clauses: list[str] = []
        params: list[Any] = []
        if key_name:
            clauses.append("key_name = ?")
            params.append(key_name)
        if action:
            clauses.append("action = ?")
            params.append(action)
        if role:
            clauses.append("role = ?")
            params.append(role)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        rows = self.api.database.query(
            f"SELECT * FROM credential_audit {where} ORDER BY created_at DESC LIMIT ?",
            (*params, limit))
        return [{k: r[k] for k in r.keys()} for r in rows]

    def _credential_audit(self, key_name: str, query: dict[str, str]) -> None:
        entries = [e for e in self._manifest_entries() if e["key_name"] == key_name]
        manager = self.api.credential_manager
        manager_ready = manager is not None and manager.available()
        if self._credentials_manifest() is not None and not entries and not (
                manager_ready and key_name in manager.key_names()):
            raise ApiError(404, "KEY_NOT_FOUND", f"key_name 不存在: {key_name}")
        action = query.get("action")
        if action and action not in ("inject", "deny", "rotate", "reencrypt"):
            raise ApiError(400, "INVALID_ACTION_FILTER", f"action 值域 inject/deny/rotate/reencrypt: {action!r}")
        items = self._audit_rows(key_name=key_name, action=action, role=query.get("role"),
                                 limit=_clamp_limit(query.get("limit")))
        self._json(200, {"items": items, "next_cursor": None, "has_more": False})

    def _credential_check(self, body_bytes: bytes) -> None:
        api = self.api
        body = self._parse_json(body_bytes)
        role = str(body.get("role") or "")
        key_name = str(body.get("key_name") or "")
        inject_path = str(body.get("inject_path") or "")
        if inject_path not in ("env", "header"):
            raise ApiError(400, "INVALID_INJECT_PATH", f"inject_path 取值 env|header: {inject_path!r}")
        roles_cfg = (api.rules_cfg or {}).get("roles")
        if isinstance(roles_cfg, dict) and isinstance(roles_cfg.get("roles"), dict):
            roles_obj = roles_cfg["roles"]  # roles.yaml 文档形（装载器原样）
        elif isinstance(roles_cfg, dict):
            roles_obj = roles_cfg
        else:
            roles_obj = {}
        if role not in roles_obj:
            raise ApiError(400, "ROLE_UNKNOWN", f"roles.yaml 无此角色: {role!r}")
        authorized_groups = set((roles_obj[role] or {}).get("credential_groups") or [])
        manifest = self._credentials_manifest()
        entries = [e for e in self._manifest_entries() if e["key_name"] == key_name]
        manager = self.api.credential_manager
        if manager is not None and manager.available():
            # 凭证管理器接线：三闸门真值（预检只判定不注入不审计——ICON §11.4）
            pair = manager.entry(key_name)
            group_authorized = bool(pair and pair[0] in authorized_groups)
            key_exists = pair is not None
            kind_match = None
            if pair is not None:
                entry = pair[1]
                kind_match = (entry.get("env") is not None) if inject_path == "env" \
                    else (entry.get("header") is not None)
            allowed = bool(group_authorized and key_exists and (kind_match is True))
            denial = None
            if not allowed:
                reason = "group_not_authorized" if not group_authorized \
                    else ("key_not_found" if not key_exists else "kind_mismatch")
                denial = {"reason": reason, "key_name": key_name}
            with api.database.transaction() as conn:
                emit_event(conn, component="credential_manager", event_type="credential_check",
                           payload={"role": role, "key_name": key_name, "allowed": allowed,
                                    "inject_path": inject_path,
                                    "note": "预检不是注入路径，不产生 credential_audit（ICON §11.4）"})
            return self._json(200, {"allowed": allowed, "role": role, "key_name": key_name,
                                    "gates": {"group_authorized": group_authorized,
                                              "key_exists": key_exists, "kind_match": kind_match},
                                    **({"denial": denial} if denial else {})})
        if manifest is None:
            group_authorized = None  # key 的组未知（凭证通道未接线），角色侧授权面无法独立判定
        else:
            group_authorized = any(e["group"] in authorized_groups for e in entries)
        key_exists = bool(entries) if manifest is not None else None
        kind_match = None
        if entries and inject_path:
            entry = entries[0]
            kind_match = (entry.get("env") is not None) if inject_path == "env" \
                else (entry.get("header") is not None)
        allowed = bool(group_authorized and key_exists and (kind_match is not False))
        denial = None
        if not allowed:
            if manifest is None:
                reason = "key_not_found"  # 凭证通道未接线：首个未知闸门是 key 存在性
            elif not group_authorized:
                reason = "group_not_authorized"
            elif not key_exists:
                reason = "key_not_found"
            else:
                reason = "kind_mismatch"
            denial = {"reason": reason, "key_name": key_name}
        with api.database.transaction() as conn:
            emit_event(conn, component="credential_manager", event_type="credential_check",
                       payload={"role": role, "key_name": key_name, "allowed": allowed,
                                "inject_path": inject_path,
                                "note": "预检不是注入路径，不产生 credential_audit（ICON §11.4）"})
        self._json(200, {"allowed": allowed, "role": role, "key_name": key_name,
                         "gates": {"group_authorized": group_authorized,
                                   "key_exists": key_exists, "kind_match": kind_match},
                         **({"denial": denial} if denial else {})})

    def _credentials_expiring(self, query: dict[str, str]) -> None:
        raw = query.get("within_days") or "30"
        try:
            within_days = int(raw)
        except ValueError as exc:
            raise ApiError(400, "INVALID_WITHIN_DAYS", f"within_days 必须是整数: {raw!r}") from exc
        if within_days < 1:
            raise ApiError(400, "INVALID_WITHIN_DAYS", f"within_days 必须 ≥1: {raw!r}")
        expiring = []
        expired_in_use = []
        today = datetime.now(UTC).date()
        for entry in self._manifest_entries():
            rotate_at = str(entry.get("rotate_at") or "")
            if not rotate_at:
                continue
            try:
                rotate_date = datetime.strptime(rotate_at, "%Y-%m-%d").date()
            except ValueError:
                continue
            days_left = (rotate_date - today).days
            if days_left <= within_days:
                expiring.append({"key_name": entry["key_name"], "group": entry["group"],
                                 "rotate_at": rotate_at, "days_left": days_left,
                                 "state": "due_now" if days_left <= 0 else "due_soon"})
        self._json(200, {"within_days": within_days, "expiring": expiring,
                         "expired_in_use": expired_in_use, "generated_at": utc_now_iso(),
                         "degraded": not self._manifest_entries()})

    # =========================================================================
    # 静态托管（impl/web/）
    # =========================================================================

    def _handle_static(self, path: str) -> None:
        api = self.api
        web_dir = api.web_dir
        if web_dir is None or not web_dir.exists():
            self._json(404, {"error": {"code": "NOT_FOUND", "message": "静态目录未配置"}})
            return
        rel = path.strip("/") or "index.html"
        candidate = (web_dir / rel).resolve()
        root = web_dir.resolve()
        if candidate != root and root not in candidate.parents:
            raise ApiError(404, "NOT_FOUND", "路径越界")
        if not candidate.is_file():
            self._json(404, {"error": {"code": "NOT_FOUND", "message": f"静态文件不存在: {path}"}})
            return
        content_type = STATIC_CONTENT_TYPES.get(candidate.suffix.lower(), "application/octet-stream")
        self._send(200, candidate.read_bytes(), content_type)


# ---------------------------------------------------------------------------
# 服务启动
# ---------------------------------------------------------------------------

class KernelHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], api: KernelAPI) -> None:
        self.api = api
        super().__init__(address, ApiHandler)


def serve(api: KernelAPI, host: str = "0.0.0.0", port: int = 8787) -> KernelHTTPServer:
    """创建并返回监听中的 HTTP 服务（调用方负责 serve_forever/shutdown）。"""
    server = KernelHTTPServer((host, port), api)
    thread = threading.Thread(target=server.serve_forever, name="api-server", daemon=True)
    thread.start()
    return server
