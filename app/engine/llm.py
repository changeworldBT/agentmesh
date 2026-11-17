"""llm.py — 统一 LLM API 网关内核侧适配层：OPENAI_COMPAT（stdlib urllib）+ STUB（确定性响应）。

设计文档出处（模块顶部注记，按 ask 要求）：
- sys-arch（ARCH-ROOT-01）§2.3：外部 LLM API 边界——一切智能调用统一经网关，绝不本地
  推理（本模块无任何本地模型加载路径）；§7.1：每次 LLM 调用（含 token 计量）事件化落库；
  §7.3：llm_usage 计量点；§9.2「内核 ⇄ LLM」行：chat/completions 语义 + 计量回调 +
  429/重试策略归网关侧。
- interface-contracts（ICON-01）§2：event_type 词表——`llm_call`（payload 要点：model、
  tokens_in、tokens_out、cost_usd 估算、耗时）；§14.1：网关计量回调字段级契约演进时以
  迁移脚本定稿（本模块只发 llm_call 事件，不落 metrics 表）。
- credentials-spec（CRED-01）§7：明文禁令——本模块不硬编码任何 key；key 由调用方经
  环境变量/凭证注入提供，不落日志（事件 payload 不含 key）。
- deployment-ops §4：.env 提供容器环境变量层；sys-arch §10.1：网关 key 落
  credentials.enc 的 llm_gateway_key 条目（env=LLM_GATEWAY_KEY），环境变量读取位即
  凭证注入器的落点。

偏离与取舍（如实声明）：
- 本 ask 指定适配层直接读 LLM_BASE_URL/LLM_API_KEY/LLM_MODEL 环境变量（LLM_PROVIDER=
  STUB 时无 key 验收）。终态架构中网关 key 走 credentials.enc 短寿命注入
  （sys-arch §10.1 注释），from_env() 的读取位即后续凭证注入器的接线点。
- token 计量以 `llm_call` 事件承载（ICON §2 词表字段 tokens_in/tokens_out/cost_usd_est，
  cost_usd_est 恒 None——单价表为配置值归可观测台，§7.4 计量精度声明），不落 metrics
  表（deployment-ops §5.1：metrics 归可观测台计量器）。
- 429/重试策略归网关侧（sys-arch §2.3）：本适配层 429 即抛 LLMRateLimitedError 不重试，
  避免与网关侧重试叠加；LLM 请求失败落 `llm_call_failed` 事件（词表外增补，ICON §2
  允许向后兼容新增）。
- STUB 适配器按请求 kind（plan/execute/chat）+ stub_payload 产出确定性响应，供无 key
  验收链路（规划→执行→审批全链可跑通）；OPENAI_COMPAT 响应原样透传，schema 校验归
  调用方（planner/executor）。
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any

from app.engine.db import Database, emit_event

PROVIDER_OPENAI_COMPAT = "openai_compat"
PROVIDER_STUB = "stub"

DEFAULT_TIMEOUT_S = 60.0


class LLMGatewayError(RuntimeError):
    """网关调用失败（网络/超时/非 429 HTTP 错误/畸形响应）。"""


class LLMRateLimitedError(LLMGatewayError):
    """网关 429（sys-arch §2.3：429 处理归网关侧，内核侧不重试直接上抛）。"""


class LLMConfigError(LLMGatewayError):
    """适配器配置缺失（如 OPENAI_COMPAT 缺 LLM_BASE_URL/LLM_API_KEY/LLM_MODEL）。"""


@dataclass
class LLMRequest:
    """一次 LLM 调用的请求（适配器无关）。"""

    messages: list[dict[str, str]]                     # [{"role": "system"|"user"|"assistant"|"tool", "content": str}]
    tools: list[dict[str, Any]] | None = None          # function schema 列表（executor 工具面）
    tool_results: list[dict[str, Any]] | None = None   # 预留：工具回包随 messages 走，此字段暂不参与请求体
    json_mode: bool = False                            # OPENAI_COMPAT: response_format=json_object
    kind: str = "chat"                                 # chat/plan/execute —— STUB 确定性响应分类位
    stub_payload: dict[str, Any] | None = None         # STUB 确定性输入（goal/objective 等）
    task_id: str | None = None
    subtask_id: str | None = None                      # E2 任务/子任务成本明细的拆分维度（ICON §8.2）
    component: str = "kernel"
    temperature: float = 0.2
    max_tokens: int = 1024


@dataclass
class LLMResponse:
    """一次 LLM 调用的响应（适配器无关）。"""

    content: str | None
    tool_calls: list[dict[str, str]] = field(default_factory=list)
    # tool_calls 元素: {"id": str, "name": str, "arguments": str(JSON 文本)}
    raw_tool_calls: list[dict[str, Any]] = field(default_factory=list)  # 原样回传给 OPENAI_COMPAT 多轮协议
    finish_reason: str = "stop"
    model: str = ""
    provider: str = ""
    usage: dict[str, int] = field(default_factory=dict)  # {"prompt_tokens": n, "completion_tokens": n}
    latency_ms: int = 0


class OpenAICompatClient:
    """OPENAI_COMPAT 适配器：POST {LLM_BASE_URL}/chat/completions（stdlib urllib，无第三方包）。"""

    def __init__(
        self,
        base_url: str,
        api_key: str,
        model: str,
        *,
        database: Database | None = None,
        timeout_s: float = DEFAULT_TIMEOUT_S,
    ) -> None:
        if not base_url or not api_key or not model:
            raise LLMConfigError(
                "OPENAI_COMPAT requires LLM_BASE_URL / LLM_API_KEY / LLM_MODEL (all non-empty)"
            )
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.database = database
        self.timeout_s = timeout_s

    def chat(self, request: LLMRequest) -> LLMResponse:
        started = time.perf_counter()
        try:
            response = self._complete(request)
        except LLMGatewayError as exc:
            self._emit_event(request, None, latency_ms=int((time.perf_counter() - started) * 1000),
                             error=str(exc))
            raise
        latency_ms = int((time.perf_counter() - started) * 1000)
        response.latency_ms = latency_ms
        self._emit_event(request, response, latency_ms=latency_ms)
        return response

    def _complete(self, request: LLMRequest) -> LLMResponse:
        body: dict[str, Any] = {
            "model": self.model,
            "messages": [dict(m) for m in request.messages],
            "temperature": request.temperature,
            "max_tokens": request.max_tokens,
        }
        if request.tools:
            body["tools"] = [{"type": "function", "function": t} for t in request.tools]
            body["tool_choice"] = "auto"
        if request.json_mode:
            body["response_format"] = {"type": "json_object"}
        http = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            data=json.dumps(body, ensure_ascii=False).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(http, timeout=self.timeout_s) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as exc:
            if exc.code == 429:
                raise LLMRateLimitedError(f"gateway 429 rate limited (url={self.base_url})") from exc
            raise LLMGatewayError(f"gateway HTTP {exc.code}: {exc.reason}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise LLMGatewayError(f"gateway unreachable: {exc}") from exc
        try:
            data = json.loads(raw.decode("utf-8"))
            choice = data["choices"][0]
            message = choice["message"]
        except (ValueError, KeyError, IndexError) as exc:
            raise LLMGatewayError(f"malformed gateway response: {exc}") from exc
        raw_tool_calls = message.get("tool_calls") or []
        tool_calls = []
        for tc in raw_tool_calls:
            fn = tc.get("function") or {}
            tool_calls.append({
                "id": str(tc.get("id") or ""),
                "name": str(fn.get("name") or ""),
                "arguments": str(fn.get("arguments") or "{}"),
            })
        usage = data.get("usage") or {}
        return LLMResponse(
            content=message.get("content"),
            tool_calls=tool_calls,
            raw_tool_calls=raw_tool_calls,
            finish_reason=str(choice.get("finish_reason") or "stop"),
            model=str(data.get("model") or self.model),
            provider=PROVIDER_OPENAI_COMPAT,
            usage={"prompt_tokens": int(usage.get("prompt_tokens") or 0),
                   "completion_tokens": int(usage.get("completion_tokens") or 0)},
        )

    def _emit_event(self, request: LLMRequest, response: LLMResponse | None,
                    *, latency_ms: int, error: str | None = None) -> None:
        """sys-arch §7.1：每次 LLM 调用（含 token 计量）事件化落库；失败也落事件可 replay。"""
        if self.database is None:
            return
        try:
            with self.database.transaction() as conn:
                if response is None:
                    emit_event(conn, task_id=request.task_id, component=request.component,
                               event_type="llm_call_failed",
                               payload={"provider": PROVIDER_OPENAI_COMPAT, "model": self.model,
                                        "kind": request.kind, "error": error,
                                        "subtask_id": request.subtask_id,
                                        "latency_ms": latency_ms})
                else:
                    # ICON §2 llm_call payload：model、tokens_in、tokens_out、cost_usd 估算、耗时
                    emit_event(conn, task_id=request.task_id, component=request.component,
                               event_type="llm_call",
                               payload={"provider": response.provider, "model": response.model,
                                        "kind": request.kind,
                                        "tokens_in": response.usage.get("prompt_tokens", 0),
                                        "tokens_out": response.usage.get("completion_tokens", 0),
                                        "cost_usd_est": None,  # 单价表为配置值归可观测台（sys-arch §7.4）
                                        "subtask_id": request.subtask_id,
                                        "latency_ms": latency_ms,
                                        "finish_reason": response.finish_reason})
        except Exception:
            pass  # 计量事件失败不阻断调用主流程（与 ledger 降级原则同向）


class StubClient:
    """STUB 适配器：LLM_PROVIDER=STUB 时的确定性响应（无 key 验收链路）。

    确定性 = 同一请求恒返回同一响应：kind=plan 依 stub_payload.goal 产出最小合规任务树
    JSON；kind=execute 依 stub_payload.objective 产出含 summary 的执行结果 JSON；其余
    chat 请求回显首条 user 消息摘要。token 计量按字符数//4 估算（确定性）。
    """

    def __init__(self, *, database: Database | None = None, model: str = "stub-deterministic") -> None:
        self.database = database
        self.model = model

    def chat(self, request: LLMRequest) -> LLMResponse:
        started = time.perf_counter()
        content = self._deterministic_content(request)
        tool_calls, raw_tool_calls = self._deterministic_tool_calls(request)
        latency_ms = int((time.perf_counter() - started) * 1000)
        usage = {
            "prompt_tokens": sum(len(str(m.get("content") or "")) for m in request.messages) // 4,
            "completion_tokens": len(content) // 4,
        }
        response = LLMResponse(content=None if tool_calls else content,
                               tool_calls=tool_calls, raw_tool_calls=raw_tool_calls,
                               finish_reason="tool_calls" if tool_calls else "stop",
                               model=self.model, provider=PROVIDER_STUB,
                               usage=usage, latency_ms=latency_ms)
        self._emit_event(request, response, latency_ms=latency_ms)
        return response

    def _deterministic_tool_calls(self, request: LLMRequest) -> tuple[list[dict[str, str]], list[dict[str, Any]]]:
        """STUB 的工具面：kind=execute 且 brief 授权 file_write、且尚未调用过工具时，
        先发一次 file_write（内容=确定性 summary），让 STUB 验收也走真实工具路径
        （allowlist → 工作区越界守卫 → tool_calls 审计），而不是只返回一段文本。
        第二轮（messages 里已有 tool 回包）返回空，executor 收终答。
        """
        if request.kind != "execute" or not request.tools:
            return [], []
        offered = {str(t.get("name")) for t in request.tools if isinstance(t, dict)}
        if "file_write" not in offered:
            return [], []
        if any(str(m.get("role")) == "tool" for m in request.messages):
            return [], []  # 工具已回包 → 本轮给终答
        payload = dict(request.stub_payload or {})
        path = _stub_deliverable_name(payload)
        summary = _stub_execute(payload)["summary"]
        body = json.dumps({"summary": summary, "stub": True}, ensure_ascii=False)
        arguments = json.dumps({"path": path, "content": body}, ensure_ascii=False)
        call_id = "stub-call-1"
        return ([{"id": call_id, "name": "file_write", "arguments": arguments}],
                [{"id": call_id, "type": "function",
                  "function": {"name": "file_write", "arguments": arguments}}])

    def _deterministic_content(self, request: LLMRequest) -> str:
        payload = dict(request.stub_payload or {})
        if request.kind == "plan":
            return json.dumps(_stub_plan(payload), ensure_ascii=False)
        if request.kind == "execute":
            return json.dumps(_stub_execute(payload), ensure_ascii=False)
        last_user = ""
        for message in reversed(request.messages):
            if message.get("role") == "user":
                last_user = str(message.get("content") or "")
                break
        return json.dumps({"stub": True, "reply": f"STUB echo: {last_user[:160]}"}, ensure_ascii=False)

    def _emit_event(self, request: LLMRequest, response: LLMResponse, *, latency_ms: int) -> None:
        if self.database is None:
            return
        try:
            with self.database.transaction() as conn:
                emit_event(conn, task_id=request.task_id, component=request.component,
                           event_type="llm_call",
                           payload={"provider": response.provider, "model": response.model,
                                    "kind": request.kind,
                                    "tokens_in": response.usage.get("prompt_tokens", 0),
                                    "tokens_out": response.usage.get("completion_tokens", 0),
                                    "cost_usd_est": None,
                                    "subtask_id": request.subtask_id,
                                    "latency_ms": latency_ms,
                                    "finish_reason": response.finish_reason})
        except Exception:
            pass


def _stub_plan(payload: dict[str, Any]) -> dict[str, Any]:
    """STUB 最小合规任务树（planner.validate_plan 可过）：单分组单子任务。"""
    goal = str(payload.get("goal") or "")
    task_type = str(payload.get("task_type") or "generic")
    objective = (goal[:120] or "stub objective") if goal else "stub objective"
    return {
        "task_type": task_type,
        "budget_usd": 1.0,
        "groups": [{
            "id": "g1", "name": "执行组", "depends_on": [],
            "batch_mode": False, "batch_total_items": None, "partial_ok": False,
        }],
        "subtasks": [{
            "id": "g1-1", "group_id": "g1", "objective": objective,
            "task_type": task_type,
            "self_contained_context": f"主任务目标（必要摘录）: {goal[:200]}",
            "acceptance_criteria": ["结果为 JSON 且含非空 summary 字段"],
            "allowed_tools": ["http_get", "file_write", "agent_run"],
            "risk_tier_hint": "reversible",
            "budget_usd": 0.5,
            "max_iterations": 3,
        }],
    }


def _stub_deliverable_name(payload: dict[str, Any]) -> str:
    """STUB 写盘文件名：优先取 brief.deliverable_path 的文件名段（相对任务工作区），
    缺省 result.json。保证 STUB 验收也在工作区留下可核查的产物。"""
    raw = str(payload.get("deliverable_path") or "").strip()
    if raw:
        name = raw.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
        if name and name not in (".", ".."):
            return name
    return "result.json"


def _stub_execute(payload: dict[str, Any]) -> dict[str, Any]:
    objective = str(payload.get("objective") or "stub objective")
    return {"summary": f"STUB completed: {objective}", "details": {"stub": True}}


def from_env(environ: dict[str, str] | None = None, *, database: Database | None = None,
             credential_manager: Any | None = None) -> OpenAICompatClient | StubClient:
    """按环境变量选择适配器（ask 约定：LLM_PROVIDER=STUB 时无 key 验收）。

    - LLM_PROVIDER=STUB（大小写不敏感）→ StubClient；
    - LLM_PROVIDER=OPENAI_COMPAT → 必须同时具备 LLM_BASE_URL/网关 key/LLM_MODEL，
      缺任一 → LLMConfigError（fail fast）；
    - LLM_PROVIDER 未设：有 LLM_BASE_URL 且有网关 key → OPENAI_COMPAT，否则 STUB
      （无 key 环境默认可跑）。

    网关 key 唯一来源：凭证管理器密文库 llm_gateway_key（CRED §10.2 短寿命注入）。
    明文通道全部关闭——LLM_API_KEY env（ARCH §10.1：明文禁止网关 key 进 environment）
    与 LLM_API_KEY_FILE secrets 文件（CRED §7：无明文持久面）都不再读取；只给这两者
    而密文库无 key → 按无 key 处理（OPENAI_COMPAT 下 fail fast / 未设 provider 时 STUB）。
    """
    env = dict(os.environ if environ is None else environ)
    provider = str(env.get("LLM_PROVIDER") or "").strip().upper()
    if provider == "STUB":
        return StubClient(database=database)
    base_url = env.get("LLM_BASE_URL")
    # 唯一来源：密文库（凭证管理器接线；age 解密后内存持有）
    api_key: str | None = None
    if credential_manager is not None:
        try:
            api_key = credential_manager.gateway_key()
        except Exception:
            api_key = None
    # 明文兜底通道已删除：LLM_API_KEY_FILE（CRED §7）与 LLM_API_KEY env（ARCH §10.1）
    # 均不参与注入，也不参与 provider 选择；仅保留「已声明但被拒」的诊断提示位。
    env_key_declared = bool(env.get("LLM_API_KEY") or env.get("LLM_API_KEY_FILE"))
    model = env.get("LLM_MODEL")
    if provider == "OPENAI_COMPAT" or (not provider and base_url and api_key):
        missing = [k for k, v in (("LLM_BASE_URL", base_url), ("LLM_API_KEY", api_key), ("LLM_MODEL", model)) if not v]
        if missing:
            hint = ("（已声明明文 key 但明文通道已按 ARCH §10.1/CRED §7 移除——"
                    "请把网关 key 加密进 credentials.enc 的 llm_gateway_key 条目）"
                    if ("LLM_API_KEY" in missing and env_key_declared) else "")
            raise LLMConfigError(f"OPENAI_COMPAT missing credentials: {', '.join(missing)}{hint}")
        return OpenAICompatClient(base_url=str(base_url), api_key=str(api_key), model=str(model),
                                  database=database)
    return StubClient(database=database)
