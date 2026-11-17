"""test_llm_gateway.py — llm.py 统一 LLM 网关测试（OPENAI_COMPAT 真实 HTTP 往返 + STUB 确定性）。

覆盖验收面：
- OPENAI_COMPAT：stdlib urllib 对本地 http.server 真实 POST（Authorization Bearer、model、
  tools/response_format 请求体映射、tool_calls 解析、usage 计量、llm_call 事件）；
  429 → LLMRateLimitedError + llm_call_failed 事件；500 → LLMGatewayError；畸形响应 → 错误。
- STUB：LLM_PROVIDER=STUB 确定性响应（同请求同输出）、kind=plan/execute 产出可供
  planner/executor 消费的合规 JSON、llm_call 事件落库。
- from_env：STUB 显式选择、OPENAI_COMPAT 缺环境变量 fail fast、未设 provider 时按
  LLM_BASE_URL/LLM_API_KEY 存在性回退。
出处：ask 第 1 条（llm.py 环境变量与适配器约定）；sys-arch §2.3/§7.1；ICON §2 llm_call。
"""

from __future__ import annotations

import json
import os
import unittest.mock as mock
from pathlib import Path

from _helpers import chat_completion_body, cleanup, fresh_db, local_http_server

from app.engine.db import json_dumps
from app.engine.llm import (
    LLMConfigError,
    LLMGatewayError,
    LLMRateLimitedError,
    LLMRequest,
    OpenAICompatClient,
    StubClient,
    from_env,
)


def test_openai_compat_roundtrip_with_local_server() -> None:
    database, directory = fresh_db()
    try:
        script = [(200, chat_completion_body('{"ok": true}', finish_reason="tool_calls",
                                             tool_calls=[{"id": "c1", "type": "function",
                                                          "function": {"name": "file_write",
                                                                       "arguments": '{"path": "a.json"}'}}],
                                             prompt_tokens=11, completion_tokens=7))]
        with local_http_server(script) as (base_url, captured):
            client = OpenAICompatClient(base_url=base_url, api_key="test-key",
                                        model="test-model", database=database)
            response = client.chat(LLMRequest(
                messages=[{"role": "user", "content": "你好"}],
                tools=[{"name": "file_write", "description": "w", "parameters": {"type": "object"}}],
                json_mode=True, kind="execute", task_id=None, component="worker_runtime",
            ))
        # 请求形态：Bearer 鉴权、model、tools 包装、json_mode → response_format
        assert captured[0]["headers"].get("Authorization") == "Bearer test-key"
        assert captured[0]["body"]["model"] == "test-model"
        assert captured[0]["body"]["tool_choice"] == "auto"
        assert captured[0]["body"]["tools"][0] == {"type": "function",
                                                   "function": {"name": "file_write", "description": "w",
                                                                "parameters": {"type": "object"}}}
        assert captured[0]["body"]["response_format"] == {"type": "json_object"}
        # 响应解析
        assert response.content == '{"ok": true}'
        assert response.finish_reason == "tool_calls"
        assert response.tool_calls == [{"id": "c1", "name": "file_write", "arguments": '{"path": "a.json"}'}]
        assert response.raw_tool_calls[0]["function"]["name"] == "file_write"
        assert response.usage == {"prompt_tokens": 11, "completion_tokens": 7}
        assert response.provider == "openai_compat" and response.model == "test-model"
        assert response.latency_ms >= 0
        # sys-arch §7.1 / ICON §2：llm_call 事件化落库（tokens_in/tokens_out/耗时）
        events = database.query("SELECT * FROM events WHERE event_type = 'llm_call'")
        assert len(events) == 1
        payload = json.loads(events[0]["payload"])
        assert payload["tokens_in"] == 11 and payload["tokens_out"] == 7
        assert payload["provider"] == "openai_compat" and payload["kind"] == "execute"
        assert "latency_ms" in payload and "cost_usd_est" in payload
    finally:
        cleanup(database, directory)


def test_openai_compat_429_and_500() -> None:
    database, directory = fresh_db()
    try:
        # 429：sys-arch §2.3——内核适配层不重试，直接 LLMRateLimitedError
        with local_http_server([(429, {"error": {"message": "rate limited"}})]) as (base_url, _):
            client = OpenAICompatClient(base_url=base_url, api_key="k", model="m", database=database)
            try:
                client.chat(LLMRequest(messages=[{"role": "user", "content": "hi"}]))
            except LLMRateLimitedError:
                pass
            else:
                raise AssertionError("429 must raise LLMRateLimitedError")
        failed = database.query("SELECT * FROM events WHERE event_type = 'llm_call_failed'")
        assert len(failed) == 1
        assert json.loads(failed[0]["payload"])["error"]
        # 500：一般网关错误（带 database → llm_call_failed 事件落库）
        with local_http_server([(500, {"error": "boom"})]) as (base_url, _):
            client = OpenAICompatClient(base_url=base_url, api_key="k", model="m", database=database)
            try:
                client.chat(LLMRequest(messages=[{"role": "user", "content": "hi"}]))
            except LLMGatewayError as exc:
                assert not isinstance(exc, LLMRateLimitedError)
                assert "500" in str(exc)
            else:
                raise AssertionError("500 must raise LLMGatewayError")
        assert len(database.query("SELECT * FROM events WHERE event_type = 'llm_call_failed'")) == 2
    finally:
        cleanup(database, directory)


def test_openai_compat_malformed_response() -> None:
    with local_http_server([(200, {"unexpected": "shape"})]) as (base_url, _):
        client = OpenAICompatClient(base_url=base_url, api_key="k", model="m")  # 无 database → 计量面可选
        try:
            client.chat(LLMRequest(messages=[{"role": "user", "content": "hi"}]))
        except LLMGatewayError as exc:
            assert "malformed" in str(exc)
        else:
            raise AssertionError("malformed response must raise")


def test_stub_deterministic_and_kind_aware() -> None:
    database, directory = fresh_db()
    try:
        client = StubClient(database=database)
        req = LLMRequest(messages=[{"role": "user", "content": "目标 A"}], kind="plan",
                         stub_payload={"goal": "调研两个 SaaS 定价页", "task_type": "web_research"})
        first = client.chat(req)
        second = client.chat(req)
        assert first.content == second.content  # 确定性：同请求同输出
        plan = json.loads(first.content or "")
        assert plan["groups"][0]["id"] == "g1" and plan["subtasks"][0]["group_id"] == "g1"
        assert plan["subtasks"][0]["allowed_tools"] == ["http_get", "file_write"]
        assert plan["subtasks"][0]["risk_tier_hint"] in ("irreversible", "reversible_costly", "reversible")
        # kind=execute：含非空 summary 的 JSON（executor 终答契约）
        exec_req = LLMRequest(messages=[{"role": "user", "content": "执行"}], kind="execute",
                              stub_payload={"objective": "抓取定价页"})
        exec_resp = client.chat(exec_req)
        executed = json.loads(exec_resp.content or "")
        assert executed["summary"].startswith("STUB completed:")
        # kind=chat：确定性回显
        echo = client.chat(LLMRequest(messages=[{"role": "user", "content": "hello world"}], kind="chat"))
        assert "STUB echo: hello world" in (echo.content or "")
        assert echo.provider == "stub"
        # llm_call 事件（ICON §2：tokens_in/tokens_out）：plan×2（同请求重发）+ execute + echo = 4
        events = database.query("SELECT * FROM events WHERE event_type = 'llm_call'")
        assert len(events) == 4
        payload = json.loads(events[0]["payload"])
        assert payload["tokens_in"] >= 0 and payload["tokens_out"] > 0  # 短消息 tokens_in 允许为 0
        assert payload["provider"] == "stub"
        kinds = [json.loads(e["payload"])["kind"] for e in events]
        assert kinds == ["plan", "plan", "execute", "chat"]
    finally:
        cleanup(database, directory)


def test_from_env_selection() -> None:
    # 显式 STUB
    with mock.patch.dict(os.environ, {"LLM_PROVIDER": "stub"}, clear=True):
        assert isinstance(from_env(), StubClient)
    # OPENAI_COMPAT 缺环境变量 → fail fast
    with mock.patch.dict(os.environ, {"LLM_PROVIDER": "OPENAI_COMPAT"}, clear=True):
        try:
            from_env()
        except LLMConfigError as exc:
            assert "LLM_BASE_URL" in str(exc) and "LLM_API_KEY" in str(exc) and "LLM_MODEL" in str(exc)
        else:
            raise AssertionError("missing env must raise LLMConfigError")
    # ARCH §10.1：明文 LLM_API_KEY 不得作为注入源 → 只给 env 明文仍 fail fast
    with mock.patch.dict(os.environ, {"LLM_PROVIDER": "OPENAI_COMPAT",
                                      "LLM_BASE_URL": "http://gw.internal",
                                      "LLM_API_KEY": "k", "LLM_MODEL": "m"}, clear=True):
        try:
            from_env()
        except LLMConfigError as exc:
            assert "LLM_API_KEY" in str(exc)
        else:
            raise AssertionError("plaintext LLM_API_KEY must not be accepted (ARCH §10.1)")
    # 网关 key 唯一来源 = 凭证管理器密文库（CRED §10.2）
    class _Mgr:
        def gateway_key(self) -> str:
            return "k-from-vault"

    env = {"LLM_PROVIDER": "OPENAI_COMPAT", "LLM_BASE_URL": "http://gw.internal",
           "LLM_MODEL": "m"}
    with mock.patch.dict(os.environ, env, clear=True):
        client = from_env(credential_manager=_Mgr())
        assert isinstance(client, OpenAICompatClient)
        assert client.base_url == "http://gw.internal"
        assert client.api_key == "k-from-vault"
    # 未设 provider：base_url + 密文库 key → OPENAI_COMPAT；否则 STUB（无 key 默认可跑）
    with mock.patch.dict(os.environ, {"LLM_BASE_URL": "http://x", "LLM_MODEL": "m"}, clear=True):
        assert isinstance(from_env(credential_manager=_Mgr()), OpenAICompatClient)
    with mock.patch.dict(os.environ, {}, clear=True):
        assert isinstance(from_env(), StubClient)
    # environ 参数注入（不经 os.environ）
    client = from_env({"LLM_PROVIDER": "OPENAI_COMPAT", "LLM_BASE_URL": "http://y",
                       "LLM_MODEL": "m2"}, credential_manager=_Mgr())
    assert isinstance(client, OpenAICompatClient) and client.api_key == "k-from-vault"
    # 明文文件通道已删除（CRED §7 无明文持久面）：只给 LLM_API_KEY_FILE → 不算 key，fail fast
    tmp_key = Path(__file__).parent / "_tmp_llmkey"
    tmp_key.mkdir(parents=True, exist_ok=True)
    (tmp_key / "llm_api_key").write_text("k-from-file\n", encoding="utf-8")
    with mock.patch.dict(os.environ, {"LLM_PROVIDER": "OPENAI_COMPAT",
                                      "LLM_BASE_URL": "http://gw.internal",
                                      "LLM_API_KEY_FILE": str(tmp_key / "llm_api_key"),
                                      "LLM_MODEL": "m"}, clear=True):
        try:
            from_env()
        except LLMConfigError as exc:
            assert "LLM_API_KEY" in str(exc)
        else:
            raise AssertionError("LLM_API_KEY_FILE must be ignored (CRED §7)")
    import shutil
    shutil.rmtree(tmp_key, ignore_errors=True)
    _ = json_dumps  # 保持导入面稳定（同 db.json_dumps 单源）
