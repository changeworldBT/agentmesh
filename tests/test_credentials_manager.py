"""test_credentials_manager.py — 凭证管理器（app/engine/credentials.py）接线测试。

评审收口项回归：CRED §3A'（age 解密经 decrypt_fn 注入，不依赖本机 age 二进制）、
§4.2 三闸门、§5.1 短寿命注入（value 只在 resolve 返回值瞬时窗口）、§6.1 credential_audit
（deny/inject 落行）、§10.2（agentmesh_api_token / llm_gateway_key 承载于密文库）、
ICON §11（H 域经 manager 出真实元数据，永不返回明文）、G1/G6 secret_ref 核验与解析、
llm.from_env 密文库 key 优先与 env 明文通道移除（ARCH §10.1）。
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from pathlib import Path

from _helpers import TestSkipped, cleanup, fresh_db, temp_workspace_root
from test_api_server import TOKEN, _boot, _json_of, _request

from app.engine import executor, state, triggers
from app.engine.credentials import CredentialManager, age_decrypt, maybe_build
from app.engine.llm import LLMConfigError, OpenAICompatClient, StubClient, from_env
from app.engine.db import Database
from _helpers import local_http_server

ROLES_CFG = {"roles": {
    "worker": {"tools": ["memory-read"], "credential_groups": ["accounts"]},
    "credential_manager": {"tools": [], "credential_groups": ["api_keys", "accounts",
                                                             "vps_inventory"]},
}}

CRED_JSON = {
    "api_keys": {
        "agentmesh_api_token": {"value": "tok-boot-000", "env": "AGENTMESH_API_TOKEN",
                                 "header": None, "header_prefix": "", "rotate_at": "2027-01-01",
                                 "notes": "API 令牌（CRED §10.2）"},
        "llm_gateway_key": {"value": "gw-key-111", "env": "LLM_GATEWAY_KEY",
                            "header": "Authorization", "header_prefix": "Bearer ",
                            "rotate_at": "2027-01-01", "notes": "LLM 网关"},
    },
    "accounts": {
        "smtp_notify": {"value": "smtp-pass-222", "kind": "password", "env": "SMTP_PASSWORD",
                        "header": None, "rotate_at": "2027-02-01", "notes": "SMTP"},
    },
    "vps_inventory": {},
}


def _manager(database: Database) -> CredentialManager:
    manager = CredentialManager(database, encrypted_path="dummy.enc", age_key_path="dummy.key",
                                decrypt_fn=lambda enc, key: json.loads(json.dumps(CRED_JSON)))
    manager.set_roles_cfg(ROLES_CFG)
    return manager


def test_manager_gates_deny_and_inject_with_audit() -> None:
    database, directory = fresh_db()
    try:
        manager = _manager(database)
        # 三闸门 deny：worker（accounts 组）请求 api_keys 组 key → group_not_authorized
        result = manager.resolve("llm_gateway_key", "worker", "env", task_id="g1-1")
        assert result["allowed"] is False
        assert result["denial"] == {"reason": "group_not_authorized", "key_name": "llm_gateway_key"}
        # key 不存在 → key_not_found
        result2 = manager.resolve("nope", "worker", "env")
        assert result2["denial"]["reason"] == "key_not_found"
        # kind 不匹配（header 注入 env 型条目）→ kind_mismatch
        result3 = manager.resolve("smtp_notify", "worker", "header")
        assert result3["denial"]["reason"] == "kind_mismatch"
        # 注入（env）：value 只在返回值瞬时窗口
        ok = manager.resolve("smtp_notify", "worker", "env", task_id="g1-1")
        assert ok["allowed"] is True and ok["inject"]["env"] == {"SMTP_PASSWORD": "smtp-pass-222"}
        # 注入（header）：prefix 拼接
        ok2 = manager.resolve("llm_gateway_key", "credential_manager", "header")
        assert ok2["inject"]["header"] == ("Authorization", "Bearer gw-key-111")
        # CRED §6.1：deny 与 inject 都落 credential_audit（detail 无 value）
        rows = manager.audit_rows(limit=10)
        assert {r["action"] for r in rows} == {"deny", "inject"}
        assert any(r["action"] == "deny" and r["detail"] == "group_not_authorized"
                   for r in rows)
        assert any(r["action"] == "deny" and r["detail"] == "key_not_found" for r in rows)
        assert any(r["action"] == "deny" and r["detail"] == "kind_mismatch" for r in rows)
        assert all("smtp-pass" not in json.dumps(r) and "gw-key" not in json.dumps(r) for r in rows)
    finally:
        database.close()


def test_manager_metadata_and_secrets() -> None:
    database, directory = fresh_db()
    try:
        manager = _manager(database)
        # CRED §10.2：令牌与网关 key 承载于密文库
        assert manager.api_token() == "tok-boot-000"
        assert manager.gateway_key() == "gw-key-111"
        # ICON §11：元数据面剔除 value（永不返回明文）
        entries = manager.metadata_entries()
        assert {e["key_name"] for e in entries} == {"agentmesh_api_token", "llm_gateway_key",
                                                    "smtp_notify"}
        assert all("value" not in json.dumps(e) for e in entries)
        assert next(e for e in entries if e["key_name"] == "smtp_notify")["group"] == "accounts"
    finally:
        database.close()


def test_maybe_build_degrades_without_age() -> None:
    tmp = Path(__file__).parent / "_tmp_cred1"
    tmp.mkdir(parents=True, exist_ok=True)
    old = dict(os.environ)
    try:
        os.environ["AGENTMESH_AGE_BIN"] = str(tmp / "no-such-age")
        os.environ["AGENTMESH_CREDENTIALS_ENC"] = str(tmp / "credentials.enc")
        os.environ["AGENTMESH_AGE_KEY_FILE"] = str(tmp / "age.key")
        (tmp / "credentials.enc").write_bytes(b"not-a-real-age-file")
        manager = maybe_build(Database((tmp / "db.sqlite")))
        assert manager is None  # 降级运行（CRED 密文可后置，deployment-ops §5.3）
    finally:
        os.environ.clear()
        os.environ.update(old)
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


def test_h_domain_wired_with_manager() -> None:
    tmp = Path(__file__).parent / "_tmp_cred2"
    probe = Database(tmp / "agentmesh.db")
    probe.connect()
    manager = _manager(probe)
    probe.close()
    database, rules, api, server, base = _boot(tmp, credential_manager=manager)
    try:
        # H1：真实元数据（非降级），无 value
        status, payload, _ = _request("GET", base, "/api/v1/credentials")
        body = _json_of(payload)
        assert status == 200 and body["degraded"] is False
        assert {i["key_name"] for i in body["items"]} == {"agentmesh_api_token", "llm_gateway_key",
                                                          "smtp_notify"}
        assert "value" not in json.dumps(body)
        # H2：单条 + recent_audit
        status, payload, _ = _request("GET", base, "/api/v1/credentials/smtp_notify")
        assert status == 200 and _json_of(payload)["group"] == "accounts"
        # H4：三闸门真值（manager 接线：worker 对 accounts 组 key 允许）
        status, payload, _ = _request("POST", base, "/api/v1/credentials/check",
                                      body={"role": "worker", "key_name": "smtp_notify",
                                            "inject_path": "env"})
        check = _json_of(payload)
        assert check["allowed"] is True
        assert check["gates"] == {"group_authorized": True, "key_exists": True,
                                  "kind_match": True}
        # H4 拒绝：worker 对 api_keys 组 → group_not_authorized（真值，非 null）
        status, payload, _ = _request("POST", base, "/api/v1/credentials/check",
                                      body={"role": "worker", "key_name": "llm_gateway_key",
                                            "inject_path": "env"})
        check2 = _json_of(payload)
        assert check2["gates"]["group_authorized"] is False
        assert check2["denial"]["reason"] == "group_not_authorized"
        # H5 到期报告（rotate_at 2027-01-01 → 未来 → 空 expiring）
        status, payload, _ = _request("GET", base, "/api/v1/credentials/expiring?within_days=30")
        assert status == 200 and _json_of(payload)["expiring"] == []
    finally:
        import test_api_server as _t
        _t._stop(server, api)
        cleanup(database, tmp)


def test_secret_ref_with_manager_wired() -> None:
    tmp = Path(__file__).parent / "_tmp_cred3"
    probe = Database(tmp / "agentmesh.db")
    probe.connect()
    manager = _manager(probe)
    probe.close()
    database, rules, api, server, base = _boot(tmp, credential_manager=manager)
    try:
        # G1：manager 接线 → secret_ref 核验通过（key 存在于密文库）
        status, payload, _ = _request("POST", base, "/api/v1/triggers",
                                      body={"type": "webhook", "goal_template": "处理 {{payload.event}}",
                                            "secret_ref": "smtp_notify"})
        assert status == 201, payload
        hook = _json_of(payload)
        assert hook["secret_mode"] == "ref" and hook.get("secret_once") is None
        # 密文库不存在的 key → 400 SECRET_REF_NOT_FOUND
        status, payload, _ = _request("POST", base, "/api/v1/triggers",
                                      body={"type": "webhook", "goal_template": "x",
                                            "secret_ref": "no-such-key"})
        assert status == 400 and _json_of(payload)["error"]["code"] == "SECRET_REF_NOT_FOUND"
        # G6：HMAC 用密文库条目 value 验签（短寿命注入语义）
        token = hook["ingest_path"].rsplit("/", 1)[-1]
        body = json.dumps({"event": "opened"}).encode()
        ts = str(int(time.time()))
        sig = "sha256=" + hmac.new(b"smtp-pass-222", f"{ts}.".encode() + body,
                                   hashlib.sha256).hexdigest()
        status, payload, _ = _request("POST", base, f"/api/v1/triggers/webhook/{token}",
                                      raw_body=body, token=None,
                                      headers={"X-Agentmesh-Timestamp": ts,
                                               "X-Agentmesh-Signature": sig})
        assert status == 202 and _json_of(payload)["source"] == "webhook"
    finally:
        import test_api_server as _t
        _t._stop(server, api)
        cleanup(database, tmp)


def test_llm_gateway_key_from_credential_store() -> None:
    database, directory = fresh_db()
    try:
        manager = _manager(database)
        # ① 密文库优先：client.api_key == 密文库值（LLM_API_KEY env 明文通道已移除）
        client = from_env({"LLM_PROVIDER": "OPENAI_COMPAT", "LLM_BASE_URL": "http://gw",
                           "LLM_MODEL": "m"}, database=database,
                          credential_manager=manager)
        assert isinstance(client, OpenAICompatClient)
        assert client.api_key == "gw-key-111"
        # ② env 声明了 LLM_API_KEY 但无密文库/FILE → fail fast 且提示明文通道已移除
        try:
            from_env({"LLM_PROVIDER": "OPENAI_COMPAT", "LLM_BASE_URL": "http://gw",
                      "LLM_API_KEY": "plaintext", "LLM_MODEL": "m"}, database=database)
        except LLMConfigError as exc:
            assert "明文通道已按 ARCH §10.1/CRED §7 移除" in str(exc)
        else:
            raise AssertionError("env plaintext key must not be accepted")
        # ③ 明文 FILE 过渡通道已删除（CRED §7 无明文持久面）→ 只给文件不算 key，fail fast
        tmp = Path(__file__).parent / "_tmp_cred4"
        tmp.mkdir(parents=True, exist_ok=True)
        key_file = tmp / "llm_key"
        key_file.write_text("file-key-333", encoding="utf-8")
        try:
            from_env({"LLM_PROVIDER": "OPENAI_COMPAT", "LLM_BASE_URL": "http://gw",
                      "LLM_API_KEY_FILE": str(key_file), "LLM_MODEL": "m"},
                     database=database)
        except LLMConfigError:
            pass
        else:
            raise AssertionError("LLM_API_KEY_FILE must be ignored (CRED §7)")
    finally:
        database.close()
        import shutil
        shutil.rmtree(Path(__file__).parent / "_tmp_cred4", ignore_errors=True)


def test_tool_call_short_lived_injection_six_steps() -> None:
    """CRED §5.1 六步：工具参数只有 credential:<key_name> 占位符 → 管理器三闸门 →
    header 型注入本次请求头 → 明文不进 tool_calls 摘要/事件 → 调用返回即丢弃。"""
    database, directory = fresh_db()
    try:
        manager = _manager(database)
        task_id = state.create_task(database, title="注入", goal="凭证注入六步")
        box = executor.ToolBox(database, task_id, "s1", root=directory / "ws",
                              role="credential_manager:executor",
                              credential_manager=manager)
        with local_http_server([(200, {"ok": True})]) as (base_url, captured):
            result = box.call("http_get", {"url": f"{base_url}/prices",
                                           "token": "credential:llm_gateway_key"})
            assert result["status"] == 200
            sent = captured[-1]
            # ④ 注入：请求头带 Bearer + 密文库值
            assert sent["headers"].get("Authorization") == "Bearer gw-key-111"
            # ① 占位符本身不外发（引用标记剥离，key 名不出内核）
            assert "credential:" not in json.dumps(sent)
        # ⑥ 丢弃：tool_calls 摘要与事件里都没有明文值
        rows = database.query("SELECT params_digest FROM tool_calls WHERE tool_name='http_get'")
        assert rows and all("gw-key-111" not in r["params_digest"] for r in rows)
        events = database.query("SELECT payload FROM events WHERE event_type='tool_call'")
        assert events and all("gw-key-111" not in e["payload"] for e in events)
        # deny 落 credential_audit（worker 对 api_keys 组 → group_not_authorized）
        box_denied = executor.ToolBox(database, task_id, "s2", root=directory / "ws",
                                     role="worker:executor", credential_manager=manager)
        try:
            box_denied.call("http_get", {"url": "http://127.0.0.1:1/x",
                                         "token": "credential:agentmesh_api_token"})
        except executor.ToolError as exc:
            assert exc.error_type == "credential_denied"
            assert exc.params["reason"] == "group_not_authorized"
        else:
            raise AssertionError("denied credential must raise ToolError")
        audit = manager.audit_rows(key_name="agentmesh_api_token")
        assert any(r["action"] == "deny" and r["detail"] == "group_not_authorized" for r in audit)
    finally:
        database.close()
        import shutil
        shutil.rmtree(directory, ignore_errors=True)


def test_env_kind_and_unwired_channel_are_hard_denied() -> None:
    """env 型条目无 in-process 注入面 → credential_inject_unsupported（不伪造注入）；
    管理器未接线 → credential_channel_unavailable（fail-closed）。"""
    database, directory = fresh_db()
    try:
        manager = _manager(database)
        task_id = state.create_task(database, title="注入边界", goal="硬拒绝")
        box = executor.ToolBox(database, task_id, "s1", root=directory / "ws",
                              credential_manager=manager)
        try:
            box.call("http_get", {"url": "http://127.0.0.1:1/x",
                                  "token": "credential:smtp_notify"})
        except executor.ToolError as exc:
            assert exc.error_type == "credential_inject_unsupported"
        else:
            raise AssertionError("env-kind credential has no injection surface")
        # 非 http_get 工具带占位符 → 同样硬拒绝
        try:
            box.call("file_write", {"path": "a.txt", "content": "credential:smtp_notify"})
        except executor.ToolError as exc:
            assert exc.error_type == "credential_inject_unsupported"
        else:
            raise AssertionError("file_write has no injection surface")
        # 未接线：占位符 → credential_channel_unavailable
        box2 = executor.ToolBox(database, task_id, "s2", root=directory / "ws")
        try:
            box2.call("http_get", {"url": "http://127.0.0.1:1/x",
                                   "token": "credential:llm_gateway_key"})
        except executor.ToolError as exc:
            assert exc.error_type == "credential_channel_unavailable"
        else:
            raise AssertionError("unwired channel must fail closed")
        # 无占位符的工具调用完全不受影响（回归）
        with local_http_server([(200, {"ok": 1})]) as (base_url, _captured):
            assert box2.call("http_get", {"url": f"{base_url}/plain"})["status"] == 200
    finally:
        database.close()
        import shutil
        shutil.rmtree(directory, ignore_errors=True)


def test_engine_loop_passes_credential_manager_to_executor() -> None:
    """引擎主循环把凭证管理器透传到执行器（CRED §6.1「工具调用路径强制过凭证管理器」）。"""
    from app.main import EngineLoop
    database, directory = fresh_db()
    try:
        manager = _manager(database)
        engine = EngineLoop(database, StubClient(database=database),
                            credential_manager=manager)
        assert engine.credential_manager is manager
        task_id = state.create_task(database, title="透传", goal="STUB 全链")
        with temp_workspace_root():
            engine.tick()
        assert database.query_one("SELECT status FROM tasks WHERE id = ?",
                                  (task_id,))["status"] == "done"
    finally:
        database.close()
        import shutil
        shutil.rmtree(directory, ignore_errors=True)


def test_age_decrypt_real_binary_or_skip() -> None:
    """age 解密执行体：本机无 age 二进制时诚实跳过（不谎报 PASS），有则真解密往返。"""
    import shutil as _shutil
    import subprocess
    binary = _shutil.which("age")
    keygen = _shutil.which("age-keygen")
    if not binary or not keygen:
        raise TestSkipped("本机无 age/age-keygen 二进制——解密执行体待目标机验收")
    tmp = Path(__file__).parent / "_tmp_age1"
    tmp.mkdir(parents=True, exist_ok=True)
    try:
        key = tmp / "age.key"
        subprocess.run([keygen, "-o", str(key)], check=True, capture_output=True)
        pub = subprocess.run([keygen, "-y", str(key)], check=True, capture_output=True,
                             text=True).stdout.strip()
        plain = tmp / "plain.json"
        plain.write_text(json.dumps({"api_keys": {"llm_gateway_key": {"value": "v"}}}),
                         encoding="utf-8")
        enc = tmp / "credentials.enc"
        subprocess.run([binary, "-r", pub, "-o", str(enc), str(plain)], check=True,
                       capture_output=True)
        assert "api_keys" in age_decrypt(enc, key, age_binary=binary)
        # 私钥缺失 → CredentialsNotAvailable（降级路径）
        try:
            age_decrypt(enc, tmp / "nope.key", age_binary=binary)
        except Exception as exc:
            assert "私钥" in str(exc)
        else:
            raise AssertionError("missing key must raise")
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


def test_roles_cfg_production_wiring_full_rules_cfg() -> None:
    """评审遗留项回归（high）：main.build_runtime 把**全量** rules_cfg 交给凭证管理器，
    而 rules.yaml 顶层键就是 `roles`（load_rules 再以同名键收进 rules_cfg），实际是两层
    `{"roles": {"roles": {role: ...}}}`——只剥一层会让角色表恒空，真实部署下任何
    credential:<key> 注入被 group_not_authorized 拒绝。本用例按生产接线形态复现。"""
    from app.main import load_rules

    database, directory = fresh_db()
    try:
        rules_cfg = load_rules(Path(__file__).resolve().parent.parent / "rules", database)
        assert isinstance(rules_cfg.get("roles"), dict)
        manager = CredentialManager(database, encrypted_path="dummy.enc", age_key_path="dummy.key",
                                    decrypt_fn=lambda enc, key: json.loads(json.dumps(CRED_JSON)))
        manager.set_roles_cfg(rules_cfg)  # 生产接线形态（app/main.py build_runtime）
        assert manager._roles_cfg().get("worker") is not None
        allowed = manager.resolve("smtp_notify", "worker", "env", task_id="g1-1")
        assert allowed["allowed"] is True, allowed
        # 三闸门 B 不被放宽：worker 仍不得取 api_keys 组
        denied = manager.resolve("llm_gateway_key", "worker", "env")
        assert denied["allowed"] is False
        assert denied["denial"]["reason"] == "group_not_authorized"
    finally:
        cleanup(database, directory)


def test_api_token_plaintext_file_channel_removed() -> None:
    """CRED §7：AGENTMESH_API_TOKEN_FILE 明文文件读取位已删除——即使文件存在且可读，
    令牌也只从密文库（或本地验收 env）来；两者都缺 → None（fail-closed）。"""
    import app.main as main_mod

    old = dict(os.environ)
    tmp = Path(__file__).parent / "_tmp_cred5"
    try:
        tmp.mkdir(parents=True, exist_ok=True)
        (tmp / "api_token").write_text("file-token-777", encoding="utf-8")
        os.environ.pop("AGENTMESH_API_TOKEN", None)
        os.environ["AGENTMESH_API_TOKEN_FILE"] = str(tmp / "api_token")
        assert main_mod._read_secret_token() is None
    finally:
        os.environ.clear()
        os.environ.update(old)
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)
