"""credentials.py — 凭证管理器（Credential Manager 组件落点；评审收口项 P-cred）。

设计文档出处（模块顶部注记，按 ask 要求）：
- credentials-spec（CRED-01）§3 路径 A'：容器经 AGENTMESH_AGE_KEY_FILE（tmpfs 只读副本）
  拿 age 私钥解密 credentials.enc，明文 JSON 只存在于进程内存（解密结果缓存不落盘、
  不写日志、不进任何 SQLite 字段）；§4.1/§4.2：角色 → credential_groups 授权、B/C/D
  三闸门（授权组 → key 存在 → 注入路径与 kind 匹配）；§5.1：六步短寿命注入协议
  （③解密结果本轮内复用、⑥调用返回即丢弃——本组件只承担闸门与审计，注入即返回值）；
  §6.1：credential_audit 表（inject/deny 每步终点落行，只记 key 名，源头上不接收 value）；
  §10.2：agentmesh_api_token 承载于 credentials.enc 三组结构（api_keys 组）。
- sys-arch（ARCH-ROOT-01）§6.1：工具调用路径强制过凭证管理器；§9.3 不变量 2：
  凭证明文只存在于「解密→注入单次调用→丢弃」的瞬时窗口。
- interface-contracts（ICON-01）§11：H 域只触碰元数据与审计，永不返回明文；
  §11.4：预检不解密不注入、不产生 credential_audit。
- memory-design §8.1：写入过 write_guard()。

实现边界（如实声明）：
- age 解密执行体：age v1 X25519+ChaCha20-Poly1305 无法用 stdlib 实现（hashlib 无 AEAD），
  本组件经 subprocess 调外部 age 二进制（CRED §1.1 允许的依赖形态：`age` ~10MB 量级）；
  二进制缺失或解密失败 → 接线失败（降级），不假装解密成功。测试经 decrypt_fn 注入。
- 部署面（impl/deploy/install.sh 步骤 4）只建 age 密文库：age keypair 落宿主
  /etc/agentmesh/age-key.txt（0600 root:root），credentials.enc 承载 agentmesh_api_token
  与 llm_gateway_key，.env 只有路径指针，磁盘上不生成任何明文令牌文件。
- 明文持久通道全部关闭（CRED §7）：AGENTMESH_API_TOKEN_FILE 与 LLM_API_KEY_FILE 两个
  0600 明文文件读取位已删除；密文库是唯一持久凭证源（API 令牌另有 AGENTMESH_API_TOKEN
  env 兼容位，仅本地验收、进程内存、部署面 .env 不含）。
- credential_audit 写入经 write_guard（detail 源头上不接收 value，CRED §6.1）。
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import threading
from pathlib import Path
from typing import Any, Callable

from app.engine import ledger as ledger_mod
from app.engine.db import Database

CRED_GROUPS = ("api_keys", "accounts", "vps_inventory")
AUDIT_ACTIONS = ("inject", "deny", "rotate", "reencrypt")

# CRED §6.1 DDL 逐字（单一事实源：server._ensure_credential_audit_table 与本模块共用）
CREDENTIAL_AUDIT_DDL = """
            CREATE TABLE IF NOT EXISTS credential_audit (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                role        TEXT NOT NULL,
                task_id     TEXT NOT NULL,
                key_name    TEXT NOT NULL,
                action      TEXT NOT NULL,
                detail      TEXT,
                created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
            )
        """
CREDENTIAL_AUDIT_INDEXES = (
    "CREATE INDEX IF NOT EXISTS idx_credential_audit_role_time ON credential_audit(role, created_at)",
    "CREATE INDEX IF NOT EXISTS idx_credential_audit_key_time ON credential_audit(key_name, created_at)",
)


class CredentialsNotAvailable(RuntimeError):
    """凭证通道未接线（age 缺失/解密失败/密文缺失）——调用方按降级路径处理。"""


def age_decrypt(encrypted_path: str | os.PathLike[str], age_key_path: str | os.PathLike[str],
                *, age_binary: str | None = None) -> dict[str, Any]:
    """age 解密 credentials.enc（CRED §3 路径 A'）：subprocess 调 age 二进制，stdout JSON。

    私钥只作为进程参数传给 age（tmpfs 只读副本路径，CRED §3.2），解密结果由调用方
    持有于进程内存；本函数不落任何持久位置。
    """
    binary = age_binary or os.environ.get("AGENTMESH_AGE_BIN") or shutil.which("age")
    if not binary:
        raise CredentialsNotAvailable("age 二进制不可用（AGENTMESH_AGE_BIN/PATH）")
    enc = Path(encrypted_path)
    key = Path(age_key_path)
    if not enc.exists():
        raise CredentialsNotAvailable(f"credentials.enc 不存在: {enc}")
    if not key.exists():
        raise CredentialsNotAvailable(f"age 私钥文件不存在: {key}")
    result = subprocess.run([binary, "--decrypt", "-i", str(key), str(enc)],
                            capture_output=True, timeout=30)
    if result.returncode != 0:
        raise CredentialsNotAvailable(f"age 解密失败 rc={result.returncode}")
    try:
        data = json.loads(result.stdout.decode("utf-8"))
    except ValueError as exc:
        raise CredentialsNotAvailable(f"解密结果不是合法 JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise CredentialsNotAvailable("解密结果必须是 JSON 对象")
    return data


class CredentialManager:
    """凭证管理器单例：age 解密缓存（进程内存）+ 三闸门 + credential_audit 审计。

    明文纪律（CRED §7）：value 只在 inject 返回值（短寿命）中出现；metadata()/audit()
    等一切持久面/响应面永远只有 key 名与注入方式的存在性。
    """

    def __init__(self, database: Database, *,
                 encrypted_path: str | os.PathLike[str],
                 age_key_path: str | os.PathLike[str],
                 decrypt_fn: Callable[[str, str], dict[str, Any]] | None = None) -> None:
        self.database = database
        self.encrypted_path = str(encrypted_path)
        self.age_key_path = str(age_key_path)
        self._decrypt_fn = decrypt_fn or age_decrypt
        self._lock = threading.Lock()
        self._plaintext: dict[str, Any] | None = None
        self._decrypted = False

    # -- 解密缓存（CRED §5.1 ③：本轮内复用；进程内存，不落盘）-------------------

    def _ensure_plaintext(self) -> dict[str, Any]:
        with self._lock:
            if self._decrypted:
                assert self._plaintext is not None
                return self._plaintext
            data = self._decrypt_fn(self.encrypted_path, self.age_key_path)
            self._plaintext = data
            self._decrypted = True
            return data

    def available(self) -> bool:
        """凭证通道是否接线成功（解密成功一次即视为接线）。"""
        try:
            self._ensure_plaintext()
            return True
        except Exception:
            return False

    # -- 条目索引（key_name → (组, 条目)，剔除 value 的元数据面）------------------

    def _index(self) -> dict[str, tuple[str, dict[str, Any]]]:
        data = self._ensure_plaintext()
        index: dict[str, tuple[str, dict[str, Any]]] = {}
        for group in CRED_GROUPS:
            items = data.get(group) or {}
            for key_name, entry in items.items():
                index[str(key_name)] = (group, dict(entry or {}))
        return index

    def key_names(self) -> list[str]:
        """密文库全部 key 名（G1 secret_ref 核验用；不含任何 value）。"""
        return sorted(self._index())

    def metadata_entries(self) -> list[dict[str, Any]]:
        """H1/H2 元数据面（CRED §2.2 剔除 value；ICON §11.1 形态）。"""
        entries = []
        for key_name, (group, entry) in sorted(self._index().items()):
            entries.append({
                "group": group, "key_name": key_name,
                "kind": entry.get("kind") or ("api_key" if group == "api_keys" else "password"),
                "env": entry.get("env"),
                "env_injection": entry.get("env") is not None,
                "header": entry.get("header"),
                "header_prefix_present": bool(entry.get("header_prefix")),
                "rotate_at": entry.get("rotate_at"),
                "notes": entry.get("notes"),
            })
        return entries

    def entry(self, key_name: str) -> tuple[str, dict[str, Any]] | None:
        found = self._index().get(key_name)
        return found if found else None

    # -- 六步闸门 + 短寿命注入（CRED §4.2/§5.1）----------------------------------

    def resolve(self, key_name: str, role: str, inject_path: str, *,
                task_id: str = "system") -> dict[str, Any]:
        """六步协议 ②校验→③解密→④组装（env 名值对/请求头）；返回注入载荷或拒绝详情。

        - 允许：{"allowed": True, "inject": {"env": {...}} 或 {"header": (name, prefixed_value)}}
          ——value 只存在于本返回值的瞬时窗口，调用方消费后即刻丢弃（⑤⑥）；
        - 拒绝：{"allowed": False, "denial": {"reason": ..., "key_name": ...}}
          ——同时写 credential_audit（deny，CRED §4.3）。
        """
        data = self._ensure_plaintext()
        role_cfg = self._role_groups(role)
        entry_pair = self._index().get(key_name)
        group_authorized = bool(entry_pair and entry_pair[0] in role_cfg)
        key_exists = entry_pair is not None
        kind_match: bool | None = None
        if key_exists:
            entry = entry_pair[1]
            kind_match = (entry.get("env") is not None) if inject_path == "env" \
                else (entry.get("header") is not None)
        allowed = bool(group_authorized and key_exists and kind_match)
        if not allowed:
            if not key_exists:
                reason = "key_not_found"  # ICON §11.4 示例 B：组闸门需 key 的组先可知
            elif not group_authorized:
                reason = "group_not_authorized"
            else:
                reason = "kind_mismatch"
            self._audit(role, task_id, key_name, "deny", reason)
            return {"allowed": False,
                    "denial": {"reason": reason, "key_name": key_name}}
        entry = entry_pair[1]
        value = str(entry.get("value") or "")
        if inject_path == "env" and entry.get("env"):
            inject = {"env": {str(entry["env"]): value}}
        elif inject_path == "header" and entry.get("header"):
            prefix = str(entry.get("header_prefix") or "")
            inject = {"header": (str(entry["header"]), prefix + value)}
        else:
            reason = "kind_mismatch"
            self._audit(role, task_id, key_name, "deny", reason)
            return {"allowed": False, "denial": {"reason": reason, "key_name": key_name}}
        self._audit(role, task_id, key_name, "inject", None)
        return {"allowed": True, "inject": inject}

    def _role_groups(self, role: str) -> set[str]:
        """角色 → credential_groups（roles.yaml 装载面由 main 注入 rules_cfg；
        本组件按 CRED §4.1 读取 credential_groups 列表键）。"""
        roles = self._roles_cfg()
        cfg = roles.get(role) or {}
        groups = cfg.get("credential_groups") or []
        bad = [g for g in groups if g not in CRED_GROUPS]
        if bad:
            # CRED §4.1：非法组名拒绝加载该角色并登记 error_ledger
            try:
                ledger_mod.ledger_write(self.database, "rule_schema_violation", "credential_manager",
                                        {"role": role, "groups": json.dumps(bad)},
                                        f"credential_groups 越界: {bad}", "kernel-boot",
                                        "credential_manager")
            except Exception:
                pass
            groups = [g for g in groups if g in CRED_GROUPS]
        return set(groups)

    _roles_source: dict[str, Any] | None = None

    def set_roles_cfg(self, roles_cfg: dict[str, Any]) -> None:
        self._roles_source = roles_cfg

    def _roles_cfg(self) -> dict[str, Any]:
        """剥到真正的角色表（生产接线实测：rules.yaml 顶层键就是 `roles`，
        load_rules 又以同名键收进 rules_cfg，故 main 传入全量 rules_cfg 时是
        `{"roles": {"roles": {role: ...}}}` 两层；只剥一层会让角色表恒空，
        所有 credential:<key> 注入被 group_not_authorized 拒绝）。"""
        node: Any = self._roles_source
        for _ in range(4):  # 防御性上限：畸形输入不无限剥
            if not isinstance(node, dict):
                return {}
            inner = node.get("roles")
            if isinstance(inner, dict):
                node = inner
                continue
            return node
        return node if isinstance(node, dict) else {}

    # -- 审计（CRED §6.1：inject/deny 每步终点；写入过 write_guard）----------------

    def _ensure_audit_table(self) -> None:
        with self.database.transaction() as conn:
            conn.execute(CREDENTIAL_AUDIT_DDL)
            for stmt in CREDENTIAL_AUDIT_INDEXES:
                conn.execute(stmt)

    def _audit(self, role: str, task_id: str, key_name: str, action: str, detail: str | None) -> None:
        assert action in AUDIT_ACTIONS
        self._ensure_audit_table()
        guarded = ledger_mod.write_guard(str(detail)) if detail else None
        with self.database.transaction() as conn:
            conn.execute(
                "INSERT INTO credential_audit (role, task_id, key_name, action, detail)"
                " VALUES (?, ?, ?, ?, ?)",
                (str(role), str(task_id), str(key_name), action, guarded))

    def audit_rows(self, *, key_name: str | None = None, action: str | None = None,
                   role: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
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
        rows = self.database.query(
            f"SELECT * FROM credential_audit {where} ORDER BY created_at DESC LIMIT ?",
            (*params, limit))
        return [{k: r[k] for k in r.keys()} for r in rows]

    # -- 令牌与网关 key（CRED §10.2：承载于 credentials.enc 三组结构）--------------

    def api_token(self) -> str | None:
        """api_keys.agentmesh_api_token 条目 value（CRED §10.2）；永不写日志/响应。"""
        data = self._ensure_plaintext()
        entry = ((data.get("api_keys") or {}).get("agentmesh_api_token") or {})
        return str(entry.get("value")) if entry.get("value") else None

    def gateway_key(self) -> str | None:
        """api_keys.llm_gateway_key 条目 value（CRED §2.2 示例条目）。"""
        data = self._ensure_plaintext()
        entry = ((data.get("api_keys") or {}).get("llm_gateway_key") or {})
        return str(entry.get("value")) if entry.get("value") else None


def maybe_build(database: Database, *, roles_cfg: dict[str, Any] | None = None) -> CredentialManager | None:
    """构建凭证管理器（main.build_runtime 的接线位）。

    环境面：AGENTMESH_CREDENTIALS_ENC（首选名）/ AGENTMESH_CREDENTIALS_FILE
    （deployment-ops §2.1 env 表用名，二者等价）——默认
    /opt/agentmesh/credentials/credentials.enc；AGENTMESH_AGE_KEY_FILE 默认
    /run/secrets/age_key（CRED §3 路径 A'，compose file 型 secret 落点）。
    age 二进制缺失/解密失败 → 返回 None（内核降级运行，H 域空 + degraded，
    secrets 文件过渡形态继续生效——启动不因此 FATAL：CRED 密文可后置，deployment-ops §5.3）。
    """
    enc = (os.environ.get("AGENTMESH_CREDENTIALS_ENC")
           or os.environ.get("AGENTMESH_CREDENTIALS_FILE")
           or "/opt/agentmesh/credentials/credentials.enc")
    key = os.environ.get("AGENTMESH_AGE_KEY_FILE") or "/run/secrets/age_key"
    manager = CredentialManager(database, encrypted_path=enc, age_key_path=key)
    try:
        manager._ensure_plaintext()
    except Exception as exc:
        print(f"[credential-manager] 凭证通道未接线（降级运行）: {type(exc).__name__}: {exc}",
              flush=True)
        return None
    if roles_cfg:
        manager.set_roles_cfg(roles_cfg)
    return manager
