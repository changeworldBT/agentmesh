"""triggers.py — 触发器组件：cron（五字段最小解析）+ webhook 触发器（ICON §7 语义）。

设计文档出处（模块顶部注记，按 ask 要求）：
- sys-arch（ARCH-ROOT-01）§2.4：触发器组件（cron + webhook）；§2.2 拓扑 CRONJOB/WEBHOOK
  两条入口线；§3.2 T1：触发产出 pending 任务；§7.1：每步动作事件化落库。
- interface-contracts（ICON-01）§7：触发器域全部语义——触发即建任务（走 §5.1 同一入口
  语义，source=cron|webhook，goal 由 goal_template 展开）；cron 解析时区基准容器 TZ、
  每触发器 timezone 字段覆盖（IANA 名）；错过补偿：停机期间错过的 cron 触发恢复后
  补跑一次并登记 trigger_missed 事件（payload 含原定时刻），不按倍数补跑不无限追赶；
  next_fire_at 按 schedule+timezone 实时计算，webhook 恒 null；webhook 鉴权
  X-Agentmesh-Signature: sha256=<hex(HMAC-SHA256(secret, "<ts>.<raw_body>"))> +
  X-Agentmesh-Timestamp，偏差 >300s → WEBHOOK_TIMESTAMP_SKEW，签名不符 →
  WEBHOOK_SIGNATURE_INVALID；goal_template 支持 {{payload.<dotted.path>}} 占位，路径
  不存在时任务照建、占位符保留原文字样、trigger_fired 带 template_degraded: true；
  模板不含占位符时 webhook 场景整包 JSON（截 4KB）作为 goal；Idempotency-Key 24h 窗口
  幂等（§1.3）。
- deployment-ops §5.1：triggers 表归触发器组件，首个触发器 CRUD（G1）写入前按需建表；
  §2 env 表：cron 解析基准 = 容器 TZ。
- rules-config §2.2：locale.timezone 为容器时区权威（本模块缺省 TZ 环境变量）。

偏离与取舍（如实声明）：
- webhook body JSON 解析失败按契约返回 400 INVALID_WEBHOOK_BODY（ICON §7.6 错误码表
  逐字，评审修正：此前「事件先落」降级与契约错误码表冲突，已按契约收紧；
  模板占位符缺路径仍照建任务 + template_degraded 事件——§7.6 明文保留）。
- secret_ref 模式依赖凭证管理器（credentials-spec 交付物，age 解密面后续接线）：
  创建时无法核验密文库条目 → 一律 400 SECRET_REF_NOT_FOUND（从严，不假装可核验）；
  generated secret 模式完整可用（HMAC 校验/轮换/删除，密文落 triggers 表——ICON §7.2
  显式边界决策：动态 secret 存 sqlite-data 卷的 triggers 表）。
- 调度线程为 stdlib time 轮询（分钟级对齐 + 可配置 tick），非 asyncio 定时器
  （sys-arch §1.3 运行形态 asyncio 单进程——API/内核主体在 server.py 保持同步实现，
  asyncio 化为部署形态后续项；SQLite 单写者不受影响）。
- cron 解析为五字段最小实现（* , - / 与数字），不支持 @daily 等别名与秒级字段。
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from datetime import UTC, datetime, timedelta, timezone as dt_timezone
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from app.engine.db import Database, emit_event, iso_shift, json_dumps, new_ulid, utc_now_iso

TRIGGER_TABLE_STATEMENTS: tuple[str, ...] = (
    """
    CREATE TABLE IF NOT EXISTS triggers (
      id            TEXT PRIMARY KEY,
      type          TEXT NOT NULL CHECK (type IN ('cron','webhook')),
      schedule      TEXT,
      timezone      TEXT NOT NULL,
      goal_template TEXT NOT NULL,
      enabled       INTEGER NOT NULL DEFAULT 1,
      secret        TEXT,
      ingest_token  TEXT,
      secret_ref    TEXT,
      last_fired_at TEXT,
      next_fire_at  TEXT,
      created_at    TEXT NOT NULL,
      updated_at    TEXT NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_triggers_enabled ON triggers(enabled, type)",
)

INGEST_TOKEN_PREFIX = "whk_"
SECRET_PREFIX = "whsec_"
WEBHOOK_TIMESTAMP_SKEW_S = 300      # ICON §7.6 重放窗口
GOAL_TEMPLATE_MAX = 8000            # ICON §7.2 goal_template ≤8000 字符
WEBHOOK_GOAL_FALLBACK_BYTES = 4096  # ICON §7.2 无占位符时整包 JSON 截 4KB
MISSED_FIRE_GRACE_S = 120           # 原定时刻落后当前时刻超过该值 → 登记 trigger_missed
IDEMPOTENCY_WINDOW_S = 24 * 3600    # ICON §1.3：Idempotency-Key 24h 窗口


class TriggerError(ValueError):
    """触发器参数/状态错误（携带 ICON 错误码）。"""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


# ---------------------------------------------------------------------------
# cron 五字段最小解析（ICON §7.2：非法 → INVALID_SCHEDULE）
# ---------------------------------------------------------------------------

_FIELD_RANGES = {"minute": (0, 59), "hour": (0, 23), "dom": (1, 31),
                 "month": (1, 12), "dow": (0, 7)}
_FIELD_ORDER = ("minute", "hour", "dom", "month", "dow")


def _parse_field(field: str, name: str) -> frozenset[int]:
    """解析单个 cron 字段为取值集合；支持 * , - / 与数字（dow 7 视作 0=Sunday）。"""
    lo, hi = _FIELD_RANGES[name]
    values: set[int] = set()
    for part in field.split(","):
        part = part.strip()
        if not part:
            raise TriggerError("INVALID_SCHEDULE", f"empty field part in {name}: {field!r}")
        step = 1
        body = part
        if "/" in part:
            body, _, step_str = part.partition("/")
            if not step_str.isdigit() or int(step_str) < 1:
                raise TriggerError("INVALID_SCHEDULE", f"bad step in {name}: {part!r}")
            step = int(step_str)
        if body == "*":
            start, end = lo, hi
        elif "-" in body:
            a, _, b = body.partition("-")
            if not (a.isdigit() and b.isdigit()):
                raise TriggerError("INVALID_SCHEDULE", f"bad range in {name}: {part!r}")
            start, end = int(a), int(b)
        elif body.isdigit():
            start = end = int(body)
        else:
            raise TriggerError("INVALID_SCHEDULE", f"bad atom in {name}: {part!r}")
        if not (lo <= start <= hi and lo <= end <= hi and start <= end):
            raise TriggerError("INVALID_SCHEDULE", f"value out of range in {name}: {part!r}")
        values.update(range(start, end + 1, step))
    if name == "dow":
        normalized = {0 if v == 7 else v for v in values}
        return frozenset(normalized)
    return frozenset(values)


def parse_cron(schedule: str) -> dict[str, frozenset[int]]:
    """解析标准五段 cron 表达式 → {minute,hour,dom,month,dow} 取值集合。"""
    fields = str(schedule or "").split()
    if len(fields) != 5:
        raise TriggerError("INVALID_SCHEDULE",
                           f"cron schedule must have exactly 5 fields, got {len(fields)}")
    return dict(zip(_FIELD_ORDER, (_parse_field(f, n) for f, n in zip(fields, _FIELD_ORDER))))


def resolve_timezone(name: str | None, default_tz: str | None = None) -> Any:
    """解析 IANA 时区名（ICON §7.1：缺省用容器 TZ）；非法 → INVALID_TIMEZONE。

    UTC 族键名直接落 datetime.timezone.utc：Windows 无系统 tzdata 时 zoneinfo 不可用
    （目标机 Debian 13 系统自带 tzdata，完整 IANA 面在容器内生效——real-vps-facts）。
    """
    key = (name or default_tz or "UTC").strip()
    if not key:
        key = "UTC"
    if key in ("UTC", "Etc/UTC", "GMT", "Etc/GMT"):
        return dt_timezone.utc
    try:
        return ZoneInfo(key)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise TriggerError("INVALID_TIMEZONE", f"unknown IANA timezone: {key!r}") from exc


def next_cron_fire(schedule: str, after: datetime, tz: Any) -> str:
    """计算 schedule 在 after 之后（>after）的下一次触发时刻（ISO8601 UTC Z 形）。

    dom/dow 均受限时按标准 cron OR 语义（任一命中即当日触发）。
    扫描上限 366 天（ICON §7.1 不无限追赶的同向取舍；扫描不到即无解 → 异常）。
    """
    fields = parse_cron(schedule)
    minutes = fields["minute"]
    hours = fields["hour"]
    doms = fields["dom"]
    months = fields["month"]
    dows = fields["dow"]
    dom_all = doms == frozenset(range(1, 32))
    dow_all = dows == frozenset(range(0, 7))
    local_after = after.astimezone(tz) if after.tzinfo else after.replace(tzinfo=UTC).astimezone(tz)
    candidate = local_after.replace(second=0, microsecond=0) + timedelta(minutes=1)
    for _ in range(366 * 24 * 60):
        dom_match = candidate.day in doms
        dow_match = candidate.isoweekday() % 7 in dows  # isoweekday: Mon=1..Sun=7 → Sun=0
        # 标准 cron：dom 与 dow 都受限 → OR；任一为 * → AND
        if dom_all and dow_all:
            date_match = True
        elif dom_all:
            date_match = dow_match
        elif dow_all:
            date_match = dom_match
        else:
            date_match = dom_match or dow_match
        if (date_match and candidate.month in months
                and candidate.hour in hours and candidate.minute in minutes):
            return candidate.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        candidate += timedelta(minutes=1)
    raise TriggerError("INVALID_SCHEDULE", f"no fire time within 366 days for {schedule!r}")


# ---------------------------------------------------------------------------
# triggers 表 CRUD（ICON §7.2-§7.5 数据面；G1-G5 由 api/server.py 调用）
# ---------------------------------------------------------------------------

def _ensure_triggers_table(database: Database) -> None:
    with database.transaction() as conn:
        for stmt in TRIGGER_TABLE_STATEMENTS:
            conn.execute(stmt)


def _gen_ingest_token() -> str:
    return INGEST_TOKEN_PREFIX + secrets.token_hex(8)


def _gen_secret() -> str:
    return SECRET_PREFIX + secrets.token_urlsafe(24)


def create_trigger(database: Database, *, trigger_type: str, goal_template: str,
                   schedule: str | None = None, timezone_name: str | None = None,
                   enabled: bool = True, secret_ref: str | None = None,
                   default_tz: str | None = None,
                   idempotency_key: str | None = None,
                   credential_store: Any | None = None) -> dict[str, Any]:
    """G1 创建触发器（ICON §7.2）；返回响应形态（created=true 时含 secret_once）。
    secret_ref 模式：凭证管理器接线（app/engine/credentials.py）后核验 key_name 在密文库
    存在（CRED §2.2 引用协议，密文本体不动）；未接线 → SECRET_REF_NOT_FOUND（从严）。
    """
    _ensure_triggers_table(database)
    if secret_ref is not None:
        if credential_store is None or not credential_store.available():
            raise TriggerError("SECRET_REF_NOT_FOUND",
                               "secret_ref requires the credentials manager (not wired)")
        if secret_ref not in credential_store.key_names():
            raise TriggerError("SECRET_REF_NOT_FOUND",
                               f"secret_ref key_name not in credentials store: {secret_ref!r}")
    if not str(goal_template or "").strip():
        raise TriggerError("TEMPLATE_TOO_LONG", "goal_template must be non-empty")
    if len(goal_template) > GOAL_TEMPLATE_MAX:
        raise TriggerError("TEMPLATE_TOO_LONG", f"goal_template exceeds {GOAL_TEMPLATE_MAX} chars")
    if idempotency_key:
        existing = lookup_idempotency(database, f"trigger:{idempotency_key}")
        if existing is not None:
            return {**existing, "created": False}
    tz = resolve_timezone(timezone_name, default_tz)
    tz_name_str = str(timezone_name or default_tz or "UTC").strip() or "UTC"
    now_ts = utc_now_iso()
    trigger_id = "trg-" + new_ulid()
    row: dict[str, Any] = {
        "id": trigger_id, "type": str(trigger_type), "schedule": None,
        "timezone": tz_name_str, "goal_template": goal_template,
        "enabled": 1 if enabled else 0, "secret": None, "ingest_token": None,
        "secret_ref": secret_ref, "last_fired_at": None, "next_fire_at": None,
        "created_at": now_ts, "updated_at": now_ts,
    }
    secret_once: str | None = None
    if trigger_type == "cron":
        if not schedule:
            raise TriggerError("INVALID_SCHEDULE", "cron trigger requires schedule")
        parse_cron(schedule)  # 非法即抛 INVALID_SCHEDULE
        row["schedule"] = schedule
        row["next_fire_at"] = next_cron_fire(schedule, datetime.now(UTC), tz)
    elif trigger_type == "webhook":
        if secret_ref is None:
            # 动态 secret 模式：一次性生成并落库（ICON §7.2 显式边界决策）
            secret_once = _gen_secret()
            row["secret"] = secret_once
        # secret_ref 模式：密文本体留在密文库，triggers 表只存引用（CRED §2.2），
        # 响应不带 secret_once（ICON §7.3：secret_mode=ref 时 secret_once 为 null）
        row["ingest_token"] = _gen_ingest_token()
    else:
        raise TriggerError("INVALID_SCHEDULE", f"type must be cron/webhook, got {trigger_type!r}")
    with database.transaction() as conn:
        conn.execute(
            "INSERT INTO triggers (id, type, schedule, timezone, goal_template, enabled,"
            " secret, ingest_token, secret_ref, last_fired_at, next_fire_at,"
            " created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (row["id"], row["type"], row["schedule"], row["timezone"], row["goal_template"],
             row["enabled"], row["secret"], row["ingest_token"], row["secret_ref"],
             row["last_fired_at"], row["next_fire_at"], row["created_at"], row["updated_at"]),
        )
        emit_event(conn, component="trigger", event_type="trigger_created",
                   payload={"trigger_id": trigger_id, "type": trigger_type,
                            "schedule": schedule, "timezone": tz_name_str})
    if idempotency_key:
        store_idempotency(database, f"trigger:{idempotency_key}", {"trigger_id": trigger_id})
    return {**_public_trigger(row), "secret_once": secret_once, "created": True}


def _public_trigger(row: dict[str, Any]) -> dict[str, Any]:
    """ICON §7.3 响应形态（不含 secret 本体）。"""
    is_cron = row["type"] == "cron"
    return {
        "trigger_id": row["id"],
        "type": row["type"],
        "ingest_path": (f"/api/v1/triggers/webhook/{row['ingest_token']}"
                        if not is_cron and row.get("ingest_token") else None),
        "secret_mode": (None if is_cron else ("ref" if row.get("secret_ref") else "generated")),
        "secret_ref": row.get("secret_ref"),
        "schedule": row.get("schedule"),
        "timezone": row["timezone"],
        "goal_template": row["goal_template"],
        "enabled": bool(row["enabled"]),
        "next_fire_at": row.get("next_fire_at") if is_cron else None,
        "last_fired_at": row.get("last_fired_at"),
        "last_task_id": None,
        "recent_fires": [],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def _row_to_dict(row: Any) -> dict[str, Any]:
    return {k: row[k] for k in row.keys()}


def get_trigger(database: Database, trigger_id: str) -> dict[str, Any] | None:
    """G3 详情（含 recent_fires ≤10 条，溯源 trigger_fired 事件）。"""
    row = database.query_one("SELECT * FROM triggers WHERE id = ?", (trigger_id,))
    if row is None:
        return None
    data = _public_trigger(_row_to_dict(row))
    fires = database.query(
        "SELECT ts, payload FROM events WHERE event_type = 'trigger_fired' AND payload LIKE ?"
        " ORDER BY ts DESC LIMIT 10",
        (f'%{trigger_id}%',),
    )
    recent = []
    for fire in fires:
        payload = json.loads(str(fire["payload"]))
        recent.append({"fired_at": fire["ts"], "task_id": payload.get("task_id"),
                       "task_status": payload.get("task_status")})
    data["recent_fires"] = recent
    data["last_task_id"] = recent[0]["task_id"] if recent else None
    return data


def list_triggers(database: Database) -> list[dict[str, Any]]:
    rows = database.query("SELECT * FROM triggers ORDER BY created_at DESC")
    return [_public_trigger(_row_to_dict(r)) for r in rows]


def update_trigger(database: Database, trigger_id: str, *, enabled: bool | None = None,
                   goal_template: str | None = None, schedule: str | None = None,
                   rotate_secret: bool = False,
                   default_tz: str | None = None) -> dict[str, Any]:
    """G4 修改/启停/轮换 secret（ICON §7.4）。rotate 仅 webhook 合法；返回更新后对象
    （rotate 时响应附 secret_once，只此一次）。"""
    row = database.query_one("SELECT * FROM triggers WHERE id = ?", (trigger_id,))
    if row is None:
        return {}
    data = _row_to_dict(row)
    updates: dict[str, Any] = {}
    secret_once: str | None = None
    if rotate_secret:
        if data["type"] != "webhook":
            raise TriggerError("ROTATE_ON_CRON", "rotate_secret is webhook-only")
        if data.get("secret_ref"):
            raise TriggerError("SECRET_REF_IMMUTABLE",
                               "secret_ref rotation goes through the credentials store (CRED §9.1)")
        secret_once = _gen_secret()
        updates["secret"] = secret_once  # 旧 secret 立即失效（ICON §7.4）
    if enabled is not None:
        updates["enabled"] = 1 if enabled else 0
    if goal_template is not None:
        if len(goal_template) > GOAL_TEMPLATE_MAX:
            raise TriggerError("TEMPLATE_TOO_LONG", f"goal_template exceeds {GOAL_TEMPLATE_MAX} chars")
        updates["goal_template"] = goal_template
    if schedule is not None and data["type"] == "cron":
        tz = resolve_timezone(data["timezone"], default_tz)
        parse_cron(schedule)
        updates["schedule"] = schedule
        updates["next_fire_at"] = next_cron_fire(schedule, datetime.now(UTC), tz)
    if updates:
        sets = ", ".join(f"{k} = ?" for k in updates)
        with database.transaction() as conn:
            conn.execute(f"UPDATE triggers SET {sets}, updated_at = ? WHERE id = ?",
                         (*updates.values(), utc_now_iso(), trigger_id))
            emit_event(conn, component="trigger", event_type="trigger_updated",
                       payload={"trigger_id": trigger_id, "fields": sorted(updates),
                                "rotated": rotate_secret})
    refreshed = database.query_one("SELECT * FROM triggers WHERE id = ?", (trigger_id,))
    result = _public_trigger(_row_to_dict(refreshed)) if refreshed is not None else {}
    if secret_once is not None:
        result["secret_once"] = secret_once
    return result


def delete_trigger(database: Database, trigger_id: str) -> bool:
    """G5 删除（204 语义；历史任务与触发器解耦）。"""
    with database.transaction() as conn:
        cur = conn.execute("DELETE FROM triggers WHERE id = ?", (trigger_id,))
        deleted = cur.rowcount > 0
        if deleted:
            emit_event(conn, component="trigger", event_type="trigger_deleted",
                       payload={"trigger_id": trigger_id})
    return deleted


# ---------------------------------------------------------------------------
# webhook 入口（G6 数据面：HMAC 校验 + 模板展开 + 建任务）
# ---------------------------------------------------------------------------

def ingest_webhook(database: Database, token: str, raw_body: bytes, *,
                   signature: str | None, timestamp: str | None,
                   idempotency_key: str | None = None,
                   credential_store: Any | None = None,
                   now: datetime | None = None) -> tuple[dict[str, Any] | None, str | None]:
    """ICON §7.6：校验 HMAC → 展开模板 → 建 pending 任务（source=webhook）。

    返回 (响应 dict, 错误码)；响应 dict 非空表示 202 可返回，错误码非 None 表示拒绝。
    """
    _ensure_triggers_table(database)
    if raw_body and len(raw_body) > 256 * 1024:
        return None, "PAYLOAD_TOO_LARGE"
    row = database.query_one("SELECT * FROM triggers WHERE ingest_token = ?", (token,))
    if row is None:
        return None, "TRIGGER_NOT_FOUND"
    data = _row_to_dict(row)
    if not data["enabled"]:
        return None, "TRIGGER_DISABLED"
    # HMAC 校验（ICON §7.6：比对失败不区分细节给调用方）
    secret = _resolve_secret(data, credential_store)
    if secret is None:
        return None, "KERNEL_NOT_READY"  # secret_ref 模式且凭证通道未接线
    if not timestamp or not signature:
        return None, "WEBHOOK_SIGNATURE_INVALID"
    try:
        ts_int = int(timestamp)
    except ValueError:
        return None, "WEBHOOK_SIGNATURE_INVALID"
    now_dt = now or datetime.now(UTC)
    if abs(now_dt.timestamp() - ts_int) > WEBHOOK_TIMESTAMP_SKEW_S:
        return None, "WEBHOOK_TIMESTAMP_SKEW"
    expected = hmac.new(secret.encode("utf-8"), f"{ts_int}.".encode("utf-8") + raw_body,
                        hashlib.sha256).hexdigest()
    provided = signature.removeprefix("sha256=").strip()
    if not hmac.compare_digest(expected, provided):
        return None, "WEBHOOK_SIGNATURE_INVALID"
    # 24h 幂等（ICON §1.3：同键返回既有任务，HTTP 200 而非 202——由调用方区分）
    scope = f"webhook:{data['id']}"
    if idempotency_key:
        existing = lookup_idempotency(database, f"{scope}:{idempotency_key}")
        if existing is not None:
            task_row = database.query_one("SELECT * FROM tasks WHERE id = ?",
                                          (existing["task_id"],))
            replay = {
                "task_id": existing["task_id"],
                "status": task_row["status"] if task_row else "pending",
                "correlation_id": task_row["correlation_id"] if task_row else "",
                "source": "webhook",
                "trigger_id": data["id"],
                "created_at": task_row["created_at"] if task_row else utc_now_iso(),
                "replayed": True,
            }
            return replay, None
    # ICON §7.6 错误码表：JSON 解析失败 → 400 INVALID_WEBHOOK_BODY（非空 body 才判）。
    # 占位符路径缺失不在此列——契约明文「模板缺键任务照建」（事件源语义保留于此）。
    body_invalid = False
    if raw_body:
        try:
            payload_obj = json.loads(raw_body.decode("utf-8"))
            if not isinstance(payload_obj, dict):
                payload_obj = {}
        except ValueError:
            return None, "INVALID_WEBHOOK_BODY"
    goal, degraded = expand_template(str(data["goal_template"]), payload_obj)
    from app.engine import state  # 局部导入（与 server 共用状态机模块）
    task_id = state.create_task(database, title=goal[:80], goal=goal,
                                source="webhook", correlation_id=None)
    with database.transaction() as conn:
        emit_event(conn, task_id=task_id, component="trigger", event_type="trigger_fired",
                   payload={"trigger_id": data["id"], "type": "webhook",
                            "goal_summary": goal[:200],
                            "template_degraded": degraded or body_invalid,
                            "body_invalid": body_invalid})
        conn.execute("UPDATE triggers SET last_fired_at = ?, updated_at = ? WHERE id = ?",
                     (utc_now_iso(), utc_now_iso(), data["id"]))
    if idempotency_key:
        store_idempotency(database, f"{scope}:{idempotency_key}",
                          {"task_id": task_id, "trigger_id": data["id"]})
    task_row = database.query_one("SELECT * FROM tasks WHERE id = ?", (task_id,))
    response = {
        "task_id": task_id,
        "status": task_row["status"] if task_row else "pending",
        "correlation_id": task_row["correlation_id"] if task_row else "",
        "source": "webhook",
        "trigger_id": data["id"],
        "created_at": task_row["created_at"] if task_row else utc_now_iso(),
    }
    response["replayed"] = False  # 正常路径非重放（幂等重放分支带 replayed=True）
    return response, None


def _resolve_secret(data: dict[str, Any], credential_store: Any | None = None) -> str | None:
    """generated 模式取 triggers 表内动态 secret（ICON §7.2 显式边界决策：存 sqlite-data 卷）；
    secret_ref 模式经凭证管理器按 key_name 解析密文库条目 value（CRED §2.2 引用协议，
    短寿命注入语义：secret 只进 HMAC 计算瞬时窗口）；通道未接线/条目缺失 → None
    （KERNEL_NOT_READY / 失效）。"""
    if data.get("secret_ref"):
        if credential_store is None or not credential_store.available():
            return None
        pair = credential_store.entry(str(data["secret_ref"]))
        if pair is None:
            return None
        return str(pair[1].get("value") or "") or None
    secret = data.get("secret")
    return str(secret) if secret else None


def expand_template(template: str, payload: dict[str, Any]) -> tuple[str, bool]:
    """展开 {{payload.<dotted.path>}}；路径不存在 → 占位符保留原文字样 + degraded=True
    （ICON §7.6：事件源语义，事件先落，解释尽力）。无占位符 → 整包 JSON 截 4KB。"""
    import re
    pattern = re.compile(r"\{\{payload\.([A-Za-z0-9_.]+)\}\}")
    degraded = False

    def repl(match: re.Match[str]) -> str:
        nonlocal degraded
        node: Any = payload
        for part in match.group(1).split("."):
            if isinstance(node, dict) and part in node:
                node = node[part]
            else:
                degraded = True
                return match.group(0)  # 保留原文字样
        if isinstance(node, (dict, list)):
            return json.dumps(node, ensure_ascii=False)
        return str(node)

    expanded = pattern.sub(repl, template)
    if "{{payload." not in template:  # 模板不含占位符 → 整包 JSON 截 4KB（ICON §7.2）
        expanded = f"{template}\n{json.dumps(payload, ensure_ascii=False)[:WEBHOOK_GOAL_FALLBACK_BYTES]}"
    return expanded, degraded


# ---------------------------------------------------------------------------
# cron 调度线程（ICON §7.1：内核进程内 cron，错过补偿补跑一次）
# ---------------------------------------------------------------------------

class CronScheduler:
    """进程内 cron 调度线程：每 tick 核对到期触发器 → 建任务（source=cron）→
    原定时刻落后超过 MISSED_FIRE_GRACE_S 时先登记 trigger_missed（补跑一次不追赶）。"""

    def __init__(self, database: Database, *, default_tz: str | None = None,
                 tick_seconds: float = 5.0) -> None:
        self.database = database
        self.default_tz = default_tz or os.environ.get("TZ") or "UTC"
        self.tick_seconds = tick_seconds
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        _ensure_triggers_table(database)

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="cron-scheduler", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)

    def _run(self) -> None:
        while not self._stop.wait(self.tick_seconds):
            try:
                self.tick()
            except Exception as exc:  # 调度循环不因单次异常死亡
                print(f"[cron-scheduler] tick error: {type(exc).__name__}: {exc}", flush=True)

    def tick(self, now: datetime | None = None) -> list[dict[str, Any]]:
        """单次调度核对（可测试直调）；返回本次触发的任务摘要。"""
        now_dt = now or datetime.now(UTC)
        now_iso = now_dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        fired: list[dict[str, Any]] = []
        rows = self.database.query(
            "SELECT * FROM triggers WHERE type = 'cron' AND enabled = 1 AND next_fire_at IS NOT NULL"
            " AND next_fire_at <= ?", (now_iso,))
        for row in rows:
            data = _row_to_dict(row)
            scheduled = str(data["next_fire_at"])
            from app.engine import state
            task_id = state.create_task(self.database, title=data["goal_template"][:80],
                                        goal=data["goal_template"], source="cron",
                                        correlation_id=None, now=now_iso)
            missed = iso_shift(scheduled, MISSED_FIRE_GRACE_S) < now_iso
            with self.database.transaction() as conn:
                if missed:
                    emit_event(conn, task_id=task_id, component="trigger",
                               event_type="trigger_missed",
                               payload={"trigger_id": data["id"],
                                        "scheduled_at": scheduled,
                                        "note": "停机错过，恢复后补跑一次，不按倍数追赶（ICON §7.1）"})
                emit_event(conn, task_id=task_id, component="trigger",
                           event_type="trigger_fired",
                           payload={"trigger_id": data["id"], "type": "cron",
                                    "goal_summary": data["goal_template"][:200],
                                    "task_id": task_id,
                                    "scheduled_at": scheduled, "missed": missed})
                tz = resolve_timezone(data["timezone"], self.default_tz)
                next_fire = next_cron_fire(str(data["schedule"]), now_dt, tz)
                conn.execute(
                    "UPDATE triggers SET last_fired_at = ?, next_fire_at = ?, updated_at = ?"
                    " WHERE id = ?",
                    (now_iso, next_fire, now_iso, data["id"]))
            fired.append({"trigger_id": data["id"], "task_id": task_id,
                          "scheduled_at": scheduled, "missed": missed})
        return fired


# ---------------------------------------------------------------------------
# Idempotency-Key 存储（ICON §1.3：24h 窗口；复用 rules_kv JSON 键值面）
# ---------------------------------------------------------------------------

def store_idempotency(database: Database, key: str, value: dict[str, Any]) -> None:
    from app.engine.db import kv_set
    kv_set(database, f"idem:{key}", {"value": value, "stored_at": utc_now_iso()})


def lookup_idempotency(database: Database, key: str) -> dict[str, Any] | None:
    from app.engine.db import kv_get
    wrapped = kv_get(database, f"idem:{key}")
    if not wrapped:
        return None
    stored_at = str(wrapped.get("stored_at") or "")
    if iso_shift(stored_at, IDEMPOTENCY_WINDOW_S) < utc_now_iso():
        return None  # 窗口过期
    return dict(wrapped.get("value") or {})


def time_source() -> float:
    """暴露 time.time 便于测试替身（不直接使用）。"""
    return time.time()
