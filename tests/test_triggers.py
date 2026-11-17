"""test_triggers.py — triggers.py 测试：cron 五字段解析、next_fire、webhook HMAC 与模板展开、
调度线程（错过补偿）、Idempotency-Key 24h 窗口。

覆盖验收面（ask 第 2 条；ICON §7/§1.3；deployment-ops §5.1 triggers 按需建表）。
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from datetime import UTC, datetime, timedelta

from _helpers import cleanup, fresh_db

from app.engine import state, triggers
from app.engine.db import iso_shift, utc_now_iso


def test_parse_cron_valid_and_invalid() -> None:
    fields = triggers.parse_cron("*/5 9-17 * * 1-5")
    assert fields["minute"] == frozenset(range(0, 60, 5))
    assert fields["hour"] == frozenset(range(9, 18))
    assert fields["dow"] == frozenset({1, 2, 3, 4, 5})
    fields2 = triggers.parse_cron("0 9 1,15 * 7")  # dow 7 == 0 (Sunday)
    assert fields2["dom"] == frozenset({1, 15})
    assert fields2["dow"] == frozenset({0})
    for bad in ("0 9 * *", "61 * * * *", "a * * * *", "*/0 * * * *", "0 9 1-0 * *"):
        try:
            triggers.parse_cron(bad)
        except triggers.TriggerError as exc:
            assert exc.code == "INVALID_SCHEDULE"
        else:
            raise AssertionError(f"must reject: {bad!r}")


def test_next_cron_fire() -> None:
    # 每天 09:00 UTC：从 10:00 起下一次是次日 09:00
    after = datetime(2026, 11, 17, 10, 0, tzinfo=UTC)
    tz = triggers.resolve_timezone("UTC")
    nxt = triggers.next_cron_fire("0 9 * * *", after, tz)
    assert nxt.startswith("2026-11-18T09:00:00")
    # 每 15 分钟
    nxt2 = triggers.next_cron_fire("*/15 * * * *", after, tz)
    assert nxt2.startswith("2026-11-17T10:15:00")
    # 每周日 00:00（2026-11-17 是周二 → 下一个周日是 11-22）
    nxt3 = triggers.next_cron_fire("0 0 * * 0", after, tz)
    assert nxt3.startswith("2026-11-22T00:00:00")
    # dom 与 dow 都受限 → OR 语义（每月 1 号或周日）
    nxt4 = triggers.next_cron_fire("0 0 1 * 0", datetime(2026, 11, 17, 1, 0, tzinfo=UTC), tz)
    assert nxt4.startswith("2026-11-22T00:00:00")  # 先到周日 11-22


def test_timezone_resolution() -> None:
    from datetime import timedelta
    utc = triggers.resolve_timezone("UTC")
    assert utc.utcoffset(None) == timedelta(0)  # Windows 无 tzdata 时 UTC 族落 timezone.utc
    assert triggers.resolve_timezone(None, default_tz="UTC").utcoffset(None) == timedelta(0)
    try:
        triggers.resolve_timezone("Not/AZone")
    except triggers.TriggerError as exc:
        assert exc.code == "INVALID_TIMEZONE"
    else:
        raise AssertionError("unknown timezone must be rejected")


def test_create_trigger_cron_and_webhook() -> None:
    database, directory = fresh_db()
    try:
        assert "triggers" not in {r["name"] for r in database.query(
            "SELECT name FROM sqlite_master WHERE type='table'")}  # 未发生 CRUD 前不存在
        cron = triggers.create_trigger(database, trigger_type="cron",
                                       goal_template="每天汇总 HN", schedule="0 9 * * *",
                                       timezone_name="UTC")
        assert "triggers" in {r["name"] for r in database.query(
            "SELECT name FROM sqlite_master WHERE type='table'")}  # 首写前按需建表（deployment-ops §5.1）
        assert cron["type"] == "cron" and cron["schedule"] == "0 9 * * *"
        assert cron["next_fire_at"] and cron["ingest_path"] is None
        assert "secret_once" not in cron or cron["secret_once"] is None
        hook = triggers.create_trigger(database, trigger_type="webhook",
                                       goal_template="处理 webhook")
        assert hook["ingest_path"].startswith("/api/v1/triggers/webhook/whk_")
        assert hook["secret_once"].startswith("whsec_")
        assert hook["next_fire_at"] is None  # webhook 恒 null（ICON §7.1）
        detail = triggers.get_trigger(database, hook["trigger_id"])
        assert detail is not None and detail["recent_fires"] == []
        # secret 本体不出现在详情（只此一次面；键级断言，勿用子串匹配）
        assert "secret_once" not in detail and detail.get("secret") is None
    finally:
        cleanup(database, directory)


def test_create_trigger_errors() -> None:
    database, directory = fresh_db()
    try:
        for kwargs, code in (
            ({"trigger_type": "cron", "goal_template": "x"}, "INVALID_SCHEDULE"),
            ({"trigger_type": "cron", "goal_template": "x", "schedule": "0 9 * *",
              "timezone_name": "UTC"}, "INVALID_SCHEDULE"),
            ({"trigger_type": "cron", "goal_template": "x", "schedule": "0 9 * * *",
              "timezone_name": "Not/AZone"}, "INVALID_TIMEZONE"),
            ({"trigger_type": "webhook", "goal_template": "x", "secret_ref": "llm_gateway_key"},
             "SECRET_REF_NOT_FOUND"),
            ({"trigger_type": "webhook", "goal_template": "x" * 8001}, "TEMPLATE_TOO_LONG"),
            ({"trigger_type": "timer", "goal_template": "x"}, "INVALID_SCHEDULE"),
        ):
            try:
                triggers.create_trigger(database, **kwargs)
            except triggers.TriggerError as exc:
                assert exc.code == code, (kwargs, exc.code)
            else:
                raise AssertionError(f"must reject: {kwargs}")
    finally:
        cleanup(database, directory)


def test_update_and_delete_trigger() -> None:
    database, directory = fresh_db()
    try:
        cron = triggers.create_trigger(database, trigger_type="cron", goal_template="t",
                                       schedule="0 9 * * *", timezone_name="UTC")
        updated = triggers.update_trigger(database, cron["trigger_id"], enabled=False)
        assert updated["enabled"] is False
        # rotate 在 cron 上非法
        try:
            triggers.update_trigger(database, cron["trigger_id"], rotate_secret=True)
        except triggers.TriggerError as exc:
            assert exc.code == "ROTATE_ON_CRON"
        else:
            raise AssertionError("rotate on cron must be rejected")
        hook = triggers.create_trigger(database, trigger_type="webhook", goal_template="t")
        rotated = triggers.update_trigger(database, hook["trigger_id"], rotate_secret=True)
        assert rotated["secret_once"].startswith("whsec_")
        # 旧 secret 立即失效：旧签名校验失败
        old_secret = hook["secret_once"]
        raw = b"{}"
        ts = str(int(time.time()))
        old_sig = "sha256=" + hmac.new(old_secret.encode(), f"{ts}.".encode() + raw,
                                       hashlib.sha256).hexdigest()
        result, code = triggers.ingest_webhook(database, hook["ingest_path"].rsplit("/", 1)[-1],
                                               raw, signature=old_sig, timestamp=ts)
        assert result is None and code == "WEBHOOK_SIGNATURE_INVALID"
        assert triggers.delete_trigger(database, cron["trigger_id"]) is True
        assert triggers.get_trigger(database, cron["trigger_id"]) is None
        assert triggers.delete_trigger(database, cron["trigger_id"]) is False
    finally:
        cleanup(database, directory)


def test_webhook_ingest_hmac_and_template() -> None:
    database, directory = fresh_db()
    try:
        hook = triggers.create_trigger(database, trigger_type="webhook",
                                       goal_template="处理 {{payload.repository.full_name}} 的"
                                                     " {{payload.action}} 事件，issue #{{payload.issue.number}}")
        token = hook["ingest_path"].rsplit("/", 1)[-1]
        secret = hook["secret_once"]
        body = json.dumps({"action": "opened", "repository": {"full_name": "acme/api"},
                           "issue": {"number": 42}}).encode()
        ts = str(int(time.time()))
        sig = "sha256=" + hmac.new(secret.encode(), f"{ts}.".encode() + body,
                                   hashlib.sha256).hexdigest()
        result, code = triggers.ingest_webhook(database, token, body, signature=sig, timestamp=ts)
        assert code is None and result["task_id"]
        task = database.query_one("SELECT * FROM tasks WHERE id = ?", (result["task_id"],))
        assert task["source"] == "webhook"
        assert "acme/api" in task["goal"] and "opened" in task["goal"] and "#42" in task["goal"]
        # trigger_fired 事件（ICON §2）
        fires = database.query("SELECT * FROM events WHERE event_type = 'trigger_fired'")
        assert len(fires) == 1
        # 错误签名 → 401 WEBHOOK_SIGNATURE_INVALID
        _, code_bad = triggers.ingest_webhook(database, token, body,
                                              signature="sha256=" + "0" * 64, timestamp=ts)
        assert code_bad == "WEBHOOK_SIGNATURE_INVALID"
        # 时间戳偏差 >300s → WEBHOOK_TIMESTAMP_SKEW
        _, code_skew = triggers.ingest_webhook(database, token, body, signature=sig,
                                               timestamp=str(int(time.time()) - 3600))
        assert code_skew == "WEBHOOK_TIMESTAMP_SKEW"
        # 停用后 → TRIGGER_DISABLED
        triggers.update_trigger(database, hook["trigger_id"], enabled=False)
        _, code_off = triggers.ingest_webhook(database, token, body, signature=sig, timestamp=ts)
        assert code_off == "TRIGGER_DISABLED"
    finally:
        cleanup(database, directory)


def test_webhook_template_degraded_and_fallback() -> None:
    database, directory = fresh_db()
    try:
        hook = triggers.create_trigger(database, trigger_type="webhook",
                                       goal_template="看 {{payload.missing.path}} 与 {{payload.present}}")
        token = hook["ingest_path"].rsplit("/", 1)[-1]
        body = json.dumps({"present": "值"}).encode()
        ts = str(int(time.time()))
        sig = "sha256=" + hmac.new(hook["secret_once"].encode(), f"{ts}.".encode() + body,
                                   hashlib.sha256).hexdigest()
        result, code = triggers.ingest_webhook(database, token, body, signature=sig, timestamp=ts)
        assert code is None  # 事件源语义：任务照建（ICON §7.6）
        task = database.query_one("SELECT * FROM tasks WHERE id = ?", (result["task_id"],))
        assert "{{payload.missing.path}}" in task["goal"]  # 占位符保留原文字样
        assert "值" in task["goal"]
        fires = database.query("SELECT payload FROM events WHERE event_type = 'trigger_fired'")
        assert json.loads(fires[-1]["payload"])["template_degraded"] is True
        # 无占位符模板 → 整包 JSON 截 4KB
        hook2 = triggers.create_trigger(database, trigger_type="webhook", goal_template="静态目标")
        body2 = json.dumps({"big": "y" * 100}).encode()
        ts2 = str(int(time.time()))
        sig2 = "sha256=" + hmac.new(hook2["secret_once"].encode(), f"{ts2}.".encode() + body2,
                                    hashlib.sha256).hexdigest()
        result2, _ = triggers.ingest_webhook(database,
                                             hook2["ingest_path"].rsplit("/", 1)[-1],
                                             body2, signature=sig2, timestamp=ts2)
        task2 = database.query_one("SELECT * FROM tasks WHERE id = ?", (result2["task_id"],))
        assert '"big"' in task2["goal"]  # 整包 JSON 作为 goal
    finally:
        cleanup(database, directory)


def test_scheduler_fires_and_missed_compensation() -> None:
    database, directory = fresh_db()
    try:
        scheduler = triggers.CronScheduler(database, default_tz="UTC", tick_seconds=60)
        trigger = triggers.create_trigger(database, trigger_type="cron", goal_template="分钟任务",
                                          schedule="* * * * *", timezone_name="UTC")
        now = datetime(2026, 11, 17, 10, 5, tzinfo=UTC)
        # next_fire_at 回拨到 10 分钟前（> 120s 宽限）→ 补跑一次 + trigger_missed
        scheduled = iso_shift(utc_now_iso(), -600)
        database.execute("UPDATE triggers SET next_fire_at = ? WHERE id = ?",
                         (scheduled, trigger["trigger_id"]))
        fired = scheduler.tick(now=now)
        assert len(fired) == 1 and fired[0]["missed"] is True
        task = database.query_one("SELECT * FROM tasks WHERE id = ?", (fired[0]["task_id"],))
        assert task["source"] == "cron"
        missed_events = database.query("SELECT * FROM events WHERE event_type = 'trigger_missed'")
        assert len(missed_events) == 1
        # next_fire_at 已推进 → 同一 tick 不重复触发
        fired2 = scheduler.tick(now=now + timedelta(seconds=10))
        assert fired2 == []
        # 宽限内的迟到（<120s）→ 补跑但不登记 missed
        trigger2 = triggers.create_trigger(database, trigger_type="cron", goal_template="小迟到",
                                           schedule="* * * * *", timezone_name="UTC")
        database.execute("UPDATE triggers SET next_fire_at = ? WHERE id = ?",
                         (iso_shift(utc_now_iso(), -30), trigger2["trigger_id"]))
        fired3 = scheduler.tick(now=datetime.now(UTC))
        assert len(fired3) == 1 and fired3[0]["missed"] is False
        assert len(database.query("SELECT * FROM events WHERE event_type = 'trigger_missed'")) == 1
    finally:
        cleanup(database, directory)


def test_idempotency_window() -> None:
    database, directory = fresh_db()
    try:
        triggers.store_idempotency(database, "k1", {"task_id": "task-1"})
        assert triggers.lookup_idempotency(database, "k1") == {"task_id": "task-1"}
        assert triggers.lookup_idempotency(database, "missing") is None
        # 过期（>24h）→ None
        from app.engine.db import kv_set
        kv_set(database, "idem:k2", {"value": {"task_id": "task-2"},
                                     "stored_at": iso_shift(utc_now_iso(), -25 * 3600)})
        assert triggers.lookup_idempotency(database, "k2") is None
    finally:
        cleanup(database, directory)
