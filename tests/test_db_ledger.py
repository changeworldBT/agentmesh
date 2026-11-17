"""test_db_ledger.py — db.py / state.py / ledger.py 内核 MVP 测试（纯 stdlib，由 run_all.py 顺序执行）。

覆盖对应设计文档验收面（每条断言注明出处）：
- WAL/PRAGMA/表集合/FTS5 触发器同步（memory-design §1.3 实测口径、§2.1/§3.1、sys-arch §10.3 首验 3）
- 签名规范化与文档实算指纹 27eab67e62892fc8（memory-design §2.2）
- write_guard 先判拒后脱敏（memory-design §8.1 e2e 修正点）
- ledger_write 单一入口：脱敏/截断首 4000/签名/事件（memory-design §2.3/§2.4/§6.3、sys-arch §7.1）
- FTS5 检索模板：连字符 token 双引号、前缀星号在引号外（memory-design §1.3/§6.1）+ LIKE 降级（§1.4）
- 沉淀全链路：滑窗 ≥2 门槛、回放校验先红（重归纳 1 次）、去重合并、occurrences 累计、
  待确认位 candidate+reviewed_by NULL、白名单两道闸（memory-design §5/§5.1/§5.3/§3.2）
- 规则状态机：批准/废止必填理由/废止可逆（memory-design §3.2/§4 末行）
- 状态机：T1–T10 守卫、T5 子任务终态收敛检查、转移原子性（task_transitions+事件同事务）、
  task_transitions 按需建表时机、T9 设计缺口如实保留（sys-arch §3.2/§3.3、deployment-ops §5.1）
- 超时兜底：T1/T2/T5/T6/T8 扫描与兜底动作、T4 审批超时 skip、动作落事件可 replay
  （sys-arch §3.2 超时列/§3.3/§5.3）
- rules_kv 读写、events 载荷 64KB 截断（sys-arch §7.2）、recovery_view（sys-arch §3.3 崩溃恢复）
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

IMPL_ROOT = Path(__file__).resolve().parent.parent
if str(IMPL_ROOT) not in sys.path:
    sys.path.insert(0, str(IMPL_ROOT))

from app.engine import db as dbmod
from app.engine import ledger, state
from app.engine.db import Database, iso_shift, json_dumps
from app.engine.state import InvalidTransitionError, SubtaskStatus, TaskStatus


# ---------------------------------------------------------------------------
# 辅助
# ---------------------------------------------------------------------------

def _fresh_db(tmp: Path, *, fts: str = "auto", name: str = "agentmesh.db",
              fallback_dir: str | Path | None = None) -> Database:
    database = Database(tmp / name, fts=fts, fallback_dir=fallback_dir)
    database.connect()
    return database


def _tmpdir() -> Path:
    return Path(tempfile.mkdtemp(prefix="agentmesh-mvp-test-"))


def _backdate(database: Database, table: str, row_id: str, seconds: float,
              *, now: str | None = None) -> None:
    """把状态进入时刻回拨 seconds 秒（超时扫描测试用）。"""
    base = now or dbmod.utc_now_iso()
    database.execute(
        f"UPDATE {table} SET status_changed_at = ? WHERE id = ?",
        (iso_shift(base, -seconds), row_id),
    )


def _task_status(database: Database, task_id: str) -> str:
    return str(database.query_one("SELECT status FROM tasks WHERE id = ?", (task_id,))["status"])


def _subtask_status(database: Database, subtask_id: str) -> str:
    return str(database.query_one("SELECT status FROM subtasks WHERE id = ?", (subtask_id,))["status"])


def _task_detail(database: Database, task_id: str) -> dict | None:
    row = database.query_one("SELECT status_detail FROM tasks WHERE id = ?", (task_id,))
    return json.loads(row["status_detail"]) if row["status_detail"] else None


def _events(database: Database, event_type: str, task_id: str | None = None) -> list:
    if task_id is None:
        return database.query("SELECT * FROM events WHERE event_type = ? ORDER BY ts, event_id", (event_type,))
    return database.query(
        "SELECT * FROM events WHERE event_type = ? AND task_id = ? ORDER BY ts, event_id",
        (event_type, task_id),
    )


def _table_names(database: Database) -> set[str]:
    return {
        str(r["name"])
        for r in database.query("SELECT name FROM sqlite_master WHERE type IN ('table','view')")
    }


def _two_same_signature_errors(database: Database, task_id: str) -> tuple[int, int]:
    """同一签名两条错误（URL 不同、归一化后同指纹）——「同签名重复犯」的等价类。"""
    e1 = ledger.ledger_write(
        database, "TypeError", "http_client",
        {"url": "https://a.example.com/v1", "retry": "3"},
        "TypeError timeout calling a.example.com", task_id, "worker:researcher",
    )
    e2 = ledger.ledger_write(
        database, "TypeError", "http_client",
        {"url": "https://b.example.org/v2", "retry": "3"},
        "TypeError timeout calling b.example.org", task_id, "worker:researcher",
    )
    return e1, e2


# ---------------------------------------------------------------------------
# db.py：连接管理、PRAGMA、表集合
# ---------------------------------------------------------------------------

def test_wal_pragmas_and_files() -> None:
    tmp = _tmpdir()
    database = _fresh_db(tmp)
    try:
        # sys-arch §10.3 首验 3 / memory-design §10.2：journal_mode=wal
        assert database.journal_mode == "wal", database.journal_mode
        assert database.conn.execute("PRAGMA busy_timeout").fetchone()[0] == 5000  # §8.2
        assert database.conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        assert database.conn.execute("PRAGMA synchronous").fetchone()[0] == 1  # NORMAL
        tid = state.create_task(database, title="探针", goal="验证 WAL")
        files = os.listdir(tmp)
        assert "agentmesh.db-wal" in files, files   # memory-design §1.3 实测 2
        assert "agentmesh.db-shm" in files, files
        row = database.query_one("SELECT value FROM schema_meta WHERE key = 'schema_version'")
        assert row["value"] == "2"                  # v2：approvals.decision CHECK 扩容（db.py 迁移注记）
        assert _task_status(database, tid) == "pending"
    finally:
        database.close()
        shutil.rmtree(tmp, ignore_errors=True)


def test_schema_tables_and_fts_meta() -> None:
    tmp = _tmpdir()
    database = _fresh_db(tmp)
    try:
        names = _table_names(database)
        expected = {
            "tasks", "groups", "subtasks", "events", "error_ledger", "prevention_rules",
            "approvals", "rules_kv", "error_ledger_fts", "prevention_rules_fts", "schema_meta",
        }
        assert expected <= names, expected - names
        # deployment-ops §5.1：task_transitions 由状态机模块按需建表，首移前不存在
        assert "task_transitions" not in names
        assert database.fts_available is True
        assert database.query_one("SELECT value FROM schema_meta WHERE key = 'fts_mode'")["value"] == "fts5"
    finally:
        database.close()
        shutil.rmtree(tmp, ignore_errors=True)


def test_rules_kv_roundtrip() -> None:
    tmp = _tmpdir()
    database = _fresh_db(tmp)
    try:
        dbmod.kv_set(database, "prevention_auto_activate_whitelist", ["timeout", "dry-run-first"])
        assert dbmod.kv_get(database, "prevention_auto_activate_whitelist") == ["timeout", "dry-run-first"]
        dbmod.kv_set(database, "prevention_auto_activate_whitelist", ["timeout"])  # upsert 覆盖
        assert dbmod.kv_get(database, "prevention_auto_activate_whitelist") == ["timeout"]
        assert dbmod.kv_get(database, "missing_key", "default") == "default"
        row = database.query_one("SELECT updated_at FROM rules_kv WHERE key = 'missing_key'")
        assert row is None
    finally:
        database.close()
        shutil.rmtree(tmp, ignore_errors=True)


def test_events_payload_truncation_64kb() -> None:
    tmp = _tmpdir()
    database = _fresh_db(tmp)
    try:
        tid = state.create_task(database, title="载荷", goal="验证截断")
        with database.transaction() as conn:
            eid = dbmod.emit_event(conn, task_id=tid, component="test",
                                   event_type="big_payload", payload={"blob": "y" * 70000})
        stored = json.loads(database.query_one("SELECT payload FROM events WHERE event_id = ?", (eid,))["payload"])
        assert stored["truncated"] is True                       # sys-arch §7.2：64KB 截断存引用
        assert stored["size_chars"] > dbmod.PAYLOAD_MAX_CHARS
        small = _events(database, "task_created", tid)
        assert json.loads(small[0]["payload"])["title"] == "载荷"  # 正常载荷不截断
    finally:
        database.close()
        shutil.rmtree(tmp, ignore_errors=True)


# ---------------------------------------------------------------------------
# ledger.py：签名规范化 / write_guard / ledger_write
# ---------------------------------------------------------------------------

def test_signature_normalization_doc_example() -> None:
    # memory-design §2.2 示例与实算指纹（27eab67e62892fc8，16 hex）
    readable, digest = ledger.make_signature(
        "TypeError", "http_client", {"url": "https://api.a.com/v1", "retry": "3"}
    )
    assert readable == "TypeError @ http_client [retry=<N>,url=<URL>]"
    assert digest == "27eab67e62892fc8"
    # 值归一化规则（§2.2 第 3 步，按序匹配）
    assert ledger.normalize_param("https://api.example.com/x?y=1") == "<URL>"
    assert ledger.normalize_param("/var/log/agentmesh/app.log") == "<PATH>"
    assert ledger.normalize_param("~/data/kb/note.md") == "<PATH>"
    assert ledger.normalize_param("550e8400-e29b-41d4-a716-446655440000") == "<UUID>"
    assert ledger.normalize_param("42") == "<N>"
    assert ledger.normalize_param("42.5") == "<N>"
    assert ledger.normalize_param("sk-abcdef1234567890abcd") == "<SECRET>"
    assert ledger.normalize_param("AKIAABCDEFGHIJKLMNOP") == "<SECRET>"
    assert ledger.normalize_param("plain value") == "plain value"
    assert ledger.normalize_param("x" * 100) == "x" * 64  # 其余截 64 字符


def test_write_guard_reject_before_redact() -> None:
    # 整字段即凭证 → 拒绝写入（ValueError），且拒绝分支在脱敏之前可达（§8.1 e2e 修正点）
    for whole in ("sk-" + "a" * 20, "AKIA" + "B" * 20, "AGE-SECRET-KEY-" + "A1B2" * 12):
        try:
            ledger.write_guard(whole)
        except ValueError:
            pass
        else:
            raise AssertionError(f"whole-field credential must be rejected: {whole[:20]}...")
    # 内嵌凭证 → 替换式脱敏
    out = ledger.write_guard("token expired: sk-" + "b" * 20 + " and password=hunter2 in body")
    assert "<REDACTED:api_key>" in out and "b" * 20 not in out
    assert "password=<REDACTED>" in out and "hunter2" not in out
    out2 = ledger.write_guard("leaked AGE-SECRET-KEY-" + "A1B2" * 12)
    assert "<REDACTED:age_key>" in out2 and "AGE-SECRET-KEY-A1B2" not in out2
    out3 = ledger.write_guard("call with Bearer abcdefghijklmn123456 header")
    assert "<REDACTED:bearer>" in out3
    # 普通文本原样通过
    assert ledger.write_guard("plain message without secrets") == "plain message without secrets"


def test_ledger_write_single_entry() -> None:
    tmp = _tmpdir()
    database = _fresh_db(tmp)
    try:
        tid = state.create_task(database, title="账本", goal="单一入口")
        raw = "HTTP 429 from gateway; " + "x" * 5000
        entry = ledger.ledger_write(
            database, "HTTP_429", "http_client",
            {"url": "https://api.a.com/v1", "retry": "3"}, raw, tid,
            "worker:researcher", root_cause="upstream saturated", fix_applied="backoff 30s",
        )
        row = database.query_one("SELECT * FROM error_ledger WHERE id = ?", (entry,))
        assert row["raw_error"] == ("HTTP 429 from gateway; " + "x" * 5000)[:4000]  # §2.3 截首 4000
        assert row["error_signature"] == "HTTP_429 @ http_client [retry=<N>,url=<URL>]"
        # 指纹与 make_signature 一致（文档实算指纹 27eab67e62892fc8 属 TypeError 签名，
        # 已在 test_signature_normalization_doc_example 钉死）
        assert row["signature_hash"] == ledger.make_signature(
            "HTTP_429", "http_client", {"url": "https://api.a.com/v1", "retry": "3"}
        )[1]
        assert row["task_id"] == tid and row["role"] == "worker:researcher"
        assert row["root_cause"] == "upstream saturated" and row["fix_applied"] == "backoff 30s"
        events = _events(database, "error_registered", tid)
        assert len(events) == 1 and json.loads(events[0]["payload"])["entry_id"] == entry  # sys-arch §7.1
        # 内嵌凭证落库前脱敏（§8.1）
        entry2 = ledger.ledger_write(
            database, "ValueError", "mailer", {}, "send failed with sk-CDEFGHIJKLMNOPqrstuv token",
            tid, "worker:mailer",
        )
        row2 = database.query_one("SELECT raw_error FROM error_ledger WHERE id = ?", (entry2,))
        assert "sk-CDEFGHIJKLMNOPqrstuv" not in row2["raw_error"]
        assert "<REDACTED:api_key>" in row2["raw_error"]
        # 整字段凭证 → 拒绝写入且不落库（§8.1）
        before = database.query_one("SELECT COUNT(*) AS n FROM error_ledger")["n"]
        try:
            ledger.ledger_write(database, "ValueError", "vault", {}, "sk-" + "z" * 24, tid, "worker")
        except ValueError:
            pass
        else:
            raise AssertionError("whole-field credential must be rejected")
        after = database.query_one("SELECT COUNT(*) AS n FROM error_ledger")["n"]
        assert after == before
    finally:
        database.close()
        shutil.rmtree(tmp, ignore_errors=True)


# ---------------------------------------------------------------------------
# ledger.py：FTS5 检索（含实测教训口径）与 LIKE 降级
# ---------------------------------------------------------------------------

def test_fts_search_errors_and_trigger_sync() -> None:
    tmp = _tmpdir()
    database = _fresh_db(tmp)
    try:
        tid = state.create_task(database, title="检索", goal="FTS5")
        e1 = ledger.ledger_write(
            database, "ASAN", "requestspy", {},
            "AddressSanitizer heap-buffer-overflow in module requestspy param url=<URL_PATTERN>",
            tid, "worker",
        )
        e2 = ledger.ledger_write(
            database, "TypeError", "http_client", {"url": "https://api.example.com", "retry": "3"},
            "TypeError timeout in module http_client param url=https://api.example.com retry=3",
            tid, "worker",
        )
        # 连字符 token 必须双引号短语才能命中（memory-design §1.3 实测 1）
        hits = ledger.search_errors(database, ["heap-buffer-overflow", "requestspy"])
        assert [h["id"] for h in hits] == [e1]
        hits2 = ledger.search_errors(database, ["timeout", "http_client"])
        assert [h["id"] for h in hits2] == [e2]
        # 前缀匹配：星号在引号外（§6.1 实测口径）
        hits3 = ledger.search_errors(database, ["timeou*"])
        assert [h["id"] for h in hits3] == [e2]
        assert ledger.search_errors(database, []) == []  # 空 token → 空查询 → 空结果
        # UPDATE 触发器同步（trg_ledger_au）
        database.execute("UPDATE error_ledger SET root_cause = ? WHERE id = ?",
                         ("kubernetes pod evicted", e2))
        hits4 = ledger.search_errors(database, ["evicted"])
        assert [h["id"] for h in hits4] == [e2]
        # DELETE 触发器同步（trg_ledger_ad）
        database.execute("DELETE FROM error_ledger WHERE id = ?", (e1,))
        assert ledger.search_errors(database, ["heap-buffer-overflow", "requestspy"]) == []
    finally:
        database.close()
        shutil.rmtree(tmp, ignore_errors=True)


def test_search_rules_active_only_and_task_types() -> None:
    tmp = _tmpdir()
    database = _fresh_db(tmp)
    try:
        # candidate 不参与检索注入（memory-design §3.2）
        with database.transaction() as conn:
            conn.execute(
                "INSERT INTO prevention_rules (rule_text, match_keywords, task_types, status,"
                " source_error_ids, occurrences, risk_level)"
                " VALUES ('对外 HTTP 调用必须显式设置 connect/read 超时，且重试次数 ≤ 2',"
                " 'http timeout retry', '*', 'candidate', '[]', 2, 'high')"
            )
        rule_a = int(database.query_one("SELECT id FROM prevention_rules")["id"])
        assert ledger.search_rules(database, ["http", "timeout"], task_type="web_research") == []
        ledger.review_rule(database, rule_a, "alice")
        hits = ledger.search_rules(database, ["http", "timeout"], task_type="image_gen")
        assert [h["id"] for h in hits] == [rule_a]  # task_types='*' 全适用
        assert hits[0]["occurrences"] == 2
        # task_types 过滤（§6.1 SQL：task_types = '*' OR LIKE）
        with database.transaction() as conn:
            conn.execute(
                "INSERT INTO prevention_rules (rule_text, match_keywords, task_types, status,"
                " source_error_ids, occurrences, risk_level)"
                " VALUES ('HTTP 调用超时上限 10 秒', 'http timeout', 'web_research', 'candidate', '[]', 1, 'low')"
            )
        rule_b = int(database.query_one("SELECT MAX(id) AS id FROM prevention_rules")["id"])
        ledger.review_rule(database, rule_b, "bob")
        ids_web = {h["id"] for h in ledger.search_rules(database, ["http", "timeout"], task_type="web_research")}
        assert ids_web == {rule_a, rule_b}
        ids_img = {h["id"] for h in ledger.search_rules(database, ["http", "timeout"], task_type="image_gen")}
        assert ids_img == {rule_a}
        # 废止即刻退出检索（§3.2）
        ledger.retire_rule(database, rule_a, "规则过时", "carol")
        assert {h["id"] for h in ledger.search_rules(database, ["http", "timeout"], task_type="image_gen")} == set()
        assert {h["id"] for h in ledger.search_rules(database, ["http", "timeout"], task_type="web_research")} == {rule_b}
        # 废止可逆：再审核复活（§3.2 复用同一审核动作）
        res = ledger.review_rule(database, rule_a, "dave")
        assert res["status"] == "active"
        row = database.query_one("SELECT * FROM prevention_rules WHERE id = ?", (rule_a,))
        assert row["retire_reason"] is None and row["retired_at"] is None
        assert row["reviewed_by"] == "dave" and row["reviewed_at"] is not None
    finally:
        database.close()
        shutil.rmtree(tmp, ignore_errors=True)


def test_fts_fallback_like_path() -> None:
    tmp = _tmpdir()
    database = _fresh_db(tmp, fts="off")  # 显式触发 §1.4 降级路径
    try:
        assert database.fts_available is False
        assert database.query_one("SELECT value FROM schema_meta WHERE key = 'fts_mode'")["value"] == "like_fallback"
        assert {"error_ledger_fts", "prevention_rules_fts"} <= _table_names(database)  # 同名普通表
        tid = state.create_task(database, title="降级", goal="LIKE 扫描")
        ledger.ledger_write(database, "TypeError", "http_client", {"url": "https://a.com", "retry": "3"},
                            "TypeError timeout in module http_client", tid, "worker")
        # 接口签名不变（§1.4）：同一 search_errors 形态返回
        hits = ledger.search_errors(database, ["timeout", "http_client"])
        assert len(hits) == 1 and hits[0]["module"] == "http_client"
        assert ledger.search_errors(database, ["heap-buffer-overflow"]) == []
        # 规则检索同样可用
        with database.transaction() as conn:
            conn.execute(
                "INSERT INTO prevention_rules (rule_text, match_keywords, status, risk_level)"
                " VALUES ('外部请求必须先设超时', 'timeout http_client', 'candidate', 'high')"
            )
        rule_id = int(database.query_one("SELECT id FROM prevention_rules")["id"])
        assert ledger.search_rules(database, ["timeout", "http_client"]) == []
        ledger.review_rule(database, rule_id, "alice")
        hits2 = ledger.search_rules(database, ["timeout", "http_client"])
        assert [h["id"] for h in hits2] == [rule_id]
    finally:
        database.close()
        shutil.rmtree(tmp, ignore_errors=True)


# ---------------------------------------------------------------------------
# ledger.py：沉淀全链路（滑窗 ≥2 / 先红 / 去重合并 / 待确认位 / 白名单）
# ---------------------------------------------------------------------------

def test_consolidation_threshold_draft_and_merge() -> None:
    tmp = _tmpdir()
    database = _fresh_db(tmp)
    try:
        tid = state.create_task(database, title="沉淀", goal="同签名 ≥2")
        e1, e2 = _two_same_signature_errors(database, tid)
        res = ledger.consolidation_check(database, tid)
        assert res["checked_signatures"] == 1 and res["below_threshold"] == 0
        assert len(res["drafted"]) == 1 and res["merged"] == [] and res["aborted"] == []
        rule_id = res["drafted"][0]["rule_id"]
        row = database.query_one("SELECT * FROM prevention_rules WHERE id = ?", (rule_id,))
        # 待确认位：candidate + reviewed_by NULL（memory-design §3.2），不参与检索注入
        assert row["status"] == "candidate" and row["reviewed_by"] is None
        assert row["occurrences"] == 2                       # §5.1 ① 滑窗全局计数
        assert set(json.loads(row["source_error_ids"])) == {e1, e2}
        assert row["risk_level"] == "high"                   # 确定性草案从严
        assert ledger.search_rules(database, ["http_client", "TypeError"]) == []
        assert len(_events(database, "rule_candidate", tid)) == 1
        # 同签名第三条 → 再沉淀走 ④ 合并分支：不新建，只追加 source_error_ids 与 occurrences（§5.1 ④/§5.3）
        e3 = ledger.ledger_write(database, "TypeError", "http_client",
                                 {"url": "https://c.example.net/v3", "retry": "3"},
                                 "TypeError timeout calling c.example.net", tid, "worker")
        res2 = ledger.consolidation_check(database, tid)
        assert res2["drafted"] == [] and len(res2["merged"]) == 1
        assert res2["merged"][0]["rule_id"] == rule_id
        assert res2["merged"][0]["added_source_error_ids"] == [e3]
        row = database.query_one("SELECT * FROM prevention_rules WHERE id = ?", (rule_id,))
        assert row["occurrences"] == 3                       # §5.3：累计触发次数
        assert set(json.loads(row["source_error_ids"])) == {e1, e2, e3}
        # 低于门槛（单条）不立规（§5 铁律 1）
        tid2 = state.create_task(database, title="单条", goal="不立规")
        ledger.ledger_write(database, "KeyError", "parser", {"field": "config"}, "missing key", tid2, "worker")
        res3 = ledger.consolidation_check(database, tid2)
        assert res3["drafted"] == [] and res3["below_threshold"] == 1
        assert len(_events(database, "consolidation_check", tid2)) == 1  # T11 事件化
    finally:
        database.close()
        shutil.rmtree(tmp, ignore_errors=True)


def test_consolidation_replay_validation_aborts() -> None:
    tmp = _tmpdir()
    database = _fresh_db(tmp)
    try:
        tid = state.create_task(database, title="先红", goal="回放校验")
        _two_same_signature_errors(database, tid)

        def bad_drafter(rows: list[dict], retry: bool) -> dict:
            # 声称要防的错误连它自己的关键词都查不到 → 必须被 ③ 回放校验击落
            return {"rule_text": "毫无关系的规则文本", "match_keywords": "zzznope qqqmissing",
                    "task_types": "*", "risk_level": "medium"}

        res = ledger.consolidation_check(database, tid, llm_drafter=bad_drafter)
        assert res["drafted"] == [] and len(res["aborted"]) == 1
        assert res["aborted"][0]["reason"] == "replay_validation_missed_or_llm_unavailable"
        assert int(database.query_one("SELECT COUNT(*) AS n FROM prevention_rules")["n"]) == 0
        degraded = _events(database, "memory_degraded")
        assert any(json.loads(e["payload"])["surface"] == "rule_draft_aborted" for e in degraded)
    finally:
        database.close()
        shutil.rmtree(tmp, ignore_errors=True)


def test_consolidation_replay_retry_once_then_pass() -> None:
    tmp = _tmpdir()
    database = _fresh_db(tmp)
    try:
        tid = state.create_task(database, title="重归纳", goal="先红一次后修正")
        _two_same_signature_errors(database, tid)
        calls: list[bool] = []

        def flaky_drafter(rows: list[dict], retry: bool) -> dict:
            calls.append(retry)
            if not retry:
                return {"rule_text": "无关键词命中", "match_keywords": "zzznope",
                        "task_types": "*", "risk_level": "low"}
            return {"rule_text": "对外 HTTP 调用必须显式设置超时", "match_keywords": "http_client timeout",
                    "task_types": "*", "risk_level": "low"}

        # §5.1 ③：不命中 → 退回 ② 重新归纳（最多重归纳 1 次）；whitelist=[] 使 low 草案保持 candidate
        res = ledger.consolidation_check(database, tid, llm_drafter=flaky_drafter, whitelist=[])
        assert calls == [False, True]
        assert len(res["drafted"]) == 1 and res["drafted"][0]["risk_level"] == "low"
        assert res["drafted"][0]["status"] == "candidate"
        row = database.query_one("SELECT * FROM prevention_rules WHERE id = ?", (res["drafted"][0]["rule_id"],))
        assert row["match_keywords"] == "http_client timeout"
    finally:
        database.close()
        shutil.rmtree(tmp, ignore_errors=True)


def test_consolidation_whitelist_auto_activate_gates() -> None:
    tmp = _tmpdir()
    database = _fresh_db(tmp)
    try:
        tid = state.create_task(database, title="白名单", goal="两道闸")

        def low_drafter(rows: list[dict], retry: bool) -> dict:
            return {"rule_text": "外部请求必须先设超时上限再重试", "match_keywords": "timeout retry-limit",
                    "task_types": "*", "risk_level": "low"}

        for i in range(2):
            ledger.ledger_write(database, "TimeoutError", "http_client", {},
                                "timeout retry-limit exceeded in module http_client", tid, "worker")
        # 两道闸同时满足（low + match_keywords 命中白名单）→ active，无人工审核（§3.2）
        res = ledger.consolidation_check(database, tid, llm_drafter=low_drafter)
        d = res["drafted"][0]
        assert d["status"] == "active" and d["auto_activated"] is True
        row = database.query_one("SELECT * FROM prevention_rules WHERE id = ?", (d["rule_id"],))
        assert row["auto_activated"] == 1 and row["reviewed_by"] is None
        assert row["activated_at"] is not None
        # 非白名单关键词的 low 草案 → 保持 candidate（清单外一律人工）
        tid2 = state.create_task(database, title="清单外", goal="不自动生效")

        def low_drafter_offlist(rows: list[dict], retry: bool) -> dict:
            return {"rule_text": "解析器字段缺失时先校验", "match_keywords": "weirdkeyword other",
                    "task_types": "*", "risk_level": "low"}

        for i in range(2):
            ledger.ledger_write(database, "KeyError", "weirdmodule", {},
                                "weirdkeyword other failure in weirdmodule", tid2, "worker")
        res2 = ledger.consolidation_check(database, tid2, llm_drafter=low_drafter_offlist)
        d2 = res2["drafted"][0]
        assert d2["status"] == "candidate" and d2["auto_activated"] is False
    finally:
        database.close()
        shutil.rmtree(tmp, ignore_errors=True)


def test_review_and_retire_rejections() -> None:
    tmp = _tmpdir()
    database = _fresh_db(tmp)
    try:
        tid = state.create_task(database, title="审核", goal="状态机动作")
        _two_same_signature_errors(database, tid)
        rule_id = ledger.consolidation_check(database, tid)["drafted"][0]["rule_id"]
        # 驳回去向设计未定义（§3.2 candidate 无 reject 出边）→ 如实抛错不假成功
        try:
            ledger.review_rule(database, rule_id, "alice", approve=False)
        except ValueError:
            pass
        else:
            raise AssertionError("reject must raise (design gap)")
        # candidate → active
        res = ledger.review_rule(database, rule_id, "alice")
        assert res["status"] == "active"
        # 重复审核拒绝
        try:
            ledger.review_rule(database, rule_id, "alice")
        except ValueError:
            pass
        else:
            raise AssertionError("already-active rule must not be re-reviewed")
        # 废止必填理由（§3.1/§3.2）
        try:
            ledger.retire_rule(database, rule_id, "  ", "bob")
        except ValueError:
            pass
        else:
            raise AssertionError("retire_reason is required")
        res2 = ledger.retire_rule(database, rule_id, "规则过时", "bob")
        assert res2["status"] == "retired"
        try:
            ledger.retire_rule(database, rule_id, "再来一次", "bob")
        except ValueError:
            pass
        else:
            raise AssertionError("already-retired rule must not be retired twice")
        assert len(_events(database, "rule_retired")) == 1
    finally:
        database.close()
        shutil.rmtree(tmp, ignore_errors=True)


# ---------------------------------------------------------------------------
# state.py：状态机守卫与原子性
# ---------------------------------------------------------------------------

def test_state_machine_full_path_and_guards() -> None:
    tmp = _tmpdir()
    database = _fresh_db(tmp)
    try:
        tid = state.create_task(database, title="主链路", goal="T1→done")
        assert "task_transitions" not in _table_names(database)  # deployment-ops §5.1 按需建表时机
        state.transition_task(database, tid, TaskStatus.PLANNING, component="orchestrator", reason="claim")
        assert "task_transitions" in _table_names(database)
        assert _task_status(database, tid) == "planning"
        # 转移原子性：state_transition 事件与 task_transitions 行同事务落库（sys-arch §3.3）
        ev = _events(database, "state_transition", tid)
        assert len(ev) == 1
        payload = json.loads(ev[0]["payload"])
        assert payload["transition"] == "T1" and payload["from"] == "pending" and payload["to"] == "planning"
        tr = database.query_one("SELECT * FROM task_transitions WHERE task_id = ?", (tid,))
        assert tr["transition"] == "T1" and tr["layer"] == "top" and tr["event_id"] == ev[0]["event_id"]
        state.transition_task(database, tid, TaskStatus.RUNNING, component="orchestrator")
        # T5 守卫：存在未终态子任务时 running→reviewing 拒绝（sys-arch §3.2 T5）
        tid3 = state.create_task(database, title="T5守卫", goal="收敛检查")
        gid = state.create_group(database, tid3, name="G1")
        sid = state.create_subtask(database, tid3, gid, objective="抓取定价页")
        state.transition_task(database, tid3, TaskStatus.PLANNING, component="orchestrator")
        state.transition_task(database, tid3, TaskStatus.RUNNING, component="orchestrator")
        try:
            state.transition_task(database, tid3, TaskStatus.REVIEWING, component="orchestrator")
        except InvalidTransitionError as exc:
            assert "T5" in str(exc)
        else:
            raise AssertionError("T5 guard must reject with non-terminal subtasks")
        state.transition_subtask(database, sid, SubtaskStatus.RUNNING, component="worker")   # T2 (sub)
        state.transition_subtask(database, sid, SubtaskStatus.DONE, component="worker")      # 子任务终态
        state.transition_task(database, tid3, TaskStatus.REVIEWING, component="reviewer")    # T5 通过
        state.transition_task(database, tid3, TaskStatus.REWORK, component="reviewer", reason="defect")  # T7
        state.transition_task(database, tid3, TaskStatus.RUNNING, component="orchestrator")  # T8
        state.transition_task(database, tid3, TaskStatus.REVIEWING, component="reviewer")
        state.transition_task(database, tid3, TaskStatus.DONE, component="reviewer")         # T6
        assert state.done_callback(database, tid3)  # T11 终态回调
        # T11 仅限 done（终态回调守卫）
        tid2 = state.create_task(database, title="T10", goal="失败")
        state.transition_task(database, tid2, TaskStatus.PLANNING, component="orchestrator")
        state.transition_task(database, tid2, TaskStatus.FAILED, component="orchestrator")   # T10
        try:
            state.done_callback(database, tid2)
        except InvalidTransitionError:
            pass
        else:
            raise AssertionError("T11 callback requires done")
        # 非法转移与终态锁定
        tid9 = state.create_task(database, title="守卫", goal="非法转移")
        try:
            state.transition_task(database, tid9, TaskStatus.DONE, component="orchestrator")
        except InvalidTransitionError:
            pass
        else:
            raise AssertionError("pending→done is not a legal transition")
        state.transition_task(database, tid9, TaskStatus.PLANNING, component="orchestrator")
        try:
            state.transition_task(database, tid9, "planning → aborted 直接跳", component="x")
        except InvalidTransitionError:
            pass
        else:
            raise AssertionError("unknown status must be rejected")
        tid10 = state.create_task(database, title="T9", goal="中止")
        state.transition_task(database, tid10, TaskStatus.PLANNING, component="orchestrator")
        state.transition_task(database, tid10, TaskStatus.RUNNING, component="orchestrator")
        state.transition_task(database, tid10, TaskStatus.ABORTED, component="orchestrator", reason="预算熔断")
        try:
            state.transition_task(database, tid10, TaskStatus.RUNNING, component="orchestrator")
        except InvalidTransitionError:
            pass
        else:
            raise AssertionError("no exit from terminal state")
        # T9 设计缺口如实保留：paused_for_approval 不在 §3.2 T9 的 from 集合内
        tid11 = state.create_task(database, title="缺口", goal="paused 不可中止")
        state.transition_task(database, tid11, TaskStatus.PLANNING, component="orchestrator")
        state.transition_task(database, tid11, TaskStatus.RUNNING, component="orchestrator")
        state.open_approval(database, tid11, action_type="email.send", risk_tier="irreversible",
                            summary="发送邮件", now=dbmod.utc_now_iso())
        assert _task_status(database, tid11) == "paused_for_approval"
        try:
            state.transition_task(database, tid11, TaskStatus.ABORTED, component="orchestrator")
        except InvalidTransitionError:
            pass
        else:
            raise AssertionError("sys-arch §3.2 T9 does not allow paused_for_approval → aborted")
    finally:
        database.close()
        shutil.rmtree(tmp, ignore_errors=True)


def test_request_transition_single_driver() -> None:
    tmp = _tmpdir()
    database = _fresh_db(tmp)
    try:
        tid = state.create_task(database, title="请求", goal="单一驱动者")
        eid = state.request_transition(database, tid, TaskStatus.PLANNING, component="planner", reason="ready")
        events = _events(database, "transition_request", tid)
        assert len(events) == 1 and events[0]["event_id"] == eid
        assert _task_status(database, tid) == "pending"  # 请求不动状态，只发事件（sys-arch §3.3）
        try:
            state.request_transition(database, tid, TaskStatus.DONE, component="planner")
        except InvalidTransitionError:
            pass
        else:
            raise AssertionError("illegal request must be pre-validated")
    finally:
        database.close()
        shutil.rmtree(tmp, ignore_errors=True)


def test_task_tree_creation_fields() -> None:
    tmp = _tmpdir()
    database = _fresh_db(tmp)
    try:
        tid = state.create_task(database, title="三层", goal="主任务-分组-子任务", source="cron",
                                budget_usd=5.0, risk_level="medium")
        row = database.query_one("SELECT * FROM tasks WHERE id = ?", (tid,))
        assert row["source"] == "cron" and row["budget_usd"] == 5.0
        assert row["correlation_id"] and row["brief_refs"] == "[]"
        gid = state.create_group(database, tid, name="批量处理组", depends_on=[],
                                 batch_mode=True, batch_total_items=20, partial_ok=False)
        g = database.query_one("SELECT * FROM groups WHERE id = ?", (gid,))
        assert g["task_id"] == tid and g["batch_mode"] == 1 and g["batch_total_items"] == 20
        assert json.loads(g["depends_on"]) == []
        sid = state.create_subtask(database, tid, gid, objective="抓取并摘要定价页",
                                   risk_tier_hint="reversible")
        s = database.query_one("SELECT * FROM subtasks WHERE id = ?", (sid,))
        assert s["status"] == "planning" and s["brief_version"] == 1 and s["attempts"] == 0
        assert s["risk_tier_hint"] == "reversible"
        assert len(_events(database, "task_created", tid)) == 1
        assert len(_events(database, "group_created", tid)) == 1
        assert len(_events(database, "subtask_created", tid)) == 1
    finally:
        database.close()
        shutil.rmtree(tmp, ignore_errors=True)


# ---------------------------------------------------------------------------
# state.py：审批域 T3/T4
# ---------------------------------------------------------------------------

def test_approval_flow_t3_t4() -> None:
    tmp = _tmpdir()
    database = _fresh_db(tmp)
    try:
        tid = state.create_task(database, title="审批", goal="R2 拦截")
        state.transition_task(database, tid, TaskStatus.PLANNING, component="orchestrator")
        state.transition_task(database, tid, TaskStatus.RUNNING, component="orchestrator")
        now = dbmod.utc_now_iso()
        apr = state.open_approval(database, tid, action_type="email.send", risk_tier="irreversible",
                                  summary="发送邮件至 cto@example-corp.com：报价确认",
                                  payload={"to": "cto@example-corp.com", "subject": "报价确认"},
                                  evidence={"subtask_id": "s1"}, now=now)
        assert apr.startswith("apr-")
        row = database.query_one("SELECT * FROM approvals WHERE id = ?", (apr,))
        assert row["status"] == "waiting" and row["task_id"] == tid
        assert row["wait_expires_at"] == iso_shift(now, state.APPROVAL_DEFAULT_WAIT)  # §5.3 默认等待期 24h
        assert row["timeout_fallback"] == "skip_and_continue"
        assert _task_status(database, tid) == "paused_for_approval"                   # T3
        assert _task_detail(database, tid) == {"waiting_approval_id": apr}            # ICON §5.3
        # risk_tier 三档校验（ARCH §5.1）
        try:
            state.open_approval(database, tid, action_type="x", risk_tier="medium", summary="s")
        except ValueError:
            pass
        else:
            raise AssertionError("risk_tier must be one of the three tiers")
        # 审批行 + T3 转移同一事务（sys-arch §3.3）：T3 守卫失败时审批行必须一并回滚
        tid_orphan = state.create_task(database, title="孤儿审批", goal="pending 态直接拦截")
        try:
            state.open_approval(database, tid_orphan, action_type="email.send",
                                risk_tier="irreversible", summary="s", now=dbmod.utc_now_iso())
        except InvalidTransitionError:
            pass
        else:
            raise AssertionError("T3 guard must reject non-running task")
        orphan_count = int(database.query_one("SELECT COUNT(*) AS n FROM approvals WHERE task_id = ?",
                                              (tid_orphan,))["n"])
        assert orphan_count == 0, "approval row must roll back with failed T3 transition"
        # T4 use_edited 必填 edited_payload（ICON §6.3）
        try:
            state.decide_approval(database, apr, "use_edited")
        except ValueError:
            pass
        else:
            raise AssertionError("edited_payload required")
        res = state.decide_approval(database, apr, "use_edited",
                                    edited_payload={"to": "cfo@example-corp.com"}, decided_by="user-1")
        assert res["task_status"] == "running"
        row = database.query_one("SELECT * FROM approvals WHERE id = ?", (apr,))
        assert row["status"] == "decided" and row["decision"] == "use_edited"
        assert json.loads(row["edited_payload"]) == {"to": "cfo@example-corp.com"}
        assert _task_status(database, tid) == "running"
        # 已裁决的审批不可重复裁决
        try:
            state.decide_approval(database, apr, "approve")
        except InvalidTransitionError:
            pass
        else:
            raise AssertionError("decided approval cannot be decided again")
        # regenerate：批注必填，裁决后 running 内局部回退（§5.2 三按钮）
        tid2 = state.create_task(database, title="重生成", goal="三按钮")
        state.transition_task(database, tid2, TaskStatus.PLANNING, component="orchestrator")
        state.transition_task(database, tid2, TaskStatus.RUNNING, component="orchestrator")
        apr2 = state.open_approval(database, tid2, action_type="im.send", risk_tier="irreversible",
                                   summary="发消息", now=dbmod.utc_now_iso())
        try:
            state.decide_approval(database, apr2, "regenerate")
        except ValueError:
            pass
        else:
            raise AssertionError("comment required for regenerate")
        res2 = state.decide_approval(database, apr2, "regenerate", comment="收件人抄送加财务")
        assert res2["task_status"] == "running"
        assert _task_detail(database, tid2)["regenerated"] is True
        assert len(_events(database, "approval_decision", tid2)) == 1
    finally:
        database.close()
        shutil.rmtree(tmp, ignore_errors=True)


# ---------------------------------------------------------------------------
# state.py：超时兜底统一扫描（sys-arch §3.2 超时列 / §3.3 统一实现）
# ---------------------------------------------------------------------------

def test_timeout_pending_force_claim_and_planning_failed() -> None:
    tmp = _tmpdir()
    database = _fresh_db(tmp)
    try:
        tid = state.create_task(database, title="T1兜底", goal="pending 超时")
        _backdate(database, "tasks", tid, state.TASK_PENDING_TIMEOUT + 60)
        actions = state.scan_timeouts(database)
        assert [a.kind for a in actions] == ["pending_force_claim"]
        res = state.apply_timeout_action(database, actions[0])
        assert res["status"] == "planning" and _task_status(database, tid) == "planning"
        # T2 兜底第一段：planning 超时 → 重试 1 次（重置计时，状态保持）
        _backdate(database, "tasks", tid, state.PLANNING_TIMEOUT + 60)
        actions = state.scan_timeouts(database)
        assert [a.kind for a in actions] == ["planning_timeout_retry"]
        state.apply_timeout_action(database, actions[0])
        assert _task_status(database, tid) == "planning"
        assert len(_events(database, "planning_timeout", tid)) == 1
        # T2 兜底第二段：再超时 → failed + 错误登记（签名 planning_timeout）
        _backdate(database, "tasks", tid, state.PLANNING_TIMEOUT + 60)
        actions = state.scan_timeouts(database)
        assert [a.kind for a in actions] == ["planning_timeout_failed"]
        res = state.apply_timeout_action(database, actions[0])
        assert res["status"] == "failed"
        assert _task_status(database, tid) == "failed"
        entry = database.query_one(
            "SELECT * FROM error_ledger WHERE task_id = ? AND error_type = 'planning_timeout'", (tid,)
        )
        assert entry is not None and entry["role"] == "orchestrator"
        assert entry["signature_hash"] == ledger.make_signature("planning_timeout", "orchestrator", {})[1]
        assert len(_events(database, "planning_timeout", tid)) == 2  # 重试 + 放弃，动作均落事件（§3.3）
    finally:
        database.close()
        shutil.rmtree(tmp, ignore_errors=True)


def test_timeout_review_retry_then_escalate() -> None:
    tmp = _tmpdir()
    database = _fresh_db(tmp)
    try:
        tid = state.create_task(database, title="T6兜底", goal="reviewing 超时")
        state.transition_task(database, tid, TaskStatus.PLANNING, component="orchestrator")
        state.transition_task(database, tid, TaskStatus.RUNNING, component="orchestrator")
        state.transition_task(database, tid, TaskStatus.REVIEWING, component="reviewer")
        _backdate(database, "tasks", tid, state.REVIEW_TIMEOUT + 60)
        actions = state.scan_timeouts(database)
        assert [a.kind for a in actions] == ["review_timeout_retry"]
        state.apply_timeout_action(database, actions[0])
        assert _task_status(database, tid) == "reviewing"  # 重试：保持 reviewing
        _backdate(database, "tasks", tid, state.REVIEW_TIMEOUT + 60)
        actions = state.scan_timeouts(database)
        assert [a.kind for a in actions] == ["review_timeout_escalate"]
        state.apply_timeout_action(database, actions[0])
        assert _task_status(database, tid) == "reviewing"  # 人工升级后保持 reviewing，防误杀（§3.2 T6）
        assert _task_detail(database, tid) == {"needs_human": True}
        # 升级事件已发，再次扫描不再重复产生动作（防事件刷屏）
        _backdate(database, "tasks", tid, state.REVIEW_TIMEOUT + 60)
        assert state.scan_timeouts(database) == []
    finally:
        database.close()
        shutil.rmtree(tmp, ignore_errors=True)


def test_timeout_rework_redispatch_three_then_failed() -> None:
    tmp = _tmpdir()
    database = _fresh_db(tmp)
    try:
        tid = state.create_task(database, title="T8兜底", goal="rework 超时")
        state.transition_task(database, tid, TaskStatus.PLANNING, component="orchestrator")
        state.transition_task(database, tid, TaskStatus.RUNNING, component="orchestrator")
        state.transition_task(database, tid, TaskStatus.REVIEWING, component="reviewer")
        state.transition_task(database, tid, TaskStatus.REWORK, component="reviewer", reason="defect")
        for round_no in range(state.REWORK_MAX_REDISPATCH):
            _backdate(database, "tasks", tid, state.REWORK_TIMEOUT + 60)
            actions = state.scan_timeouts(database)
            assert [a.kind for a in actions] == ["rework_redispatch"], round_no
            state.apply_timeout_action(database, actions[0])
            assert _task_status(database, tid) == "rework"
        assert len(_events(database, "rework_redispatch", tid)) == state.REWORK_MAX_REDISPATCH
        _backdate(database, "tasks", tid, state.REWORK_TIMEOUT + 60)
        actions = state.scan_timeouts(database)
        assert [a.kind for a in actions] == ["rework_failed"]
        res = state.apply_timeout_action(database, actions[0])
        assert res["status"] == "failed" and _task_status(database, tid) == "failed"
    finally:
        database.close()
        shutil.rmtree(tmp, ignore_errors=True)


def test_timeout_subtask_redispatch_then_failed() -> None:
    tmp = _tmpdir()
    database = _fresh_db(tmp)
    try:
        tid = state.create_task(database, title="T5兜底", goal="子任务超时")
        gid = state.create_group(database, tid, name="G1")
        sid = state.create_subtask(database, tid, gid, objective="批量项")
        state.transition_task(database, tid, TaskStatus.PLANNING, component="orchestrator")
        state.transition_task(database, tid, TaskStatus.RUNNING, component="orchestrator")
        state.transition_subtask(database, sid, SubtaskStatus.RUNNING, component="worker")
        for round_no in range(state.MAX_RETRIES):
            _backdate(database, "subtasks", sid, state.SUBTASK_RUNNING_TIMEOUT + 60)
            actions = state.scan_timeouts(database)
            kinds = [a.kind for a in actions]
            assert "subtask_redispatch" in kinds, (round_no, kinds)
            act = next(a for a in actions if a.kind == "subtask_redispatch")
            state.apply_timeout_action(database, act)
            assert _subtask_status(database, sid) == "running"
        attempts = int(database.query_one("SELECT attempts FROM subtasks WHERE id = ?", (sid,))["attempts"])
        assert attempts == state.MAX_RETRIES
        _backdate(database, "subtasks", sid, state.SUBTASK_RUNNING_TIMEOUT + 60)
        actions = state.scan_timeouts(database)
        act = next(a for a in actions if a.kind == "subtask_failed")
        res = state.apply_timeout_action(database, act)
        assert res["status"] == "failed"
        assert _subtask_status(database, sid) == "failed"
        assert len(_events(database, "subtask_redispatch", tid)) == state.MAX_RETRIES
        assert len(_events(database, "subtask_timeout", tid)) == 1
    finally:
        database.close()
        shutil.rmtree(tmp, ignore_errors=True)


def test_timeout_approval_expiry_skip_strict() -> None:
    tmp = _tmpdir()
    database = _fresh_db(tmp)
    try:
        tid = state.create_task(database, title="T4兜底", goal="付款审批超时")
        state.transition_task(database, tid, TaskStatus.PLANNING, component="orchestrator")
        state.transition_task(database, tid, TaskStatus.RUNNING, component="orchestrator")
        now = dbmod.utc_now_iso()
        apr = state.open_approval(database, tid, action_type="payment.charge", risk_tier="irreversible",
                                  summary="付款", timeout_fallback="skip_strict", wait_seconds=0, now=now)
        assert _task_status(database, tid) == "paused_for_approval"
        scan_at = iso_shift(now, 5)
        actions = state.scan_timeouts(database, now=scan_at)
        assert [a.kind for a in actions] == ["approval_expired"]
        res = state.apply_timeout_action(database, actions[0], now=scan_at)
        assert res["status"] == "running"
        assert _task_status(database, tid) == "running"  # 跳过该动作继续推进非风险部分（§5.3）
        row = database.query_one("SELECT * FROM approvals WHERE id = ?", (apr,))
        assert row["status"] == "expired"
        events = _events(database, "approval_timeout_skip", tid)
        assert len(events) == 1
        payload = json.loads(events[0]["payload"])
        assert payload["timeout_fallback"] == "skip_strict"   # 付款类：不降级执行也不换路径，直接跳过
        assert payload["action_type"] == "payment.charge"
        # 已过期审批不再重复扫描
        assert state.scan_timeouts(database, now=iso_shift(now, 10)) == []
    finally:
        database.close()
        shutil.rmtree(tmp, ignore_errors=True)


# ---------------------------------------------------------------------------
# state.py：崩溃恢复视图（sys-arch §3.3）
# ---------------------------------------------------------------------------

def test_recovery_view() -> None:
    tmp = _tmpdir()
    database = _fresh_db(tmp)
    try:
        t_pending = state.create_task(database, title="p", goal="g")                     # pending：两表都不进
        t_planning = state.create_task(database, title="p", goal="g")
        state.transition_task(database, t_planning, TaskStatus.PLANNING, component="orchestrator")
        t_running = state.create_task(database, title="p", goal="g")
        state.transition_task(database, t_running, TaskStatus.PLANNING, component="orchestrator")
        state.transition_task(database, t_running, TaskStatus.RUNNING, component="orchestrator")
        t_reviewing = state.create_task(database, title="p", goal="g")
        for target in (TaskStatus.PLANNING, TaskStatus.RUNNING, TaskStatus.REVIEWING):
            state.transition_task(database, t_reviewing, target, component="orchestrator")
        t_paused = state.create_task(database, title="p", goal="g")
        state.transition_task(database, t_paused, TaskStatus.PLANNING, component="orchestrator")
        state.transition_task(database, t_paused, TaskStatus.RUNNING, component="orchestrator")
        state.open_approval(database, t_paused, action_type="email.send", risk_tier="irreversible",
                            summary="s", now=dbmod.utc_now_iso())
        t_done = state.create_task(database, title="p", goal="g")
        for target in (TaskStatus.PLANNING, TaskStatus.RUNNING, TaskStatus.REVIEWING, TaskStatus.DONE):
            state.transition_task(database, t_done, target, component="orchestrator")
        view = state.recovery_view(database)
        resume = {item["task_id"]: item["status"] for item in view["resume"]}
        assert resume == {t_planning: "planning", t_running: "running", t_reviewing: "reviewing"}
        assert [item["task_id"] for item in view["waiting_user"]] == [t_paused]  # paused 原样保留等待用户
        all_ids = resume | {t_pending: "pending", t_done: "done"}
        assert t_done not in resume and t_pending not in resume
        _ = all_ids
    finally:
        database.close()
        shutil.rmtree(tmp, ignore_errors=True)
