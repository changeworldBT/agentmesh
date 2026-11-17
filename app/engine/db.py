"""db.py — SQLite WAL 连接管理 + 内核 MVP 全部数据表 + error_ledger/prevention_rules 的 FTS5 虚表。

设计文档出处（模块顶部注记，按本 ask 要求）：
- sys-arch（ARCH-ROOT-01）§1.3/§2.1：SQLite WAL 单写者、单容器单进程；§3.3：转移原子性、
  busy_timeout 兜底；§7.1：events 表字段（event_id ULID / ts / task_id / component /
  event_type / payload / correlation_id）；§7.2：载荷超限（默认 64KB）截断存引用；
  §9.3 不变量 5：全局单写连接，任何组件不得自建连接池绕过。
- memory-design（MEM-ERR-01）§1.1：错误账本与记忆库共用单文件库；§2.1：error_ledger DDL
  + error_ledger_fts + 三触发器（逐字落地）；§3.1：prevention_rules DDL +
  prevention_rules_fts + 三触发器（逐字落地）+ schema_meta；§8.2：共用同一连接管理器
  （WAL + busy_timeout=5000 + 全局单写连接，不另起第二库文件、不另起连接池）；
  §10.2：PRAGMA 头（journal_mode=WAL / busy_timeout=5000 / synchronous=NORMAL /
  foreign_keys=ON）；§1.4：FTS5 不可用时的降级路径（同名普通表 + LIKE 扫描，接口签名不变）。
- interface-contracts（ICON-01）§5.2/§5.3：tasks/groups/subtasks 的 API 投影字段；
  §6.1–§6.3：审批域字段（approval_id / risk_tier 三档 / wait_expires_at /
  timeout_fallback / decision 三按钮）。
- deployment-ops §5.1：表清单注记——tasks / events / error_ledger(+fts) /
  prevention_rules(+fts) 属建库脚本范围；task_transitions 由内核状态机模块按需建表
  （见 state.py，首次转移写入前）；groups / subtasks / approvals / rules_kv 为本 ask
  指定的内核 MVP 表集落点。

偏离与取舍（如实声明）：
- tasks 表以 memory-design §7/§10.2 字段为基底，另加状态机必需列（correlation_id /
  status_detail / status_changed_at / source / budget_usd / cost_usd_est）：sys-arch §3.2
  各超时兜底需要「状态进入时刻」作扫描基准，updated_at 会被非状态写入冲掉，不能替代。
- approvals 表名按本 ask 表集落地（sys-arch §5.3 原名 approval_events、归属审批门按需
  建表；本 ask 收敛为常驻表，字段覆盖 ICON §6.1–§6.3 渲染/裁决面；审批动作审计同时落
  events 总线表满足 §7.1「每步动作事件化」与 replay）。
- rules_kv 为本 ask 指定的键值表（内核规则/配置运行态，value 为 JSON 文本）；设计文档中
  的 rules_history（rules-config §7.1）属规则装载器，不在本 ask 表集内，未建。
- schema_meta 按 memory-design §10.2 建入（部署首验第 3 条依赖），并落 fts_mode 值。
- schema v2（本 ask）：approvals.decision CHECK 扩容 '+reject'（approval.py 驳回动作，
  语义取 sys-arch §5.3 超时兜底分支的人工即时版），旧库经 _migrate_approvals_add_reject
  表重建迁移（SQLite 不能 ALTER CHECK），schema_version 落 '2'。
"""

from __future__ import annotations

import contextlib
import json
import os
import sqlite3
import threading
import time
from collections.abc import Iterator, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "2"                # v2：approvals.decision CHECK 扩容（+reject，approval.py 驳回动作，本 ask）
                                    # v1 基线：memory-design §3.1/§10.2（部署首验第 3 条）
DEFAULT_BUSY_TIMEOUT_MS = 5000      # memory-design §8.2/§10.2
PAYLOAD_MAX_CHARS = 65536           # sys-arch §7.2：载荷超限（默认 64KB）截断存引用


# ---------------------------------------------------------------------------
# 时间与 ID 工具（memory-design §2.1 的时间戳形态：ISO8601 UTC 毫秒精度 + 'Z'）
# ---------------------------------------------------------------------------

def utc_now_iso() -> str:
    """当前时刻，ISO8601 UTC（毫秒精度），与 SQLite strftime('%Y-%m-%dT%H:%M:%fZ','now') 同形。"""
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def parse_iso(ts: str) -> datetime:
    """解析本库统一时间戳（兼容 'Z' 后缀，Python 3.11+ fromisoformat）。"""
    return datetime.fromisoformat(str(ts).replace("Z", "+00:00"))


def iso_shift(ts: str, seconds: float) -> str:
    """从给定时刻偏移 seconds 秒，返回同形态时间戳（超时扫描/等待期计算用）。"""
    shifted = parse_iso(ts) + timedelta(seconds=seconds)
    return shifted.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


_ULID_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"  # Crockford Base32


def _ulid_encode(value: int, length: int) -> str:
    out: list[str] = []
    for _ in range(length):
        out.append(_ULID_ALPHABET[value & 0x1F])
        value >>= 5
    return "".join(reversed(out))


_ULID_LOCK = threading.Lock()
_ULID_LAST_TS = 0
_ULID_LAST_RAND = 0


def new_ulid() -> str:
    """ULID（26 字符 Crockford Base32）：48bit 毫秒时间戳 + 80bit 随机数。

    sys-arch §7.1：event_id 为 ULID；memory-design §7：tasks.id 为 ULID（编排引擎生成）。
    单调性：同一毫秒内递增随机位（标准 ULID monotonic 语义）——events 以 (ts, event_id)
    排序，同毫秒事件的先后必须确定（replay/时间线正确性依赖，实测踩中随机翻转）。
    """
    global _ULID_LAST_TS, _ULID_LAST_RAND
    with _ULID_LOCK:
        ts_ms = int(time.time() * 1000) & ((1 << 48) - 1)
        if ts_ms == _ULID_LAST_TS:
            rand = (_ULID_LAST_RAND + 1) & ((1 << 80) - 1)
        else:
            _ULID_LAST_TS = ts_ms
            rand = int.from_bytes(os.urandom(10), "big")
        _ULID_LAST_RAND = rand
        return _ulid_encode(ts_ms, 10) + _ulid_encode(rand, 16)


def json_dumps(obj: Any) -> str:
    """库内 JSON 文本统一序列化（紧凑、保留非 ASCII）。"""
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


# ---------------------------------------------------------------------------
# DDL：八张业务表（本 ask 表集）+ schema_meta
# ---------------------------------------------------------------------------

_SCHEMA_STATEMENTS: tuple[str, ...] = (
    # ---- tasks（memory-design §7/§10.2 基底 + 状态机列；九态枚举 sys-arch §3.1）----
    """
    CREATE TABLE IF NOT EXISTS tasks (
      id                TEXT PRIMARY KEY,
      title             TEXT NOT NULL,
      goal              TEXT NOT NULL,
      status            TEXT NOT NULL DEFAULT 'pending' CHECK (status IN
                        ('pending','planning','paused_for_approval','running',
                         'reviewing','rework','done','failed','aborted')),
      status_detail     TEXT,
      correlation_id    TEXT NOT NULL,
      risk_level        TEXT NOT NULL DEFAULT 'medium',
      source            TEXT NOT NULL DEFAULT 'user' CHECK (source IN ('user','cron','webhook')),
      budget_usd        REAL,
      cost_usd_est      REAL NOT NULL DEFAULT 0,
      brief_refs        TEXT NOT NULL DEFAULT '[]',
      result_summary    TEXT,
      status_changed_at TEXT NOT NULL,
      created_at        TEXT NOT NULL,
      updated_at        TEXT NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status, status_changed_at)",
    "CREATE INDEX IF NOT EXISTS idx_tasks_corr ON tasks(correlation_id)",
    # ---- groups（sys-arch §4.1 三层模型第二层；ICON §5.3 groups[] 投影字段）----
    """
    CREATE TABLE IF NOT EXISTS groups (
      id                TEXT PRIMARY KEY,
      task_id           TEXT NOT NULL REFERENCES tasks(id),
      name              TEXT NOT NULL,
      depends_on        TEXT NOT NULL DEFAULT '[]',
      batch_mode        INTEGER NOT NULL DEFAULT 0,
      batch_total_items INTEGER,
      partial_ok        INTEGER NOT NULL DEFAULT 0,
      created_at        TEXT NOT NULL,
      updated_at        TEXT NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_groups_task ON groups(task_id)",
    # ---- subtasks（sys-arch §4.1 最小执行单元；ICON §5.3 subtasks[] 投影字段）----
    """
    CREATE TABLE IF NOT EXISTS subtasks (
      id                TEXT PRIMARY KEY,
      task_id           TEXT NOT NULL REFERENCES tasks(id),
      group_id          TEXT NOT NULL REFERENCES groups(id),
      objective         TEXT NOT NULL,
      status            TEXT NOT NULL DEFAULT 'planning' CHECK (status IN
                        ('pending','planning','running','paused_for_approval',
                         'rework','done','failed','aborted')),
      status_detail     TEXT,
      brief_version     INTEGER NOT NULL DEFAULT 1,
      attempts          INTEGER NOT NULL DEFAULT 0,
      risk_tier_hint    TEXT,
      deliverable_path  TEXT,
      cost_usd_est      REAL NOT NULL DEFAULT 0,
      status_changed_at TEXT NOT NULL,
      created_at        TEXT NOT NULL,
      updated_at        TEXT NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_subtasks_task ON subtasks(task_id)",
    "CREATE INDEX IF NOT EXISTS idx_subtasks_group_status ON subtasks(group_id, status)",
    "CREATE INDEX IF NOT EXISTS idx_subtasks_status_time ON subtasks(status, status_changed_at)",
    # ---- events（sys-arch §7.1 事件表，字段级落地；payload 为 JSON 文本）----
    """
    CREATE TABLE IF NOT EXISTS events (
      event_id      TEXT PRIMARY KEY,
      ts            TEXT NOT NULL,
      task_id       TEXT,
      component     TEXT NOT NULL,
      event_type    TEXT NOT NULL,
      payload       TEXT NOT NULL DEFAULT '{}',
      correlation_id TEXT
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_events_task_ts ON events(task_id, ts)",
    "CREATE INDEX IF NOT EXISTS idx_events_corr_ts ON events(correlation_id, ts)",
    # sys-arch §7.2「按日期分组」：date(ts) 表达式索引支撑执行记录按日组织
    "CREATE INDEX IF NOT EXISTS idx_events_date ON events(date(ts), ts)",
    "CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type, ts)",
    # ---- error_ledger（memory-design §2.1/§10.2 逐字）----
    """
    CREATE TABLE IF NOT EXISTS error_ledger (
      id                   INTEGER PRIMARY KEY,
      error_signature      TEXT    NOT NULL,
      signature_hash       TEXT    NOT NULL,
      error_type           TEXT    NOT NULL,
      module               TEXT    NOT NULL,
      param_pattern        TEXT    NOT NULL,
      raw_error            TEXT    NOT NULL,
      root_cause           TEXT    NOT NULL DEFAULT '',
      fix_applied          TEXT    NOT NULL DEFAULT '',
      prevention_suggestion TEXT   NOT NULL DEFAULT '',
      task_id              TEXT    NOT NULL,
      role                 TEXT    NOT NULL,
      occurred_at          TEXT    NOT NULL,
      created_at           TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_ledger_hash_time ON error_ledger(signature_hash, occurred_at)",
    "CREATE INDEX IF NOT EXISTS idx_ledger_task ON error_ledger(task_id)",
    # ---- prevention_rules（memory-design §3.1/§10.2 逐字；状态机 candidate→active→retired）----
    """
    CREATE TABLE IF NOT EXISTS prevention_rules (
      id              INTEGER PRIMARY KEY,
      rule_text       TEXT    NOT NULL,
      match_keywords  TEXT    NOT NULL,
      task_types      TEXT    NOT NULL DEFAULT '*',
      status          TEXT    NOT NULL DEFAULT 'candidate'
                      CHECK (status IN ('candidate','active','retired')),
      source_error_ids TEXT   NOT NULL DEFAULT '[]',
      occurrences     INTEGER NOT NULL DEFAULT 0,
      risk_level      TEXT    NOT NULL DEFAULT 'high' CHECK (risk_level IN ('low','medium','high')),
      reviewed_by     TEXT,
      reviewed_at     TEXT,
      auto_activated  INTEGER NOT NULL DEFAULT 0,
      activated_at    TEXT,
      retired_at      TEXT,
      retire_reason   TEXT
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_rules_status ON prevention_rules(status, task_types)",
    # ---- approvals（ICON §6.1–§6.3 审批域；ARCH §5.2/§5.3 语义）----
    """
    CREATE TABLE IF NOT EXISTS approvals (
      id               TEXT PRIMARY KEY,
      task_id          TEXT NOT NULL REFERENCES tasks(id),
      subtask_id       TEXT,
      correlation_id   TEXT NOT NULL,
      status           TEXT NOT NULL DEFAULT 'waiting' CHECK (status IN ('waiting','decided','expired')),
      action_type      TEXT NOT NULL,
      risk_tier        TEXT NOT NULL CHECK (risk_tier IN ('irreversible','reversible_costly','reversible')),
      summary          TEXT NOT NULL,
      payload          TEXT NOT NULL DEFAULT '{}',
      evidence         TEXT NOT NULL DEFAULT '{}',
      edited_payload   TEXT,
      decision         TEXT CHECK (decision IN ('approve','use_edited','regenerate','reject')),
      decision_comment TEXT,
      decided_by       TEXT,
      decided_at       TEXT,
      wait_expires_at  TEXT NOT NULL,
      timeout_fallback TEXT NOT NULL DEFAULT 'skip_and_continue'
                       CHECK (timeout_fallback IN ('skip_and_continue','skip_strict')),
      created_at       TEXT NOT NULL,
      updated_at       TEXT NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_approvals_status ON approvals(status, wait_expires_at)",
    "CREATE INDEX IF NOT EXISTS idx_approvals_task ON approvals(task_id)",
    # ---- rules_kv（本 ask 指定：内核规则/配置运行态键值表，value 为 JSON 文本）----
    """
    CREATE TABLE IF NOT EXISTS rules_kv (
      key        TEXT PRIMARY KEY,
      value      TEXT NOT NULL,
      updated_at TEXT NOT NULL
    )
    """,
    # ---- schema_meta（memory-design §3.1/§10.2：部署首验与迁移用）----
    "CREATE TABLE IF NOT EXISTS schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
)

# FTS5 虚表 + 同步触发器（memory-design §2.1/§3.1 逐字）
_FTS_STATEMENTS: tuple[str, ...] = (
    # raw_error 必须进索引：实测证明只索引签名列时，"timeout" 这类只出现在原始错误
    # 文本里的关键词匹配不到（memory-design §1.3 实测 3 修正点）
    """
    CREATE VIRTUAL TABLE IF NOT EXISTS error_ledger_fts USING fts5(
      error_signature, raw_error, root_cause, fix_applied, prevention_suggestion,
      content='error_ledger', content_rowid='id'
    )
    """,
    """
    CREATE TRIGGER IF NOT EXISTS trg_ledger_ai AFTER INSERT ON error_ledger BEGIN
      INSERT INTO error_ledger_fts(rowid, error_signature, raw_error, root_cause, fix_applied, prevention_suggestion)
      VALUES (new.id, new.error_signature, new.raw_error, new.root_cause, new.fix_applied, new.prevention_suggestion);
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS trg_ledger_ad AFTER DELETE ON error_ledger BEGIN
      INSERT INTO error_ledger_fts(error_ledger_fts, rowid, error_signature, raw_error, root_cause, fix_applied, prevention_suggestion)
      VALUES ('delete', old.id, old.error_signature, old.raw_error, old.root_cause, old.fix_applied, old.prevention_suggestion);
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS trg_ledger_au AFTER UPDATE ON error_ledger BEGIN
      INSERT INTO error_ledger_fts(error_ledger_fts, rowid, error_signature, raw_error, root_cause, fix_applied, prevention_suggestion)
      VALUES ('delete', old.id, old.error_signature, old.raw_error, old.root_cause, old.fix_applied, old.prevention_suggestion);
      INSERT INTO error_ledger_fts(rowid, error_signature, raw_error, root_cause, fix_applied, prevention_suggestion)
      VALUES (new.id, new.error_signature, new.raw_error, new.root_cause, new.fix_applied, new.prevention_suggestion);
    END
    """,
    """
    CREATE VIRTUAL TABLE IF NOT EXISTS prevention_rules_fts USING fts5(
      rule_text, match_keywords,
      content='prevention_rules', content_rowid='id'
    )
    """,
    """
    CREATE TRIGGER IF NOT EXISTS trg_rules_ai AFTER INSERT ON prevention_rules BEGIN
      INSERT INTO prevention_rules_fts(rowid, rule_text, match_keywords)
      VALUES (new.id, new.rule_text, new.match_keywords);
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS trg_rules_ad AFTER DELETE ON prevention_rules BEGIN
      INSERT INTO prevention_rules_fts(prevention_rules_fts, rowid, rule_text, match_keywords)
      VALUES ('delete', old.id, old.rule_text, old.match_keywords);
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS trg_rules_au AFTER UPDATE ON prevention_rules BEGIN
      INSERT INTO prevention_rules_fts(prevention_rules_fts, rowid, rule_text, match_keywords)
      VALUES ('delete', old.id, old.rule_text, old.match_keywords);
      INSERT INTO prevention_rules_fts(rowid, rule_text, match_keywords)
      VALUES (new.id, new.rule_text, new.match_keywords);
    END
    """,
)

# FTS5 不可用降级路径（memory-design §1.4：虚表替换为同名普通表 + LIKE 扫描，接口签名不变）。
# 普通表带显式 id_ 列承接 content_rowid 语义，触发器改为实体 DELETE/UPDATE。
_FTS_FALLBACK_STATEMENTS: tuple[str, ...] = (
    """
    CREATE TABLE IF NOT EXISTS error_ledger_fts (
      id_                   INTEGER PRIMARY KEY,
      error_signature       TEXT NOT NULL DEFAULT '',
      raw_error             TEXT NOT NULL DEFAULT '',
      root_cause            TEXT NOT NULL DEFAULT '',
      fix_applied           TEXT NOT NULL DEFAULT '',
      prevention_suggestion TEXT NOT NULL DEFAULT ''
    )
    """,
    """
    CREATE TRIGGER IF NOT EXISTS trg_ledger_ai AFTER INSERT ON error_ledger BEGIN
      INSERT INTO error_ledger_fts(id_, error_signature, raw_error, root_cause, fix_applied, prevention_suggestion)
      VALUES (new.id, new.error_signature, new.raw_error, new.root_cause, new.fix_applied, new.prevention_suggestion);
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS trg_ledger_ad AFTER DELETE ON error_ledger BEGIN
      DELETE FROM error_ledger_fts WHERE id_ = old.id;
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS trg_ledger_au AFTER UPDATE ON error_ledger BEGIN
      UPDATE error_ledger_fts SET error_signature = new.error_signature, raw_error = new.raw_error,
        root_cause = new.root_cause, fix_applied = new.fix_applied,
        prevention_suggestion = new.prevention_suggestion
      WHERE id_ = new.id;
    END
    """,
    """
    CREATE TABLE IF NOT EXISTS prevention_rules_fts (
      id_            INTEGER PRIMARY KEY,
      rule_text      TEXT NOT NULL DEFAULT '',
      match_keywords TEXT NOT NULL DEFAULT ''
    )
    """,
    """
    CREATE TRIGGER IF NOT EXISTS trg_rules_ai AFTER INSERT ON prevention_rules BEGIN
      INSERT INTO prevention_rules_fts(id_, rule_text, match_keywords)
      VALUES (new.id, new.rule_text, new.match_keywords);
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS trg_rules_ad AFTER DELETE ON prevention_rules BEGIN
      DELETE FROM prevention_rules_fts WHERE id_ = old.id;
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS trg_rules_au AFTER UPDATE ON prevention_rules BEGIN
      UPDATE prevention_rules_fts SET rule_text = new.rule_text, match_keywords = new.match_keywords
      WHERE id_ = new.id;
    END
    """,
)


# ---------------------------------------------------------------------------
# schema 迁移（v1→v2：approvals.decision CHECK 扩容 +reject）
# ---------------------------------------------------------------------------

_APPROVALS_INDEX_STATEMENTS: tuple[str, ...] = (
    "CREATE INDEX IF NOT EXISTS idx_approvals_status ON approvals(status, wait_expires_at)",
    "CREATE INDEX IF NOT EXISTS idx_approvals_task ON approvals(task_id)",
)


def _migrate_approvals_add_reject(conn: sqlite3.Connection) -> None:
    """v1→v2 迁移：approvals.decision CHECK 增加 'reject'（approval.py 驳回动作，
    语义取 sys-arch §5.3 超时兜底分支的人工即时版：动作不执行，任务链跳过继续推进）。

    SQLite 不能 ALTER CHECK 约束，用「重命名旧表 → 按新 DDL 重建 → 拷贝 → 删旧 →
    重建索引」完成；迁移在单一事务内，任何一步失败整体回滚（sys-arch §3.3 原子性同源）。
    全新库直接建 v2 DDL，本函数检测到 'reject' 已存在时为 no-op。
    """
    row = conn.execute("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'approvals'").fetchone()
    if row is None:
        return  # 全新库：_SCHEMA_STATEMENTS 已按 v2 DDL 建表
    sql = str(row["sql"])
    if "'reject'" in sql:
        return  # 已是 v2
    conn.execute("BEGIN IMMEDIATE")
    try:
        conn.execute("ALTER TABLE approvals RENAME TO approvals_old_v1")
        conn.execute("""
            CREATE TABLE approvals (
              id               TEXT PRIMARY KEY,
              task_id          TEXT NOT NULL REFERENCES tasks(id),
              subtask_id       TEXT,
              correlation_id   TEXT NOT NULL,
              status           TEXT NOT NULL DEFAULT 'waiting' CHECK (status IN ('waiting','decided','expired')),
              action_type      TEXT NOT NULL,
              risk_tier        TEXT NOT NULL CHECK (risk_tier IN ('irreversible','reversible_costly','reversible')),
              summary          TEXT NOT NULL,
              payload          TEXT NOT NULL DEFAULT '{}',
              evidence         TEXT NOT NULL DEFAULT '{}',
              edited_payload   TEXT,
              decision         TEXT CHECK (decision IN ('approve','use_edited','regenerate','reject')),
              decision_comment TEXT,
              decided_by       TEXT,
              decided_at       TEXT,
              wait_expires_at  TEXT NOT NULL,
              timeout_fallback TEXT NOT NULL DEFAULT 'skip_and_continue'
                               CHECK (timeout_fallback IN ('skip_and_continue','skip_strict')),
              created_at       TEXT NOT NULL,
              updated_at       TEXT NOT NULL
            )
        """)
        conn.execute("INSERT INTO approvals SELECT * FROM approvals_old_v1")
        conn.execute("DROP TABLE approvals_old_v1")
        for stmt in _APPROVALS_INDEX_STATEMENTS:
            conn.execute(stmt)
        conn.execute("COMMIT")
    except BaseException:
        conn.execute("ROLLBACK")
        raise


# ---------------------------------------------------------------------------
# 连接管理器（memory-design §8.2：WAL + busy_timeout=5000 + 全局单写连接）
# ---------------------------------------------------------------------------

class Database:
    """SQLite WAL 单写连接管理器。

    - 单连接（check_same_thread=False）+ 进程内 RLock 串行化写——sys-arch §9.3 不变量 5
      「SQLite 单写连接」的进程内落点；
    - transaction() 为显式 BEGIN IMMEDIATE 写事务（可嵌套：内层并入外层事务，
      满足 sys-arch §3.3「状态变更与对应事件落库在同一 SQLite 事务内」）；
    - fts='auto'（默认）在 init 时探测 FTS5 可用性；不可用或 fts='off' 时按
      memory-design §1.4 降级为同名普通表 + LIKE 扫描（接口签名不变）。
    """

    def __init__(
        self,
        path: str | os.PathLike[str],
        *,
        busy_timeout_ms: int = DEFAULT_BUSY_TIMEOUT_MS,
        fts: str = "auto",
        fallback_dir: str | os.PathLike[str] | None = None,
    ) -> None:
        if fts not in ("auto", "off"):
            raise ValueError("fts must be 'auto' or 'off'")
        self.path: str = os.fspath(path)
        self.busy_timeout_ms: int = int(busy_timeout_ms)
        self.fts_mode_requested: str = fts
        self.fallback_dir: Path | None = Path(fallback_dir) if fallback_dir is not None else None
        self.fts_available: bool = False
        self.journal_mode: str = ""
        self._conn: sqlite3.Connection | None = None
        self._lock = threading.RLock()
        self._txn_depth = 0

    # -- 生命周期 -----------------------------------------------------------

    def connect(self) -> "Database":
        """建立连接并初始化 schema（幂等）。"""
        if self._conn is not None:
            return self
        if self.path != ":memory:":
            os.makedirs(os.path.dirname(os.path.abspath(self.path)) or ".", exist_ok=True)
        conn = sqlite3.connect(
            self.path,
            timeout=self.busy_timeout_ms / 1000.0,
            check_same_thread=False,
            isolation_level=None,  # 显式事务控制（BEGIN IMMEDIATE / COMMIT / ROLLBACK）
        )
        conn.row_factory = sqlite3.Row
        # memory-design §10.2 PRAGMA 头（顺序对齐）
        if self.path != ":memory:":
            self.journal_mode = str(conn.execute("PRAGMA journal_mode = WAL").fetchone()[0])
        else:
            self.journal_mode = "memory"
        conn.execute(f"PRAGMA busy_timeout = {self.busy_timeout_ms}")
        conn.execute("PRAGMA synchronous = NORMAL")
        conn.execute("PRAGMA foreign_keys = ON")
        self._conn = conn
        self.init_schema()
        return self

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                try:
                    self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                except sqlite3.Error:
                    pass  # checkpoint 失败（如他连接占用）不视为致命
                self._conn.close()
                self._conn = None
                self._txn_depth = 0

    def __enter__(self) -> "Database":
        return self.connect()

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.close()

    @property
    def conn(self) -> sqlite3.Connection:
        if self._conn is None:
            raise RuntimeError("database not connected; call connect() first")
        return self._conn

    # -- schema -------------------------------------------------------------

    def init_schema(self) -> None:
        """建全部表 + FTS5 虚表（或降级普通表）+ schema_meta（幂等）；含 v1→v2 迁移。"""
        conn = self.conn
        for stmt in _SCHEMA_STATEMENTS:
            conn.execute(stmt)
        _migrate_approvals_add_reject(conn)
        if self.fts_mode_requested == "auto":
            try:
                # FTS5 可用性探测（memory-design §10.3 部署首验第 1 条的进程内等价探针）
                conn.execute("CREATE VIRTUAL TABLE _fts5_probe USING fts5(x)")
                conn.execute("DROP TABLE _fts5_probe")
                for stmt in _FTS_STATEMENTS:
                    conn.execute(stmt)
                self.fts_available = True
                fts_mode = "fts5"
            except sqlite3.OperationalError:
                self._install_fts_fallback(conn)
                fts_mode = "like_fallback"
        else:
            self._install_fts_fallback(conn)
            fts_mode = "like_fallback"
        conn.execute("INSERT OR REPLACE INTO schema_meta VALUES ('fts_mode', ?)", (fts_mode,))
        conn.execute("INSERT OR REPLACE INTO schema_meta VALUES ('schema_version', ?)", (SCHEMA_VERSION,))

    @staticmethod
    def _install_fts_fallback(conn: sqlite3.Connection) -> None:
        """memory-design §1.4 降级：FTS5 虚表替换为同名普通表（触发器换实体同步），检索层换 LIKE。"""
        for stmt in _FTS_FALLBACK_STATEMENTS:
            conn.execute(stmt)

    # -- 读写入口 ------------------------------------------------------------

    @contextlib.contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """写事务上下文：BEGIN IMMEDIATE 起手，异常 ROLLBACK，正常 COMMIT。

        可嵌套（内层并入外层事务，最外层提交），用于把「状态变更 + 对应事件落库」
        放进同一事务（sys-arch §3.3 转移原子性）。
        """
        conn = self.conn
        with self._lock:
            if self._txn_depth == 0:
                conn.execute("BEGIN IMMEDIATE")
            self._txn_depth += 1
            try:
                yield conn
            except BaseException:
                self._txn_depth -= 1
                if self._txn_depth == 0:
                    conn.execute("ROLLBACK")
                raise
            else:
                self._txn_depth -= 1
                if self._txn_depth == 0:
                    conn.execute("COMMIT")

    def execute(self, sql: str, params: Sequence[Any] = ()) -> sqlite3.Cursor:
        """单条语句执行（自动提交模式；写路径请优先用 transaction()）。"""
        with self._lock:
            return self.conn.execute(sql, tuple(params))

    def query(self, sql: str, params: Sequence[Any] = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self.conn.execute(sql, tuple(params)).fetchall()

    def query_one(self, sql: str, params: Sequence[Any] = ()) -> sqlite3.Row | None:
        with self._lock:
            return self.conn.execute(sql, tuple(params)).fetchone()


# ---------------------------------------------------------------------------
# events 写入口（sys-arch §7.1：每条事件同步写 events 表，持久化以库为准）
# ---------------------------------------------------------------------------

def emit_event(
    conn: sqlite3.Connection,
    *,
    component: str,
    event_type: str,
    task_id: str | None = None,
    payload: dict[str, Any] | None = None,
    correlation_id: str | None = None,
    event_id: str | None = None,
    ts: str | None = None,
) -> str:
    """落一条事件并返回 event_id（ULID）。

    payload 为 JSON 文本；超 64KB 截断存 preview（sys-arch §7.2 载荷留存策略，
    大二进制落 artifacts 的引用面归后续交付物）。
    """
    eid = event_id or new_ulid()
    ts_val = ts or utc_now_iso()
    payload_text = json_dumps(payload if payload is not None else {})
    if len(payload_text) > PAYLOAD_MAX_CHARS:
        payload_text = json_dumps(
            {"truncated": True, "size_chars": len(payload_text), "preview": payload_text[:PAYLOAD_MAX_CHARS]}
        )
    if correlation_id is None and task_id is not None:
        row = conn.execute("SELECT correlation_id FROM tasks WHERE id = ?", (task_id,)).fetchone()
        correlation_id = row["correlation_id"] if row is not None else None
    conn.execute(
        "INSERT INTO events (event_id, ts, task_id, component, event_type, payload, correlation_id)"
        " VALUES (?, ?, ?, ?, ?, ?, ?)",
        (eid, ts_val, task_id, component, event_type, payload_text, correlation_id),
    )
    return eid


# ---------------------------------------------------------------------------
# rules_kv 访问器（本 ask 指定表；value 任意 JSON 可序列化对象）
# ---------------------------------------------------------------------------

def kv_set(database: Database, key: str, value: Any) -> None:
    with database.transaction() as conn:
        conn.execute(
            "INSERT INTO rules_kv (key, value, updated_at) VALUES (?, ?, ?)"
            " ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
            (key, json_dumps(value), utc_now_iso()),
        )


def kv_get(database: Database, key: str, default: Any = None) -> Any:
    row = database.query_one("SELECT value FROM rules_kv WHERE key = ?", (key,))
    if row is None:
        return default
    return json.loads(row["value"])
