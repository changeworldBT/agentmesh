"""ledger.py — 错误账本：签名规范化 / write_guard 脱敏 / ledger_write 单一写入口 / FTS5 检索 /
同签名滑窗 ≥2 次自动生成 prevention_rules 草案（待确认位）。

设计文档出处（模块顶部注记，按本 ask 要求）：
- memory-design（MEM-ERR-01）§2.1：error_ledger 表（建表在 db.py，本模块只读写）；
  §2.2 签名规范化算法（normalize_param / make_signature 逐字，含指纹 = sha256 前 16 位）；
  §2.3 raw_error 截断（超 4000 字符截取首 4000 字符）；§2.4/§6.3 ledger_write() 单一
  写入入口（签名固定为 error_type, module, params, raw_error, task_id, role,
  root_cause, fix_applied）；
- memory-design §3.1：prevention_rules 表（建表在 db.py）；§3.2 状态机 candidate →
  active → retired（待确认位 = status='candidate' 且 reviewed_by IS NULL，不参与检索
  注入）；白名单自动生效判据（risk_level='low' 且 match_keywords 命中白名单，两道闸
  同时满足才跳过人工）；
- memory-design §4：读写时机矩阵与统一降级原则（读接口失败返回空 + memory_degraded
  事件；写失败重试一次 → 兜底文件 + 降级事件，不中断任务主流程）；
- memory-design §5：沉淀流程全链路（①滑窗 ≥2 唯一门槛 → ②LLM 归纳 → ③回放校验
  「先红」（最多重归纳 1 次）→ ④FTS 去重合并 → ⑤入库定级 → ⑥人工审核）；§5.2 归纳
  约束（祈使句、禁 URL/凭证值、LLM 失败不重试超过 1 次）；§5.3 occurrences 语义
  （记录该规则关联签名的累计触发次数）；
- memory-design §6.1：FTS5 MATCH 模板（token 强制双引号包裹，前缀 * 必须在引号外，
  引号内带 * 返回空——实测教训）与 search_errors / search_rules；
- memory-design §8.1：write_guard()（先判拒后脱敏——e2e 实测修正点；与 credentials-spec
  日志脱敏钩子共用同一份 _SANITIZERS 定义）；
- sys-arch（ARCH-ROOT-01）§3.2 T11：done 触发规则沉淀检查；§4.2/§4.3：prevention_rules
  强制注入与规则沉淀闭环；§7.1：错误登记等每步动作事件化落库。

偏离与取舍（如实声明）：
- 布局：设计文档把 error_signature / write_guard / memory_store 分列在
  app/engine/core/ 三模块（§2.2/§8.1/§6.1 的路径注释）；本 ask 的内核 MVP 布局为
  app/engine/ledger.py 单模块，三函数族合并于此，函数名 / 签名 / 正则逐字保持设计文档
  定义。search_errors/search_rules 的首参按 §8.2「共用同一连接管理器」取 Database。
- 沉淀第 ② 步 LLM 归纳需要统一 API 网关（sys-arch §2.3），不在本 MVP 范围：
  consolidation_check 以 llm_drafter 可调参数预留归纳位；未注入时按确定性模板生成草案
  （文案取自账本已脱敏字段，不含 URL/凭证值——§5.2 约束），risk_level 一律 'high'
  （从严：必走人工审核位，永不触发白名单自动生效）。
- occurrences 合并语义取 §5.3「累计触发次数」：合并分支按新增 source_error_ids 数量
  追加（§3.1 DDL 注释「累计追加」的同向解读），不重复累计同一滑窗内的旧行。
- lessons.yaml 导出（§5.1 第 ⑦ 步）与 errors→规则的人工多按钮路由 UI 归规则装载器/
  审批门组件，不在本 ask 范围，未实现。
- §5.1 第 ⑥ 步「驳回」按钮的 candidate 去向设计未定义（§3.2 状态机 candidate 只有两个
  出边：→active、（§5.1 ⑧ 随时废止）→retired）：review_rule 仅实现批准（candidate→
  active 与 retired→active 复活），驳回抛错并注明设计缺口。
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from collections.abc import Callable, Sequence
from typing import Any

from app.engine.db import (
    Database,
    emit_event,
    iso_shift,
    json_dumps,
    utc_now_iso,
)

# ---------------------------------------------------------------------------
# 签名规范化（memory-design §2.2 逐字）
# ---------------------------------------------------------------------------

_VALUE_PATTERNS = [
    (re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*://\S+"), "<URL>"),
    (re.compile(r"^[~/][^\s]*"), "<PATH>"),
    (re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I), "<UUID>"),
    (re.compile(r"^\d+(\.\d+)?$"), "<N>"),
    (re.compile(r"^(sk-|AKIA|Bearer\s+)[A-Za-z0-9._\-]{8,}$"), "<SECRET>"),
]


def normalize_param(value: str) -> str:
    """参数值归一化（memory-design §2.2 第 3 步：URL/路径/UUID/数字/疑似凭证 → 占位符，其余截 64）。"""
    v = str(value).strip()
    for pat, repl in _VALUE_PATTERNS:
        if pat.match(v):
            return repl
    return v[:64]


def make_signature(error_type: str, module: str, params: dict[str, str]) -> tuple[str, str]:
    """返回 (可读签名, 指纹)。指纹 = sha256(签名) 前 16 位 hex（memory-design §2.2）。"""
    param_mode = ",".join(
        f"{k}={normalize_param(v)}" for k, v in sorted(params.items())
    )
    readable = f"{error_type} @ {module} [{param_mode}]"
    digest = hashlib.sha256(readable.encode("utf-8")).hexdigest()[:16]
    return readable, digest


# ---------------------------------------------------------------------------
# write_guard（memory-design §8.1 逐字；先判拒后脱敏）
# ---------------------------------------------------------------------------

_SANITIZERS = [
    (re.compile(r"sk-[A-Za-z0-9]{16,}"), "<REDACTED:api_key>"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "<REDACTED:aws_key>"),
    (re.compile(r"Bearer\s+[A-Za-z0-9._\-]{16,}"), "<REDACTED:bearer>"),
    (re.compile(r"AGE-SECRET-KEY-[A-Z0-9]{40,}"), "<REDACTED:age_key>"),
    (re.compile(r"(?i)(password|passwd|secret|token|api_key)\s*[=:]\s*\S+"),
     r"\1=<REDACTED>"),
]

# 整字段即凭证：原始输入整体命中的，拒绝写入
_REJECT = re.compile(r"^(sk-|AKIA|AGE-SECRET-KEY-)[A-Za-z0-9._\-]{16,}$")


def write_guard(text: str) -> str:
    """写入前校验钩子（memory-design §8.1）。

    拒绝校验必须在脱敏之前：先脱敏会把整字段凭证改成 <REDACTED:...>，
    拒绝分支就永远不可达（e2e 实测发现后修正）。
    """
    out = str(text)
    if _REJECT.match(out.strip()):
        raise ValueError("write rejected: field itself looks like a credential")
    for pat, repl in _SANITIZERS:
        out = pat.sub(repl, out)
    return out


# ---------------------------------------------------------------------------
# FTS5 MATCH 模板（memory-design §6.1 逐字，含实测教训）
# ---------------------------------------------------------------------------

def _fts_query(tokens: list[str], operator: str = "AND") -> str:
    """把关键词列表编译成安全的 FTS5 MATCH 表达式。

    实测 1：无引号的 'heap-buffer-overflow' 报 no such column: buffer，
            双引号短语查询则正确命中。
    实测 2：'\"timeou*\"' 返回空；'\"timeou\"*'（星号在引号外）正确前缀匹配。
    operator=AND（默认，§6.1 语义）/ OR（注入场景任一命中即候选，调用方 limit 截断）。
    """
    if operator not in ("AND", "OR"):
        raise ValueError(f"fts operator must be AND/OR, got {operator!r}")
    cleaned = []
    for t in tokens:
        t = t.replace('"', "").strip()
        if not t:
            continue
        if t.endswith("*"):
            cleaned.append(f'"{t[:-1]}"*')  # 星号必须在引号外
        else:
            cleaned.append(f'"{t}"')
    return f" {operator} ".join(cleaned)


def _like_tokens(tokens: Sequence[str]) -> list[str]:
    """LIKE 降级扫描用的纯子串 token（去引号与前缀星号）。"""
    out: list[str] = []
    for t in tokens:
        t = t.replace('"', "").strip()
        if t.endswith("*"):
            t = t[:-1]
        if t:
            out.append(t)
    return out


# ---------------------------------------------------------------------------
# 常量（memory-design §2.3 / §5.1 / §4）
# ---------------------------------------------------------------------------

RAW_ERROR_MAX_CHARS = 4000      # §2.3：超 4000 字符截取首 4000
SLIDING_WINDOW_HOURS = 24       # §5.1 ①：滑窗 = 最近 24h
CONSOLIDATION_THRESHOLD = 2     # §5 铁律 1：同类错犯两次才立规矩（≥2 唯一门槛）
DEGRADED_EVENT_TYPE = "memory_degraded"   # §4 统一降级事件
DEFAULT_WHITELIST: tuple[str, ...] = ("timeout", "retry-limit", "disk-check", "dry-run-first")
# —— 白名单初始值出处：rules-config §2.1「prevention_auto_activate_whitelist」
#    （memory-design §3.2 引用为 global.yaml 键；本 MVP 以参数/默认值承接，yaml 装载归规则装载器）

LLMDrafter = Callable[[list[dict[str, Any]], bool], dict[str, Any] | None]
"""沉淀第 ② 步 LLM 归纳位（§5.1 ②/§5.2）。

入参：(同签名最近 3 条错误的 {error_signature, raw_error, root_cause, fix_applied,
prevention_suggestion}（已脱敏）, retry 标记)。返回 {rule_text, match_keywords,
task_types, risk_level} 或 None（LLM 失败/超时 → 候选不强行生成，留待下次 done 补跑）。
"""


# ---------------------------------------------------------------------------
# 降级路径（memory-design §4）
# ---------------------------------------------------------------------------

def _emit_degraded(database: Database, surface: str, detail: Sequence[Any]) -> None:
    """统一降级事件：memory_degraded（可观测台按事件计数告警，不允许「悄悄变瞎」）。"""
    try:
        with database.transaction() as conn:
            emit_event(conn, component="error_ledger", event_type=DEGRADED_EVENT_TYPE,
                       payload={"surface": surface,
                                "detail": [str(d) for d in detail][:8]})
    except sqlite3.Error:
        pass  # 库不可用时降级事件本身也写不进——不再级联抛出


def _write_fallback_file(database: Database, record: dict[str, Any]) -> str | None:
    """§4 写降级兜底文件：<fallback_dir>/<ts>.json；未配置 fallback_dir 时跳过。"""
    if database.fallback_dir is None:
        return None
    database.fallback_dir.mkdir(parents=True, exist_ok=True)
    # 文件名取 UTC 时间戳，冒号/点替换为 Windows/Linux 双安全形态
    stamp = utc_now_iso().replace(":", "").replace(".", "-")
    path = database.fallback_dir / f"{stamp}.json"
    path.write_text(json_dumps(record), encoding="utf-8")
    return str(path)


# ---------------------------------------------------------------------------
# ledger_write 单一写入口（memory-design §2.4/§6.3）
# ---------------------------------------------------------------------------

def _ledger_write_once(
    database: Database,
    error_type: str,
    module: str,
    params: dict[str, str],
    guarded_raw: str,
    task_id: str,
    role: str,
    guarded_root: str,
    guarded_fix: str,
    guarded_suggestion: str,
    occurred_at: str | None,
) -> int:
    # 内部顺序（§6.3）：write_guard 脱敏已完成（先判拒后脱敏 §8.1，见 ledger_write）
    # → raw_error 截断首 4000（§2.3）→ make_signature 计算签名与指纹（§2.2）
    # → 单写连接 INSERT + error_registered 事件（§7.1）
    raw_stored = guarded_raw[:RAW_ERROR_MAX_CHARS]
    readable, digest = make_signature(
        str(error_type), str(module),
        {str(k): str(v) for k, v in (params or {}).items()},
    )
    occurred = occurred_at or utc_now_iso()
    with database.transaction() as conn:
        cur = conn.execute(
            "INSERT INTO error_ledger (error_signature, signature_hash, error_type, module,"
            " param_pattern, raw_error, root_cause, fix_applied, prevention_suggestion,"
            " task_id, role, occurred_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (readable, digest, str(error_type), str(module),
             ",".join(f"{k}={normalize_param(str(v))}" for k, v in sorted((params or {}).items())),
             raw_stored, guarded_root, guarded_fix, guarded_suggestion,
             str(task_id), str(role), occurred),
        )
        entry_id = int(cur.lastrowid)
        emit_event(conn, task_id=str(task_id), component="error_ledger",
                   event_type="error_registered",
                   payload={"entry_id": entry_id, "error_signature": readable,
                            "signature_hash": digest, "module": str(module), "role": str(role)})
    return entry_id


def ledger_write(
    database: Database,
    error_type: str,
    module: str,
    params: dict[str, str],
    raw_error: str,
    task_id: str,
    role: str,
    root_cause: str = "",
    fix_applied: str = "",
    *,
    prevention_suggestion: str = "",
    occurred_at: str | None = None,
) -> int:
    """错误账本唯一写入入口（memory-design §2.4/§6.3，签名固定），返回 entry_id。

    内部顺序（§6.3）：write_guard 脱敏（先判拒后脱敏 §8.1）→ raw_error 截断首 4000（§2.3）
    → make_signature 签名与指纹（§2.2）→ 单写连接 INSERT + error_registered 事件（§7.1）。
    调用方传入的 params 为 dict[str, str]（键名保留、值按 §2.2 归一化折叠进 param_pattern）。
    写失败本地重试一次，仍失败 → 兜底文件 + memory_degraded 事件（§4）；write_guard 的
    整字段凭证拒绝（ValueError）属调用方错误，不重试直接上抛（§8.1 拒绝写入）。
    """
    # write_guard 在重试循环外只算一次：拒绝分支（ValueError）在此直接上抛，
    # 后续重试不再重复脱敏
    guarded_raw = write_guard(raw_error)
    guarded_root = write_guard(root_cause) if root_cause else ""
    guarded_fix = write_guard(fix_applied) if fix_applied else ""
    guarded_suggestion = write_guard(prevention_suggestion) if prevention_suggestion else ""
    last_error: sqlite3.Error | None = None
    for attempt in (1, 2):
        try:
            return _ledger_write_once(
                database, error_type, module, params, guarded_raw, task_id, role,
                guarded_root, guarded_fix, guarded_suggestion, occurred_at,
            )
        except sqlite3.Error as exc:
            last_error = exc
    record = {
        "error_type": str(error_type), "module": str(module),
        "params": {str(k): normalize_param(str(v)) for k, v in (params or {}).items()},
        "raw_error": guarded_raw[:RAW_ERROR_MAX_CHARS],
        "task_id": str(task_id), "role": str(role),
        "root_cause": guarded_root, "fix_applied": guarded_fix,
        "occurred_at": occurred_at or utc_now_iso(),
    }
    fallback_path = _write_fallback_file(database, record)
    _emit_degraded(database, "ledger_write", [str(module), str(error_type), fallback_path or "no_fallback_dir"])
    assert last_error is not None
    raise last_error


# ---------------------------------------------------------------------------
# 检索接口（memory-design §6.1/§6.2；外层 try/except → [] + memory_degraded 事件）
# ---------------------------------------------------------------------------

_ERRORS_COLUMNS = (
    "id", "error_signature", "error_type", "module",
    "root_cause", "fix_applied", "prevention_suggestion", "occurred_at",
)


def _search_errors_inner(database: Database, keywords: list[str], limit: int,
                         keyword_operator: str = "AND") -> list[dict[str, Any]]:
    q = _fts_query(keywords, operator=keyword_operator)
    if not q:
        return []
    conn = database.conn
    if database.fts_available:
        rows = conn.execute(
            """
            SELECT e.id, e.error_signature, e.error_type, e.module,
                   e.root_cause, e.fix_applied, e.prevention_suggestion,
                   e.occurred_at
            FROM error_ledger e
            JOIN error_ledger_fts f ON f.rowid = e.id
            WHERE error_ledger_fts MATCH :q
            ORDER BY rank
            LIMIT :limit
            """,
            {"q": q, "limit": limit},
        ).fetchall()
    else:
        # memory-design §1.4 降级：同名普通表 + LIKE 扫描（接口签名不变，仅实现换）
        tokens = _like_tokens(keywords)
        if not tokens:
            return []
        conds = []
        params: dict[str, Any] = {"limit": limit}
        for i, tok in enumerate(tokens):
            conds.append(
                f"(f.error_signature LIKE :l{i} OR f.raw_error LIKE :l{i}"
                f" OR f.root_cause LIKE :l{i} OR f.fix_applied LIKE :l{i}"
                f" OR f.prevention_suggestion LIKE :l{i})"
            )
            params[f"l{i}"] = f"%{tok}%"
        rows = conn.execute(
            "SELECT e.id, e.error_signature, e.error_type, e.module,"
            " e.root_cause, e.fix_applied, e.prevention_suggestion, e.occurred_at"
            " FROM error_ledger e JOIN error_ledger_fts f ON f.id_ = e.id"
            f" WHERE {' AND '.join(conds)} ORDER BY e.occurred_at DESC LIMIT :limit",
            params,
        ).fetchall()
    return [dict(zip(_ERRORS_COLUMNS, r)) for r in rows]


def search_errors(database: Database, keywords: list[str], limit: int = 5,
                  *, keyword_operator: str = "AND") -> list[dict[str, Any]]:
    """相似错误检索（memory-design §6.1；默认 limit=5 对应 Planner→brief 场景，§6.2）。

    keyword_operator：AND（默认，§6.1 全词命中）/ OR（brief 注入场景任一词命中即候选）。
    """
    try:
        return _search_errors_inner(database, keywords, limit, keyword_operator)
    except sqlite3.Error:
        _emit_degraded(database, "search_errors", keywords)
        return []


def _search_rules_inner(database: Database, keywords: list[str], task_type: str, limit: int,
                        keyword_operator: str = "AND") -> list[dict[str, Any]]:
    q = _fts_query(keywords, operator=keyword_operator)
    if not q:
        return []
    conn = database.conn
    if database.fts_available:
        rows = conn.execute(
            """
            SELECT p.id, p.rule_text, p.task_types, p.risk_level, p.occurrences
            FROM prevention_rules p
            JOIN prevention_rules_fts f ON f.rowid = p.id
            WHERE prevention_rules_fts MATCH :q
              AND p.status = 'active'
              AND (p.task_types = '*' OR p.task_types LIKE :tt)
            ORDER BY rank
            LIMIT :limit
            """,
            {"q": q, "limit": limit, "tt": f"%{task_type}%"},
        ).fetchall()
    else:
        tokens = _like_tokens(keywords)
        if not tokens:
            return []
        conds = []
        params: dict[str, Any] = {"limit": limit, "tt": f"%{task_type}%"}
        for i, tok in enumerate(tokens):
            conds.append(f"(f.rule_text LIKE :l{i} OR f.match_keywords LIKE :l{i})")
            params[f"l{i}"] = f"%{tok}%"
        rows = conn.execute(
            "SELECT p.id, p.rule_text, p.task_types, p.risk_level, p.occurrences"
            " FROM prevention_rules p JOIN prevention_rules_fts f ON f.id_ = p.id"
            f" WHERE {' AND '.join(conds)} AND p.status = 'active'"
            " AND (p.task_types = '*' OR p.task_types LIKE :tt)"
            " ORDER BY p.occurrences DESC LIMIT :limit",
            params,
        ).fetchall()
    return [dict(zip(("id", "rule_text", "task_types", "risk_level", "occurrences"), r)) for r in rows]


def search_rules(
    database: Database,
    keywords: list[str],
    task_type: str = "*",
    limit: int = 3,
    *,
    keyword_operator: str = "AND",
) -> list[dict[str, Any]]:
    """生效预防规则检索（memory-design §6.1；仅 status='active' 参与，candidate 不参与注入）。

    keyword_operator：AND（默认，§6.1 全词命中）/ OR（brief 注入场景任一词命中即候选）。
    """
    try:
        return _search_rules_inner(database, keywords, task_type, limit, keyword_operator)
    except sqlite3.Error:
        _emit_degraded(database, "search_rules", keywords)
        return []


# ---------------------------------------------------------------------------
# 沉淀流程（memory-design §5 全链路；sys-arch §3.2 T11 的执行体）
# ---------------------------------------------------------------------------

def count_signature_occurrences(
    database: Database,
    signature_hash: str,
    *,
    window_hours: float | None = SLIDING_WINDOW_HOURS,
    now: str | None = None,
) -> int:
    """滑窗计数（memory-design §5.1 ①：最近 24h 内同 signature_hash 的全局行数，SQL 等值匹配，不走 FTS）。

    window_hours=None 计全时段（规则沉淀固定用 24h 滑窗；审批门 R1 升级计数
    rules-config §2.1 escalate_after_occurrences 未限定窗口，按全时段累计）。
    """
    if window_hours is None:
        row = database.query_one(
            "SELECT COUNT(*) AS n FROM error_ledger WHERE signature_hash = ?",
            (signature_hash,),
        )
        return int(row["n"]) if row is not None else 0
    now_ts = now or utc_now_iso()
    cutoff = iso_shift(now_ts, -window_hours * 3600)
    row = database.query_one(
        "SELECT COUNT(*) AS n FROM error_ledger WHERE signature_hash = ? AND occurred_at >= ?",
        (signature_hash, cutoff),
    )
    return int(row["n"]) if row is not None else 0


def _raw_tokens(raw: str, count: int) -> list[str]:
    """从原始错误文本提取前 count 个去重 ASCII 词 token（重归纳时扩展关键词用）。"""
    out: list[str] = []
    for tok in re.findall(r"[A-Za-z_][A-Za-z0-9_\-]{3,}", raw or ""):
        t = tok.strip("-_")
        if t and t not in out:
            out.append(t)
        if len(out) >= count:
            break
    return out


def _draft_rule(
    group_rows: list[sqlite3.Row],
    window_count: int,
    *,
    llm_drafter: LLMDrafter | None = None,
    retry: bool = False,
) -> dict[str, Any] | None:
    """沉淀第 ② 步：产出候选规则 {rule_text, match_keywords, task_types, risk_level}。

    llm_drafter 注入时走 LLM 归纳（§5.2，失败返回 None → 不强行生成）；未注入时按
    确定性模板生成（MVP：文案取自账本已脱敏字段，risk_level='high' 从严，必走人工审核位）。
    """
    source_rows = [
        {k: row[k] for k in ("error_signature", "raw_error", "root_cause", "fix_applied", "prevention_suggestion")}
        for row in group_rows[-3:]
    ]
    source_error_ids = [int(row["id"]) for row in group_rows]
    signature_hash = str(group_rows[0]["signature_hash"])
    if llm_drafter is not None:
        spec = llm_drafter(source_rows, retry)
        if spec is None:
            return None  # §5.2：LLM 失败或超时不重试超过 1 次，候选不强行生成
        rule_text = str(spec["rule_text"]).strip()
        match_keywords = str(spec["match_keywords"]).strip()
        task_types = str(spec.get("task_types", "*") or "*").strip() or "*"
        risk_level = str(spec.get("risk_level", "high")).strip().lower()
        if risk_level not in ("low", "medium", "high"):
            risk_level = "high"
        if not rule_text or not match_keywords:
            return None
        return {"rule_text": rule_text, "match_keywords": match_keywords, "task_types": task_types,
                "risk_level": risk_level, "signature_hash": signature_hash,
                "window_count": window_count, "source_error_ids": source_error_ids}
    # 确定性草案（本 MVP 默认路径）
    latest = group_rows[-1]
    error_type = str(latest["error_type"])
    module = str(latest["module"])
    suggestion = str(latest["prevention_suggestion"] or "").strip()
    if suggestion:
        rule_text = suggestion
    else:
        rule_text = (
            f"再次调用 {module} 出现 {error_type} 前，先复核参数模式 "
            f"[{latest['param_pattern']}] 并按既往修复方式处置后再重试，避免同签名错误重复发生"
        )
    tokens = [module, error_type]
    tokens += [p.split("=", 1)[0] for p in str(latest["param_pattern"]).split(",") if p]
    if retry:
        tokens += _raw_tokens(str(latest["raw_error"]), 3)
    match_keywords = " ".join(dict.fromkeys(tokens))  # 去重保序
    return {"rule_text": rule_text, "match_keywords": match_keywords, "task_types": "*",
            "risk_level": "high", "signature_hash": signature_hash,
            "window_count": window_count, "source_error_ids": source_error_ids}


def _replay_validate(database: Database, candidate: dict[str, Any]) -> bool:
    """沉淀第 ③ 步回放校验「先红」（memory-design §5.1 ③ / poteto-methodology M23）。

    以 match_keywords 对（error_signature / raw_error / root_cause / ...）做 FTS 检索，
    必须命中候选 source_error_ids 中的全部错误（≥1 条）；检索层故障视为未命中
    （候选放弃，不进入人工审核——防止连来源错误都匹配不上的空规则注入后形同虚设）。
    """
    keywords = [t for t in candidate["match_keywords"].split() if t]
    try:
        hits = {int(row["id"]) for row in _search_errors_inner(database, keywords, limit=10)}
    except sqlite3.Error:
        return False
    needed = set(candidate["source_error_ids"])
    return bool(needed) and needed <= hits


def _find_similar_rule(database: Database, candidate: dict[str, Any]) -> sqlite3.Row | None:
    """沉淀第 ④ 步去重：FTS MATCH rule_text/match_keywords 找相近的 active/candidate 规则。"""
    conn = database.conn
    for token_source in (candidate["rule_text"].split(), candidate["match_keywords"].split()):
        q = _fts_query([t for t in token_source if t][:8])
        if not q:
            continue
        if database.fts_available:
            row = conn.execute(
                "SELECT p.* FROM prevention_rules p JOIN prevention_rules_fts f ON f.rowid = p.id"
                " WHERE prevention_rules_fts MATCH :q AND p.status IN ('active','candidate')"
                " ORDER BY rank LIMIT 1",
                {"q": q},
            ).fetchone()
        else:
            tokens = _like_tokens([t for t in token_source if t][:8])
            if not tokens:
                continue
            conds = []
            params: dict[str, Any] = {}
            for i, tok in enumerate(tokens):
                conds.append(f"(f.rule_text LIKE :l{i} OR f.match_keywords LIKE :l{i})")
                params[f"l{i}"] = f"%{tok}%"
            row = conn.execute(
                "SELECT p.* FROM prevention_rules p JOIN prevention_rules_fts f ON f.id_ = p.id"
                f" WHERE {' AND '.join(conds)} AND p.status IN ('active','candidate') LIMIT 1",
                params,
            ).fetchone()
        if row is not None:
            return row
    return None


def _insert_rule(database: Database, candidate: dict[str, Any], task_id: str) -> int:
    """沉淀第 ⑤ 步入库定级：INSERT candidate（待确认位：status='candidate' 且 reviewed_by NULL）。"""
    with database.transaction() as conn:
        cur = conn.execute(
            "INSERT INTO prevention_rules (rule_text, match_keywords, task_types, status,"
            " source_error_ids, occurrences, risk_level) VALUES (?, ?, ?, 'candidate', ?, ?, ?)",
            (candidate["rule_text"], candidate["match_keywords"], candidate["task_types"],
             json_dumps(candidate["source_error_ids"]), int(candidate["window_count"]),
             candidate["risk_level"]),
        )
        rule_id = int(cur.lastrowid)
        emit_event(conn, task_id=task_id, component="error_ledger", event_type="rule_candidate",
                   payload={"rule_id": rule_id, "status": "candidate",
                            "risk_level": candidate["risk_level"],
                            "match_keywords": candidate["match_keywords"],
                            "signature_hash": candidate["signature_hash"],
                            "occurrences": int(candidate["window_count"]),
                            "source_error_ids": candidate["source_error_ids"],
                            "note": "待确认位：candidate + reviewed_by NULL，不参与检索注入（memory-design §3.2）"})
    return rule_id


def auto_activate_if_whitelisted(
    database: Database,
    rule_id: int,
    *,
    whitelist: Sequence[str] | None = None,
    now: str | None = None,
) -> bool:
    """§3.2 白名单自动生效（两道闸：risk_level='low' 且 match_keywords 命中白名单任一关键词）。

    清单外或非 low 一律人工；本 MVP 确定性草案 risk_level='high'，永不自动生效。
    """
    wl = tuple(whitelist) if whitelist is not None else DEFAULT_WHITELIST
    row = database.query_one(
        "SELECT id, match_keywords, risk_level, status FROM prevention_rules WHERE id = ?", (rule_id,)
    )
    if row is None or row["status"] != "candidate" or row["risk_level"] != "low":
        return False
    kws = [t for t in str(row["match_keywords"]).split() if t]
    if not any(w == t or w in t for w in wl for t in kws):
        return False
    now_ts = now or utc_now_iso()
    with database.transaction() as conn:
        conn.execute(
            "UPDATE prevention_rules SET status = 'active', auto_activated = 1, activated_at = ?"
            " WHERE id = ?",
            (now_ts, rule_id),
        )
        emit_event(conn, component="error_ledger", event_type="rule_auto_activated",
                   payload={"rule_id": rule_id, "note": "白名单自动生效（auto_activated=1，无人工审核）"})
    return True


def consolidation_check(
    database: Database,
    task_id: str,
    *,
    now: str | None = None,
    whitelist: Sequence[str] | None = None,
    llm_drafter: LLMDrafter | None = None,
) -> dict[str, Any]:
    """T11 沉淀检查（memory-design §5.1 全链路 ①–⑤ + §5.3 occurrences 语义）。

    步骤：① 取本任务全部 error_ledger 行按 signature_hash 分组、查 24h 全局滑窗 →
    ≥2 才进入沉淀 → ② 归纳（llm_drafter 或确定性模板）→ ③ 回放校验先红（不命中退回
    ② 重归纳 1 次，仍不命中放弃并落 memory_degraded 类降级事件，不进入人工审核）→
    ④ FTS 去重合并（只追加 source_error_ids 与 occurrences）→ ⑤ 入库 candidate
    （待确认位），low+白名单两道闸满足才 auto_activated。
    """
    now_ts = now or utc_now_iso()
    drafted: list[dict[str, Any]] = []
    merged: list[dict[str, Any]] = []
    aborted: list[dict[str, Any]] = []
    below_threshold = 0
    rows = database.query(
        "SELECT * FROM error_ledger WHERE task_id = ? ORDER BY id", (task_id,)
    )
    groups: dict[str, list[sqlite3.Row]] = {}
    for row in rows:
        groups.setdefault(str(row["signature_hash"]), []).append(row)

    for signature_hash, group_rows in groups.items():
        window_count = count_signature_occurrences(database, signature_hash, now=now_ts)
        if window_count < CONSOLIDATION_THRESHOLD:
            below_threshold += 1
            continue  # §5 铁律 1：滑窗 ≥2 是唯一沉淀门槛，不因单次错误的严重性提前立规
        candidate = _draft_rule(group_rows, window_count, llm_drafter=llm_drafter)
        # ③ 回放校验（最多重归纳 1 次；§5.2 LLM 失败候选不强行生成）
        if candidate is None or not _replay_validate(database, candidate):
            candidate = _draft_rule(group_rows, window_count, llm_drafter=llm_drafter, retry=True)
            if candidate is None or not _replay_validate(database, candidate):
                _emit_degraded(database, "rule_draft_aborted", [signature_hash])
                aborted.append({"signature_hash": signature_hash,
                                "reason": "replay_validation_missed_or_llm_unavailable"})
                continue
        # ④ 去重合并：已存在相近 active/candidate 规则 → 只追加 source_error_ids 与 occurrences
        existing = _find_similar_rule(database, candidate)
        if existing is not None:
            existing_sources = set(json.loads(str(existing["source_error_ids"] or "[]")))
            added = [i for i in candidate["source_error_ids"] if i not in existing_sources]
            if added:
                with database.transaction() as conn:
                    conn.execute(
                        "UPDATE prevention_rules SET source_error_ids = ?, occurrences = occurrences + ?"
                        " WHERE id = ?",
                        (json_dumps(sorted(existing_sources | set(added))), len(added), int(existing["id"])),
                    )
            after = database.query_one(
                "SELECT occurrences FROM prevention_rules WHERE id = ?", (int(existing["id"]),)
            )
            with database.transaction() as conn:
                emit_event(conn, task_id=task_id, component="error_ledger", event_type="rule_merged",
                           payload={"rule_id": int(existing["id"]),
                                    "signature_hash": signature_hash,
                                    "added_source_error_ids": added,
                                    "occurrences_after": int(after["occurrences"]) if after is not None else None})
            merged.append({"rule_id": int(existing["id"]), "added_source_error_ids": added,
                           "occurrences_after": int(after["occurrences"]) if after is not None else None})
            continue
        # ⑤ 入库定级（待确认位）+ low+白名单两道闸自动生效
        rule_id = _insert_rule(database, candidate, task_id)
        activated = auto_activate_if_whitelisted(database, rule_id, whitelist=whitelist, now=now_ts)
        drafted.append({"rule_id": rule_id, "status": "active" if activated else "candidate",
                        "auto_activated": activated,
                        "risk_level": candidate["risk_level"],
                        "occurrences": int(candidate["window_count"]),
                        "signature_hash": signature_hash})

    with database.transaction() as conn:
        emit_event(conn, task_id=task_id, component="error_ledger", event_type="consolidation_check",
                   payload={"checked_signatures": len(groups), "drafted": len(drafted),
                            "merged": len(merged), "aborted": len(aborted),
                            "below_threshold": below_threshold})
    return {"task_id": task_id, "checked_signatures": len(groups), "drafted": drafted,
            "merged": merged, "aborted": aborted, "below_threshold": below_threshold}


# ---------------------------------------------------------------------------
# 规则状态机人工动作（memory-design §3.2 状态机；§4 矩阵末行：审核动作直接报错给人，
# 无静默降级——人工操作不许假成功）
# ---------------------------------------------------------------------------

def review_rule(
    database: Database,
    rule_id: int,
    reviewer: str,
    *,
    approve: bool = True,
    now: str | None = None,
) -> dict[str, Any]:
    """人工审核规则（§3.2）：candidate → active（批准，置 reviewed_by/reviewed_at）；
    retired → active（废止可逆：重新人工审核，复用同一动作，更新 reviewed_by/reviewed_at，
    不允许自动复活）。

    reject（驳回）未实现：§3.2 未定义 candidate 的驳回去向（设计缺口，如实抛错不假成功）。
    """
    if not approve:
        raise ValueError(
            "review reject target undefined in memory-design §3.2 (candidate has no reject edge);"
            " use retire_rule with an explicit reason"
        )
    if not str(reviewer).strip():
        raise ValueError("reviewer required (人工审核位，reviewed_by 必为非空)")
    now_ts = now or utc_now_iso()
    with database.transaction() as conn:
        row = conn.execute("SELECT * FROM prevention_rules WHERE id = ?", (rule_id,)).fetchone()
        if row is None:
            raise KeyError(f"rule not found: {rule_id}")
        status = row["status"]
        if status == "active":
            raise ValueError(f"rule {rule_id} already active")
        if status == "retired":
            conn.execute(
                "UPDATE prevention_rules SET status = 'active', reviewed_by = ?, reviewed_at = ?,"
                " retired_at = NULL, retire_reason = NULL WHERE id = ?",
                (str(reviewer), now_ts, rule_id),
            )
            event_type = "rule_reactivated"
        else:  # candidate
            conn.execute(
                "UPDATE prevention_rules SET status = 'active', reviewed_by = ?, reviewed_at = ?"
                " WHERE id = ?",
                (str(reviewer), now_ts, rule_id),
            )
            event_type = "rule_activated"
        emit_event(conn, component="error_ledger", event_type=event_type,
                   payload={"rule_id": rule_id, "reviewer": str(reviewer),
                            "reviewed_at": now_ts})
    return {"rule_id": rule_id, "status": "active", "reviewed_by": str(reviewer),
            "reviewed_at": now_ts}


def retire_rule(
    database: Database,
    rule_id: int,
    reason: str,
    reviewer: str,
    *,
    now: str | None = None,
) -> dict[str, Any]:
    """人工废止规则（§3.2/§5.1 ⑧：随时可废止，retire_reason 必填；retired 即刻退出检索）。"""
    if not str(reason).strip():
        raise ValueError("retire_reason 必填（memory-design §3.1/§3.2 废止必填理由）")
    if not str(reviewer).strip():
        raise ValueError("reviewer required")
    now_ts = now or utc_now_iso()
    with database.transaction() as conn:
        row = conn.execute("SELECT * FROM prevention_rules WHERE id = ?", (rule_id,)).fetchone()
        if row is None:
            raise KeyError(f"rule not found: {rule_id}")
        if row["status"] == "retired":
            raise ValueError(f"rule {rule_id} already retired")
        conn.execute(
            "UPDATE prevention_rules SET status = 'retired', retired_at = ?, retire_reason = ?"
            " WHERE id = ?",
            (now_ts, str(reason), rule_id),
        )
        emit_event(conn, component="error_ledger", event_type="rule_retired",
                   payload={"rule_id": rule_id, "retire_reason": str(reason),
                            "reviewer": str(reviewer), "previous_status": row["status"]})
    return {"rule_id": rule_id, "status": "retired", "retired_at": now_ts}


def list_rules(database: Database, *, status: str | None = None) -> list[dict[str, Any]]:
    """规则行读取（观测/测试辅助；按 id 升序）。"""
    if status is None:
        rows = database.query("SELECT * FROM prevention_rules ORDER BY id")
    else:
        rows = database.query("SELECT * FROM prevention_rules WHERE status = ? ORDER BY id", (status,))
    return [dict(r) for r in rows]
