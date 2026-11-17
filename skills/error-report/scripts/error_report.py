#!/usr/bin/env python3
"""skills/error-report/scripts/error_report.py —— 错误账本唯一写入口的技能封装。

签名算法（skills-config §4.1，无 LLM，同输入必同签名）：错误类型 + 模块 + 参数模式
→ 指纹；登记走内核账本单一写入口 app/engine/ledger.py 的 ledger_write
（memory-design §2.4：脱敏、截断、账本侧签名/指纹计算不被本脚本绕过）。

接口适配（如实声明）：skills-config §4.2 文档版调 `ledger.ledger_write(...)`；
本交付树真实签名为模块级函数 `ledger_write(database, error_type, module, params,
raw_error, task_id, role, root_cause=..., fix_applied=...)`
（impl/app/engine/ledger.py:255），字段语义逐字一致，仅显式传 database。
导入基准（skills-config §2.2）：AGENTMESH_ROOT（缺省 /opt/agentmesh）入 sys.path。
"""
import argparse
import json
import os
import re
import sys
from pathlib import Path

_ROOT = os.environ.get("AGENTMESH_ROOT")
if not _ROOT:
    # 双基准注入（skills-config §8.2 同法）：向上找含 app/engine/db.py 的目录；
    # 容器内首层命中 /opt/agentmesh，宿主/仓库内就地运行命中交付树根
    _here = Path(__file__).resolve().parent
    for _cand in (_here, *_here.parents):
        if (_cand / "app" / "engine" / "db.py").exists():
            _ROOT = str(_cand)
            break
_ROOT = _ROOT or "/opt/agentmesh"
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

TYPE_DIRECT = re.compile(
    r"\b([A-Z][A-Za-z0-9_]*(?:Error|Exception|Warning))\b")
HTTP_CODE = re.compile(r"\bHTTP (\d{3})\b")
PATH_RE = re.compile(
    r"(?:/[A-Za-z0-9._~+-]+){2,}|[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n]+\\?)+")
UUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\b"
    r"|\b[0-9a-f]{16,}\b")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
HOST_RE = re.compile(r"\bhttps?://[A-Za-z0-9.-]+(?::\d+)?\b")
STR_RE = re.compile(r"(['\"])(?:(?!\1).){2,}?\1")
NUM_RE = re.compile(r"\b\d+\b")
# 技能面阶段 ∈ sys-arch §3.1 状态机非终态（app/engine/skills/loader.py:41 同枚举）
PHASE_ENUM = {"planning", "running", "reviewing", "rework",
              "paused_for_approval"}


def _clip(s: str, n: int) -> str:
    return s[:n]


def normalize_error_type(raw: str) -> str:
    """① 错误类型归一：HTTP 状态 → http_<code>；Python 异常名保留小写；
    其余取首个冒号前短句去标点，截 32。"""
    m = HTTP_CODE.search(raw)
    if m:
        return f"http_{m.group(1)}"
    m = TYPE_DIRECT.search(raw)
    if m:
        return m.group(1).lower()
    head = raw.split("：")[0].split(":")[0]
    head = re.sub(r"[^0-9A-Za-z_\u4e00-\u9fff]+", "_", head)
    return _clip(head.strip("_").lower() or "unknown", 32)


def normalize_module(context: dict, phase: str) -> str:
    """② 模块归一：context.component 优先，缺省用 phase。截 24。"""
    comp = str(context.get("component") or phase or "unknown")
    comp = re.sub(r"\s+", "_", comp.strip().lower())
    return _clip(comp, 24)


def normalize_params(raw: str) -> str:
    """③ 参数模式归一：路径/UUID/邮箱/URL host/字符串字面量/数字依次
    替换为占位符，保证同因异参同签名；归一后截 48。"""
    s = raw
    s = PATH_RE.sub("<PATH>", s)
    s = UUID_RE.sub("<ID>", s)
    s = EMAIL_RE.sub("<EMAIL>", s)
    s = HOST_RE.sub("<HOST>", s)
    s = STR_RE.sub("<STR>", s)
    s = NUM_RE.sub("<N>", s)
    s = re.sub(r"[^0-9A-Za-z_<>\|\s]", " ", s)
    s = re.sub(r"\s+", " ", s).strip().lower()
    return _clip(s, 48)


def make_signature(raw_error: str, phase: str, context: dict) -> str:
    """④ 拼接：error_type|module|param_pattern，全小写，总长截 120。"""
    sig = f"{normalize_error_type(raw_error)}|" \
          f"{normalize_module(context, phase)}|" \
          f"{normalize_params(raw_error)}"
    return _clip(sig, 120)


def run(raw_error: str, phase: str, context: dict, database) -> dict:
    """结构化登记（skills-config §4.2）：必填 error_signature/raw_error/phase。
    写路径走账本单一写入口 ledger_write；root_cause/fix_applied 允许暂空，
    由 Reviewer 回填或沉淀流程归纳。返回 entry_id 即登记 id。"""
    if phase not in PHASE_ENUM:
        raise ValueError(f"phase 越界: {phase!r}")
    sig = make_signature(raw_error, phase, context)
    from app.engine.ledger import ledger_write

    entry_id = ledger_write(
        database,
        error_type=sig.split("|", 1)[0][:64],
        module=str(context.get("component") or phase or "unknown")[:24],
        params={"error_signature": sig,
                "phase": phase,
                "task_type": str(context.get("task_type") or ""),
                "tool_list": ",".join(context.get("tool_list") or [])},
        raw_error=raw_error[:2000],
        task_id=str(context.get("task_id") or ""),
        role=str(context.get("role") or ""),
        root_cause=str(context.get("root_cause") or ""),
        fix_applied=str(context.get("fix_applied") or ""),
    )
    return {"status": "registered", "entry_id": int(entry_id),
            "error_signature": sig}


def render(out: dict) -> None:
    """输出唯一 JSON 块（skills-config §1.3：出参只能以 JSON 块打印到 stdout）。"""
    print("```json")
    print(json.dumps(out, ensure_ascii=False, indent=2))
    print("```")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--raw-error", required=True)
    ap.add_argument("--phase", required=True)
    ap.add_argument("--context", default="{}")
    args = ap.parse_args()
    try:
        context = json.loads(args.context)
        if not isinstance(context, dict):
            raise ValueError("--context 必须是 JSON 对象")
    except json.JSONDecodeError as exc:
        print(f"[error-report] --context JSON 解析失败: {exc}", file=sys.stderr)
        return 1
    from pathlib import Path

    from app.engine.db import Database

    data_dir = Path(os.environ.get("AGENTMESH_DATA_DIR")
                    or (Path(_ROOT) / "data"))
    database = Database(data_dir / "agentmesh.db")
    database.connect()
    try:
        out = run(args.raw_error, args.phase, context, database)
    except ValueError as exc:
        print(f"[error-report] {exc}", file=sys.stderr)
        return 1
    finally:
        database.close()
    render(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
