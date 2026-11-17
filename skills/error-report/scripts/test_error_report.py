#!/usr/bin/env python3
"""skills/error-report/scripts/test_error_report.py —— error-report 技能测试（skills-config §8.1 约定）。

验收面：
  ① 签名归一四样例（skills-config §4.1 实测口径：HTTP 429 / KeyError /
     TimeoutError / 中文冒号短句）；
  ② 同因异参不变式（task_id/时长变体 → 同签名）；
  ③ 结构化登记回查（ledger_write 落库 → 按 entry_id 回查行存在且字段一致）；
  ④ phase 越界拒绝（终态 done 不在非终态集）；
  ⑤ 出参形状 = SKILL.md front-matter outputs。
退出码 0 = 全过；断言失败抛 AssertionError（退出码非 0）。
"""
import json
import os
import sys
import tempfile
from pathlib import Path

_ROOT = os.environ.get("AGENTMESH_ROOT") or "/opt/agentmesh"
_HERE = Path(__file__).resolve().parent
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
_IMPL_ROOT = _HERE.parent.parent.parent
if _IMPL_ROOT.is_dir() and (_IMPL_ROOT / "app" / "engine" / "db.py").exists() \
        and str(_IMPL_ROOT) not in sys.path:
    sys.path.insert(0, str(_IMPL_ROOT))

from app.engine.db import Database  # noqa: E402
from error_report import make_signature, run  # noqa: E402


def main() -> int:
    # ① 签名归一样例（skills-config §4.1 CLI 实跑口径）
    sig = make_signature(
        "HTTP 429 while calling POST /v1/video/generations"
        " task_id=8f14e45f1234567890abcdef12345678 retry after 30s",
        "running", {"component": "worker", "task_type": "video_gen"})
    assert sig == "http_429|worker|http <n> while calling post <path> task_id <id> ", \
        f"HTTP 429 签名不符: {sig!r}"
    assert make_signature("KeyError: 'port'", "planning",
                          {"component": "orchestrator"}) \
        == "keyerror|orchestrator|keyerror <str>"
    assert make_signature(
        "TimeoutError: connection to https://api.example.com:8443 timed out after 30s",
        "running", {"component": "agent_runtime"}) \
        == "timeouterror|agent_runtime|timeouterror connection to <host> timed out afte"
    assert make_signature("部署失败：端口 5432 已被占用", "running", {}) \
        == "部署失败|running|<n>"

    # ② 同因异参不变式（skills-config §4.1 实测口径：task_id 与时长两组变体；
    # 差异段落在 48 字符 param_pattern 截断点之后——同 doc 示例字符串）
    base = make_signature(
        "HTTP 429 while calling POST /v1/video/generations"
        " task_id=8f14e45f1234567890abcdef12345678 retry after 30s",
        "running", {"component": "worker", "task_type": "video_gen"})
    same_a = make_signature(
        "HTTP 429 while calling POST /v1/video/generations"
        " task_id=deadbeefdeadbeefdeadbeefdeadbeef retry after 45s",
        "running", {"component": "worker", "task_type": "video_gen"})
    assert base == same_a, f"同因异参必须同签名: {base!r} vs {same_a!r}"
    assert base == "http_429|worker|http <n> while calling post <path> task_id <id> "

    with tempfile.TemporaryDirectory() as tmp:
        database = Database(Path(tmp) / "agentmesh.db")
        database.connect()
        try:
            # ③ 登记回查：entry_id 落库可回查，字段一致
            out = run("HTTP 429 while calling POST /v1/video/generations",
                      "running",
                      {"component": "worker", "task_type": "video_gen",
                       "task_id": "t-42", "role": "worker",
                       "root_cause": "上游负载饱和", "fix_applied": "稍后重试"},
                      database)
            assert set(out) == {"status", "entry_id", "error_signature"}
            assert out["status"] == "registered" and out["entry_id"] > 0
            row = database.conn.execute(
                "SELECT id, error_type, module, raw_error, root_cause, task_id"
                " FROM error_ledger WHERE id = ?", (out["entry_id"],)).fetchone()
            assert row is not None, "登记行应存在"
            assert row[1] == "http_429" and row[2] == "worker"
            assert "HTTP 429" in row[3] and row[4] == "上游负载饱和" and row[5] == "t-42"
            json.dumps(out, ensure_ascii=False)  # JSON 可序列化

            # ④ phase 越界拒绝（终态不在非终态集），且不落库
            before = database.conn.execute(
                "SELECT COUNT(*) FROM error_ledger").fetchone()[0]
            try:
                run("x", "done", {}, database)
            except ValueError:
                pass
            else:
                raise AssertionError("phase 越界必须拒绝")
            after = database.conn.execute(
                "SELECT COUNT(*) FROM error_ledger").fetchone()[0]
            assert before == after, "拒绝的登记不得落库"
        finally:
            database.close()

    print("test_error_report: all assertions passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
