#!/usr/bin/env python3
"""skills/memory-read/scripts/test_memory_read.py —— memory-read 技能测试（skills-config §8.1 约定）。

用临时库 seed 数据后直调 run()，验收面：
  ① active 预防规则命中（candidate/retired 不参与）；
  ② 错误账本历史命中（root_cause/fix_applied 提取）；
  ③ 关键词全空返回空块而非全量；
  ④ 签名去重 + 截前 10 条；
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
# 允许就地跑：impl 根 = scripts→memory-read→skills→impl 三级上溯（app 包所在）
_IMPL_ROOT = _HERE.parent.parent.parent
if _IMPL_ROOT.is_dir() and (_IMPL_ROOT / "app" / "engine" / "db.py").exists() \
        and str(_IMPL_ROOT) not in sys.path:
    sys.path.insert(0, str(_IMPL_ROOT))

from app.engine.db import Database  # noqa: E402
from memory_read import run  # noqa: E402


def _seed(database: Database) -> None:
    with database.transaction() as conn:
        # ① active 预防规则（FTS 触发器同步 prevention_rules_fts）
        conn.execute(
            "INSERT INTO prevention_rules (id, rule_text, match_keywords, task_types,"
            " status, risk_level, occurrences)"
            " VALUES (1, '部署前必须先跑 bash -n 自检所有 .sh', 'deploy,shell-check',"
            " '*', 'active', 'low', 3)")
        # candidate 不参与注入（search_rules SQL 内置 status='active' 过滤）
        conn.execute(
            "INSERT INTO prevention_rules (id, rule_text, match_keywords, task_types,"
            " status, risk_level, occurrences)"
            " VALUES (2, 'candidate 不应命中', 'deploy', '*', 'candidate', 'low', 1)")
        # ② 错误账本历史（ledger_write 单一写入口；FTS 触发器同步）
        conn.execute(
            "INSERT INTO error_ledger (id, error_signature, signature_hash, error_type,"
            " module, param_pattern, raw_error, root_cause, fix_applied, task_id,"
            " role, occurred_at)"
            " VALUES (10, 'deploy|worker|bash -n missing', 'h123', 'deploy', 'worker',"
            " '', 'install 时未跑 bash -n', '上线前统一跑 bash -n 自检', '已加入 install.sh',"
            " 't-1', 'worker', '2026-11-16T08:00:00Z')")


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        database = Database(Path(tmp) / "agentmesh.db")
        database.connect()
        try:
            _seed(database)

            # ① active 规则命中 + ② 错误历史命中
            out = run("deploy", ["file.write_in_workspace"], [], database)
            assert out["hits"], "应命中 active 规则或错误历史"
            rule_hits = [h for h in out["hits"] if h["rule_id"] == 1]
            err_hits = [h for h in out["hits"] if h["rule_id"] is None]
            assert rule_hits, "active 预防规则应命中："
            assert rule_hits[0]["risk_level"] == "low"
            assert err_hits, "错误账本历史应命中"
            assert "bash -n" in err_hits[0]["rule_text"]
            assert not any(h["rule_id"] == 2 for h in out["hits"]), \
                "candidate 规则不得命中（status='active' 过滤）"
            assert out["memory_block"].startswith("【记忆库检索命中】")

            # ③ 关键词全空 → 空块而非全量（skills-config §3.1 第 1 步「全空」=
            # task_type+tool_list+keywords 三组全空；task_type 本身在合并关键词内）
            empty = run("", [], [], database)
            assert empty["hits"] == [], "全空关键词应返回空块"
            assert empty["memory_block"].endswith("无。")

            # ④ 去重 + 截前 10 条：seed 12 条 active 规则 → hits ≤10
            with database.transaction() as conn:
                for i in range(3, 16):
                    conn.execute(
                        "INSERT INTO prevention_rules (id, rule_text, match_keywords,"
                        " task_types, status, risk_level, occurrences)"
                        f" VALUES ({i}, '部署规则 {i} 条款', 'deploy', '*', 'active',"
                        " 'low', 1)")
            capped = run("deploy", [], [], database)
            assert len(capped["hits"]) == 10, f"应截前 10 条，实得 {len(capped['hits'])}"
            ids = [h["rule_id"] for h in capped["hits"] if h["rule_id"]]
            assert len(ids) == len(set(ids)), "规则 id 应去重"

            # ⑤ 出参形状 = front-matter outputs
            assert set(out) == {"memory_block", "hits"}
            for h in out["hits"]:
                assert set(h) == {"rule_id", "rule_text", "risk_level", "occurred_at"}
            json.dumps(out, ensure_ascii=False)  # JSON 可序列化
            print("test_memory_read: all assertions passed")
        finally:
            database.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
