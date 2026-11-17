#!/usr/bin/env python3
"""skills/memory-read/scripts/memory_read.py —— 强制检索记忆库 + 错误账本的唯一读入口。

skills-config §3.1 检索算法（确定性，无 LLM）：关键词合并 → 账本检索 → 按 occurred_at
降序、签名去重、截前 10 条 → 渲染 memory_block。只读，无任何写路径。

接口适配（如实声明）：skills-config §3.2 文档版以单一 FTS MATCH 查询串调
`ledger.search_rules(query, ...)`；本交付树唯一账本实现是 impl/app/engine/ledger.py，
其真实签名为 `search_rules(database, keywords: list[str], task_type=..., limit=...,
keyword_operator=...)` / `search_errors(database, keywords, limit, keyword_operator)`——
文档版的「关键词合并 OR 连接」语义由关键词列表 + keyword_operator='OR' 等价承载
（_fts_query 内部做 token 引号包裹与 OR 连接，app/engine/ledger.py:129）。

导入基准（skills-config §2.2 双基准声明）：AGENTMESH_ROOT（缺省 /opt/agentmesh）
入 sys.path 后 `from app.engine.…` 导入顶层包 app。
"""
import argparse
import json
import os
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


def run(task_type: str, tool_list: list[str], keywords: list[str],
        database) -> dict:
    """检索算法（skills-config §3.1）：
      search_rules(database, keywords, task_type, limit, keyword_operator='OR')
        → id/rule_text/task_types/risk_level/occurrences（SQL 内置 status='active'）；
      search_errors(database, keywords, limit, keyword_operator='OR')
        → id/error_signature/error_type/module/root_cause/fix_applied/
          prevention_suggestion/occurred_at（app/engine/ledger.py:316 起查询列）。
      结果按 occurred_at 降序、签名去重，截前 10 条。
    """
    from app.engine.ledger import search_errors, search_rules

    tokens = [str(t).strip() for t in [task_type, *tool_list, *keywords]
              if str(t).strip()]
    hits: list[dict] = []
    if tokens:  # 全空时返回空块而非全量（skills-config §3.1 第 1 步）
        seen: set[str] = set()
        for r in search_rules(database, tokens, task_type=task_type,
                              limit=10, keyword_operator="OR"):
            sig = str(r["id"])          # 规则条目无签名列，用规则 id 去重
            if sig in seen:
                continue
            seen.add(sig)
            hits.append({"rule_id": r["id"],
                         "rule_text": r["rule_text"],
                         "risk_level": r["risk_level"],
                         "occurred_at": None})
        for e in search_errors(database, tokens, limit=10,
                               keyword_operator="OR"):
            sig = e["error_signature"]
            if sig in seen:
                continue
            seen.add(sig)
            hits.append({"rule_id": None,
                         "rule_text": e["root_cause"] or e["fix_applied"]
                                      or "（暂无生效规则，仅历史记录）",
                         "risk_level": None,
                         "occurred_at": e["occurred_at"]})
    hits.sort(key=lambda h: (h["occurred_at"] or ""), reverse=True)
    hits = hits[:10]
    lines = []
    for h in hits:
        lines.append(f"- {h['rule_text']}")
    memory_block = ("【记忆库检索命中】\n" + "\n".join(lines)) if hits \
        else "【记忆库检索命中】无。"
    return {"memory_block": memory_block, "hits": hits}


def render(out: dict) -> None:
    """输出唯一 JSON 块（skills-config §1.3：出参只能以 JSON 块打印到 stdout）。"""
    print("```json")
    print(json.dumps(out, ensure_ascii=False, indent=2))
    print("```")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--task-type", required=True)
    ap.add_argument("--tools", default="")
    ap.add_argument("--keywords", default="")
    args = ap.parse_args()
    from pathlib import Path

    from app.engine.db import Database

    data_dir = Path(os.environ.get("AGENTMESH_DATA_DIR")
                    or (Path(_ROOT) / "data"))
    database = Database(data_dir / "agentmesh.db")
    database.connect()
    try:
        out = run(args.task_type,
                  [t for t in args.tools.split(",") if t.strip()],
                  [k for k in args.keywords.split(",") if k.strip()],
                  database)
    finally:
        database.close()
    render(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
