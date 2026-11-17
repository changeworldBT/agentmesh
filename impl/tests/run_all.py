"""run_all.py（兼容入口）— 让 `python impl/tests/run_all.py` 在任意世界根下都成立。

背景（实测事实，非推测）：本任务链的工作流世界根先后出现过三种取值——
`<ws>`（当时交付树在 `<ws>/impl`，命令解析为 `<ws>/impl/tests/run_all.py`）、
`<ws>/out`（解析为 `out/impl/tests/run_all.py`，可用）、
`<ws>/out/impl`（解析为 `out/impl/impl/tests/run_all.py`，缺文件即报
`can't open file`）。所以不靠移动目录赌单一 cwd，而在缺文件的那些位置放一个
零逻辑的转发入口：向上逐级在已知相对位（`tests/`、`out/impl/tests/`、`impl/tests/`）
寻找**真实**运行器，找到后原样执行，输出与退出码不变。

真实运行器仍是 `out/impl/tests/run_all.py`（唯一事实源）。本文件不含任何测试逻辑，
不参与用例收集（收集器只认 `test_*.py`）；找不到真实运行器时以非 0 退出并说明原因，
绝不静默成功。
"""

from __future__ import annotations

import runpy
import sys
from pathlib import Path

# 真实运行器的判据：与 test_db_ledger.py 同级、且其父目录含 app/ 包
_MARKER_TEST = "test_db_ledger.py"
_CANDIDATE_DIRS = ("tests", "out/impl/tests", "impl/tests")


def locate_real_runner(here: Path) -> Path:
    """向上逐级在已知相对位寻找真实运行器（含 marker 校验，避免命中另一个转发入口）。"""
    for base in (here.parent, *here.parents):
        for rel in _CANDIDATE_DIRS:
            candidate = base / rel / "run_all.py"
            if candidate.resolve() == here:
                continue
            if not candidate.is_file():
                continue
            if not (candidate.parent / _MARKER_TEST).is_file():
                continue
            if not (candidate.parent.parent / "app").is_dir():
                continue
            return candidate
    raise SystemExit(
        f"run_all.py 转发入口找不到真实测试运行器（自 {here} 向上查找 "
        f"{' / '.join(_CANDIDATE_DIRS)} 且需含 {_MARKER_TEST} 与 app/ 包）")


if __name__ == "__main__":
    real_runner = locate_real_runner(Path(__file__).resolve())
    sys.argv[0] = str(real_runner)
    runpy.run_path(str(real_runner), run_name="__main__")
