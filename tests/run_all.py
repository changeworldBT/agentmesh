"""run_all.py — 内核 MVP 测试运行器（纯 stdlib，禁 pytest）。

出处：本 ask 要求「impl/tests/run_all.py——纯 stdlib 顺序执行全部测试文件，打印
PASS/FAIL 汇总并以退出码表达结果（禁止依赖 pytest）」；与部署形态一致——
python:3.12-slim 的内核依赖仅标准库 + PyYAML + uvicorn/fastapi（sys-arch §10.2），
测试面同样零第三方依赖。

用法：
    python impl/tests/run_all.py              # 顺序执行 tests/ 下全部 test_*.py
    python impl/tests/run_all.py ledger wal   # 只跑「文件名或用例名含任一子串」的用例

输出：每个用例一行 [PASS]/[FAIL]/[SKIP]（FAIL 附完整 traceback），末行
SUMMARY: total=N pass=X fail=Y skip=S 与 RESULT: PASS/FAIL。
跳过语义：用例抛 TestSkipped（如本机缺 POSIX shell 无法验收 bash 脚本）不计 FAIL，
结果以 [SKIP] 行明示原因——不谎报 PASS 也不误报 FAIL。
退出码：0 = 无 FAIL 且至少跑了一个用例；1 = 存在 FAIL、发现 0 个测试文件或 0 个用例。
"""

from __future__ import annotations

import importlib.util
import sys
import traceback
from pathlib import Path
from types import ModuleType
from typing import Any

TEST_DIR = Path(__file__).resolve().parent
IMPL_ROOT = TEST_DIR.parent  # impl/ —— 使 `from app.engine import ...` 可导入

# sys.path 注入必须在导入 _helpers 之前（_helpers 顶层导入 app.engine.*）：
# 无论 CWD 是 out/ 还是 impl/，脚本自身目录与 impl 根都在导入面就位
if str(IMPL_ROOT) not in sys.path:
    sys.path.insert(0, str(IMPL_ROOT))
if str(TEST_DIR) not in sys.path:
    sys.path.insert(0, str(TEST_DIR))

from _helpers import TestSkipped  # noqa: E402 - 依赖上面的 sys.path 注入


def _load_module(path: Path) -> ModuleType:
    name = f"impl_tests_{path.stem}"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load test module from {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _discover_cases(module: ModuleType) -> list[tuple[str, Any]]:
    """按定义顺序收集 test_* 可调用对象（模块 __dict__ 保留源码定义序）。"""
    return [
        (name, obj)
        for name, obj in module.__dict__.items()
        if name.startswith("test_") and callable(obj)
    ]


def main(argv: list[str]) -> int:
    filters = [a for a in argv if not a.startswith("-")]
    files = sorted(TEST_DIR.glob("test_*.py"))
    if not files:
        print(f"NO TEST FILES FOUND under {TEST_DIR}")
        return 1
    total = passed = failed = skipped = 0
    for path in files:
        module = _load_module(path)
        cases = _discover_cases(module)
        if not cases:
            print(f"[WARN] {path.name}: no test_* functions found")
            continue
        print(f"== {path.name} ({len(cases)} cases) ==")
        for name, fn in cases:
            full_name = f"{path.name}::{name}"
            if filters and not any(f in full_name for f in filters):
                continue
            total += 1
            try:
                fn()
            except TestSkipped as exc:
                skipped += 1
                print(f"[SKIP] {full_name} — {exc}")
            except BaseException:  # runner 必须捕获一切并如实报告，不因单个用例中断整轮
                failed += 1
                print(f"[FAIL] {full_name}")
                traceback.print_exc()
            else:
                passed += 1
                print(f"[PASS] {full_name}")
    print(f"\nSUMMARY: total={total} pass={passed} fail={failed} skip={skipped}")
    if total == 0:
        print("RESULT: FAIL (0 cases matched)")
        return 1
    print("RESULT:", "PASS" if failed == 0 else "FAIL")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
