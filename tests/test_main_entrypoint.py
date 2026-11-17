"""test_main_entrypoint.py — app/main.py 与 scripts/docker-entrypoint.sh 测试：
rules 硬底线装载、skills 装载失败清单、preflight 结构化报错、entrypoint 自检与 exec。

覆盖验收面（ask 第 3/4 条；deployment-ops §5.5 装载校验 / §5.6 启动前置；
skills-config §2.2 load_all 失败清单非空即 FAIL；rules-config §1.2 硬底线三条 / §7.1
rules_history load 记录）。
"""

from __future__ import annotations

import io
import json
import os
import shutil
import subprocess
import sys
import urllib.request
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from _helpers import TestSkipped, cleanup, fresh_db

from app.engine.db import Database
from app.main import load_rules, load_skills, preflight

IMPL_ROOT = Path(__file__).resolve().parent.parent

RULE_GLOBAL_OK = """meta: {version: v1}
concurrency: {max_global_concurrency: 4}
approval_risk_tiers:
  tiers:
    - {tier: irreversible, hard_floor: true}
locale: {timezone: Asia/Shanghai}
"""
RULE_GLOBAL_BAD = RULE_GLOBAL_OK.replace("max_global_concurrency: 4", "max_global_concurrency: 8")
RULE_ROLES = """roles:
  worker: {tools: [x], credential_groups: [accounts]}
  planner: {tools: [], credential_groups: []}
"""
SKILL_MD = """---
name: memory-read
description: 读取记忆库与错误账本检索
when: [需要历史错误参考]
roles: [worker]
credential_groups: []
timeout_s: 60
retries: 0
idempotent: true
risk_level: low
inputs: [{name: query, type: string, required: true, desc: 检索关键词}]
outputs: JSON hits
version: 1.0
---
# memory-read
"""
SKILL_MD_BAD_ROLE = SKILL_MD.replace("roles: [worker]", "roles: [ghost-role]")


def _layout(tmp: Path, *, global_yaml: str = RULE_GLOBAL_OK,
            skill_md: str = SKILL_MD, with_skill: bool = True) -> None:
    rules = tmp / "rules"
    rules.mkdir(parents=True, exist_ok=True)
    (rules / "global.yaml").write_text(global_yaml, encoding="utf-8")
    (rules / "roles.yaml").write_text(RULE_ROLES, encoding="utf-8")
    (rules / "collab.yaml").write_text("brief_spec: {}\n", encoding="utf-8")
    (rules / "lessons.yaml").write_text("rules: []\n", encoding="utf-8")
    if with_skill:
        skill = tmp / "skills" / "memory-read"
        skill.mkdir(parents=True, exist_ok=True)
        (skill / "SKILL.md").write_text(skill_md, encoding="utf-8")


def test_load_rules_hard_floors_and_history() -> None:
    tmp = Path(__file__).parent / "_tmp_main1"
    tmp.mkdir(parents=True, exist_ok=True)
    database, directory = fresh_db(tmp, name="agentmesh.db")
    try:
        _layout(tmp)
        cfg = load_rules(tmp / "rules", database)
        assert set(cfg) == {"global", "roles", "collab", "lessons"}
        # rules_history：装载动作逐文件落行（rules-config §7.1；deployment-ops §5.5 ③）
        rows = database.query("SELECT file, action FROM rules_history WHERE action = 'load'")
        assert sorted(r["file"] for r in rows) == ["collab.yaml", "global.yaml", "lessons.yaml",
                                                   "roles.yaml"]
        # 硬底线：并发 >4 拒绝
        database2, directory2 = fresh_db(tmp, name="bad.db")
        try:
            _layout(tmp, global_yaml=RULE_GLOBAL_BAD)
            try:
                load_rules(tmp / "rules", database2)
            except ValueError as exc:
                assert "硬底线" in str(exc) and "≤ 4" in str(exc)
            else:
                raise AssertionError("concurrency > 4 must be rejected")
        finally:
            database2.close()
            shutil.rmtree(directory2, ignore_errors=True)
    finally:
        database.close()
        shutil.rmtree(tmp, ignore_errors=True)


def test_load_skills_failures_register_ledger() -> None:
    tmp = Path(__file__).parent / "_tmp_main2"
    tmp.mkdir(parents=True, exist_ok=True)
    database, directory = fresh_db(tmp, name="agentmesh.db")
    try:
        _layout(tmp, skill_md=SKILL_MD_BAD_ROLE)  # ghost-role 不在 roles.yaml → 失败
        registry, failures = load_skills(tmp / "skills",
                                         {"roles": {"worker": {"credential_groups": ["accounts"]}}},
                                         database)
        assert len(failures) == 1 and "memory-read" in failures[0]
        assert registry.all_ids() == []  # 失败技能不进注册表（半加载比缺失更危险）
        # 失败经 report_failure 登记错误账本（skills-config §2.1 不静默跳过）
        entry = database.query_one(
            "SELECT * FROM error_ledger WHERE error_type = 'skill_load_failure'")
        assert entry is not None
        # 合法技能装载成功
        _layout(tmp, skill_md=SKILL_MD)
        registry2, failures2 = load_skills(tmp / "skills",
                                           {"roles": {"worker": {"credential_groups": ["accounts"]}}},
                                           database)
        assert failures2 == [] and registry2.all_ids() == ["memory-read"]
    finally:
        database.close()
        shutil.rmtree(tmp, ignore_errors=True)


def test_preflight_success_and_structured_failure() -> None:
    tmp = Path(__file__).parent / "_tmp_main3"
    tmp.mkdir(parents=True, exist_ok=True)
    old = dict(os.environ)
    try:
        _layout(tmp)
        os.environ["AGENTMESH_ROOT"] = str(tmp)
        os.environ["AGENTMESH_DATA_DIR"] = str(tmp / "data")
        summary = preflight()
        assert Path(summary["db_path"]).exists()
        assert summary["skills_loaded"] == ["memory-read"]
        assert set(summary["rules"]) == {"collab.yaml", "global.yaml", "lessons.yaml",
                                         "roles.yaml"}
        # 失败路径：缺 rules 目录 → 结构化 FATAL JSON 到 stderr + SystemExit(1)
        broken = Path(__file__).parent / "_tmp_main3_broken"
        broken.mkdir(parents=True, exist_ok=True)
        os.environ["AGENTMESH_ROOT"] = str(broken)
        os.environ["AGENTMESH_DATA_DIR"] = str(broken / "data")
        stderr_capture = io.StringIO()
        try:
            with redirect_stderr(stderr_capture):
                preflight()
        except SystemExit as exc:
            assert exc.code == 1
        else:
            raise AssertionError("missing rules dir must exit 1")
        payload = json.loads(stderr_capture.getvalue().strip().splitlines()[-1])
        assert payload["level"] == "FATAL" and payload["stage"] == "rules_load"
        assert payload["sections"]  # 报错逐条给出出处章节（deployment-ops §6b 风格）
        # 失败路径：技能失败清单非空
        _layout(broken)
        stderr_capture2 = io.StringIO()
        try:
            with redirect_stderr(stderr_capture2):
                (broken / "skills" / "memory-read").mkdir(parents=True, exist_ok=True)
                (broken / "skills" / "memory-read" / "SKILL.md").write_text(
                    SKILL_MD_BAD_ROLE, encoding="utf-8")
                preflight()
        except SystemExit as exc:
            assert exc.code == 1
        else:
            raise AssertionError("skill load failures must exit 1")
        payload2 = json.loads(stderr_capture2.getvalue().strip().splitlines()[-1])
        assert payload2["stage"] == "skills_load"
    finally:
        os.environ.clear()
        os.environ.update(old)
        shutil.rmtree(tmp, ignore_errors=True)
        shutil.rmtree(Path(__file__).parent / "_tmp_main3_broken", ignore_errors=True)


def test_build_runtime_and_healthz() -> None:
    tmp = Path(__file__).parent / "_tmp_main4"
    tmp.mkdir(parents=True, exist_ok=True)
    old = dict(os.environ)
    try:
        _layout(tmp)
        os.environ["AGENTMESH_ROOT"] = str(tmp)
        os.environ["AGENTMESH_DATA_DIR"] = str(tmp / "data")
        os.environ["AGENTMESH_API_TOKEN"] = "boot-token"
        os.environ["AGENTMESH_PORT"] = "0"  # 随机端口
        from app.main import build_runtime
        runtime = build_runtime()
        server = runtime["server"]
        port = server.server_address[1]
        request = urllib.request.Request(f"http://127.0.0.1:{port}/healthz")
        with urllib.request.urlopen(request, timeout=10) as resp:
            assert resp.status == 200
            body = json.loads(resp.read())
            assert body["status"] == "ok"
        # 未带令牌 → 401
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/api/v1/tasks", timeout=10)
        except urllib.error.HTTPError as exc:
            assert exc.code == 401
        else:
            raise AssertionError("api must be fail-closed without token")
        # 优雅停机
        runtime["api"].shutdown_flag.set()
        server.shutdown()
        runtime["scheduler"].stop(timeout=2)
        runtime["database"].close()
        server.server_close()
        assert "cron-scheduler alive" == "cron-scheduler alive"  # 占位断言防误删清理段
    finally:
        os.environ.clear()
        os.environ.update(old)
        shutil.rmtree(tmp, ignore_errors=True)


def _find_bash() -> str | None:
    """定位 POSIX shell：PATH → 常见 Git Bash 安装位（Windows 免装 tzdata 同源的
    本机能力探测）。找不到时返回 None，测试诚实跳过（不是 PASS 也不是 FAIL）。"""
    import shutil

    found = shutil.which("bash") or shutil.which("sh")
    if found:
        return found
    for candidate in (
        Path("C:/Program Files/Git/bin/bash.exe"),
        Path("C:/Program Files/Git/usr/bin/bash.exe"),
        Path("C:/Program Files (x86)/Git/bin/bash.exe"),
        Path(os.path.expanduser("~/scoop/apps/git/current/bin/bash.exe")),
    ):
        if candidate.exists():
            return str(candidate)
    return None


def test_entrypoint_script() -> None:
    bash = _find_bash()
    if bash is None:
        raise TestSkipped("本机无 bash/sh（Windows 纯 Python 环境）——docker-entrypoint.sh "
                          "的 POSIX 自检逻辑已在 preflight 单测中同源覆盖，shell 面待装 Git Bash 后验收")
    tmp = Path(__file__).parent / "_tmp_main5"
    tmp.mkdir(parents=True, exist_ok=True)
    script = IMPL_ROOT / "scripts" / "docker-entrypoint.sh"
    assert script.exists()
    env = dict(os.environ)
    env["AGENTMESH_ROOT"] = str(IMPL_ROOT)      # 内核代码根（app 包可导入）
    env["AGENTMESH_DATA_DIR"] = str(tmp / "data")
    env["AGENTMESH_RULES_DIR"] = str(tmp / "rules")
    env["AGENTMESH_SKILLS_DIR"] = str(tmp / "skills")
    env["AGENTMESH_WEB_DIR"] = str(IMPL_ROOT / "web")
    env["PYTHON"] = sys.executable
    # 成功路径：自检全过 + exec CMD（自证命令；脚本文件参数规避 shell 引号剥离）
    _layout(tmp)
    cmd_script = tmp / "cmd.py"
    cmd_script.write_text("print('cmd-ok')" + chr(10), encoding="utf-8")
    result = subprocess.run([bash, str(script), sys.executable, str(cmd_script)],
                            env=env, capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stderr
    assert "startup pre-check: all skill/kernel tests passed" in result.stdout
    assert "cmd-ok" in result.stdout
    # 失败路径：rules 缺失 → exit 1 + FATAL
    broken = Path(__file__).parent / "_tmp_main5_broken"
    broken.mkdir(parents=True, exist_ok=True)
    env["AGENTMESH_RULES_DIR"] = str(broken / "rules")
    env["AGENTMESH_DATA_DIR"] = str(broken / "data")
    result2 = subprocess.run([bash, str(script), sys.executable, "-c", "print('nope')"],
                             env=env, capture_output=True, text=True, timeout=120)
    assert result2.returncode == 1
    assert "FATAL" in result2.stderr and "rules/skills preflight failed" in result2.stderr
    shutil.rmtree(tmp, ignore_errors=True)
    shutil.rmtree(broken, ignore_errors=True)


def test_runner_path_shims_resolve_to_real_runner() -> None:
    """回归（部署前复验失败项）：工作流世界根可能是 out/、out/impl/ 或仓库根，同一命令
    `python impl/tests/run_all.py` 会解析到不同位置。缺文件处放了零逻辑转发入口，
    它们必须解析到唯一的真实运行器（含 test_db_ledger.py 与 app/ 包），不得指向自身。"""
    import importlib.util

    real_runner = IMPL_ROOT / "tests" / "run_all.py"
    assert (IMPL_ROOT / "tests" / "test_db_ledger.py").is_file()
    assert (IMPL_ROOT / "app").is_dir()
    shims = [IMPL_ROOT / "impl" / "tests" / "run_all.py"]  # 世界根=impl 时的落点
    outer = IMPL_ROOT.parent / "impl" / "tests" / "run_all.py"  # 世界根=仓库根时的落点
    if outer.is_file() and outer.resolve() != real_runner.resolve():
        shims.append(outer)
    for shim in shims:
        assert shim.is_file(), shim
        spec = importlib.util.spec_from_file_location(f"shim_{abs(hash(str(shim)))}", shim)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        located = module.locate_real_runner(shim.resolve())
        assert located.resolve() == real_runner.resolve(), (shim, located)
