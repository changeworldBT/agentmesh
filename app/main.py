"""main.py — AgentMesh 内核入口：初始化 db → 装载 rules/skills（失败即结构化报错退出）→
启动 triggers → 启动 API（监听 0.0.0.0:8787，AGENTMESH_PORT 可覆盖）。

设计文档出处（模块顶部注记，按 ask 要求）：
- sys-arch（ARCH-ROOT-01）§1.3 运行形态：python:3.12-slim 单容器单进程、SQLite WAL 单写者、
  对外唯一 HTTP 端口 8787；§2.1 架构原则 2/4：状态外置到命名卷、横切组件走代理/总线；
  §10.1 compose：AGENTMESH_CONFIG=/opt/agentmesh/rules、APPROVAL_DEFAULT_WAIT、
  BUDGET_GLOBAL_DAILY、healthz 探针。
- skills-config（SKILLS-01）§1.1：`/opt/agentmesh/app/main.py` 入口 + `app/engine/…` 布局；
  §2.2：启动时序 = 先读 rules/roles.yaml → SkillRegistry.load_all() → 失败清单逐条
  error-report 登记并写启动日志 → 注册表只读；导入基准 = app/ 的父目录
  （`from app.engine.…` 导入顶层包 app——sys.path 必须含 AGENTMESH_ROOT，不得误插 app 本身）。
- deployment-ops §5.5：rules/skills 装载校验（四份规则 YAML 可解析 + 硬底线三条不变式；
  load_all 失败清单非空即 FAIL；装载动作落 rules_history action=load）；§5.6：启动前置
  校验包装（本模块 preflight() 供 docker-entrypoint.sh 调用，任一失败 exit 1）；§2.2：
  CMD 以顶层包导入 app.main。
- rules-config（RULES-01）§1.2：四文件装载与硬底线三条不变式（并发 ≤4 不得放宽、
  irreversible hard_floor 不得降级、时区禁歧义缩写）；§7.1：rules_history 表（装载动作
  action='load' 逐文件落行）。
- credentials-spec §1.2 / ICON §1.2：AGENTMESH_API_TOKEN 经凭证通道注入（env 落点），
  内核进程内存比对，永不返回明文。

偏离与取舍（如实声明）：
- 环境变量布局以 AGENTMESH_ROOT 为根（默认 /opt/agentmesh），数据目录
  AGENTMESH_DATA_DIR（默认 $AGENTMESH_ROOT/data）、规则目录 AGENTMESH_RULES_DIR
  （默认 $AGENTMESH_ROOT/rules）、技能目录 AGENTMESH_SKILLS_DIR、静态目录
  AGENTMESH_WEB_DIR、端口 AGENTMESH_PORT（默认 8787，本 ask 指定可覆盖）——本地/容器
  双形态同一套 env 面。
- YAML 解析依赖 PyYAML（sys-arch §10.2 依赖清单内）；缺失时以结构化 FATAL 报错退出
  （容器镜像必含 PyYAML，本地 stdlib 环境跑 main 需先装 PyYAML——本机实测已装 6.0.3）。
- rules_history 表按 rules-config §7.1 DDL 由本装载器按需建表（deployment-ops §5.1 表
  清单中该表属 init_db，但装载动作发生在内核入口，按需建表与 §5.1「内核模块首次写入前」
  同源处理）。
- 编排引擎主循环落地为 EngineLoop（评审 P2 修复）：T1 领取 → plan_task → execute_subtask
  → T5/T6 → T11 done_callback + consolidation_check，连同超时兜底统一扫描
  （scan_timeouts→apply_timeout_action）由 build_runtime 起线程周期执行；MVP 串行推进
  （并发 ≤4 为上限约束），验收器交叉验证未接线（T6 直通，如实降级声明）。
"""

from __future__ import annotations

import json
import os
import signal
import sys
import threading
from pathlib import Path
from typing import Any

from app.api import server as server_mod
from app.engine import executor as executor_mod
from app.engine import ledger as ledger_mod
from app.engine import planner as planner_mod
from app.engine import state as state_mod
from app.engine import triggers as triggers_mod
from app.engine.db import Database, utc_now_iso
from app.engine.state import TaskStatus

AGENTMESH_ROOT_DEFAULT = "/opt/agentmesh"
RULE_FILES = ("global.yaml", "roles.yaml", "collab.yaml", "lessons.yaml")


def _root() -> Path:
    return Path(os.environ.get("AGENTMESH_ROOT") or AGENTMESH_ROOT_DEFAULT)


def _data_dir(root: Path) -> Path:
    return Path(os.environ.get("AGENTMESH_DATA_DIR") or (root / "data"))


def _rules_dir(root: Path) -> Path:
    return Path(os.environ.get("AGENTMESH_RULES_DIR") or (root / "rules"))


def _skills_dir(root: Path) -> Path:
    return Path(os.environ.get("AGENTMESH_SKILLS_DIR") or (root / "skills"))


def _web_dir(root: Path) -> Path:
    return Path(os.environ.get("AGENTMESH_WEB_DIR") or (root / "web"))


def _fatal(stage: str, errors: list[str], sections: list[str]) -> None:
    """结构化报错（deployment-ops §6b/§422 风格：逐条给出出处章节）→ exit 1。"""
    payload = {"level": "FATAL", "stage": stage, "errors": errors, "sections": sections}
    print(json.dumps(payload, ensure_ascii=False), file=sys.stderr, flush=True)
    raise SystemExit(1)


# ---------------------------------------------------------------------------
# rules 装载（rules-config §1.2 硬底线 + §7.1 rules_history load 记录）
# ---------------------------------------------------------------------------

def load_rules(rules_dir: Path, database: Any) -> dict[str, Any]:
    """装载四份规则 YAML：可解析 + 硬底线三条不变式（rules-config §1.2；
    deployment-ops §5.5 ① 探针同判据）；逐文件落 rules_history（action='load'）。"""
    import yaml  # sys-arch §10.2 依赖面；缺失 → 调用方捕获 ImportError 结构化报错

    loaded: dict[str, Any] = {}
    errors: list[str] = []
    if not rules_dir.exists():
        raise FileNotFoundError(f"rules 目录不存在: {rules_dir}")
    for name in RULE_FILES:
        path = rules_dir / name
        if not path.exists():
            errors.append(f"缺 {name}（rules-config §1.1 四文件约定）")
            continue
        try:
            loaded[name.removesuffix(".yaml")] = yaml.safe_load(
                path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            errors.append(f"{name} YAML 解析失败: {exc}")
    if errors:
        raise ValueError("; ".join(errors))
    # 硬底线三条不变式（deployment-ops §5.5 ① 探针判据）
    global_cfg = loaded.get("global") or {}
    concurrency = (global_cfg.get("concurrency") or {}).get("max_global_concurrency")
    if not isinstance(concurrency, int) or concurrency > 4:
        errors.append("硬底线：global.concurrency.max_global_concurrency ≤ 4 不得放宽"
                      f"（当前 {concurrency!r}，rules-config §1.2）")
    tiers = ((global_cfg.get("approval_risk_tiers") or {}).get("tiers")) or []
    irreversible = next((t for t in tiers if t.get("tier") == "irreversible"), None)
    if not irreversible or irreversible.get("hard_floor") is not True:
        errors.append("硬底线：irreversible tier hard_floor 必须为 true"
                      "（rules-config §2.1/§2.2，R2 不得降级）")
    locale_tz = str((global_cfg.get("locale") or {}).get("timezone") or "")
    if locale_tz in ("CST", "EST"):
        errors.append("硬底线：locale.timezone 禁歧义缩写 CST/EST（rules-config §1.2）")
    if errors:
        raise ValueError("; ".join(errors))
    # rules_history 装载记录（rules-config §7.1：装载动作 action='load'；表按需建）
    with database.transaction() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS rules_history (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                ts          TEXT    NOT NULL,
                file        TEXT    NOT NULL,
                version     TEXT    NOT NULL,
                action      TEXT    NOT NULL,
                changed_by  TEXT    NOT NULL,
                diff_summary TEXT   NOT NULL,
                old_content TEXT,
                new_content TEXT,
                CHECK (action IN ('load','update','conflict','revert'))
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_rules_history_file_ts"
                     " ON rules_history(file, ts DESC)")
        for name in RULE_FILES:
            version = str((loaded[name.removesuffix(".yaml")] or {}).get("meta", {}).get("version")
                          or "v0")
            conn.execute(
                "INSERT INTO rules_history (ts, file, version, action, changed_by,"
                " diff_summary) VALUES (?, ?, ?, 'load', 'kernel-boot', ?)",
                (utc_now_iso(), name, version, f"startup load from {rules_dir}"))
    return loaded


# ---------------------------------------------------------------------------
# skills 装载（skills-config §2.2：load_all 失败清单非空即 FAIL）
# ---------------------------------------------------------------------------

def load_skills(skills_dir: Path, roles_cfg: dict[str, Any],
                database: Any) -> tuple[Any, list[str]]:
    from app.engine.skills.registry import SkillRegistry

    registry = SkillRegistry(database=database)
    if not skills_dir.exists():
        return registry, []  # 技能目录可选（空注册表合法；规则装载必选）
    failures = registry.load_all(skills_dir, roles_cfg)
    return registry, failures


# ---------------------------------------------------------------------------
# preflight（docker-entrypoint.sh 的自检位；deployment-ops §5.6 启动前置）
# ---------------------------------------------------------------------------

def preflight() -> dict[str, Any]:
    """启动前自检：db 可写 + rules 装载校验 + skills 装载校验。

    任何失败 → 结构化 FATAL JSON 到 stderr 并 SystemExit(1)（本 ask：任何失败 exit 1；
    绝不写只读路径——只触碰 AGENTMESH_DATA_DIR）。成功返回各面摘要（供 entrypoint 日志）。
    """
    root = _root()
    data_dir = _data_dir(root)
    rules_dir = _rules_dir(root)
    skills_dir = _skills_dir(root)

    # ① db 可写（只写数据目录；credentials/scripts/app 等只读挂载一律不触碰）
    errors: list[str] = []
    try:
        data_dir.mkdir(parents=True, exist_ok=True)
        probe = data_dir / ".preflight_write_probe"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        from app.engine.db import Database
        database = Database(data_dir / "agentmesh.db")
        database.connect()
        if str(database.journal_mode) != "wal" and database.path != ":memory:":
            errors.append(f"WAL 未生效: journal_mode={database.journal_mode}"
                          "（deployment-ops §6.1 首验 10）")
        database.close()
    except Exception as exc:
        _fatal("db_check", [f"数据目录不可写或 WAL 探针失败: {exc}（目录={data_dir}）"],
               ["deployment-ops §5.6", "real-vps-facts（重状态落 /data）"])

    # ② rules 装载校验
    try:
        from app.engine.db import Database
        database = Database(data_dir / "agentmesh.db")
        database.connect()
    except Exception as exc:
        _fatal("db_open", [f"数据库打开失败: {exc}"], ["deployment-ops §5.6"])
    assert database is not None
    try:
        rules_cfg = load_rules(rules_dir, database)
    except ModuleNotFoundError as exc:
        _fatal("rules_load", [f"PyYAML 不可用: {exc}（sys-arch §10.2 依赖清单内必装）"],
               ["sys-arch §10.2", "rules-config §1.2"])
    except Exception as exc:
        _fatal("rules_load", [str(exc)],
               ["rules-config §1.2", "deployment-ops §5.5 ①"])
    # ③ skills 装载校验
    try:
        registry, failures = load_skills(skills_dir, rules_cfg.get("roles") or {}, database)
    except Exception as exc:
        _fatal("skills_load", [f"技能装载器异常: {exc}"], ["skills-config §2.2"])
    if failures:
        from app.engine.skills.loader import report_failure
        for failure in failures:
            report_failure(database, f"skill_load_failure|boot", failure)
        _fatal("skills_load", [f"技能装载失败清单非空: {failures}"], ["skills-config §2.2"])
    summary = {
        "db_path": str(data_dir / "agentmesh.db"),
        "rules": sorted(p.name for p in rules_dir.glob("*.yaml")) if rules_dir.exists() else [],
        "skills_loaded": registry.all_ids() if registry else [],
        "skills_dir": str(skills_dir),
    }
    database.close()
    return summary


# ---------------------------------------------------------------------------
# 启动序列（ask：初始化 db → 装载 rules/skills → 启动 triggers → 启动 API）
# ---------------------------------------------------------------------------

def build_runtime() -> dict[str, Any]:
    """完成启动序列并返回运行时上下文（database/registry/scheduler/server）。"""
    root = _root()
    data_dir = _data_dir(root)
    database = Database(data_dir / "agentmesh.db")
    database.connect()
    rules_cfg = load_rules(_rules_dir(root), database)
    registry, failures = load_skills(_skills_dir(root), rules_cfg.get("roles") or {}, database)
    if failures:
        _fatal("skills_load", [f"技能装载失败清单非空: {failures}"], ["skills-config §2.2"])

    scheduler = triggers_mod.CronScheduler(database, default_tz=os.environ.get("TZ"))
    scheduler.start()

    # 凭证管理器接线（评审收口项：CRED §3A'/§10.2）——age 解密失败或密文缺失时降级
    # 运行（secrets 文件过渡形态继续生效，启动不 FATAL：CRED 密文可后置，deployment-ops §5.3）
    from app.engine.credentials import maybe_build as _maybe_build_cm
    credential_manager = _maybe_build_cm(database, roles_cfg=rules_cfg)

    # 编排引擎主循环（评审 P2：T1 领取 / 子任务执行 / 超时兜底 / T11 沉淀的唯一起动位）；
    # 网关 key 唯一来源：密文库 llm_gateway_key（CRED §10.2）；明文 env / secrets 文件通道
    # 均已删除（ARCH §10.1、CRED §7），见 llm.from_env
    from app.engine.llm import from_env as _llm_from_env
    llm_client = _llm_from_env(environ=os.environ, database=database,
                               credential_manager=credential_manager)
    engine = EngineLoop(database, llm_client, credential_manager=credential_manager)
    engine.start()

    budget_raw = os.environ.get("BUDGET_GLOBAL_DAILY")
    budget = float(budget_raw) if budget_raw else None
    # API 令牌来源：密文库 agentmesh_api_token（CRED §10.2，install.sh 建库时的承载位）
    # → AGENTMESH_API_TOKEN env（仅本地验收用；部署面 .env 不含该项）。明文文件通道已删除。
    api_token = None
    if credential_manager is not None:
        try:
            api_token = credential_manager.api_token()
        except Exception:
            api_token = None
    api_token = api_token or _read_secret_token()
    api = server_mod.KernelAPI(
        database, skills_registry=registry, rules_cfg=rules_cfg,
        web_dir=_web_dir(root), api_token=api_token,
        budget_global_daily=budget, tz_name=os.environ.get("AGENTMESH_TZ") or os.environ.get("TZ"),
        credential_manager=credential_manager)
    port = int(os.environ.get("AGENTMESH_PORT") or "8787")
    httpd = server_mod.serve(api, host="0.0.0.0", port=port)
    return {"database": database, "rules_cfg": rules_cfg, "registry": registry,
            "scheduler": scheduler, "engine": engine, "api": api, "server": httpd,
            "credential_manager": credential_manager, "port": httpd.server_address[1]}


def run() -> None:
    """阻塞运行直到 SIGTERM/SIGINT；优雅停机（调度线程 + 引擎循环 + API + WAL checkpoint）。"""
    runtime = build_runtime()
    httpd = runtime["server"]
    scheduler = runtime["scheduler"]
    stop = threading.Event()

    def _handle_signal(signum: int, _frame: Any) -> None:
        print(f"[main] signal {signum} received, shutting down", flush=True)
        stop.set()
        runtime["api"].shutdown_flag.set()
        threading.Thread(target=httpd.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)
    print(f"[main] agentmesh-core listening on 0.0.0.0:{runtime['port']}"
          f" (api=stdlib-http, db={runtime['database'].path})", flush=True)
    try:
        httpd.serve_forever(poll_interval=0.2)
    finally:
        scheduler.stop()
        runtime["engine"].stop()
        runtime["database"].close()
        print("[main] shutdown complete", flush=True)


class EngineLoop:
    """编排引擎主循环（ARCH §3.2/§3.3 单一驱动者落点；评审 P2 修复）：

    每 tick：① 超时兜底统一扫描 scan_timeouts → apply_timeout_action（审批到期置
    expired + T4 兜底、T2/T5/T6/T8 兜底动作落事件）；② 领取 pending 任务（≤max_claim 个）：
    T1 → plan_task → 按组拓扑序 execute_subtask → 全部子任务终态后 T5 → T6 → T11
    done_callback + consolidation_check。

    取舍（如实声明）：MVP 为单线程串行推进——全局并发 ≤4（ARCH §2.1 原则 5）是上限
    约束而非要求，串行合规；并行调度器为后续项。验收器交叉验证（ARCH §4.3）未接线，
    T6 在全部子任务终态后直接通过（如实降级声明）。STUB 适配器使无 key 环境全链可跑。
    """

    def __init__(self, database: Database, llm: Any, *, tick_seconds: float = 2.0,
                 max_claim: int = 4, credential_manager: Any | None = None) -> None:
        self.database = database
        self.llm = llm
        self.credential_manager = credential_manager
        self.tick_seconds = tick_seconds
        self.max_claim = max_claim
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="engine-loop", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)

    def _run(self) -> None:
        while not self._stop.wait(self.tick_seconds):
            try:
                self.tick()
            except Exception as exc:  # 引擎循环不因单次异常死亡
                print(f"[engine-loop] tick error: {type(exc).__name__}: {exc}", flush=True)

    def tick(self, now: str | None = None) -> dict[str, Any]:
        """单次引擎推进（可测试直调）：超时兜底 + 领取推进，返回动作摘要。"""
        now_ts = now or utc_now_iso()
        summary: dict[str, Any] = {"timeout_actions": [], "claimed": []}
        # ① 超时兜底（sys-arch §3.3 统一扫描器；所有动作本身落事件可 replay）
        for action in state_mod.scan_timeouts(self.database, now=now_ts):
            state_mod.apply_timeout_action(self.database, action, now=now_ts)
            summary["timeout_actions"].append({"kind": action.kind, "ref_id": action.ref_id})
        # ② 领取 pending（T1，sys-arch §3.2：存在且无依赖阻塞——规划前无组间依赖面）
        pending = self.database.query(
            "SELECT id FROM tasks WHERE status = 'pending' ORDER BY created_at LIMIT ?",
            (self.max_claim,))
        for row in pending:
            task_id = str(row["id"])
            outcome = self._advance_task(task_id, now_ts)
            summary["claimed"].append(outcome)
        return summary

    def _advance_task(self, task_id: str, now_ts: str) -> dict[str, Any]:
        """单任务全链推进：T1→planning→plan→逐子任务执行→T5→T6→T11 沉淀。"""
        state_mod.transition_task(self.database, task_id, TaskStatus.PLANNING,
                                  component="orchestrator", reason="T1: engine claim",
                                  now=now_ts)
        try:
            plan = planner_mod.plan_task(self.database, self.llm, task_id)
        except Exception as exc:  # PlanValidationError/网关不可用：账本已登记，T2 兜底接管
            return {"task_id": task_id, "stage": "plan", "error": str(exc)[:200]}
        # 逐子任务执行（组间 depends_on 拓扑序；串行合规于并发上限）
        for group in plan["groups"]:
            for sub in plan["subtasks"]:
                if sub["group_id"] != group["group_id"]:
                    continue
                try:
                    executor_mod.execute_subtask(self.database, self.llm, sub["subtask_id"],
                                                 credential_manager=self.credential_manager)
                except Exception as exc:  # 执行器已登记账本；异常不拖垮其余子任务
                    print(f"[engine-loop] subtask {sub['subtask_id']} crashed: {exc}", flush=True)
        # T5（全部子任务终态）→ T6 → T11（done 触发沉淀检查，sys-arch §3.2 T11）
        row = self.database.query_one("SELECT status FROM tasks WHERE id = ?", (task_id,))
        if row is None or row["status"] != TaskStatus.RUNNING.value:
            return {"task_id": task_id, "stage": "subtasks", "skipped_transition": True}
        subtasks = self.database.query("SELECT status FROM subtasks WHERE task_id = ?", (task_id,))
        if subtasks and all(s["status"] in ("done", "failed", "aborted") for s in subtasks):
            state_mod.transition_task(self.database, task_id, TaskStatus.REVIEWING,
                                      component="orchestrator", reason="T5: all subtasks terminal",
                                      now=now_ts)
            state_mod.transition_task(self.database, task_id, TaskStatus.DONE,
                                      component="reviewer", reason="T6: 交叉验证通过（MVP：无矛盾缺陷）",
                                      now=now_ts)
            state_mod.done_callback(self.database, task_id)
            ledger_mod.consolidation_check(self.database, task_id)
        return {"task_id": task_id, "stage": "done"}


def _read_secret_token() -> str | None:
    """API 令牌读取位（CRED §1.2/§10.2 衔接）。

    唯一持久来源：credentials.enc 的 agentmesh_api_token（build_runtime 里
    credential_manager.api_token() 优先，age 解密后内存持有）。
    AGENTMESH_API_TOKEN_FILE（0600 明文文件）通道已删除——CRED §7「无明文持久面」；
    AGENTMESH_API_TOKEN env 仅作本地验收兼容位（进程内存，不落盘、部署面 .env 不含）。
    都缺 → None（fail-closed：全部 /api/v1 返回 401）。"""
    return os.environ.get("AGENTMESH_API_TOKEN") or None


def main() -> int:
    # 导入基准（skills-config §2.2）：sys.path 必须含 app/ 的父目录（AGENTMESH_ROOT）
    root = str(_root())
    if root not in sys.path:
        sys.path.insert(0, root)
    try:
        run()
        return 0
    except SystemExit as exc:
        return int(exc.code or 0)


if __name__ == "__main__":
    raise SystemExit(main())
