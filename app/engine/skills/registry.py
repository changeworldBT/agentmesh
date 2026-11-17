#!/usr/bin/env python3
"""app/engine/skills/registry.py — 技能注册表（skills-config §2.2 完整可运行交付代码落盘）。

线程安全说明：内核全局并发≤4（资源调研 SQLite 边界），加互斥锁后
单写多读，与 SQLite 单写者纪律一致。注册表进程生命周期内不热更；
技能变更走容器重启加载（skills-config §2.2 启动时序）。
"""

from __future__ import annotations

import threading
from pathlib import Path
from typing import TYPE_CHECKING

import yaml

if TYPE_CHECKING:
    from app.engine.db import Database


class SkillRegistry:
    """受控注册表：只经 load_all() 写入，查询只读。"""

    def __init__(self, database: "Database | None" = None) -> None:
        self._lock = threading.Lock()
        self._skills: dict[str, dict] = {}
        self._database = database

    def load_all(self, skills_root: Path, roles_cfg: dict) -> list[str]:
        """扫描 skills/ 全目录，返回加载失败的 "skill_id: 原因" 列表。

        roles_cfg 为 rules/roles.yaml 解析结果，用于跨校验：
          skill.roles ⊆ roles.yaml 已定义角色；
          skill.credential_groups ⊆ 各角色被授权凭证组的并集。
        加载失败逐条经 loader.report_failure() 登记错误账本（skills-config §2.1
        「不静默跳过——技能注册表是审计边界」），再进入返回清单。
        """
        failures: list[str] = []
        roles_obj = roles_cfg.get("roles", {})
        if not isinstance(roles_obj, dict):
            roles_obj = {}
        known_roles = set(roles_obj)
        role2cred: dict[str, set] = {}
        for role, cfg in roles_obj.items():
            groups = (cfg or {}).get("credential_groups", [])
            role2cred[role] = set(groups or [])
        for d in sorted(Path(skills_root).iterdir()):
            if not d.is_dir():
                continue
            try:
                # 绝对导入：registry 与 loader 同为 app.engine.skills 包内模块，
                # 探针与容器内统一以 app 包根（/opt/agentmesh/app）入 sys.path
                # 后经 `from app.engine.skills.registry import SkillRegistry` 触发。
                from app.engine.skills.loader import load_skill, report_failure
                meta = load_skill(d)
                if not set(meta["roles"]) <= known_roles:
                    raise ValueError(
                        f"roles {meta['roles']} 不在 roles.yaml 定义内")
                union: set = set()
                for r in meta["roles"]:
                    union |= role2cred.get(r, set())
                if not set(meta["credential_groups"]) <= union:
                    raise ValueError(
                        f"credential_groups {meta['credential_groups']} "
                        f"超出角色授权并集 {sorted(union)}")
                with self._lock:
                    self._skills[meta["name"]] = {"meta": meta,
                                                  "dir": str(d)}
            except (ValueError, OSError, yaml.YAMLError) as exc:
                failures.append(f"{d.name}: {exc}")
                report_failure(self._database, f"skill_load_failure|{d.name}",
                               f"{d.name}: {exc}", phase="running")
        return failures

    def get(self, skill_id: str) -> dict | None:
        with self._lock:
            return self._skills.get(skill_id)

    def all_ids(self) -> list[str]:
        with self._lock:
            return sorted(self._skills)
