#!/usr/bin/env python3
"""app/engine/skills/loader.py — front-matter 解析（skills-config §2.1 完整可运行交付代码落盘）。

职责：
  1. 解析 SKILL.md 的 YAML front-matter（标准库 + PyYAML）；
  2. 逐条校验 skills-config §1.2 字段全表（封闭字段集）；
  3. load_skill() 校验目录名 == name；
  4. report_failure() 供各技能 Fail Branch 统一上报（AUTHZ_DENY 等签名）。

落盘适配（如实声明）：skills-config 原文的 report_failure 引用
`app.engine.memory.ledger.ErrorLedger.open_default()`（skills-config 侧独立布局）；
本内核树唯一账本写入口为 app.engine.ledger.ledger_write(database, ...)（memory-design
§2.4/§6.3），故本落盘版改为接受可选 Database 注入，其余校验逻辑逐字保持设计文档定义。
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import yaml  # PyYAML 6.x，requirements 固定版本

if TYPE_CHECKING:  # 循环导入避让：仅类型注解场景
    from app.engine.db import Database

FM_RE = re.compile(r"\A---\s*\n(.*?)\n---\s*\n?", re.DOTALL)

ALLOWED_FIELDS = {
    "name", "description", "when", "roles", "credential_groups",
    "timeout_s", "retries", "idempotent", "risk_level",
    "inputs", "outputs", "version",
}
ROLE_ENUM = {"planner", "worker", "reviewer",
             "approval_gate", "credential_manager", "orchestrator"}
CRED_ENUM = {"api_keys", "accounts", "vps_inventory"}
RISK_ENUM = {"low", "medium", "high"}
# 技能面阶段 ∈ sys-arch §3.1 状态机非终态（不含 pending 与三个终态）；
# 内核装载（原草案 "loading"）是组件内部动作，不冒充状态机阶段名
PHASE_ENUM = {"planning", "running", "reviewing", "rework", "paused_for_approval"}
INPUT_TYPE_ENUM = {"string", "int", "bool", "list[string]", "dict"}


class SkillConfigError(ValueError):
    """front-matter 校验失败。技能配置错误应显式失败而非静默跳过。"""


def parse_front_matter(text: str) -> dict:
    """解析并逐条校验 skills-config §1.2 字段表；违规抛 SkillConfigError，加载失败。"""
    m = FM_RE.match(text)
    if not m:
        raise SkillConfigError("SKILL.md 缺少 YAML front-matter")
    try:
        meta = yaml.safe_load(m.group(1))
    except yaml.YAMLError as exc:
        raise SkillConfigError(f"front-matter YAML 解析失败: {exc}") from exc
    if not isinstance(meta, dict):
        raise SkillConfigError("front-matter 必须是 YAML 映射")
    unknown = set(meta) - ALLOWED_FIELDS
    if unknown:
        raise SkillConfigError(f"front-matter 含未定义字段: {sorted(unknown)}")
    missing = ALLOWED_FIELDS - set(meta)
    if missing:
        raise SkillConfigError(f"front-matter 缺少必填字段: {sorted(missing)}")
    if not re.fullmatch(r"[a-z0-9]+(-[a-z0-9]+)*", str(meta["name"])):
        raise SkillConfigError(f"name 不是 kebab-case: {meta['name']!r}")
    if not isinstance(meta["description"], str) or \
            not (1 <= len(meta["description"]) <= 1024):
        raise SkillConfigError("description 必须是 1-1024 字符的字符串")
    when = meta["when"]
    if not isinstance(when, list) or not when or len(when) > 5 or \
            not all(isinstance(w, str) and 1 <= len(w) <= 120 for w in when):
        raise SkillConfigError("when 必须是 1-5 条、每条 ≤120 字符的短语列表")
    if not isinstance(meta["roles"], list) or not meta["roles"] or \
            len(meta["roles"]) > 5 or \
            not set(meta["roles"]) <= ROLE_ENUM:
        raise SkillConfigError(f"roles 越界: {meta['roles']!r}")
    cg = meta["credential_groups"]
    if not isinstance(cg, list) or not set(cg) <= CRED_ENUM:
        raise SkillConfigError(f"credential_groups 越界: {cg!r}")
    if meta["risk_level"] not in RISK_ENUM:
        raise SkillConfigError(f"risk_level 越界: {meta['risk_level']!r}")
    if isinstance(meta["timeout_s"], bool) or \
            not isinstance(meta["timeout_s"], int) or \
            not 10 <= meta["timeout_s"] <= 900:
        raise SkillConfigError("timeout_s 必须是 10-900 的整数")
    if isinstance(meta["retries"], bool) or \
            not isinstance(meta["retries"], int) or \
            not 0 <= meta["retries"] <= 3:
        raise SkillConfigError("retries 必须是 0-3 的整数")
    if not isinstance(meta["idempotent"], bool):
        raise SkillConfigError("idempotent 必须是布尔值")
    if meta["retries"] > 0 and not meta["idempotent"]:
        raise SkillConfigError("retries>0 必须声明 idempotent:true")
    if not isinstance(meta["inputs"], list) or \
            not all(isinstance(i, dict) and
                    set(i) == {"name", "type", "required", "desc"} and
                    i["type"] in INPUT_TYPE_ENUM and
                    isinstance(i["required"], bool) and
                    isinstance(i["name"], str) and i["name"] and
                    isinstance(i["desc"], str)
                    for i in meta["inputs"]):
        raise SkillConfigError("inputs 必须是 {name,type,required,desc} 对象列表")
    if not isinstance(meta["outputs"], str) or not meta["outputs"].strip():
        raise SkillConfigError("outputs 必须是非空字符串")
    v = str(meta["version"])
    if not re.fullmatch(r"\d+\.\d+", v):
        raise SkillConfigError(f"version 必须是 MAJOR.MINOR 数字点分: {v!r}")
    return meta


def load_skill(skill_dir: Path) -> dict:
    """校验目录名与 name 一致并返回 meta。目录名 = name，不一致拒绝。"""
    text = (skill_dir / "SKILL.md").read_text(encoding="utf-8")
    meta = parse_front_matter(text)
    if meta["name"] != skill_dir.name:
        raise SkillConfigError(
            f"目录名 {skill_dir.name!r} != name {meta['name']!r}")
    return meta


def report_failure(database: "Database | None", signature: str, raw: str,
                   phase: str = "running", task_id: str = "") -> None:
    """Fail Branch 统一上报入口：写错误账本 + stderr（不抛异常）。

    AUTHZ_DENY 等授权类签名走此入口（skills-config §2.4）。写路径统一走
    memory-design §2.4 的 ledger_write() 单一入口，签名/指纹由账本侧
    memory-design §2.2 算法计算，本函数不自拼签名绕过。
    database 为 None（如装载期尚未建库）时仅写 stderr，不阻塞调用方。
    """
    if phase not in PHASE_ENUM:
        phase = "running"
    if database is not None:
        try:
            from app.engine import ledger as _ledger
            _ledger.ledger_write(
                database,
                error_type=signature.split("|", 1)[0][:64] or "skill_failure",
                module="skills.loader",
                params={"signature": signature[:120], "phase": phase},
                raw_error=raw[:2000], task_id=task_id or "kernel-boot",
                role="orchestrator",
                root_cause="", fix_applied="")
        except Exception as exc:  # 上报通道自身故障不得反噬调用方
            print(f"[report_failure] ledger unavailable: {type(exc).__name__}",
                  file=sys.stderr)
    else:
        print(f"[report_failure] no database: {signature} {raw[:120]}",
              file=sys.stderr)
