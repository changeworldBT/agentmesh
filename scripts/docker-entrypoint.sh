#!/bin/sh
# /opt/agentmesh/scripts/docker-entrypoint.sh — 启动前置自检包装（ask 第 4 条；判据出处
# deployment-ops §5.5 装载校验 / §5.6 启动前置 / §6.1 首验 10 WAL；real-vps-facts 重状态落 /data）。
#
# 职责：① db 可写自检（只在数据目录写探针文件，绝不写只读挂载：credentials/scripts/app
#       等 bind :ro 一律不触碰）；② rules/skills 装载校验（与内核同一逻辑 app.main.preflight，
#       任一失败 exit 1）；③ 全过后 exec CMD（缺省 python3 -m app.main）。
# shebang 必须在第 1 行（compose 以 ["...docker-entrypoint.sh"] 直接执行）。
set -eu

log() { echo "[docker-entrypoint] $*"; }
die() { echo "[docker-entrypoint] FATAL: $*" >&2; exit 1; }

PYTHON="${PYTHON:-python3}"
AGENTMESH_ROOT="${AGENTMESH_ROOT:-/opt/agentmesh}"
export AGENTMESH_ROOT

# 导入基准 = app/ 的父目录（skills-config §2.2 导入方式声明：不得误插 app 本身）
PYTHONPATH="${AGENTMESH_ROOT}${PYTHONPATH:+:${PYTHONPATH}}"
export PYTHONPATH

# ① db 可写自检（探针只落数据目录；WAL/journal_mode 校验在 preflight 内做）
"$PYTHON" - <<'PYEOF' || die "db writable self-check failed (data dir 不可写或缺失)"
import os
import pathlib
import sys

data_dir = pathlib.Path(
    os.environ.get("AGENTMESH_DATA_DIR")
    or (pathlib.Path(os.environ["AGENTMESH_ROOT"]) / "data"))
try:
    data_dir.mkdir(parents=True, exist_ok=True)
    probe = data_dir / ".entrypoint_write_probe"
    probe.write_text("ok", encoding="utf-8")
    probe.unlink()
except OSError as exc:
    print(f"db write probe failed on {data_dir}: {exc}", file=sys.stderr)
    sys.exit(1)
print(f"db writable: {data_dir}")
PYEOF
log "db writable: ok"

# ② rules/skills 装载校验（复用内核同一装载逻辑；失败时 app.main._fatal 输出结构化 JSON 并 exit 1）
"$PYTHON" -c "from app.main import preflight; import json, sys; print(json.dumps(preflight(), ensure_ascii=False))" \
  || die "rules/skills preflight failed (装载校验未过，deployment-ops §5.5)"

log "startup pre-check: all skill/kernel tests passed"

# ③ 交回 CMD；无参数时缺省启动内核主入口（app.main，本 ask 第 3 条）
if [ "$#" -eq 0 ]; then
  set -- "$PYTHON" -m app.main
fi
exec "$@"
