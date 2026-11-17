#!/usr/bin/env bash
# impl/deploy/install.sh —— AgentMesh 单机安装脚本
# 目标机：Debian 13 (trixie) x86_64 + 预装 Docker 29（real-vps-facts.md 实测 29.8.2；
# 磁盘：系统盘 /dev/vda 16G、数据盘 /dev/vdb 20G 挂载于 /data——重状态落 /data）。
#
# 用法：把交付树整体拷到目标机（app/ scripts/ web/ rules/ skills/ deploy/ 五目录 + 本文件
#       所在 deploy/），以 root 运行：sudo bash deploy/install.sh
# 步骤链（本 ask 指定顺序，闭合无循环依赖）：
#   ① 版本校验 → ② 建目录（/data/agentmesh/{db,logs,workspaces,backups} 与安装根）
#   → ③ 落盘 rules/skills/web（连同 build 前置 app/scripts/Dockerfile/compose.yaml/.dockerignore）
#   → ④ 写 .env（600）→ ⑤ docker compose build → ⑥ up -d --wait → ⑦ curl 健康探针。
# 健康端点说明：ask 原文写 /api/health；内核实际健康端点为 /healthz（impl/app/api/server.py:333，
# 路由表无 /api/health——curl 它会 404）。本脚本按真实端点 /healthz 探活，语义即「HTTP 健康验收」。
# 幂等：重复运行安全——内容重灌（步骤③）、.env 已存在则保留现值（步骤④）、镜像重建、
#       容器按 compose 配置重建到最新（步骤⑤⑥）。
set -euo pipefail

log() { printf '[install] %s\n' "$*"; }
die() { printf '[install][FATAL] %s\n' "$*" >&2; exit 1; }

INSTALL_ROOT="${INSTALL_ROOT:-/opt/agentmesh}"   # 安装根：编排面(compose/.env/Dockerfile) + 内容(rules/skills/web/app/scripts)
DATA_ROOT="${DATA_ROOT:-/data/agentmesh}"        # 重状态根：db/logs/workspaces/backups（/data 数据盘）
RUN_UID=10001
RUN_GID=10001
HEALTH_URL="http://127.0.0.1:8787/healthz"       # 内核健康端点（impl/app/api/server.py:333）

[ "$(id -u)" = "0" ] || die "必须以 root 运行：sudo bash deploy/install.sh"

# 交付树根 = 本脚本所在 deploy/ 的上一级（app/scripts/web/rules/skills 应与之同级）
SRC_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# ---------- 前置：交付树完整性（引用即存在，断链在最早一步暴露） ----------
for d in app scripts web rules skills; do
  [ -d "$SRC_ROOT/$d" ] || die "交付树缺目录 $SRC_ROOT/$d——整体拷贝交付树后重跑"
done
[ -f "$SRC_ROOT/deploy/Dockerfile" ] || die "交付树缺 $SRC_ROOT/deploy/Dockerfile（步骤③ build 前置）"
[ -f "$SRC_ROOT/deploy/compose.yaml" ] || die "交付树缺 $SRC_ROOT/deploy/compose.yaml（步骤③ build 前置）"
for y in global.yaml roles.yaml collab.yaml lessons.yaml; do
  [ -f "$SRC_ROOT/rules/$y" ] || die "交付树缺 $SRC_ROOT/rules/$y（内核启动装载四文件，缺一 preflight 即 FATAL）"
done
[ -f "$SRC_ROOT/scripts/docker-entrypoint.sh" ] || die "交付树缺 $SRC_ROOT/scripts/docker-entrypoint.sh（镜像 entrypoint）"
[ -f "$SRC_ROOT/app/main.py" ] || die "交付树缺 $SRC_ROOT/app/main.py（内核入口 app.main）"

# ---------- 步骤 1：版本校验（Docker 已预装；real-vps-facts.md 实测 29.8.2，本步只校验不安装） ----------
command -v docker >/dev/null 2>&1 || die "docker 未安装——目标机应预装 Docker 29.x（real-vps-facts.md），请人工核查"
docker info >/dev/null 2>&1 || die "docker daemon 不可达（docker info 失败）——请先启动 docker 服务"
docker compose version >/dev/null 2>&1 || die "docker compose 插件缺失（需 compose v2：docker-compose-plugin）"
DOCKER_SERVER_VERSION="$(docker version --format '{{.Server.Version}}')"
DOCKER_MAJOR="${DOCKER_SERVER_VERSION%%.*}"
case "$DOCKER_MAJOR" in ''|*[!0-9]*) die "无法解析 docker server 版本: $DOCKER_SERVER_VERSION" ;; esac
[ "$DOCKER_MAJOR" -ge 24 ] || die "docker server $DOCKER_SERVER_VERSION 低于 24——compose v2 + mem_limit/memswap_limit 需要较新引擎"
log "步骤1 版本校验通过：docker server $DOCKER_SERVER_VERSION / compose $(docker compose version --short)"

# ---------- 步骤 2：建目录（/data/agentmesh/{db,logs,workspaces,backups} 与安装根） ----------
# 运行账号：容器内 UID=10001（compose user: "10001:10001"），宿主建同名系统用户对齐属主
if ! id -u agentmesh >/dev/null 2>&1; then
  useradd --system --uid "$RUN_UID" --home-dir "$INSTALL_ROOT" --shell /usr/sbin/nologin agentmesh
  log "步骤2 已建系统用户 agentmesh (UID=$RUN_UID, nologin)"
else
  log "步骤2 系统用户 agentmesh 已存在，跳过"
fi
mkdir -p "$INSTALL_ROOT" \
         "$DATA_ROOT/db" "$DATA_ROOT/logs" "$DATA_ROOT/workspaces" "$DATA_ROOT/backups"
# 重状态四目录：容器内 UID 10001 可写（compose bind 挂载的写落点）
chown -R "$RUN_UID:$RUN_GID" "$DATA_ROOT"
chmod 750 "$DATA_ROOT" "$DATA_ROOT/db" "$DATA_ROOT/logs" "$DATA_ROOT/workspaces" "$DATA_ROOT/backups"
# 安装根：root 属主（写路径只在部署/升级时经 root），内容目录对"其他"保持可读（容器内 UID 10001 读取）
log "步骤2 目录就绪：$(ls -d "$DATA_ROOT"/*/ | tr '\n' ' ')；安装根 $INSTALL_ROOT"

# ---------- 步骤 3：落盘内容（rules/skills/web + build 前置 app/scripts/Dockerfile/compose.yaml） ----------
# 先清旧内容再灌新（幂等升级语义），随后统一权限并清开发产物 __pycache__/*.pyc
rm -rf "$INSTALL_ROOT/app" "$INSTALL_ROOT/scripts" "$INSTALL_ROOT/rules" \
       "$INSTALL_ROOT/skills" "$INSTALL_ROOT/web"
cp -a "$SRC_ROOT/app" "$SRC_ROOT/scripts" "$SRC_ROOT/rules" \
      "$SRC_ROOT/skills" "$SRC_ROOT/web" "$INSTALL_ROOT/"
install -m 0644 "$SRC_ROOT/deploy/Dockerfile"  "$INSTALL_ROOT/Dockerfile"
install -m 0644 "$SRC_ROOT/deploy/compose.yaml" "$INSTALL_ROOT/compose.yaml"
find "$INSTALL_ROOT/app" "$INSTALL_ROOT/scripts" "$INSTALL_ROOT/rules" \
     "$INSTALL_ROOT/skills" "$INSTALL_ROOT/web" -name '__pycache__' -type d -prune -exec rm -rf {} +
find "$INSTALL_ROOT/app" "$INSTALL_ROOT/scripts" "$INSTALL_ROOT/rules" \
     "$INSTALL_ROOT/skills" "$INSTALL_ROOT/web" -name '*.pyc' -type f -delete
find "$INSTALL_ROOT/app" "$INSTALL_ROOT/scripts" "$INSTALL_ROOT/rules" \
     "$INSTALL_ROOT/skills" "$INSTALL_ROOT/web" -type d -exec chmod 0755 {} +
find "$INSTALL_ROOT/app" "$INSTALL_ROOT/scripts" "$INSTALL_ROOT/rules" \
     "$INSTALL_ROOT/skills" "$INSTALL_ROOT/web" -type f -exec chmod 0644 {} +
chmod 0755 "$INSTALL_ROOT/scripts/docker-entrypoint.sh"
# .dockerignore：构建上下文只留 app/ 与 scripts/——.env 与规则/技能/数据不入镜像层
# （deployment-ops §4.2 持久面禁令：.env 不进 build context；镜像层核查命令见 §6.1 第 5 项）
cat > "$INSTALL_ROOT/.dockerignore" <<'EOF'
.env
Dockerfile
compose.yaml
rules
skills
web
data
logs
workspaces
backups
credentials
secrets
**/__pycache__
*.pyc
EOF
chmod 0644 "$INSTALL_ROOT/.dockerignore"
log "步骤3 落盘完成：rules=$(ls "$INSTALL_ROOT/rules" | tr '\n' ' ') skills=$(ls "$INSTALL_ROOT/skills" | tr '\n' ' ') web=$(ls "$INSTALL_ROOT/web" | tr '\n' ' ')"

# ---------- 步骤 4：凭证密文建库 + .env（600；已存在则保留现值——防重跑覆盖人工改过的端点/预算） ----------
# 凭证通道（CRED §3 路径 A' / §10.1-10.2 / §10.2 令牌承载）：
#   ① 宿主 age keypair → /etc/agentmesh/age-key.txt（0600 root:root，不进镜像/卷）
#   ② compose file 型 secret 以 tmpfs 只读挂进容器 /run/secrets/age_key（AGENTMESH_AGE_KEY_FILE）
#   ③ 密文 /opt/agentmesh/credentials/credentials.enc（600 agentmesh）承载 api_keys 组：
#      agentmesh_api_token（/api/v1/* Bearer 令牌）与 llm_gateway_key（LLM 网关 key）
#   ④ 内核启动 age 解密 → 内存窗口 → 短寿命注入（app/engine/credentials.py）
# 磁盘上不再生成任何明文令牌文件。明文只经 mktemp（tmpfs /dev/shm）中转，加密后立即删除。
AGE_KEY_HOST=/etc/agentmesh/age-key.txt
CRED_DIR="$INSTALL_ROOT/credentials"
CRED_ENC="$CRED_DIR/credentials.enc"
CRED_PUB="$CRED_DIR/recipients.pub"

if ! command -v age >/dev/null 2>&1 || ! command -v age-keygen >/dev/null 2>&1; then
  log "步骤4 宿主缺 age/age-keygen，尝试 apt 安装（Debian 13 main 有 age 1.2.1-1）"
  apt-get install -y --no-install-recommends age >/dev/null 2>&1 || true
fi
if ! command -v age >/dev/null 2>&1 || ! command -v age-keygen >/dev/null 2>&1; then
  die "宿主缺 age 二进制（apt-get install -y age 失败）——凭证密文库无法建立；拒绝以明文令牌文件替代（CRED §10.1 完成判据）"
fi

install -d -m 0700 -o root -g root /etc/agentmesh
if [ ! -f "$AGE_KEY_HOST" ]; then
  TMPKEY="$(mktemp)"
  rm -f "$TMPKEY"   # age-keygen(1.2.1) 拒绝写已存在文件：mktemp 先建空文件会让 keygen 直接失败
  age-keygen -o "$TMPKEY" 2>/dev/null
  install -m 0640 -o root -g "$RUN_GID" "$TMPKEY" "$AGE_KEY_HOST"
  rm -f "$TMPKEY"
  log "步骤4 已生成 age keypair：$AGE_KEY_HOST (640 root:$RUN_GID)"
else
  log "步骤4 age 私钥已存在，保留（幂等不覆盖）：$AGE_KEY_HOST"
fi
# compose file 型 secret 以 bind mount 呈现（不重写 mode/owner）：容器内运行用户 UID/GID=10001
# 必须能读私钥，故宿主侧授予组读；/etc/agentmesh 目录仍 0700 root，其他宿主用户不可达。
chown root:"$RUN_GID" "$AGE_KEY_HOST"
chmod 0640 "$AGE_KEY_HOST"
install -d -m 0700 -o "$RUN_UID" -g "$RUN_GID" "$CRED_DIR"

if [ ! -f "$CRED_ENC" ]; then
  # 公钥（age-keygen 把 "public key: age1..." 写到 stderr，重导一次即可，不碰私钥）
  age-keygen -y "$AGE_KEY_HOST" > "$CRED_PUB"
  chown "$RUN_UID:$RUN_GID" "$CRED_PUB"; chmod 0644 "$CRED_PUB"
  API_TOKEN="$(od -An -N24 -tx1 /dev/urandom | tr -d ' 
')"
  PLAIN="$(mktemp /dev/shm/agentmesh-creds.XXXXXX 2>/dev/null || mktemp)"
  chmod 0600 "$PLAIN"
  cat > "$PLAIN" <<JSON
{
  "version": 1,
  "updated": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "api_keys": {
    "agentmesh_api_token": {
      "value": "$API_TOKEN",
      "env": "AGENTMESH_API_TOKEN",
      "header": "Authorization",
      "header_prefix": "Bearer ",
      "rotate_at": "$(date -u -d '+90 days' +%Y-%m-%d 2>/dev/null || date -u -v+90d +%Y-%m-%d)",
      "notes": "内核对外 API 面的用户 Bearer 令牌（interface-contracts §1.2）"
    },
    "llm_gateway_key": {
      "value": "",
      "env": "LLM_GATEWAY_KEY",
      "header": "Authorization",
      "header_prefix": "Bearer ",
      "rotate_at": "$(date -u -d '+90 days' +%Y-%m-%d 2>/dev/null || date -u -v+90d +%Y-%m-%d)",
      "notes": "统一 LLM API 网关凭证；LLM_PROVIDER=STUB 时留空，接真实网关前由运维重加密填入（CRED §9.1）"
    }
  },
  "accounts": {},
  "vps_inventory": {}
}
JSON
  age -r "$(cat "$CRED_PUB")" -o "$CRED_ENC" "$PLAIN"
  rm -f "$PLAIN"
  chown "$RUN_UID:$RUN_GID" "$CRED_ENC"; chmod 0600 "$CRED_ENC"
  # 完成判据（CRED §10.2 ③）：密文可解
  age -d -i "$AGE_KEY_HOST" -o /dev/null "$CRED_ENC"     || die "credentials.enc 解密自检失败（CRED §10.2 完成判据）"
  log "步骤4 已建凭证密文库：$CRED_ENC（api_keys 含 agentmesh_api_token / llm_gateway_key）"
else
  log "步骤4 credentials.enc 已存在，保留（幂等不覆盖）：$CRED_ENC"
fi

ENV_FILE="$INSTALL_ROOT/.env"
if [ -f "$ENV_FILE" ]; then
  log "步骤4 .env 已存在，保留现值（幂等不覆盖）"
else
  cat > "$ENV_FILE" <<EOF
# /opt/agentmesh/.env —— compose env_file 注入面（install.sh 步骤 4 生成，权限 600）
# 纪律（deployment-ops §4.2 + CRED §7）：本文件不含任何令牌/key 明文，只含路径指针。
# 凭证通道：AGENTMESH_CREDENTIALS_FILE（age 密文）+ AGENTMESH_AGE_KEY_FILE（compose secret 落点），
# 由 app/engine/credentials.py 解密后按 CRED §5.1 短寿命注入。
# LLM 适配面（impl/app/engine/llm.py from_env）：LLM_PROVIDER=STUB 为无 key 起步形态，
# 规划→执行→审批验收链无需外部网关；接真实网关时改 OPENAI_COMPAT 并在 credentials.enc
# 的 llm_gateway_key 条目填入 key（CRED §9.1 轮换流程），不要把 key 写进本文件。
LLM_PROVIDER=STUB
LLM_BASE_URL=
LLM_MODEL=
AGENTMESH_PORT=8787
AGENTMESH_CREDENTIALS_FILE=/opt/agentmesh/credentials/credentials.enc
AGENTMESH_AGE_KEY_FILE=/run/secrets/age_key
BUDGET_GLOBAL_DAILY=20
TZ=Asia/Shanghai
AGENTMESH_TZ=Asia/Shanghai
EOF
  log "步骤4 .env 已生成（LLM_PROVIDER=STUB；令牌/key 全部承载于 credentials.enc）"
fi
chown root:root "$ENV_FILE"
chmod 0600 "$ENV_FILE"
log "步骤4 凭证面：enc=$(stat -c '%a %U:%G' "$CRED_ENC") age_key=$(stat -c '%a %U:%G' "$AGE_KEY_HOST")"
log "步骤4 .env 权限复位：$(stat -c '%a %U:%G' "$ENV_FILE")"

# ---------- 步骤 5：docker compose build ----------
cd "$INSTALL_ROOT"
log "步骤5 构建镜像（context=$INSTALL_ROOT, dockerfile=Dockerfile）"
docker compose build
log "步骤5 完成：$(docker images agentmesh-core --format '{{.Repository}}:{{.Tag}} {{.Size}}' | head -1)"

# ---------- 步骤 6：up -d --wait（等 healthy；entrypoint 自检失败会以非 0 退出被 --wait 捕获） ----------
log "步骤6 拉起容器（--wait 等 healthz 通过）"
docker compose up -d --wait
docker compose ps

# ---------- 步骤 7：健康探针验收（curl /healthz；ask 原文 /api/health 见文件头说明） ----------
HEALTH_OK=""
for _ in $(seq 1 30); do
  if curl -fsS --max-time 5 "$HEALTH_URL" -o /tmp/agentmesh-health.json 2>/dev/null; then
    HEALTH_OK=1
    break
  fi
  sleep 2
done
if [ -z "$HEALTH_OK" ]; then
  docker compose logs --tail 50 agentmesh-core >&2 || true
  die "健康探针 60s 未通过：$HEALTH_URL（容器日志已附上）"
fi
log "步骤7 健康探针通过：$HEALTH_URL → $(cat /tmp/agentmesh-health.json)"
rm -f /tmp/agentmesh-health.json

log "全部步骤完成。管理命令：docker compose -f $INSTALL_ROOT/compose.yaml ps/logs/restart"
