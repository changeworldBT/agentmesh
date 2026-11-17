# impl/deploy/Dockerfile —— AgentMesh 内核镜像
# 安装位：install.sh（impl/deploy/install.sh 步骤 3）把本文件落到安装根 /opt/agentmesh/Dockerfile，
# 由同目录 compose.yaml 的 build 段引用：{ context: ., dockerfile: Dockerfile }（context=安装根，
# 内含 app/ 与 scripts/，故下方 COPY 路径成立——build 前置由 install.sh 步骤 3 保证）。

# 基底只用 slim（deployment-ops §2.2；python:3.12-slim amd64=43.3MB，
# Docker Hub API 实测 2026-11-17：size=43268722 bytes）；拒绝 full。
FROM python:3.12-slim

# age：凭证密文加密工具（credentials-spec 加密面；slim 基底即 Debian，
# age 包 Debian 实测 2026-11-17 sources.debian.org API：trixie=1.2.1-1 / bookworm=1.1.1-1，
# apt 直装无需外部源）。--no-install-recommends 保持最小面，装完清 apt 列表。
RUN apt-get update \
    && apt-get install -y --no-install-recommends age \
    && rm -rf /var/lib/apt/lists/*

# server 所需第三方依赖（若有）：内核运行时唯一第三方依赖 = PyYAML——
#   app/main.py:90（rules 装载）、app/engine/skills/loader.py:23 与 registry.py:15（技能装载）；
#   HTTP 层是标准库 http.server（impl/app/api/server.py:17-49 偏离声明），不装 fastapi/uvicorn。
# 版本经 PyPI JSON API 实测（2026-11-17：https://pypi.org/pypi/pyyaml/json latest=6.0.3，
# requires_python>=3.8；与 deployment-ops §2.2 依赖清单一致）。
RUN pip install --no-cache-dir --root-user-action=ignore PyYAML==6.0.3

# 代码与运维脚本进镜像（本部署形态：镜像自包含 app/ 与 scripts/；升级=替换安装根后重建镜像）
COPY app/ /opt/agentmesh/app/
COPY scripts/ /opt/agentmesh/scripts/
# 入口脚本必须可执行（compose entrypoint 直接执行）；清开发期 __pycache__/.pyc
RUN chmod 0755 /opt/agentmesh/scripts/docker-entrypoint.sh \
    && find /opt/agentmesh -name '__pycache__' -type d -prune -exec rm -rf {} + \
    && find /opt/agentmesh -name '*.pyc' -type f -delete

# 非 root 运行用户（deployment-ops §1.2 纪律 3；与 compose user: "10001:10001" 对齐）
RUN groupadd -g 10001 agentmesh \
    && useradd -u 10001 -g 10001 -m -s /usr/sbin/nologin agentmesh
USER 10001:10001

# WORKDIR=/opt/agentmesh（app/ 的父目录）：CMD 以顶层包 `app.main` 启动
# （skills-config §2.2 导入基准；impl/scripts/docker-entrypoint.sh 同基准补 PYTHONPATH）
WORKDIR /opt/agentmesh

# 对外唯一端口（sys-arch §10.1；impl/app/main.py 默认 AGENTMESH_PORT=8787）
EXPOSE 8787

# 启动链：compose entrypoint=scripts/docker-entrypoint.sh（db 可写探针 + rules/skills
# 装载校验，任一失败 exit 1）→ exec 本 CMD；健康探针端点 /healthz（impl/app/api/server.py:333）
CMD ["python3", "-m", "app.main"]
