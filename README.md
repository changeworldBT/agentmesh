# AgentMesh — 自组织任务编排内核

AgentMesh 是一个自研的任务编排内核：用户只提交自然语言目标（goal），系统自动规划任务树、按组执行、过审批闸门、记录错误账本，并在 Web 面板上呈现全过程。

- 内核：Python 3.12 stdlib（HTTP 服务 `http.server` + SQLite WAL 单写连接），第三方依赖仅 PyYAML
- 部署：Docker Compose 单机（4 核 8G 实测通过）；镜像约 206MB
- 安全：API 令牌与 LLM 网关 key 存于 age 加密的 `credentials.enc`，按角色（planner/worker/reviewer/…）与凭证组分权注入，全程审计；仓库与 `.env` 不含任何明文密钥
- 测试：`python tests/run_all.py`（98 例；无 `age` 二进制的机器上 1 例 SKIP）

## 快速部署（Debian/Ubuntu + Docker）

```bash
git clone https://github.com/changeworldBT/agentmesh.git
cd agentmesh/deploy
sudo bash install.sh        # 生成 age 密钥与 credentials.enc，构建并启动容器
curl -s http://127.0.0.1:8787/healthz
```

面板：`http://127.0.0.1:8787`（默认仅回环；公网建议反代或 SSH 隧道）。
API 令牌在 `credentials.enc` 的 `api_keys.agentmesh_api_token` 条目内（首次 `install.sh` 随机生成）。

## 提交一个任务

```bash
TOKEN=<你的令牌>
curl -s -X POST http://127.0.0.1:8787/api/v1/tasks \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"goal":"写一段 200 字以内的系统自述并保存为 md"}'
```

任务经 `planning → running → reviewing → done` 状态机推进，产物落在 `/data/agentmesh/workspaces/<task_id>/`。

## 目录

| 路径 | 内容 |
|---|---|
| `app/engine/` | planner / executor / state（T1–T11 状态机）/ approval / ledger（FTS5 错误账本）/ triggers（cron + webhook HMAC）/ credentials（age 密文库+三闸门）/ llm（STUB 与 OpenAI 兼容网关） |
| `app/api/server.py` | REST API（任务/审批/触发器/事件/凭证元数据） |
| `web/` | 任务面板（令牌门、看板、SSE 实时流） |
| `rules/` | roles / global / collab / lessons YAML（并发≤4、审批风险分层等硬底线） |
| `skills/` | memory-read、error-report 技能（SKILL.md + 脚本 + 自测） |
| `deploy/` | Dockerfile、compose.yaml、install.sh（幂等安装器） |
| `tests/` | 纯 stdlib 测试套件与 `run_all.py` 顺序执行器 |

## 切换真实 LLM

默认 `LLM_PROVIDER=STUB`（确定性假模型，用于机制验收）。接入真实网关：

1. 把网关 key 加密进 `credentials.enc` 的 `api_keys.llm_gateway_key` 条目（参考 `app/engine/credentials.py` 的 CRED §9.1 轮换流程；不要写入 `.env`）。
2. 编辑 `.env`：`LLM_PROVIDER=OPENAI_COMPAT`、`LLM_BASE_URL=<网关地址>`、`LLM_MODEL=<模型名>`。
3. `docker compose restart agentmesh-core`，`/healthz` 的 `degradations` 须为空。

## 已知边界（如实）

- MVP 内置工具仅 `http_get` / `file_write`（后者硬限制在任务工作区内）；无 shell/浏览器/邮件工具。
- T6 复核为交叉验证占位（MVP 无独立 LLM 复核员）。
- 未做长稳/负载测试；面板未做浏览器端深度验收。

## License

Apache-2.0
