"""AgentMesh 内核包（sys-arch §2.4 单进程内核）。

模块布局承接 skills-config §1.1 的 `/opt/agentmesh/app/` 内核代码树约定；本 ask
（内核 MVP 第一部分）交付 `app.engine.db / state / ledger` 三模块，其余组件
（编排引擎/规划器/审批门/凭证管理器/可观测台）按 sys-arch §2.4 模块图在本包续建。
"""
