---
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
