"""内核引擎子包：db（SQLite WAL 连接与全部表）、state（任务状态机）、ledger（错误账本）。

对应设计文档：sys-arch §2.4 内核模块图、memory-design §1.1（单文件库）、
deployment-ops §5.1（表清单与按需建表注记）。本 ask 为内核 MVP 第一部分。
"""
