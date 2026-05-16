## Context

运维场景：Linux 主机（裸机或虚拟机）出现故障后，运维人员提取 messages/journalctl/dmesg 日志，上传到本工具，工具自动定位异常时间线和根因类别。工具以内网部署为主，不依赖外部服务。

## Goals / Non-Goals

### Goals
- 支持三类日志源：/var/log/messages、journalctl -o short-iso、dmesg
- 自动检测五类故障：kernel panic/Oops、OOM、I/O error、异常关机、资源耗尽
- WebSocket 推送分析进度（0→100%）和结构化结果
- 单文件部署（Docker 一键运行）

### Non-Goals
- 不支持实时日志流式接入（syslog push 等）
- 不支持 Windows 事件日志
- 不做日志可视化图表（饼图/折线图等）
- 不做用户认证/权限管理（内网工具定位）

## Decisions

### 架构：FastAPI + SQLite + 原生 WebSocket

```
客户端（浏览器）
    ↓ HTTP POST /api/upload
FastAPI（ASGI）
    ↓ 写入 SQLite
SQLite（reports 表）
    ↓ 触发分析
background_tasks（asyncio）
    ↓ WebSocket /ws/analyze/{id}
客户端
```

### 日志解析策略

按文件魔术头（magic header）自动识别日志类型：

```
messages:     第一行含 "timestamp hostname program[pid]:" 格式
journalctl:   ISO 时间戳 + 层级日志级别（<0-7>）
dmesg:        方括号时间戳 + 无 hostname 行
```

混合文件：按行逐一检测格式，统计各部分占比。

### 故障检测正则

```
Panic:      kernel panic|NULL pointer|BUG\(|Kernel panic|Oops:|Bug:
OOM:       Out of memory|oom-kill|oom_adj|Memory cgroup
IO Error:  I/O error|EXT4-fs error|SCSI error|NOSPC|Buffer I/O error
Shutdown:  shutdown|power off|reboot: System halted
Resource:  No space|disk full|inode|Socket backlog|failed to accept
```

### WebSocket 消息协议

```json
// 进度消息
{"type": "progress", "percent": 45, "stage": "parsing journalctl"}

// 结果消息
{"type": "result", "category": "OOM", "count": 3, "timeline": [...], "severity": "critical"}

// 完成消息
{"type": "done", "report_id": "abc123"}
```

### 数据库 Schema（SQLite）

```sql
CREATE TABLE reports (
    id          TEXT PRIMARY KEY,  -- UUID
    filename    TEXT NOT NULL,
    log_type    TEXT,              -- messages|journalctl|dmesg|mixed
    status      TEXT DEFAULT 'pending',  -- pending|running|done|error
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    completed_at DATETIME
);

CREATE TABLE findings (
    id          INTEGER PRIMARY KEY,
    report_id   TEXT REFERENCES reports(id),
    category    TEXT,              -- panic|oom|io_error|shutdown|resource
    severity    TEXT,              -- critical|warning|info
    first_seen  TEXT,
    last_seen   TEXT,
    count       INTEGER DEFAULT 1,
    sample_lines TEXT              -- JSON array of raw log lines
);
```

## Risks / Trade-offs

| 风险 | 缓解措施 |
|------|---------|
| 50MB 文件全内存加载，Python 内存峰值高 | 原型阶段接受；未来改用 mmap 或分块流式 |
| SQLite 并发写入瓶颈 | 原型阶段接受；未来迁移 PostgreSQL |
| WebSocket 断连丢进度 | 前端实现重连 + 进度持久化到 DB |
| journalctl 编码非 UTF-8 | 检测编码，尝试 gbk/latin1 回退 |
