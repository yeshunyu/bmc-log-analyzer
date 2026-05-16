## ADDED Requirements

### Requirement: Fault Pattern Detection

系统自动检测五类故障并生成结构化 findings。

#### Scenario: Kernel panic detection
- **WHEN** 分析器在日志中匹配正则 `kernel panic|NULL pointer|BUG\(|Kernel panic|Oops:|Bug:`
- **THEN** 创建 finding，category="panic"，severity="critical"，记录匹配行的 first_seen/last_seen

#### Scenario: OOM detection
- **WHEN** 分析器匹配 `Out of memory|oom-kill|oom_adj|Memory cgroup`
- **THEN** 创建 finding，category="oom"，severity="critical"

#### Scenario: I/O error detection
- **WHEN** 分析器匹配 `I/O error|EXT4-fs error|SCSI error|NOSPC|Buffer I/O error`
- **THEN** 创建 finding，category="io_error"，severity="warning"（单次）或 "critical"（>=3次）

#### Scenario: Abnormal shutdown detection
- **WHEN** 分析器匹配 `shutdown|power off|reboot: System halted` 且紧邻 panic 事件
- **THEN** 创建 finding，category="shutdown"，severity="warning"

#### Scenario: Resource exhaustion detection
- **WHEN** 分析器匹配 `No space|disk full|inode|Socket backlog|failed to accept`
- **THEN** 创建 finding，category="resource"，severity="warning"

### Requirement: WebSocket Progress Reporting

分析过程中通过 WebSocket 向客户端推送实时进度。

#### Scenario: WebSocket connection established
- **WHEN** 客户端连接 /ws/analyze/{report_id}
- **THEN** 服务器发送 {"type": "connected", "report_id": "<id>"}

#### Scenario: Progress update during analysis
- **WHEN** 分析进度从 0% 变化到 100%
- **THEN** 服务器每 10% 推送一条 progress 消息，格式 {"type": "progress", "percent": N, "stage": "parsing|analyzing|finalizing"}

#### Scenario: Findings pushed as discovered
- **WHEN** 分析器发现一个 fault pattern
- **THEN** 立即推送一条 result 消息，客户端可实时渲染 finding

#### Scenario: Analysis complete
- **WHEN** 分析完成
- **THEN** 服务器发送 {"type": "done", "report_id": "<id>"} 并关闭 WebSocket 连接

### Requirement: Report Retrieval

分析完成后客户端可查询结构化报告。

#### Scenario: Fetch completed report
- **WHEN** 客户端 GET /api/report/{report_id} 且报告状态为 "done"
- **THEN** 返回 200，body 包含 id, filename, log_type, findings[], timeline[], created_at, completed_at

#### Scenario: Report not ready yet
- **WHEN** 客户端 GET /api/report/{report_id} 且报告状态为 "running"
- **THEN** 返回 202 Accepted，body 为 {"status": "running", "progress": N}

#### Scenario: Report not found
- **WHEN** 客户端 GET /api/report/{invalid_id}
- **THEN** 返回 404 Not Found
