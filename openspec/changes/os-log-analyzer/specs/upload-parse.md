## ADDED Requirements

### Requirement: Log File Upload

客户端通过 HTTP POST 上传日志文件，系统接收并存储，返回唯一 report_id。

#### Scenario: Successful single file upload
- **WHEN** 客户端 POST /api/upload 并携带 Content-Type: multipart/form-data，文件字段名为 "file"，文件小于 50MB
- **THEN** 服务器返回 200，body 为 {"report_id": "<uuid>", "filename": "<filename>", "status": "pending"}
- **THEN** 文件内容写入 SQLite reports 表，log_type 字段根据魔术头自动识别

#### Scenario: File exceeds 50MB
- **WHEN** 客户端上传文件大于 50MB
- **THEN** 服务器返回 413 Request Entity Too Large

#### Scenario: Unsupported file type
- **WHEN** 客户端上传文件扩展名不在 [.log, .txt, .out] 中
- **THEN** 服务器返回 400 Bad Request，body 为 {"detail": "Unsupported file type"}

#### Scenario: Empty file uploaded
- **WHEN** 客户端上传空文件（0 字节）
- **THEN** 服务器返回 400 Bad Request，body 为 {"detail": "Empty file"}

### Requirement: Log Type Auto-Detection

系统根据日志内容自动识别 log_type（messages/journalctl/dmesg/mixed）。

#### Scenario: Detect messages format
- **WHEN** 文件第一行匹配正则 `^\w{3}\s+\d+\s+\d+:\d+:\d+\s+\S+\s+\S+\[\d+\]:`
- **THEN** log_type = "messages"

#### Scenario: Detect journalctl format
- **WHEN** 文件包含 ISO 时间戳行 + 日志级别标记（如 `<3>`）
- **THEN** log_type = "journalctl"

#### Scenario: Detect dmesg format
- **WHEN** 文件包含方括号时间戳行（如 `[  123.456789]`）且无 hostname
- **THEN** log_type = "dmesg"

#### Scenario: Mixed log content
- **WHEN** 文件无法归入单一类型
- **THEN** log_type = "mixed"，报告中包含各类型行数统计
