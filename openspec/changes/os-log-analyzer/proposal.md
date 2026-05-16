## Why

华为 TaiShan ARM 服务器和其他 Linux 主机的 OS（系统）日志是故障排查的核心数据源。当前 BMC 日志分析工具已覆盖 BMC 固件层，但 OS 层的日志（messages、journalctl、dmesg）缺乏统一分析能力。运维人员需要手动 grep 关键字、跨文件关联异常，效率低且容易遗漏。

## What Changes

新增 os-log-analyzer 服务：一个接收 Linux 系统日志文件（messages、journalctl、dmesg 输出）的 Web 分析工具，自动检测故障模式（panic/OOM/IO error/资源耗尽），通过 WebSocket 推送分析进度和结构化报告。

## Capabilities

### New Capabilities
- **日志上传与接收**：POST /api/upload，接收 .log/.txt 文件，最大 50MB，支持多文件批量上传
- **WebSocket 实时推送**：连接 /ws/analyze/{report_id}，实时推送分析进度（0-100%）和结果分块
- **故障模式检测**：自动识别 panic/OOM/IO error/异常关机/资源耗尽五类故障
- **分析报告查询**：GET /api/report/{report_id}，返回结构化 JSON 报告，含时间线、严重等级、原始行引用

### Modified Capabilities
-（无）

## Impact
- 新增 FastAPI Web 服务，端口 8080
- 新增 WebSocket 端点 /ws/analyze/{report_id}
- 引入 SQLite 存储分析记录（原型阶段），未来可替换为 PostgreSQL
- 前端：单 HTML 文件，无外部依赖
