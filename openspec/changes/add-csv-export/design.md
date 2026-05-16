## Context

BMC Log Analyzer 的检测结果目前仅存在于内存/数据库中，用户只能通过 Web UI 查看。需要导出能力。

## Goals / Non-Goals

**Goals:**
- 支持将指定上传记录（uuid）的异常列表导出为 CSV
- CSV 包含：timestamp, source, log_type, severity, rule_id, description

**Non-Goals:**
- 不支持增量追加（每次导出是全量）
- 不支持自定义字段选择（V1）
- 不做 Excel 格式

## Decisions

1. **API 触发**：`GET /api/export/anomalies/{uuid}?format=csv`，直接返回 CSV 文件流（`Content-Type: text/csv`）
2. **Web UI 触发**：在上传历史记录行增加"导出 CSV"按钮，调用该 API 并触发下载
3. **字段编码**：CSV 字段用 UTF-8 BOM，避免 Excel 打开乱码

## Risks / Trade-offs

- 大文件导出：异常记录可能数千条，CSV 生成应在内存可控范围内做 streaming
