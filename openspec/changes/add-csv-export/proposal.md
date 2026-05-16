## Why

当前 BMC Log Analyzer 只支持在 Web UI 中查看检测到的异常，用户无法将结果导出到外部系统进行分析或归档。CSV 是最通用的交换格式，导出功能可以打通下游数据分析流程。

## What Changes

新增 CSV 导出功能：将检测到的异常记录（anomalies）导出为标准 CSV 文件，支持在 Web UI 和 API 两种方式触发。

## Capabilities

### New Capabilities
- `csv-export`: 将检测到的异常列表导出为 CSV，包含时间、日志来源、异常类型、严重程度、描述等字段

### Modified Capabilities
- （无）

## Impact

- 新增 API endpoint：`GET /api/export/anomalies?uuid=<uuid>&format=csv`
- Web UI 新增"导出 CSV"按钮
- 依赖现有 `/api/upload` 的解析结果
