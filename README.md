# BMC Log Analyzer

华为 iBMC 服务器 BMC 日志解析与智能分析工具。支持日志格式自动识别、异常检测与 LLM 根因分析。

## 版本

**v0.50rc2** - 最新测试版

English version: [README_en.md](README_en.md)

## 功能特性

### 日志解析
- 支持多种格式自动识别：app_debug_log、agentless、FDM、RAID、SEL/IPMI、syslog、maintenance、nginx_access 等
- 自动识别并解压 `.log`、`.txt`、`.gz`、`.tar.gz` 文件
- 华为一键收集包（iBMC Dump）自动解析内部嵌套归档，智能选择最关键的日志文件
- 大文件保护：自动采样（每格式最多 200 行），避免 OOM

### 异常检测
- **规则异常检测**：基于专家规则（SSL握手失败、EDMA链路丢失、内存分配慢、主机注册异常、RAID阵列故障、物理磁盘故障、CPU错误、NPU昇腾设备故障、CANN运行时错误等，共70+条规则）
- **华为ALM告警码检测**：自动解码 `ALM-0xNNXXXXXX` 格式告警码，识别14大类硬件故障（内存/电压/风扇/PCIe/驱动/RAID卡等200+告警），按诊断优先级排序
- **IPMI SEL语义增强**：基于传感器类型+事件类型判断真实严重性（Assert≠Error，传感器语义才是依据），区分CPU/Memory/ Watchdog等ERROR与温度/电压等WARNING
- **统计异常检测**：基于条目级别分布的统计模型，自动发现异常模块/级别
- **诊断优先级排序**：先外后内（电源→风扇→散热→CPU/NPU→内存→RAID→网络→服务）、先高后低（ERROR→WARNING→INFO）
- **硬件事件分类**：主板 / CPU / 内存 / 硬盘 / RAID卡 / 网卡 / NPU 七类硬件事件独立分组展示，支持点击查看详情和单独 LLM 分析

### LLM 根因分析
- **全量分析**：对所有规则+统计异常进行批量分析，带5阶段进度条
- **单条分析**：点击任意异常卡片或硬件分类的「🤖 分析此异常」按钮，单独分析该条异常
- 支持配置任意 OpenAI-compatible 或 Anthropic-compatible LLM API（DeepSeek 等），支持双接口自动探测
- **智能 Prompt**：聚焦硬件底层故障特征，忽略管理接口（如 PowerMgnt）偶发超时，定位具体槽位号（SlotId/PCIe地址）
- **优先级建议**：按业务影响（P0/P1/P2/P3）划分，强调硬盘/RAID故障不低于风扇/电源异常
- **可执行解决步骤**：提供诊断命令（如 `storcli64`）、物理操作、固件修复、厂商兜底方案

### 全部事件
- 分页展示（50/100/200/500 条每页）
- 级别过滤（ERROR / WARNING / INFO 多选）
- 时间范围筛选
- 正则/模糊搜索（message / module / level 字段）
- 页码导航 + 首页/末页

### 统计概览
- 错误/警告计数卡片
- 模块分布环形图（点击扇区查看详情）
- 异常时间线分布图
- 规则异常数 / 统计异常数 / 硬件事件数

### 分析报告
- 一键下载 Markdown/HTML 格式分析报告
- 顶部风险评估（低/中/高）+ 建议操作列表，运维一目了然
- 包含统计摘要、硬件事件汇总、规则异常采样、统计异常详情的完整报告
- 报告文件名自动包含设备型号和 SN（如能从文件名或日志内容提取）

## 技术栈

| 层次 | 技术 |
|------|------|
| Web 框架 | FastAPI + Uvicorn |
| 前端 | 原生 HTML/CSS/JavaScript（无框架依赖） |
| 日志解析 | Python 正则 + 结构化解析器（多格式） |
| 异常检测 | 专家规则引擎 + 统计模型 |
| LLM 集成 | DeepSeek / OpenAI / Anthropic API（OpenAI-compatible + Anthropic-compatible） |
| 图表 | ECharts |
| 部署 | Docker / Docker Compose |
| 测试 | pytest |

## 快速开始

### 1. 安装依赖

```bash
pip install -r requirements.txt
```

### 2. 启动服务

```bash
uvicorn app.main:app --port 8000 --reload

# 或直接运行
python -m app.main
```

### 3. 打开浏览器

```
http://localhost:8000
```

### 4. 使用

1. 上传 `.log`、`.txt`、`.gz` 或 `.tar.gz` 日志文件（或华为 iBMC 一键收集包）
2. 系统自动识别格式并解析
3. 查看统计概览、异常检测结果
4. 点击「🤖 全量 LLM 根因分析」进行批量分析
5. 或点击任意异常卡片 / 硬件分类的「🤖 分析此异常」按钮进行单条分析
6. 点击「📄 下载分析报告」导出 Markdown 报告

## 目录结构

```
app/
├── main.py              # FastAPI 入口，上传/解析/检测逻辑
├── routers/
│   └── llm.py          # LLM 分析接口（/llm、/llm-single）
├── parsers/             # 各格式解析器
│   ├── app_debug.py     # app_debug_log 格式
│   ├── agentless.py     # agentless 格式
│   ├── fdm.py           # FDM 输出格式
│   ├── raid.py          # RAID/LSI 日志
│   ├── ipmi.py          # IPMI/SEL 格式
│   ├── syslog.py        # syslog 格式
│   ├── maintenance.py   # 维护日志
│   ├── nginx_access.py  # Nginx Access 日志
│   ├── m7_imu.py        # M7 IMU 日志
│   ├── sel.py           # IPMI SEL 二进制/文本解析 + 语义增强
│   ├── huawei_alm.py    # 华为 ALM 告警码知识库
│   ├── ibmc_dump.py     # iBMC Dump 归档解析
│   └── __init__.py      # 自动格式识别
├── detectors/
│   ├── rule_based.py    # 专家规则异常检测
│   └── statistical.py   # 统计异常检测
├── schemas.py           # Pydantic 数据模型
├── static/
│   └── index.html       # 前端页面
└── uploads/             # 上传文件目录（自动清理，24h TTL）
```

## 支持的日志格式

| 格式 | 文件名关键词 |
|------|-------------|
| app_debug_log | app_debug_log_all, ipmi_mass_operate_log |
| agentless | agentless_dfl |
| FDM | dfl 文件 |
| RAID/LSI MegaRAID | raid, lsi |
| IPMI | ipmi, ipmi_mass_operate_log |
| SEL | sel, sensor_alarm_sel |
| syslog | linux_kernel_log, dmesg |
| maintenance | maintenance_log, md_so_maintenance_log |
| nginx_access + error | nginx access_log, nginx_error_log |
| M7 IMU | imu, m7 |
| iBMC Dump | BMC_dump, core_dump, dump_info, ibmc_dump |
| Huawei ALM | ALM-0xNNXXXXXX 告警码（解析到告警级别） |

## API 接口

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/upload` | 上传日志文件（最大 500MB），返回解析+检测结果 |
| POST | `/api/analyze/llm` | 全量 LLM 根因分析 |
| POST | `/api/analyze/llm-single` | 单条异常 LLM 分析 |
| GET | `/api/history` | 查询历史上传记录 |
| DELETE | `/api/history` | 清空全部历史记录 |
| POST | `/api/reanalyze/{uuid}` | 重新分析历史文件 |
| DELETE | `/api/reanalyze/{uuid}` | 删除历史文件 |
| GET | `/api/operation-logs` | 查询操作日志（默认最近7天） |
| GET | `/api/analyze/llm-settings` | 获取 LLM 配置 |
| POST | `/api/analyze/llm-settings` | 更新 LLM 配置 |
| POST | `/api/analyze/llm-settings/reset` | 重置 LLM 配置 |

## Docker 部署

镜像支持 `linux/amd64`（x86 服务器）和 `linux/arm64`（ARM 服务器 / Apple Silicon Mac）架构。支持外网和**内网（离线）两种部署模式**，零已知运行时漏洞。

### 快速启动

```bash
# 根据服务器架构选择对应镜像
# x86 服务器 (Intel/AMD CPU)
docker run -d -p 8000:8000 yuyeshun2/bmc-log-analyzer:v0.50rc2-amd64

# ARM 服务器 (华为鲲鹏、亚马逊 Graviton、Apple Silicon Mac)
docker run -d -p 8000:8000 yuyeshun2/bmc-log-analyzer:v0.50rc2-arm64

# 或者使用 latest 标签（自动选择对应架构，首次下载慢）
docker run -d -p 8000:8000 yuyeshun2/bmc-log-analyzer:latest
```

然后浏览器打开 **http://localhost:8000**。

### 自定义 LLM API（生产环境推荐）

启动后点击页面右上角 ⚙️ 按钮配置 API，支持 DeepSeek / OpenAI / Anthropic 等兼容接口。

也可通过环境变量配置，重启后配置持久化：

```bash
# x86 服务器
docker run -d -p 8000:8000 \
  -e API_KEY=your-secret-key \
  yuyeshun2/bmc-log-analyzer:v0.50rc2-amd64

# ARM 服务器
docker run -d -p 8000:8000 \
  -e API_KEY=your-secret-key \
  yuyeshun2/bmc-log-analyzer:v0.50rc2-arm64
```

| 环境变量 | 说明 | 示例 |
|---------|------|------|
| `API_KEY` | API 认证密钥（可选，不配置则无需认证） | `sk-xxxxxxxx` |
| `API_KEY_FILE` | API 密钥文件路径 | `/path/to/key` |

DeepSeek 同时提供 OpenAI-compatible（`/chat/completions`）和 Anthropic-compatible（`/anthropic`）接口。
