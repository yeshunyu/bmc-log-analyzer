# BMC Log Analyzer

华为 iBMC 服务器 BMC 日志解析与智能分析工具。支持日志格式自动识别、异常检测与 LLM 根因分析。

English version: [README_en.md](README_en.md)

## 功能特性

### 日志解析
- 支持多种格式自动识别：app_debug_log、agentless、FDM、RAID、SEL/IPMI、syslog、maintenance、nginx_access 等
- 自动识别并解压 `.log`、`.txt`、`.gz`、`.tar.gz` 文件
- 华为一键收集包（iBMC Dump）自动解析内部嵌套归档，智能选择最关键的日志文件

### 异常检测
- **规则异常检测**：基于专家规则（SSL握手失败、EDMA链路丢失、内存分配慢、主机注册异常、RAID阵列故障、物理磁盘故障、CPU错误等）
- **统计异常检测**：基于条目级别分布的统计模型，自动发现异常模块/级别
- **硬件事件分类**：CPU / 内存 / 硬盘 / RAID卡 / 网卡 硬件事件独立分组展示

### LLM 根因分析
- **全量分析**：对所有规则+统计异常进行批量分析，带5阶段进度条
- **单条分析**：点击任意异常卡片或硬件分类的「🤖 分析此异常」按钮，单独分析该条异常
- 支持配置 LLM Provider（Minimax GLM 等）和 API Key

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
- 一键下载 Markdown 格式分析报告
- 包含统计摘要、硬件事件汇总、规则异常采样、统计异常详情的完整报告

## 技术栈

| 层次 | 技术 |
|------|------|
| Web 框架 | FastAPI + Uvicorn |
| 前端 | 原生 HTML/CSS/JavaScript（无框架依赖） |
| 日志解析 | Python 正则 + 结构化解析器（多格式） |
| 异常检测 | 专家规则引擎 + 统计模型 |
| LLM 集成 | Minimax GLM API（mmx CLI） |
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
# 默认 8088 端口
uvicorn app.main:app --port 8088 --reload

# 或直接运行
python -m app.main
```

### 3. 打开浏览器

```
http://localhost:8088
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
| IPMI/SEL | ipmi, sel |
| syslog | linux_kernel_log, dmesg |
| maintenance | maintenance_log, md_so_maintenance_log |
| nginx_access | nginx access_log |
| M7 IMU | imu, m7 |

## API 接口

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/upload` | 上传日志文件，返回解析+检测结果 |
| POST | `/api/analyze/llm` | 全量 LLM 根因分析 |
| POST | `/api/analyze/llm-single` | 单条异常 LLM 分析 |
| GET | `/` | 前端页面 |

## Docker 部署

```bash
docker build -t bmc-log-analyzer .
docker run -d -p 8088:8088 bmc-log-analyzer
```

或使用 `docker-compose.yml`（如已配置）。
