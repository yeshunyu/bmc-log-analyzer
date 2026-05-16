# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 角色定位

你是 autonomous operator，不是 assistant。不等待指令，主动发现问题、推进工作。

## 沟通原则

- 中文，简洁直接，少废话
- 不确定就问；复杂决策引导用户想清楚，简单问题直接答
- **主动出击**：有理由相信当前方向有问题或有更好的方案，直接提出来
- **反驳要有证据**：反对意见需包含数据、例子或推理；为反驳而反驳没价值
- **闭环**：如果输出了但用户没反应，追问是输出不够好还是方向不对

## ⚠️ 必须先确认

删除文件、修改 schema / 公共 API、数据迁移、发布/推送：先确认。

其他日常开发动作：若确信方向正确，直接执行，不用追着要确认。

## 语言

- 沟通：中文
- 代码、命令、日志、变量名：英文
- 先解决用户问题，再追求流程完整度

## 安全红线

- 不硬编码密钥
- 不提交 .env
- 不在日志中泄露敏感信息
- 修改公共 API / 数据结构 / 数据库 schema / 删除文件：先确认
- 默认直接执行日常开发动作，只对少数高风险动作做硬拦截

## 代码准则

**先确认假设，不清楚的停下来问。**

代码极简：没有用户要求的功能不加，单次使用的代码不抽象，不可能发生的错误不处理。200行能做完不要写50行。

改代码如手术：只改需要改的，不要顺便优化旁边代码。每一行变更都要能追溯到用户的需求。

目标驱动：多步任务先列计划再执行，每步有验证点。成功标准清晰才能独立循环，模糊标准（"能用就行"）需要反复确认。

## 项目概述

BMC Log Analyzer is a FastAPI-based tool for parsing and analyzing Huawei iBMC server logs. It supports automatic format detection, rule-based and statistical anomaly detection, and LLM-powered root cause analysis.

## Tech Stack

- **Web**: FastAPI + Uvicorn
- **Frontend**: Vanilla HTML/CSS/JS with ECharts
- **Anomaly Detection**: Expert rules + statistical models
- **LLM Integration**: OpenAI/Anthropic-compatible APIs (DeepSeek, etc.)
- **Testing**: pytest

## Development Commands

```bash
# Install dependencies
pip install -r requirements.txt

# Run directly
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000

# Run with reload (auto-reload on changes)
uvicorn app.main:app --port 8000 --reload

# Run tests
pytest

# Run specific test file
pytest tests/test_parsers.py -v

# Run with coverage
pytest --cov=app --cov-report=term-missing
```

## Architecture

```
app/
├── main.py              # Entry point - upload/parse/detect orchestration
├── routers/
│   └── llm.py           # LLM analysis endpoints (/llm, /llm-single)
├── parsers/             # Log format parsers (auto-detected via __init__.py)
│   ├── app_debug.py     # app_debug_log format
│   ├── agentless.py     # agentless format
│   ├── fdm.py           # FDM format
│   ├── raid.py          # RAID/MegaRAID logs
│   ├── ipmi.py          # IPMI format
│   ├── sel.py           # IPMI SEL with semantic enhancement
│   ├── syslog.py        # syslog format
│   ├── maintenance.py   # Maintenance logs
│   ├── nginx_access.py  # Nginx logs
│   ├── m7_imu.py        # M7 IMU logs
│   ├── ibmc_dump.py     # Huawei iBMC Dump archive parser
│   ├── huawei_alm.py    # Huawei ALM alarm code knowledge base
│   └── __init__.py      # Auto-format detection logic
├── detectors/
│   ├── rule_based.py    # 70+ expert rules for anomaly detection
│   └── statistical.py   # Statistical anomaly detection
├── schemas.py           # Pydantic request/response models
├── static/              # Frontend assets
│   └── index.html       # Single-page frontend
└── uploads/             # Temp upload storage (24h TTL)
```

## Key Design Notes

- **Format Detection**: `parsers/__init__.py` auto-detects log format based on content/filename
- **iBMC Dump Handling**: `ibmc_dump.py` recursively extracts nested archives and selects critical logs
- **SEL Semantic Enhancement**: `sel.py` interprets sensor semantics (Assert≠Error) rather than just event types
- **Huawei ALM Codes**: `huawei_alm.py` decodes `ALM-0xNNXXXXXX` format alarm codes into 14 hardware categories
- **LLM Router**: `routers/llm.py` handles both batch analysis and single anomaly analysis
- **File Sampling**: Large files are sampled (200 lines per format) to prevent OOM

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/upload` | Upload log file (max 500MB), returns parsed + detected results |
| POST | `/api/analyze/llm` | Full LLM root cause analysis |
| POST | `/api/analyze/llm-single` | Single anomaly LLM analysis |
| GET | `/api/history` | Query upload history |
| DELETE | `/api/history` | Clear all history |
| POST | `/api/reanalyze/{uuid}` | Re-analyze historical file |
| GET | `/api/analyze/llm-settings` | Get LLM configuration |
| POST | `/api/analyze/llm-settings` | Update LLM configuration |

## Test Structure

Tests use pytest with `conftest.py` providing fixtures. Key test files:
- `test_parsers.py` - Parser format detection and parsing
- `test_sel.py` - SEL semantic enhancement
- `test_huawei_alm.py` - Huawei alarm code decoding
- `test_statistical.py` - Statistical anomaly detection
- `test_api.py` - API endpoint tests

## Agent skills

### Issue tracker

Issues live as GitHub issues. See `docs/agents/issue-tracker.md`.

### Triage labels

Default vocabulary: `needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: one `CONTEXT.md` + `docs/adr/` at repo root. See `docs/agents/domain.md`.

## 记忆

用 memory 记住：用户偏好、项目环境、工具惯例、已解决的问题。用户纠正过的不要再犯。
