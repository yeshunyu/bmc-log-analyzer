## 1. 项目脚手架

- [ ] 1.1 创建项目目录结构 `os_log_analyzer/`（包含 app/, tests/, static/）
- [ ] 1.2 初始化 Python 项目：pyproject.toml 或 requirements.txt（含 fastapi, uvicorn, aiosqlite, websockets）
- [ ] 1.3 编写 `app/__init__.py`、`app/main.py`（FastAPI 实例 + 路由注册）
- [ ] 1.4 编写 `Dockerfile` 和 `docker-compose.yml`（参考 bmc-log-analyzer 现有结构）
- [ ] 1.5 编写 `.env` 配置文件

## 2. 核心业务逻辑

- [ ] 2.1 编写 `app/models.py`（SQLAlchemy 模型：Report, Finding）
- [ ] 2.2 编写 `app/database.py`（aiosqlite 连接管理，init_db 函数）
- [ ] 2.3 编写 `app/parsers/__init__.py`、`app/parsers/base.py`
- [ ] 2.4 编写 `app/parsers/messages.py`（syslog 格式解析器）
- [ ] 2.5 编写 `app/parsers/journalctl.py`（journalctl ISO 格式解析器）
- [ ] 2.6 编写 `app/parsers/dmesg.py`（dmesg 方括号时间戳解析器）
- [ ] 2.7 编写 `app/parsers/detector.py`（故障模式检测器，正则规则）
- [ ] 2.8 编写 `app/analyzer.py`（分析协调器：调用 parser → detector → 写入 DB）

## 3. API 端点

- [ ] 3.1 编写 `app/api/upload.py`（POST /api/upload，文件大小校验，类型检测）
- [ ] 3.2 编写 `app/api/report.py`（GET /api/report/{report_id}）
- [ ] 3.3 编写 `app/api/reports.py`（GET /api/reports 列表）
- [ ] 3.4 编写 `app/api/websocket.py`（WebSocket /ws/analyze/{report_id}）

## 4. 前端

- [ ] 4.1 编写 `static/index.html`（文件上传表单 + WebSocket 连接 + 实时进度 + 结果展示）
- [ ] 4.2 接入 FastAPI static mount：`app/main.py` 添加 `app.mount("/static", StaticFiles(directory="static"))`

## 5. 测试

- [ ] 5.1 编写 `tests/test_parsers.py`（单元测试：messages/journalctl/dmesg 解析）
- [ ] 5.2 编写 `tests/test_detector.py`（单元测试：各类故障模式检测）
- [ ] 5.3 编写 `tests/test_api.py`（API 集成测试：upload + report）
- [ ] 5.4 编写 `tests/test_websocket.py`（WebSocket 端到端测试）

## 6. GitHub 推送准备

- [ ] 6.1 编写 `README.md`（项目介绍、快速开始、Docker 部署）
- [ ] 6.2 编写 `requirements.txt`（pip freeze 输出）
- [ ] 6.3 GitHub 创建仓库，推送代码
- [ ] 6.4 配置 GitHub Actions CI（pytest + Docker build）
