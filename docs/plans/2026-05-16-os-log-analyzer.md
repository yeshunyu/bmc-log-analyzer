# OS Log Analyzer Implementation Plan

> **For Claude:** Use `superpowers-skills/skills/collaboration/executing-plans` to implement this plan task-by-task.

**Goal:** 新增 os-log-analyzer Web 服务，接收 Linux 系统日志文件，通过 WebSocket 推送分析进度和故障报告。

**Architecture:** FastAPI + aiosqlite + 原生 WebSocket，单文件 HTML 前端。分析器按 magic header 识别日志类型（messages/journalctl/dmesg），用正则检测五类故障（panic/OOM/io_error/shutdown/resource），结果存入 SQLite。

**Tech Stack:** Python 3.11, FastAPI, uvicorn, aiosqlite, websockets

---

## Task 1: 项目脚手架

**Files:**
- Create: `os_log_analyzer/app/__init__.py`
- Create: `os_log_analyzer/app/main.py`
- Create: `os_log_analyzer/requirements.txt`
- Create: `os_log_analyzer/Dockerfile`
- Create: `os_log_analyzer/docker-compose.yml`
- Create: `os_log_analyzer/.env`

**Step 1: 创建目录结构**
```bash
mkdir -p os_log_analyzer/app/api os_log_analyzer/app/parsers os_log_analyzer/tests os_log_analyzer/static docs/plans
touch os_log_analyzer/app/__init__.py os_log_analyzer/app/api/__init__.py os_log_analyzer/app/parsers/__init__.py
```

**Step 2: 编写 requirements.txt**
```
fastapi>=0.115.0
uvicorn[standard]>=0.30.0
aiosqlite>=0.20.0
python-multipart>=0.0.12
websockets>=12.0
pytest>=8.0.0
pytest-asyncio>=0.24.0
httpx>=0.27.0
```

**Step 3: 编写 app/main.py**
```python
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse
import os

app = FastAPI(title="OS Log Analyzer")

# Mount static files
static_dir = os.path.join(os.path.dirname(__file__), "..", "static")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

@app.get("/")
async def root():
    return RedirectResponse(url="/static/index.html")

# Register routers
from app.api import upload, report, reports, websocket
app.include_router(upload.router, prefix="/api", tags=["upload"])
app.include_router(report.router, prefix="/api", tags=["report"])
app.include_router(reports.router, prefix="/api", tags=["reports"])
```

**Step 4: 验证**
```bash
cd os_log_analyzer && pip install -q -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8080 &
sleep 2 && curl -s http://localhost:8080/ | head -5
```
Expected: redirect to /static/index.html or 404 (file not found yet, that's OK)

**Step 5: 提交**
```bash
git add os_log_analyzer/
git commit -m "feat: scaffold os_log_analyzer project structure"
```

---

## Task 2: 数据库层

**Files:**
- Create: `os_log_analyzer/app/database.py`
- Modify: `os_log_analyzer/app/models.py`

**Step 1: 编写 app/models.py**
```python
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

@dataclass
class Report:
    id: str
    filename: str
    log_type: Optional[str] = None
    status: str = "pending"  # pending|running|done|error
    created_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

@dataclass
class Finding:
    id: int
    report_id: str
    category: str  # panic|oom|io_error|shutdown|resource
    severity: str  # critical|warning|info
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    count: int = 1
    sample_lines: str = "[]"  # JSON array
```

**Step 2: 编写 app/database.py**
```python
import aiosqlite
import os
from app.models import Report, Finding
from typing import Optional

DATABASE_PATH = os.getenv("DATABASE_PATH", "os_log_analyzer.db")

async def init_db():
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS reports (
                id TEXT PRIMARY KEY,
                filename TEXT NOT NULL,
                log_type TEXT,
                status TEXT DEFAULT 'pending',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                completed_at DATETIME
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                report_id TEXT REFERENCES reports(id),
                category TEXT,
                severity TEXT,
                first_seen TEXT,
                last_seen TEXT,
                count INTEGER DEFAULT 1,
                sample_lines TEXT DEFAULT '[]'
            )
        """)
        await db.commit()

async def create_report(report: Report) -> Report:
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute(
            "INSERT INTO reports (id, filename, log_type, status) VALUES (?, ?, ?, ?)",
            (report.id, report.filename, report.log_type, report.status)
        )
        await db.commit()
    return report

async def get_report(report_id: str) -> Optional[Report]:
    async with aiosqlite.connect(DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM reports WHERE id = ?", (report_id,)
        ) as cursor:
            row = await cursor.fetchone()
    if row:
        return Report(**dict(row))
    return None

async def update_report_status(report_id: str, status: str):
    async with aiosqlite.connect(DATABASE_PATH) as db:
        if status == "done":
            await db.execute(
                "UPDATE reports SET status = ?, completed_at = CURRENT_TIMESTAMP WHERE id = ?",
                (status, report_id)
            )
        else:
            await db.execute(
                "UPDATE reports SET status = ? WHERE id = ?",
                (status, report_id)
            )
        await db.commit()

async def add_finding(finding: Finding) -> int:
    async with aiosqlite.connect(DATABASE_PATH) as db:
        cursor = await db.execute(
            "INSERT INTO findings (report_id, category, severity, first_seen, last_seen, count, sample_lines) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (finding.report_id, finding.category, finding.severity, finding.first_seen, finding.last_seen, finding.count, finding.sample_lines)
        )
        await db.commit()
        return cursor.lastrowid

async def get_findings(report_id: str) -> list[Finding]:
    async with aiosqlite.connect(DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM findings WHERE report_id = ?", (report_id,)
        ) as cursor:
            rows = await cursor.fetchall()
    return [Finding(**dict(row)) for row in rows]
```

**Step 3: 验证代码**
```bash
cd os_log_analyzer && python -c "
import asyncio
from app.database import init_db, create_report, get_report
from app.models import Report
import uuid
asyncio.run(init_db())
r = asyncio.run(create_report(Report(id=uuid.uuid4().hex, filename='test.log', log_type='messages')))
print('created:', r.id)
found = asyncio.run(get_report(r.id))
print('found:', found.filename, found.status)
"
```

**Step 4: 提交**
```bash
git add os_log_analyzer/app/database.py os_log_analyzer/app/models.py
git commit -m "feat: add database layer with aiosqlite"
```

---

## Task 3: 日志解析器

**Files:**
- Create: `os_log_analyzer/app/parsers/base.py`
- Create: `os_log_analyzer/app/parsers/messages.py`
- Create: `os_log_analyzer/app/parsers/journalctl.py`
- Create: `os_log_analyzer/app/parsers/dmesg.py`
- Create: `os_log_analyzer/app/parsers/__init__.py`

**Step 1: 编写 app/parsers/base.py**
```python
from abc import ABC, abstractmethod
from dataclasses import dataclass

@dataclass
class LogLine:
    raw: str
    timestamp: str
    hostname: str = ""
    program: str = ""
    pid: str = ""
    message: str = ""

class BaseParser(ABC):
    name: str = ""

    @abstractmethod
    def detect(self, content: str) -> bool:
        """Return True if content matches this parser's format."""
        pass

    @abstractmethod
    def parse(self, content: str) -> list[LogLine]:
        """Parse content and return list of LogLine."""
        pass

    def parse_lines(self, content: str) -> list[LogLine]:
        """Default implementation splits by newline."""
        lines = []
        for line in content.splitlines():
            line = line.strip()
            if line:
                lines.append(LogLine(raw=line, timestamp="", message=line))
        return lines
```

**Step 2: 编写 app/parsers/messages.py**
```python
import re
from app.parsers.base import BaseParser, LogLine

# Example: Mar 15 04:02:01 hostname sshd[12345]: Accepted publickey for user
MESSAGES_RE = re.compile(
    r'^(\w{3}\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s+(.*)$'
)

class MessagesParser(BaseParser):
    name = "messages"

    def detect(self, content: str) -> bool:
        first_lines = content.splitlines()[:10]
        matched = sum(1 for l in first_lines if MESSAGES_RE.match(l.strip()))
        return matched >= 3

    def parse(self, content: str) -> list[LogLine]:
        lines = []
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            m = MESSAGES_RE.match(line)
            if m:
                lines.append(LogLine(
                    raw=line,
                    timestamp=m.group(1),
                    hostname=m.group(2),
                    program=m.group(3),
                    pid=m.group(4) or "",
                    message=m.group(5)
                ))
            else:
                lines.append(LogLine(raw=line, timestamp="", message=line))
        return lines
```

**Step 3: 编写 app/parsers/journalctl.py**
```python
import re
from app.parsers.base import BaseParser, LogLine

# Example: 2026-03-15T04:02:01.123456+08:00 hostname sshd[12345]: message
JOURNALCTL_RE = re.compile(
    r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[.\d+]*(?:[+-]\d{2}:?\d{2})?)\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s+(.*)$'
)

class JournalctlParser(BaseParser):
    name = "journalctl"

    def detect(self, content: str) -> bool:
        first_lines = content.splitlines()[:10]
        matched = sum(1 for l in first_lines if JOURNALCTL_RE.match(l.strip()))
        return matched >= 3

    def parse(self, content: str) -> list[LogLine]:
        lines = []
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            m = JOURNALCTL_RE.match(line)
            if m:
                lines.append(LogLine(
                    raw=line,
                    timestamp=m.group(1),
                    hostname=m.group(2),
                    program=m.group(3),
                    pid=m.group(4) or "",
                    message=m.group(5)
                ))
            else:
                lines.append(LogLine(raw=line, timestamp=line[:19], message=line))
        return lines
```

**Step 4: 编写 app/parsers/dmesg.py**
```python
import re
from app.parsers.base import BaseParser, LogLine

# Example: [  123.456789] hostname kernel: message
DMESG_RE = re.compile(r'^\[\s*([\d.]+)\]\s*(.*)$')

class DmesgParser(BaseParser):
    name = "dmesg"

    def detect(self, content: str) -> bool:
        first_lines = content.splitlines()[:10]
        matched = sum(1 for l in first_lines if DMESG_RE.match(l.strip()))
        # dmesg has no hostname in most lines, and has bracket timestamps
        has_brackets = sum(1 for l in content.splitlines()[:5] if '[' in l and ']' in l)
        return matched >= 3 and has_brackets >= 2

    def parse(self, content: str) -> list[LogLine]:
        lines = []
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            m = DMESG_RE.match(line)
            if m:
                lines.append(LogLine(
                    raw=line,
                    timestamp=m.group(1),
                    message=m.group(2)
                ))
            else:
                lines.append(LogLine(raw=line, timestamp="", message=line))
        return lines
```

**Step 5: 编写 app/parsers/__init__.py**
```python
from app.parsers.base import BaseParser, LogLine
from app.parsers.messages import MessagesParser
from app.parsers.journalctl import JournalctlParser
from app.parsers.dmesg import DmesgParser

PARSERS = [MessagesParser(), JournalctlParser(), DmesgParser()]

def detect_log_type(content: str) -> str:
    for parser in PARSERS:
        if parser.detect(content):
            return parser.name
    return "unknown"

def parse_log(content: str, log_type: str) -> list[LogLine]:
    for parser in PARSERS:
        if parser.name == log_type:
            return parser.parse(content)
    # Fallback: return raw lines
    return [LogLine(raw=l, timestamp="", message=l) for l in content.splitlines() if l.strip()]
```

**Step 6: 验证**
```bash
cd os_log_analyzer && python -c "
from app.parsers import detect_log_type, parse_log

# Test messages
sample = '''Mar 15 04:02:01 server01 sshd[12345]: Accepted publickey for user
Mar 15 04:02:02 server01 kernel: Out of memory: Killed process
Mar 15 04:02:03 server01 systemd[1]: Started some service
'''
print('Detected:', detect_log_type(sample))
lines = parse_log(sample, 'messages')
print('Lines:', len(lines))
print('Sample:', lines[1].message)
"
```

**Step 7: 提交**
```bash
git add os_log_analyzer/app/parsers/
git commit -m "feat: add log parsers for messages, journalctl, dmesg"
```

---

## Task 4: 故障检测器

**Files:**
- Create: `os_log_analyzer/app/parsers/detector.py`
- Create: `os_log_analyzer/tests/test_detector.py`

**Step 1: 编写 app/parsers/detector.py**
```python
import re
import json
from dataclasses import dataclass
from app.parsers.base import LogLine

@dataclass
class FaultMatch:
    category: str
    severity: str
    first_seen: str
    last_seen: str
    count: int
    sample_lines: list[str]

PATTERNS = [
    {
        "category": "panic",
        "severity": "critical",
        "patterns": [
            r"kernel panic",
            r"NULL pointer",
            r"BUG\(",
            r"Kernel panic",
            r"Oops:",
            r"Bug:",
        ]
    },
    {
        "category": "oom",
        "severity": "critical",
        "patterns": [
            r"Out of memory",
            r"oom-kill",
            r"oom_adj",
            r"Memory cgroup",
        ]
    },
    {
        "category": "io_error",
        "severity": "warning",
        "patterns": [
            r"I/O error",
            r"EXT4-fs error",
            r"SCSI error",
            r"NOSPC",
            r"Buffer I/O error",
        ]
    },
    {
        "category": "shutdown",
        "severity": "warning",
        "patterns": [
            r"shutdown",
            r"power off",
            r"reboot: System halted",
        ]
    },
    {
        "category": "resource",
        "severity": "warning",
        "patterns": [
            r"No space",
            r"disk full",
            r"inode",
            r"Socket backlog",
            r"failed to accept",
        ]
    },
]

def detect_faults(lines: list[LogLine]) -> list[FaultMatch]:
    matches_by_cat: dict[str, FaultMatch] = {}

    for line in lines:
        for rule in PATTERNS:
            for pat in rule["patterns"]:
                if re.search(pat, line.raw, re.IGNORECASE):
                    cat = rule["category"]
                    if cat not in matches_by_cat:
                        matches_by_cat[cat] = FaultMatch(
                            category=cat,
                            severity=rule["severity"],
                            first_seen=line.timestamp or line.raw[:40],
                            last_seen=line.timestamp or line.raw[:40],
                            count=1,
                            sample_lines=[line.raw[:200]]
                        )
                    else:
                        m = matches_by_cat[cat]
                        m.count += 1
                        m.last_seen = line.timestamp or line.raw[:40]
                        if len(m.sample_lines) < 5:
                            m.sample_lines.append(line.raw[:200])
                    break

    # Upgrade io_error to critical if count >= 3
    for m in matches_by_cat.values():
        if m.category == "io_error" and m.count >= 3:
            m.severity = "critical"

    return list(matches_by_cat.values())
```

**Step 2: 编写测试 tests/test_detector.py**
```python
import pytest
from app.parsers.detector import detect_faults
from app.parsers.base import LogLine

def test_detect_panic():
    lines = [
        LogLine(raw="Kernel panic - not syncing: VFS", timestamp="2026-03-15 04:02:01", message="Kernel panic"),
    ]
    faults = detect_faults(lines)
    assert len(faults) == 1
    assert faults[0].category == "panic"
    assert faults[0].severity == "critical"

def test_detect_oom():
    lines = [
        LogLine(raw="Out of memory: Killed process 12345", timestamp="2026-03-15 04:02:01", message="Out of memory"),
    ]
    faults = detect_faults(lines)
    assert any(f.category == "oom" for f in faults)

def test_detect_io_error_multiple():
    lines = [
        LogLine(raw="I/O error", timestamp="2026-03-15 04:02:01", message="I/O error"),
        LogLine(raw="I/O error", timestamp="2026-03-15 04:02:02", message="I/O error"),
        LogLine(raw="I/O error", timestamp="2026-03-15 04:02:03", message="I/O error"),
    ]
    faults = detect_faults(lines)
    io_fault = next((f for f in faults if f.category == "io_error"), None)
    assert io_fault is not None
    assert io_fault.severity == "critical"  # upgraded from warning
    assert io_fault.count == 3

def test_no_fault():
    lines = [
        LogLine(raw="System startup complete", timestamp="2026-03-15 04:02:01", message=" startup"),
    ]
    faults = detect_faults(lines)
    assert len(faults) == 0
```

**Step 3: 运行测试**
```bash
cd os_log_analyzer && pytest tests/test_detector.py -v
```
Expected: 4 passed

**Step 4: 提交**
```bash
git add os_log_analyzer/app/parsers/detector.py os_log_analyzer/tests/test_detector.py
git commit -m "feat: add fault pattern detector"
```

---

## Task 5: 分析协调器

**Files:**
- Create: `os_log_analyzer/app/analyzer.py`
- Create: `os_log_analyzer/tests/test_analyzer.py`

**Step 1: 编写 app/analyzer.py**
```python
import asyncio
import json
import uuid
from app.database import init_db, create_report, update_report_status, add_finding, get_report, get_findings
from app.models import Report, Finding
from app.parsers import detect_log_type, parse_log
from app.parsers.detector import detect_faults
from typing import Callable, Awaitable

async def analyze(
    report_id: str,
    filename: str,
    content: str,
    progress_callback: Callable[[int, str], Awaitable[None]] | None = None,
):
    """Analyze log content and write findings to DB."""
    await init_db()

    # Detect log type
    log_type = detect_log_type(content)
    report = Report(id=report_id, filename=filename, log_type=log_type, status="running")
    await create_report(report)

    total_lines = len(content.splitlines())

    # Parse
    if progress_callback:
        await progress_callback(10, "parsing")
    lines = parse_log(content, log_type)

    # Detect faults
    if progress_callback:
        await progress_callback(30, "analyzing")
    faults = detect_faults(lines)

    # Write findings to DB
    if progress_callback:
        await progress_callback(70, "writing results")
    for fault in faults:
        finding = Finding(
            id=0,
            report_id=report_id,
            category=fault.category,
            severity=fault.severity,
            first_seen=fault.first_seen,
            last_seen=fault.last_seen,
            count=fault.count,
            sample_lines=json.dumps(fault.sample_lines)
        )
        await add_finding(finding)

    # Mark done
    if progress_callback:
        await progress_callback(100, "done")
    await update_report_status(report_id, "done")

    return faults
```

**Step 2: 编写测试 tests/test_analyzer.py**
```python
import pytest
import asyncio
from app.analyzer import analyze
from app.database import init_db, get_report, get_findings

@pytest.mark.asyncio
async def test_analyze_detects_panic():
    content = """Mar 15 04:02:01 server01 kernel: Kernel panic - not syncing: VFS
Mar 15 04:02:02 server01 sshd[12345]: Accepted publickey
"""
    report_id = asyncio.get_event_loop().run_until_complete
    # Note: run inside pytest-asyncio event loop
    result = await analyze(
        report_id="test-report-001",
        filename="test.log",
        content=content
    )
    assert any(f.category == "panic" for f in result)

@pytest.mark.asyncio
async def test_analyze_unknown_log_type():
    content = "This is completely unrecognized log format\n" * 10
    result = await analyze(
        report_id="test-report-002",
        filename="unknown.log",
        content=content
    )
    # Should not crash, may have zero findings
    assert isinstance(result, list)
```

**Step 3: 提交**
```bash
git add os_log_analyzer/app/analyzer.py os_log_analyzer/tests/test_analyzer.py
git commit -m "feat: add analyze coordinator"
```

---

## Task 6: API 端点

**Files:**
- Create: `os_log_analyzer/app/api/upload.py`
- Create: `os_log_analyzer/app/api/report.py`
- Create: `os_log_analyzer/app/api/reports.py`
- Create: `os_log_analyzer/app/api/websocket.py`

**Step 1: 编写 app/api/upload.py**
```python
from fastapi import APIRouter, UploadFile, HTTPException, BackgroundTasks
from app.models import Report
from app.database import create_report
import uuid

router = APIRouter()
MAX_SIZE = 50 * 1024 * 1024  # 50MB
ALLOWED_EXTENSIONS = {".log", ".txt", ".out"}

@router.post("/upload")
async def upload_log(file: UploadFile, background_tasks: BackgroundTasks):
    # Check extension
    if file.filename:
        ext = "." + file.filename.rsplit(".", 1)[-1].lower()
        if ext not in ALLOWED_EXTENSIONS:
            raise HTTPException(400, detail="Unsupported file type")

    # Read content
    content = await file.read()
    if len(content) == 0:
        raise HTTPException(400, detail="Empty file")
    if len(content) > MAX_SIZE:
        raise HTTPException(413, detail="File exceeds 50MB limit")

    report_id = uuid.uuid4().hex
    report = Report(id=report_id, filename=file.filename or "unknown", status="pending")
    await create_report(report)

    # TODO: dispatch background analysis
    # background_tasks.add_task(run_analysis, report_id, file.filename, content)

    return {
        "report_id": report_id,
        "filename": file.filename,
        "status": "pending",
        "size_bytes": len(content)
    }
```

**Step 2: 编写 app/api/report.py**
```python
from fastapi import APIRouter, HTTPException
from app.database import get_report, get_findings
from app.models import Report, Finding
import json

router = APIRouter()

@router.get("/report/{report_id}")
async def get_report_endpoint(report_id: str):
    report = await get_report(report_id)
    if not report:
        raise HTTPException(404, detail="Report not found")

    findings = await get_findings(report_id)
    findings_data = [
        {
            "id": f.id,
            "category": f.category,
            "severity": f.severity,
            "first_seen": f.first_seen,
            "last_seen": f.last_seen,
            "count": f.count,
            "sample_lines": json.loads(f.sample_lines)
        }
        for f in findings
    ]

    return {
        "id": report.id,
        "filename": report.filename,
        "log_type": report.log_type,
        "status": report.status,
        "findings": findings_data,
        "created_at": str(report.created_at) if report.created_at else None,
        "completed_at": str(report.completed_at) if report.completed_at else None,
    }
```

**Step 3: 编写 app/api/reports.py**
```python
from fastapi import APIRouter
from app.database import init_db
import aiosqlite

router = APIRouter()

@router.get("/reports")
async def list_reports(limit: int = 20):
    await init_db()
    async with aiosqlite.connect("os_log_analyzer.db") as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT id, filename, log_type, status, created_at FROM reports ORDER BY created_at DESC LIMIT ?",
            (limit,)
        ) as cursor:
            rows = await cursor.fetchall()
    return {"reports": [dict(r) for r in rows]}
```

**Step 4: 编写 app/api/websocket.py**
```python
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
import asyncio
import json
from app.analyzer import analyze
from app.database import init_db

router = APIRouter()

@router.websocket("/ws/analyze/{report_id}")
async def websocket_analyze(websocket: WebSocket, report_id: str):
    await websocket.accept()
    await websocket.send_json({"type": "connected", "report_id": report_id})

    try:
        # Receive file content from client
        data = await websocket.receive_text()
        msg = json.loads(data)

        filename = msg.get("filename", "upload.log")
        content = msg.get("content", "")

        async def progress_callback(percent: int, stage: str):
            await websocket.send_json({
                "type": "progress",
                "percent": percent,
                "stage": stage
            })

        faults = await analyze(
            report_id=report_id,
            filename=filename,
            content=content,
            progress_callback=progress_callback
        )

        for fault in faults:
            await websocket.send_json({
                "type": "result",
                "category": fault.category,
                "severity": fault.severity,
                "count": fault.count,
                "first_seen": fault.first_seen,
                "sample_lines": fault.sample_lines
            })

        await websocket.send_json({"type": "done", "report_id": report_id})

    except WebSocketDisconnect:
        pass
    except Exception as e:
        await websocket.send_json({"type": "error", "message": str(e)})
```

**Step 5: 更新 app/main.py 引入路由**
在 main.py 的 routers 注册部分补充（已在 Task 1 中完成）

**Step 6: 验证**
```bash
cd os_log_analyzer && uvicorn app.main:app --port 8080 &
sleep 2
curl -s -X POST http://localhost:8080/api/upload \
  -F "file=@/etc/hosts" | python -m json.tool
```

**Step 7: 提交**
```bash
git add os_log_analyzer/app/api/
git commit -m "feat: add API endpoints (upload, report, reports, websocket)"
```

---

## Task 7: 前端

**Files:**
- Create: `os_log_analyzer/static/index.html`

**Step 1: 编写 static/index.html**
```html
<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="utf-8">
<title>OS Log Analyzer</title>
<style>
  body { font-family: system-ui; max-width: 900px; margin: 40px auto; padding: 0 20px; }
  h1 { color: #333; }
  .upload-zone { border: 2px dashed #ccc; padding: 40px; text-align: center; margin: 20px 0; }
  .upload-zone.dragover { border-color: #007bff; background: #f0f8ff; }
  #progress { margin: 20px 0; display: none; }
  #progress-bar { width: 100%; height: 20px; background: #eee; border-radius: 10px; }
  #progress-fill { height: 100%; background: #007bff; border-radius: 10px; width: 0%; transition: width 0.3s; }
  #results { margin-top: 30px; display: none; }
  .finding { background: #f8f8f8; border-left: 4px solid #007bff; padding: 12px 16px; margin: 10px 0; }
  .finding.critical { border-color: #dc3545; }
  .finding.warning { border-color: #ffc107; }
  .severity-badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 12px; color: #fff; }
  .severity-critical { background: #dc3545; }
  .severity-warning { background: #ffc107; color: #333; }
  .severity-info { background: #17a2b8; }
  #status { color: #666; font-size: 14px; margin-top: 8px; }
</style>
</head>
<body>
<h1>OS Log Analyzer</h1>
<p>上传 Linux 系统日志（messages / journalctl / dmesg），自动检测故障模式</p>

<div class="upload-zone" id="dropzone">
  <p>拖拽日志文件到这里，或 <label style="color:#007bff;cursor:pointer">点击选择<input type="file" id="file-input" accept=".log,.txt,.out" style="display:none"></label></p>
  <p id="filename-display" style="color:#666;margin-top:10px"></p>
</div>

<button id="analyze-btn" style="display:none;padding:10px 24px;font-size:16px;background:#007bff;color:#fff;border:none;border-radius:6px;cursor:pointer">开始分析</button>

<div id="progress">
  <div id="progress-bar"><div id="progress-fill"></div></div>
  <div id="status">等待中...</div>
</div>

<div id="results"></div>

<script>
const dropzone = document.getElementById('dropzone');
const fileInput = document.getElementById('file-input');
const analyzeBtn = document.getElementById('analyze-btn');
const progressDiv = document.getElementById('progress');
const progressFill = document.getElementById('progress-fill');
const statusEl = document.getElementById('status');
const resultsDiv = document.getElementById('results');

let selectedFile = null;

dropzone.addEventListener('dragover', e => { e.preventDefault(); dropzone.classList.add('dragover'); });
dropzone.addEventListener('dragleave', () => dropzone.classList.remove('dragover'));
dropzone.addEventListener('drop', e => {
  e.preventDefault();
  dropzone.classList.remove('dragover');
  if (e.dataTransfer.files.length) handleFile(e.dataTransfer.files[0]);
});
fileInput.addEventListener('change', () => { if (fileInput.files[0]) handleFile(fileInput.files[0]); });

function handleFile(file) {
  selectedFile = file;
  document.getElementById('filename-display').textContent = file.name;
  analyzeBtn.style.display = 'block';
  resultsDiv.style.display = 'none';
}

analyzeBtn.addEventListener('click', () => {
  if (!selectedFile) return;
  const reader = new FileReader();
  reader.onload = async (e) => {
    const content = e.target.result;
    const reportId = crypto.randomUUID().replace(/-/g, '').slice(0, 12);
    const ws = new WebSocket(`ws://${location.host}/ws/analyze/${reportId}`);

    ws.onopen = () => {
      ws.send(JSON.stringify({ filename: selectedFile.name, content }));
    };

    ws.onmessage = (evt) => {
      const msg = JSON.parse(evt.data);
      if (msg.type === 'connected') {
        progressDiv.style.display = 'block';
        analyzeBtn.style.display = 'none';
      }
      if (msg.type === 'progress') {
        progressFill.style.width = msg.percent + '%';
        statusEl.textContent = msg.stage === 'parsing' ? '解析日志...' :
                               msg.stage === 'analyzing' ? '检测故障...' :
                               msg.stage === 'done' ? '分析完成' : msg.stage;
      }
      if (msg.type === 'result') {
        renderFinding(msg);
      }
      if (msg.type === 'done') {
        progressFill.style.width = '100%';
        statusEl.textContent = '分析完成';
        ws.close();
      }
    };

    ws.onerror = () => {
      statusEl.textContent = 'WebSocket 连接失败';
    };
  };
  reader.readAsText(selectedFile);
});

function renderFinding(f) {
  resultsDiv.style.display = 'block';
  const div = document.createElement('div');
  div.className = `finding ${f.severity}`;
  const badge = `<span class="severity-badge severity-${f.severity}">${f.severity}</span>`;
  div.innerHTML = `
    <div>${badge} <strong>${f.category.toUpperCase()}</strong> × ${f.count}次
      <span style="color:#999;font-size:12px;margin-left:10px">首次: ${f.first_seen}</span>
    </div>
    <div style="margin-top:8px;color:#444;font-size:13px">${f.sample_lines.map(l => `<div style="font-family:monospace">${escapeHtml(l)}</div>`).join('')}</div>
  `;
  resultsDiv.appendChild(div);
}

function escapeHtml(s) {
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}
</script>
</body>
</html>
```

**Step 2: 验证**
Open browser at http://localhost:8080/static/index.html

**Step 3: 提交**
```bash
git add os_log_analyzer/static/index.html
git commit -m "feat: add frontend HTML with WebSocket upload and live results"
```

---

## Task 8: 集成与 GitHub 推送

**Files:**
- Create: `os_log_analyzer/README.md`
- Create: `os_log_analyzer/.github/workflows/ci.yml`

**Step 1: 编写 README.md**
```markdown
# OS Log Analyzer

Linux 系统日志（messages / journalctl / dmesg）Web 分析工具。自动检测 panic、OOM、I/O error、异常关机、资源耗尽五类故障。

## 快速开始

### Docker

```bash
docker build -t os-log-analyzer .
docker run -p 8080:8080 os-log-analyzer
```

### 本地开发

```bash
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8080
```

访问 http://localhost:8080
```

**Step 2: 编写 GitHub Actions CI**
```yaml
name: CI
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: '3.11' }
      - run: pip install -r os_log_analyzer/requirements.txt
      - run: pip install pytest pytest-asyncio httpx
      - run: pytest os_log_analyzer/tests/ -v
      - uses: docker/build-push-action@v5
        with:
          context: ./os_log_analyzer
          push: false
          tags: os-log-analyzer:test
```

**Step 3: GitHub 推送**
```bash
cd os_log_analyzer
git init
git add .
git commit -m "feat: initial os-log-analyzer"
gh repo create os-log-analyzer --public --source=. --push
```

**Step 4: 提交**
```bash
git add README.md .github/
git commit -m "docs: add README and GitHub Actions CI"
```
