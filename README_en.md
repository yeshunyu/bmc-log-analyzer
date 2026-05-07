# BMC Log Analyzer

Intelligent BMC (Baseboard Management Controller) log parsing and analysis tool for Huawei iBMC servers. Supports automatic format detection, anomaly detection, and LLM-powered root cause analysis.

## Version

**v1.0.0** - Latest release (Security Stable)

Chinese version: [README.md](README.md)

## Features

### Log Parsing
- Automatic format detection for: app_debug_log, agentless, FDM, RAID, SEL/IPMI, syslog, maintenance, nginx_access, and more
- Auto-decompress `.log`, `.txt`, `.gz`, `.tar.gz` files
- Huawei iBMC Dump packages: automatically extracts nested archives and intelligently selects the most relevant log files
- Large file protection: auto-sampling (max 200 lines per format) to avoid OOM

### Anomaly Detection
- **Rule-based detection**: Expert rules covering SSL handshake failures, EDMA link loss, memory allocation issues, RAID array failures, physical disk failures, CPU errors, NPU/Huawei Ascend failures, CANN runtime errors, and more (70+ rules)
- **Huawei ALM Code Detection**: Auto-decodes `ALM-0xNNXXXXXX` alarm codes, identifies 14 major hardware categories (200+ alarms)
- **IPMI SEL Semantic Enhancement**: Distinguishes true severity based on sensor semantics
- **Statistical detection**: Entry-level distribution analysis to automatically surface anomalous modules/levels
- **Diagnostic priority**: External→Internal (PSU→Fan→Thermal→CPU/NPU→Memory→RAID→Network→Service), High→Low (ERROR→WARNING→INFO)
- **Hardware event classification**: CPU / Memory / Disk / RAID / Network / NPU / BMC independently grouped with dedicated LLM analysis

### LLM Root Cause Analysis
- **Full analysis**: Batch analysis of all rule-based + statistical anomalies with 5-stage progress bar
- **Per-card analysis**: Click the "🤖 Analyze" button on any anomaly card or hardware category to analyze that specific anomaly
- Supports any OpenAI-compatible or Anthropic-compatible LLM API (DeepSeek, etc.), dual-interface auto-detection
- **Enhanced prompts**: Focus on low-level hardware fault root cause, specific slot/PCIe location, ignore management interface (PowerMgnt) timeouts
- **Priority P0/P1/P2/P3**: Based on business impact, disk/RAID failures prioritized equally with fan/PSU
- **Actionable steps**: Diagnostic commands (storcli64), physical operations, firmware fixes, vendor escalation

### All Events
- Paginated listing (50/100/200/500 per page)
- Level filtering (ERROR / WARNING / INFO multi-select)
- Time range filter
- Regex / fuzzy search across message / module / level fields
- Page navigation with first/last buttons

### Stats Overview
- Error / warning count cards
- Module distribution donut chart (click sector for details)
- Anomaly timeline distribution chart
- Rule / statistical / hardware event counts

### Analysis Report
- One-click download of Markdown/HTML analysis report
- Top risk assessment (Low/Medium/High) + recommended actions for quick ops visibility
- Report filename includes device model and SN when extractable from filename or log content
- Includes stats summary, hardware events, rule anomaly samples, and statistical anomaly details

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Web Framework | FastAPI + Uvicorn |
| Frontend | Vanilla HTML/CSS/JavaScript (no framework) |
| Log Parsing | Python regex + structured parsers (multi-format) |
| Anomaly Detection | Expert rule engine + statistical models |
| LLM Integration | DeepSeek / OpenAI / Anthropic API |
| Charts | ECharts (bundled locally, no CDN) |
| Deployment | Docker |
| Testing | pytest |

## Quick Start

### macOS Native (Without Docker)

**One-click start** (recommended):
```bash
tar -xzf bmc-log-analyzer_v1.0.0.tar.gz
cd bmc-log-analyzer
./start.sh
```

**Or manually step by step**:
```bash
# 1. Create virtual environment
python3 -m venv .venv

# 2. Activate virtual environment
source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Start the server
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Then open **http://localhost:8000** in your browser.

---

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Start the server

```bash
uvicorn app.main:app --port 8000 --reload
```

### 3. Open browser

```
http://localhost:8000
```

### 4. Usage

1. Upload a `.log`, `.txt`, `.gz` or `.tar.gz` log file (or a Huawei iBMC dump package)
2. The system auto-detects the format and parses the log
3. View the stats overview and anomaly detection results
4. Click "🤖 Full LLM Analysis" for batch analysis
5. Or click the "🤖 Analyze" button on any anomaly card or hardware category for single-entry analysis
6. Click "📄 Download Report" to export the analysis report

## Docker Deployment

Supports `linux/amd64` (x86 servers) and `linux/arm64` (ARM servers / Apple Silicon Mac) architectures. Zero known runtime vulnerabilities. Supports both online and offline deployment.

### Quick Start

```bash
# Choose image based on your server architecture
# x86 servers (Intel/AMD CPU)
docker run -d -p 8000:8000 yuyeshun2/bmc-log-analyzer:v1.0.0-amd64

# ARM servers (Huawei Kunpeng, Amazon Graviton, Apple Silicon Mac)
docker run -d -p 8000:8000 yuyeshun2/bmc-log-analyzer:v1.0.0-arm64

# Or use latest tag (auto-selects architecture, slower first download)
docker run -d -p 8000:8000 yuyeshun2/bmc-log-analyzer:latest
```

Then open **http://localhost:8000** in your browser.

## Project Structure

```
app/
├── main.py              # FastAPI entry, upload/parse/detect logic
├── routers/
│   └── llm.py          # LLM endpoints (/llm, /llm-single)
├── parsers/             # Format-specific parsers
│   ├── app_debug.py     # app_debug_log format
│   ├── agentless.py     # agentless format
│   ├── fdm.py          # FDM output format
│   ├── raid.py          # RAID/LSI logs
│   ├── ipmi.py          # IPMI/SEL format
│   ├── syslog.py        # syslog format
│   ├── maintenance.py   # maintenance logs
│   ├── nginx_access.py  # Nginx Access logs
│   ├── m7_imu.py        # M7 IMU logs
│   ├── sel.py           # IPMI SEL binary/text parser
│   ├── huawei_alm.py    # Huawei ALM alarm code knowledge base
│   ├── ibmc_dump.py    # iBMC Dump archive parser
│   └── __init__.py      # automatic format detection
├── detectors/
│   ├── rule_based.py    # expert rule anomaly detection
│   └── statistical.py   # statistical anomaly detection
├── schemas.py           # Pydantic data models
├── static/
│   └── index.html       # frontend page
└── uploads/             # uploaded files (auto-cleaned, 24h TTL)
```

## Supported Log Formats

| Format | Filename Keywords |
|--------|-------------------|
| app_debug_log | app_debug_log_all, ipmi_mass_operate_log |
| agentless | agentless_dfl |
| FDM | dfl files |
| RAID/LSI MegaRAID | raid, lsi |
| IPMI/SEL | ipmi, sel, sensor_alarm_sel |
| SEL | sel |
| syslog | linux_kernel_log, dmesg |
| maintenance | maintenance_log, md_so_maintenance_log |
| nginx_access + error | nginx access_log, nginx_error_log |
| M7 IMU | imu, m7 |
| iBMC Dump | BMC_dump, core_dump, dump_info, ibmc_dump |
| Huawei ALM | ALM-0xNNXXXXXX alarm codes |

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/upload` | Upload log file (max 500MB), returns parsed + detection results |
| POST | `/api/analyze/llm` | Full LLM root cause analysis |
| POST | `/api/analyze/llm-single` | Single anomaly LLM analysis |
| GET | `/api/history` | List uploaded file history |
| DELETE | `/api/history` | Clear all history |
| POST | `/api/reanalyze/{uuid}` | Re-analyze historical file |
| DELETE | `/api/reanalyze/{uuid}` | Delete historical file |
| GET | `/api/operation-logs` | Query operation logs (default last 7 days) |
| GET | `/api/analyze/llm-settings` | Get LLM configuration |
| POST | `/api/analyze/llm-settings` | Update LLM configuration |
| POST | `/api/analyze/llm-settings/reset` | Reset LLM configuration |
