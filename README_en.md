# BMC Log Analyzer

Intelligent BMC (Baseboard Management Controller) log parsing and analysis tool for Huawei iBMC servers. Supports automatic format detection, anomaly detection, and LLM-powered root cause analysis.

Chinese version: [README.md](README.md)

## Features

### Log Parsing
- Automatic format detection for: app_debug_log, agentless, FDM, RAID, SEL/IPMI, syslog, maintenance, nginx_access, and more
- Auto-decompress `.log`, `.txt`, `.gz`, `.tar.gz` files
- Huawei iBMC Dump packages: automatically extracts nested archives and intelligently selects the most relevant log files

### Anomaly Detection
- **Rule-based detection**: Expert rules covering SSL handshake failures, EDMA link loss, memory allocation issues, host registration anomalies, RAID array failures, physical disk failures, CPU errors, and more
- **Statistical detection**: Entry-level distribution analysis to automatically surface anomalous modules/levels
- **Hardware event classification**: CPU / Memory / Disk / RAID / Network hardware events grouped independently

### LLM Root Cause Analysis
- **Full analysis**: Batch analysis of all rule-based + statistical anomalies with 5-stage progress bar
- **Per-card analysis**: Click the "🤖 Analyze" button on any anomaly card or hardware category to analyze that specific anomaly
- Configurable LLM provider (Minimax GLM, etc.) with API key support

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
- Rule anomaly / statistical anomaly / hardware event counts

### Analysis Report
- One-click download of Markdown format analysis report
- Includes stats summary, hardware events, rule anomaly samples, and statistical anomaly details

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Web Framework | FastAPI + Uvicorn |
| Frontend | Vanilla HTML/CSS/JavaScript (no framework) |
| Log Parsing | Python regex + structured parsers (multi-format) |
| Anomaly Detection | Expert rule engine + statistical models |
| LLM Integration | Minimax GLM API (mmx CLI) |
| Charts | ECharts |
| Deployment | Docker / Docker Compose |
| Testing | pytest |

## Quick Start

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Start the server

```bash
# Default port 8088
uvicorn app.main:app --port 8088 --reload

# or run directly
python -m app.main
```

### 3. Open browser

```
http://localhost:8088
```

### 4. Usage

1. Upload a `.log`, `.txt`, `.gz` or `.tar.gz` log file (or a Huawei iBMC dump package)
2. The system auto-detects the format and parses the log
3. View the stats overview and anomaly detection results
4. Click "🤖 Full LLM Analysis" for batch analysis
5. Or click the "🤖 Analyze" button on any anomaly card or hardware category for single-entry analysis
6. Click "📄 Download Report" to export the Markdown report

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
| IPMI/SEL | ipmi, sel |
| syslog | linux_kernel_log, dmesg |
| maintenance | maintenance_log, md_so_maintenance_log |
| nginx_access | nginx access_log |
| M7 IMU | imu, m7 |

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/upload` | Upload log file, returns parsed result + detections |
| POST | `/api/analyze/llm` | Full LLM root cause analysis |
| POST | `/api/analyze/llm-single` | Single anomaly LLM analysis |
| GET | `/` | Frontend page |

## Docker Deployment

```bash
# Latest stable
docker run -d -p 8000:8000 yuyeshun2/bmc-log-analyzer

# Specific version v0.32
docker run -d -p 8000:8000 yuyeshun2/bmc-log-analyzer:v0.32
```

Then open **http://localhost:8000** in your browser.

For production with custom LLM API:

```bash
docker run -d -p 8000:8000 \
  -e LLM_API_KEY=*** \
  -e LLM_API_BASE=https://api.deepseek.com \
  -e LLM_MODEL=deepseek-chat \
  yuyeshun2/bmc-log-analyzer:v0.32
```
