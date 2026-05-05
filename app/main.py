import os
import re
import shutil
import tarfile
import uuid
import gzip
import time
from datetime import datetime as dt, timezone
from pathlib import Path
from typing import Optional
from fastapi import FastAPI, UploadFile, HTTPException, Request
from fastapi.responses import HTMLResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.templating import Jinja2Templates
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.cors import CORSMiddleware
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import threading

import json
from pathlib import Path

MAX_FILE_SIZE = 500 * 1024 * 1024  # 500 MB upload limit

# Load version from build-injected file (set by Dockerfile ARG)
_version_file = Path(__file__).parent.parent / "app_version.json"
VERSION = json.loads(_version_file.read_text())["version"] if _version_file.exists() else "dev"


def _streaming_copy(src: UploadFile, dst_path: Path, max_size: int) -> int:
    """Stream file in chunks, aborting if max_size is exceeded. Returns bytes written."""
    written = 0
    chunk_size = 64 * 1024  # 64 KB
    with dst_path.open("wb") as f:
        while True:
            chunk = src.file.read(chunk_size)
            if not chunk:
                break
            written += len(chunk)
            if written > max_size:
                dst_path.unlink(missing_ok=True)
                raise HTTPException(status_code=413, detail=f"文件超过 {max_size // (1024*1024)} MB 限制")
            f.write(chunk)
    return written

from app.schemas import AnalysisResult
from app.parsers.app_debug import parse_app_debug_log
from app.parsers.agentless import parse_agentless_log
from app.parsers.fdm import parse_fdm_output
from app.parsers.syslog import parse_syslog
from app.parsers.raid import parse_raid_log
from app.parsers.ipmi import parse_ipmi_log
from app.parsers.maintenance import parse_maintenance_log
from app.parsers.m7_imu import parse_m7_log
from app.parsers.nginx_access import parse_nginx_access_log, parse_nginx_error_log
from app.parsers.huawei_alm import enrich_entry_with_alm
from app.parsers import get_parser
from app.detectors.rule_based import detect_rule_anomalies, detect_alm_anomalies
from app.detectors.statistical import detect_statistical_anomalies
from app.routers.llm import router as llm_router
from app.operation_log import log_operation


from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app):
    # Startup
    _n = _cleanup_old_files()
    if _n:
        print(f"[cleanup] Removed {_n} stale upload(s) on startup")
    _sync_manifest()
    _thread = threading.Thread(target=_cleanup_loop, daemon=True)
    _thread.start()
    yield
    # Shutdown: daemon thread exits with process

app = FastAPI(title="BMC Log Analyzer", lifespan=lifespan)
app.include_router(llm_router)

# Rate limiter — 20 upload requests per minute per IP
limiter = Limiter(key_func=get_remote_address, default_limits=["20/minute"])


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to every response."""

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https:; "
            "connect-src 'self' https://cdn.jsdelivr.net; "
            "font-src 'self' data:;"
        )
        return response


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Single-page tool, no credential-sensitive CORS needs
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)
app.add_middleware(SecurityHeadersMiddleware)
app.state.limiter = limiter


@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    from fastapi.responses import JSONResponse
    return JSONResponse(
        status_code=429,
        content={"detail": "请求过于频繁，请稍后再试（20次/分钟）"},
    )


STATIC_DIR = Path(__file__).parent / "static"
STATIC_DIR.mkdir(exist_ok=True)
UPLOAD_DIR = Path(__file__).parent / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)
MANIFEST_PATH = UPLOAD_DIR / "manifest.json"

# Files older than this many seconds are candidates for deletion
TTL_SECONDS = 24 * 3600  # 24 hours


def _load_manifest() -> list[dict]:
    """Returns list of {name, created_at, size}."""
    if not MANIFEST_PATH.exists():
        return []
    try:
        import json
        with MANIFEST_PATH.open() as f:
            return json.load(f)
    except Exception:
        return []


def _save_manifest(manifest: list[dict]) -> None:
    import json
    with MANIFEST_PATH.open("w") as f:
        json.dump(manifest, f, ensure_ascii=False)


def _sync_manifest() -> None:
    """Remove entries whose files no longer exist; seed from disk if manifest is empty."""
    manifest = _load_manifest()
    current_files = {p.name for p in UPLOAD_DIR.iterdir()} if UPLOAD_DIR.exists() else set()
    # strip the uuid_ prefix to match manifest names
    kept = [e for e in manifest if f"{e['uuid']}_{e['name']}" in current_files]

    # If manifest is empty but there are files on disk, seed from disk (pre-feature uploads)
    if not kept and current_files:
        import re
        for fname in current_files:
            if fname == "manifest.json" or fname.endswith("_extract") or "_extract/" in fname:
                continue
            m = re.match(r'^([0-9a-f]{32})_(.+)$', fname)
            if m:
                uuid_part, orig_name = m.group(1), m.group(2)
                p = UPLOAD_DIR / fname
                if p.is_file():
                    kept.append({"uuid": uuid_part, "name": orig_name, "created_at": p.stat().st_mtime, "size": p.stat().st_size})

    if len(kept) != len(manifest):
        _save_manifest(kept)


app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(STATIC_DIR))


def _cleanup_old_files() -> int:
    """Delete files in UPLOAD_DIR older than TTL_SECONDS. Returns count deleted."""
    deleted = 0
    now = time.time()
    for p in UPLOAD_DIR.iterdir():
        try:
            if now - p.stat().st_mtime > TTL_SECONDS:
                if p.is_dir():
                    shutil.rmtree(p)
                else:
                    p.unlink()
                deleted += 1
        except OSError:
            pass
    if deleted:
        _sync_manifest()
    return deleted


def _cleanup_loop():
    """Background thread: clean up old uploads every 30 minutes."""
    while True:
        time.sleep(1800)  # 30 minutes
        n = _cleanup_old_files()
        if n:
            print(f"[cleanup] Removed {n} stale upload(s)")




@app.get("/", response_class=HTMLResponse)
async def index():
    return templates.get_template("index.html").render()


@app.get("/api/version")
async def get_version():
    return {"version": VERSION}


@app.post("/api/upload")
@limiter.limit("20/minute")
async def upload_log(request: Request, file: UploadFile) -> AnalysisResult:
    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided")

    suffix = Path(file.filename).suffix.lower()
    if suffix not in (".log", ".txt", ".gz", ".tar.gz", ""):
        raise HTTPException(status_code=400, detail="Unsupported file type")

    # Save uploaded file (streaming to disk, with size limit)
    job_id = uuid.uuid4().hex
    save_path = UPLOAD_DIR / f"{job_id}_{file.filename}"
    file_size = _streaming_copy(file, save_path, MAX_FILE_SIZE)

    # Record in manifest
    import json
    manifest = _load_manifest()
    manifest.insert(0, {"uuid": job_id, "name": file.filename, "created_at": time.time(), "size": file_size})
    # Keep last 20
    _save_manifest(manifest[:20])

    # Decompress .tar.gz if needed
    decompressed_path, all_files = _decompress_if_needed(save_path, job_id)

    # For tar.gz, scan and score all log files, parse the top-N
    format_type = "unknown"
    entries: list = []
    parse_errors = 0
    if decompressed_path != save_path and decompressed_path.is_dir():
        top_files = _find_top_log_files(decompressed_path)
        if top_files:
            format_type, entries, parse_errors = _parse_multi(top_files, file.filename)
        elif all_files:
            # Fallback: use first extracted file
            format_type, entries, parse_errors = _route_parse(file.filename, all_files[0])
    else:
        format_type, entries, parse_errors = _route_parse(file.filename, decompressed_path)

    # Post-process: enrich with Huawei ALM alarm code metadata
    for e in entries:
        enrich_entry_with_alm(e)

    # Compute time range from entries
    ts_list = [e.timestamp for e in entries if e.timestamp]
    time_range = []
    if ts_list:
        ts_list.sort()
        time_range = [
            ts_list[0].strftime("%Y-%m-%d %H:%M:%S") if hasattr(ts_list[0], 'strftime') else str(ts_list[0]),
            ts_list[-1].strftime("%Y-%m-%d %H:%M:%S") if hasattr(ts_list[-1], 'strftime') else str(ts_list[-1]),
        ]

    parsed_log = {
        "format_type": format_type,
        "total_lines": len(entries),
        "entries": entries,
        "parse_errors": parse_errors,
        "file_name": file.filename,
        "time_range": time_range,
    }

    # Run anomaly detection
    rule_anomalies = detect_rule_anomalies(entries)
    stat_anomalies = detect_statistical_anomalies(entries)
    alm_anomalies = detect_alm_anomalies(entries)  # cache — used 3× below

    # Summary stats
    level_counts: dict[str, int] = {}
    module_counts: dict[str, int] = {}
    for e in entries:
        level_counts[e.level] = level_counts.get(e.level, 0) + 1
        if e.module:
            module_counts[e.module] = module_counts.get(e.module, 0) + 1

    summary = {
        "total_entries": len(entries),
        "error_count": level_counts.get("ERROR", 0),
        "warning_count": level_counts.get("WARNING", 0),
        "level_counts": level_counts,
        "top_modules": sorted(module_counts.items(), key=lambda x: -x[1])[:5],
        "rule_anomaly_count": len(rule_anomalies),
        "alm_anomaly_count": sum(1 for a in alm_anomalies if a.severity == "ERROR"),
        "stat_anomaly_count": len(stat_anomalies),
        "parsers_used": {format_type: len(entries)},
    }

    log_operation(
        operation="upload",
        detail=f"上传文件 {file.filename}，解析格式 {format_type}，{len(entries)} 条日志",
        file_name=file.filename,
        result="ok",
        extra={"format": format_type, "entries": len(entries), "errors": parse_errors, "rule_anomalies": len(rule_anomalies), "alm_anomalies": sum(1 for a in alm_anomalies if a.severity == "ERROR"), "stat_anomalies": len(stat_anomalies)},
    )

    return AnalysisResult(
        parsed_log=parsed_log,
        rule_anomalies=rule_anomalies,
        alm_anomalies=alm_anomalies,
        statistical_anomalies=stat_anomalies,
        summary=summary,
    )
    # NOTE: uploaded files are NOT deleted here — the background cleanup
    # thread handles 24-hour TTL deletion instead.


@app.get("/api/history")
async def get_history():
    """Return last 20 uploaded file names (without uuid prefix)."""
    _sync_manifest()
    manifest = _load_manifest()
    return [{"uuid": e["uuid"], "name": e["name"], "created_at": e["created_at"], "size": e["size"]} for e in manifest]


@app.delete("/api/history")
async def clear_history():
    """Delete all history entries and their files from disk."""
    deleted = 0
    for p in UPLOAD_DIR.iterdir():
        try:
            if p.name.startswith("manifest"):
                continue
            if p.is_dir():
                shutil.rmtree(p)
            else:
                p.unlink()
            deleted += 1
        except Exception:
            pass
    if MANIFEST_PATH.exists():
        MANIFEST_PATH.unlink()
    log_operation(operation="clear_history", detail=f"清空全部历史，删除 {deleted} 个文件", result="ok")
    return {"deleted": deleted}


@app.get("/api/operation-logs")
async def get_operation_logs(days: int = 7):
    """Return operation logs for the last N days (default 7)."""
    from app.operation_log import read_logs
    if days < 1 or days > 30:
        days = 7
    return read_logs(days=days)


@app.delete("/api/reanalyze/{uuid}")
async def delete_reanalyze(uuid: str):
    """Delete a previously uploaded file from disk and manifest."""
    import shutil
    deleted = False
    original_name = ""
    for p in UPLOAD_DIR.iterdir():
        if p.name.startswith(f"{uuid}_"):
            original_name = p.name[len(uuid) + 1:]
            if p.is_dir():
                shutil.rmtree(p)
            else:
                p.unlink()
            deleted = True
            break
    if not deleted:
        raise HTTPException(status_code=404, detail="File not found")
    manifest = _load_manifest()
    manifest = [e for e in manifest if e["uuid"] != uuid]
    _save_manifest(manifest)
    log_operation(operation="delete_reanalyze", detail=f"删除历史文件 {uuid}", file_name=original_name, result="ok")
    return {"ok": True}

@app.post("/api/reanalyze/{uuid}")
async def reanalyze(uuid: str):
    """Re-run analysis on a previously uploaded file stored on disk."""
    for p in UPLOAD_DIR.iterdir():
        if p.name.startswith(f"{uuid}_"):
            file_path = p
            original_name = p.name[len(uuid) + 1:]
            break
    else:
        raise HTTPException(status_code=404, detail="File not found (may have expired)")

    # Touch file to reset its TTL timer on each access
    os.utime(file_path)

    decompressed_path, all_files = _decompress_if_needed(file_path, uuid)
    format_type = "unknown"
    entries: list = []
    parse_errors = 0
    if decompressed_path != file_path and decompressed_path.is_dir():
        top_files = _find_top_log_files(decompressed_path)
        if top_files:
            format_type, entries, parse_errors = _parse_multi(top_files, original_name)
        elif all_files:
            format_type, entries, parse_errors = _route_parse(original_name, all_files[0])
    else:
        format_type, entries, parse_errors = _route_parse(original_name, decompressed_path)

    # Post-process: enrich with Huawei ALM alarm code metadata
    for e in entries:
        enrich_entry_with_alm(e)

    rule_anomalies = detect_rule_anomalies(entries)
    stat_anomalies = detect_statistical_anomalies(entries)
    alm_anomalies = detect_alm_anomalies(entries)  # cache — used 3× below
    level_counts: dict[str, int] = {}
    module_counts: dict[str, int] = {}
    for e in entries:
        level_counts[e.level] = level_counts.get(e.level, 0) + 1
        if e.module:
            module_counts[e.module] = module_counts.get(e.module, 0) + 1

    # Compute time range from entries
    ts_list = [e.timestamp for e in entries if e.timestamp]
    time_range = []
    if ts_list:
        ts_list.sort()
        time_range = [
            ts_list[0].strftime("%Y-%m-%d %H:%M:%S") if hasattr(ts_list[0], 'strftime') else str(ts_list[0]),
            ts_list[-1].strftime("%Y-%m-%d %H:%M:%S") if hasattr(ts_list[-1], 'strftime') else str(ts_list[-1]),
        ]

    parsed_log = {
        "format_type": format_type,
        "total_lines": len(entries),
        "entries": entries,
        "parse_errors": parse_errors,
        "file_name": original_name,
        "time_range": time_range,
    }
    summary = {
        "total_entries": len(entries),
        "error_count": level_counts.get("ERROR", 0),
        "warning_count": level_counts.get("WARNING", 0),
        "level_counts": level_counts,
        "top_modules": sorted(module_counts.items(), key=lambda x: -x[1])[:5],
        "rule_anomaly_count": len(rule_anomalies),
        "alm_anomaly_count": sum(1 for a in alm_anomalies if a.severity == "ERROR"),
        "stat_anomaly_count": len(stat_anomalies),
        "parsers_used": {format_type: len(entries)},
    }
    log_operation(
        operation="reanalyze",
        detail=f"重新分析 {original_name}，{len(entries)} 条日志",
        file_name=original_name,
        result="ok",
        extra={"format": format_type, "entries": len(entries), "rule_anomalies": len(rule_anomalies), "alm_anomalies": sum(1 for a in alm_anomalies if a.severity == "ERROR"), "stat_anomalies": len(stat_anomalies)},
    )
    alm_detected = alm_anomalies
    return AnalysisResult(parsed_log=parsed_log, rule_anomalies=rule_anomalies, alm_anomalies=alm_detected, statistical_anomalies=stat_anomalies, summary=summary)


def _safe_extract(tar: tarfile.TarFile, dest: Path) -> None:
    """Extract tar into dest with ZIP SLIP protection.

    Validates each member name contains no '..' path traversal before extracting.
    Raises ValueError if any member would escape the destination directory.
    """
    dest_resolved = dest.resolve()
    for member in tar.getmembers():
        if '..' in member.name or member.name.startswith('/'):
            raise ValueError(f"Unsafe path in archive: {member.name}")
        member_path = (dest / member.name).resolve()
        if not member_path.is_relative_to(dest_resolved):
            raise ValueError(f"Path traversal attempt: {member.name}")
    tar.extractall(dest)


def _decompress_if_needed(path: Path, job_id: str) -> tuple[Path, list[Path]]:
    """Decompress .tar.gz, .gz, or nested tar files.

    Returns (primary_path, all_extracted_paths).
    Handles:
      - .tar.gz  → extract all; recurse into any inner .tar/.tar.gz found
      - Plain .gz → decompress to plain file (handles .log.gz, .txt.gz, etc.)
      - Nested tar → after extracting a tar.gz, check for inner .tar/.tar.gz members
                      and extract those too (one level of recursion)
    """
    if path.suffix.lower() == ".gz":
        if path.stem.endswith(".tar"):
            # It's a .tar.gz — extract all
            extract_dir = path.parent / f"{job_id}_extract"
            if extract_dir.exists():
                shutil.rmtree(extract_dir)
            extract_dir.mkdir()
            with tarfile.open(path, "r:gz") as tar:
                _safe_extract(tar, extract_dir)
            # Recurse into any inner tar files (tar inside tar.gz)
            all_files = _extract_inner_archives(extract_dir, job_id)
            return extract_dir, all_files
        else:
            # Plain .gz — decompress to plain file so parsers can read it directly
            decompressed = path.parent / f"{job_id}_{path.stem}"
            with gzip.open(path, "rb") as f_in:
                with decompressed.open("wb") as f_out:
                    shutil.copyfileobj(f_in, f_out)
            return decompressed, [decompressed]
    return path, [path]


def _extract_inner_archives(extract_dir: Path, job_id: str) -> list:
    """Find and extract any .tar / .tar.gz members inside an extracted directory.

    One level of recursion only (no deep nesting).
    Returns flat list of all extracted file paths (top-level + inner archive contents).
    """
    all_files: list = []
    # Include top-level files from the outer tar.gz extraction
    for p in extract_dir.iterdir():
        if p.is_file():
            all_files.append(p)

    for p in extract_dir.rglob("*"):
        if not p.is_file():
            continue
        if p.suffix == ".tar":
            sub_dir = extract_dir / f"{job_id}_inner_{p.stem}"
            sub_dir.mkdir(exist_ok=True)
            with tarfile.open(p, "r:") as tar:
                _safe_extract(tar, sub_dir)
            all_files.extend(p for p in sub_dir.rglob("*") if p.is_file())
            all_files.append(p)
        elif p.suffix == ".gz" and p.stem.endswith(".tar"):
            sub_dir = extract_dir / f"{job_id}_inner_{p.stem}"
            sub_dir.mkdir(exist_ok=True)
            with tarfile.open(p, "r:gz") as tar:
                _safe_extract(tar, sub_dir)
            all_files.extend(p for p in sub_dir.rglob("*") if p.is_file())
            all_files.append(p)
    # Deduplicate while preserving order
    seen = set()
    unique = []
    for f in all_files:
        if f not in seen:
            seen.add(f)
            unique.append(f)
    return unique


def _has_rotated_suffix(name: str, pat: str) -> bool:
    """Check if name has a rotation suffix like .1, .2, .3 or .1.gz, .2.gz."""
    base = name[len(pat):]  # everything after the pattern
    import re
    return bool(re.match(r'^\.(\d+)(\.gz)?$', base))


def _find_best_log_file(extract_dir: Path, filename: str) -> Optional[Path]:
    """Find the best log file from an extracted dump directory.

    Searches dump_info subdirectories (AppDump/BMC, LogDump, etc.) for
    the most relevant log file, preferring non-rotated, non-gzipped originals.
    """
    # Priority patterns — ordered by diagnostic value (most important first)
    # Covers Huawei iBMC一键收集 all major log types from 表3-69
    patterns = [
        # Application debug / operational logs (highest value for debugging)
        "app_debug_log_all",
        "ipmi_mass_operate_log",
        "ipmi_debug_log",
        "operate_log",
        "security_log",
        "strategy_log",
        "mass_operate_log",
        "remote_log",
        # Module dfl logs (structured diagnostic output)
        "BMC_dfl",
        "sensor_alarm_dfl",
        "PowerMgnt_dfl",
        "UPGRADE_dfl",
        "BIOS_dfl",
        "card_manage_dfl",
        "CpuMem_dfl",
        "cooling_app_dfl",
        "Snmp_dfl",
        "ddns_dfl",
        "diagnose_dfl",
        "discovery_dfl",
        "agentless_dfl",
        "kvm_vmm_dfl",
        "ipmi_app_dfl",
        "fileManage_dfl",
        "switch_card_dfl",
        "StorageMgnt_dfl",
        "rimm_dfl",
        "redfish_dfl",
        "Dft_dfl",
        "net_nat_dfl",
        "PcieSwitch_dfl",
        "MaintDebug_dfl",
        # IPMI / SEL (high diagnostic value)
        "ipmi_sel",
        "IPMI_SEL",
        "ipmi_seld",
        "BMC_dump",
        "core_dump",
        # High-availability / web / XML exports
        "ha_log",
        "web_log",
        "export.xml",
        # CPLD / FPGA version info
        "cpld_info",
        "fpga_info",
        # Additional dfl modules
        "webapp_dfl",
        "restful_dfl",
        # Additional sensor/hardware info
        "sensor_data",
        "psu_status",
        "raid_status",
        "disk_info",
        # Linux / systemd
        "syslog",
        "journal",
        # Mass / remote operate
        "ipmi_mass",
        "rmt_mnt_log",
        # Module info
        "module_info",
        # Sensor / hardware info
        "sensor_info",
        "fan_info",
        "cpu_info",
        "mem_info",
        "net_info",
        "psu_info",
        "fruinfo",
        "nandflash_info",
        "time_zone",
        "ntp_info",
        "bios_info",
        "card_info",
        # Linux / kernel
        "linux_kernel_log",
        "dmesg",
        "app_debug",
        # Maintenance
        "maintenance_log",
        "md_so_maintenance_log",
        "md_so_operate_log",
        "md_so_strategy_log",
    ]

    def find_best(pat: str) -> Optional[Path]:
        """Find the best file matching pat, preferring non-gzipped, non-rotated."""
        logdump = extract_dir / "dump_info" / "LogDump"
        candidates = []

        # Search in LogDump
        if logdump.exists():
            for p in logdump.rglob(f"{pat}*"):
                if p.is_file():
                    candidates.append(p)

        # Also search root dump_info
        for p in (extract_dir / "dump_info").rglob(f"{pat}*"):
            if p.is_file():
                candidates.append(p)

        if not candidates:
            return None

        # Filter out .gz files (they're compressed, prefer the uncompressed original)
        non_gz = [p for p in candidates if not p.name.endswith('.gz')]
        gz_only = [p for p in candidates if p.name.endswith('.gz')]

        # Prefer non-gz
        if non_gz:
            # Among non-gz, prefer the main one without numeric suffix like .1, .2
            main = [p for p in non_gz if not _has_rotated_suffix(p.name, pat)]
            if main:
                return main[0]
            return non_gz[0]

        # Fallback to gz — pick the one without numeric suffix (.1.gz, .2.gz)
        main_gz = [p for p in gz_only if not _has_rotated_suffix(p.name, pat)]
        if main_gz:
            return main_gz[0]
        return gz_only[0] if gz_only else None

    for pat in patterns:
        result = find_best(pat)
        if result:
            return result

    # Fallback: look for any log file in LogDump (prefer non-gz, non-rotated)
    logdump = extract_dir / "dump_info" / "LogDump"
    if logdump.exists():
        all_logs = sorted(logdump.glob("*.log"))
        all_logs += sorted(logdump.glob("*.log.*"))
        seen = set()
        for p in all_logs:
            if p.name in seen:
                continue
            if not _has_rotated_suffix(p.name, p.stem):
                seen.add(p.name)
                return p

    return None


# Keywords that indicate high-value diagnostic content (ordered by importance)
# Used to score and prioritize log files during multi-file scanning
_KEYWORD_PATTERN = re.compile(
    r"(?i)(error|fail|fault|Critical|Major|Minor|Warning|Asserted|Deasserted|"
    r"power|fan|thermal|memory|disk|CPU|BIOS|reboot|restart|poweroff|shutdown|"
    r"power cycle|hang|hung|unresponsive|lockup|reset|oom|out of memory|panic|"
    r"oops|bug|watchdog|MCE|Machine.Check|correctable|uncorrectable|power loss|"
    r"AC loss|segfault|core.dump)",
    re.IGNORECASE,
)

# Max top log files to parse in multi-file mode
_MAX_LOG_FILES = 5

# Skip scanning these file extensions when scoring
_SKIP_SCAN_EXTS = {".gz", ".bin", ".db", ".json", ".csv", ".txt", ".bak", ".sha256", ".ini", ".conf"}


def _score_file_by_keywords(path: Path) -> int:
    """Return count of keyword matches in first 1MB of file. Skips binary/skip-ext files."""
    ext = "." + path.suffix.lower().lstrip(".")
    if ext in _SKIP_SCAN_EXTS or path.name.endswith(".sha256"):
        return 0
    try:
        if path.stat().st_size > 20 * 1024 * 1024:  # skip > 20MB
            return 0
        # Read only first 1MB to avoid OOM while still capturing diagnostic keywords
        with path.open("rb") as f:
            text = f.read(1024 * 1024).decode("utf-8", errors="replace")
        return len(_KEYWORD_PATTERN.findall(text))
    except OSError:
        return 0


def _find_top_log_files(extract_dir: Path, top_n: int = _MAX_LOG_FILES) -> list[Path]:
    """Find top-N log files, preferring known log types scored by keyword matches.

    Two-tier selection:
    1. Priority files matching known log patterns (app_debug_log_all, operate_log,
       security_log, dfl logs, etc.) — sorted by keyword match count.
    2. If fewer than top_n found, fill with other scored files.
    """
    dump_info = extract_dir / "dump_info"
    if not dump_info.exists():
        return []

    # Priority patterns — files known to contain structured BMC log entries
    priority_pats = [
        "app_debug_log_all",
        "ipmi_mass_operate_log",
        "ipmi_debug_log",
        "operate_log",
        "security_log",
        "strategy_log",
        "mass_operate_log",
        "remote_log",
        "BMC_dfl",
        "sensor_alarm_dfl",
        "PowerMgnt_dfl",
        "UPGRADE_dfl",
        "BIOS_dfl",
        "card_manage_dfl",
        "CpuMem_dfl",
        "cooling_app_dfl",
        "Snmp_dfl",
        "ddns_dfl",
        "diagnose_dfl",
        "discovery_dfl",
        "agentless_dfl",
        "kvm_vmm_dfl",
        "ipmi_app_dfl",
        "fileManage_dfl",
        "StorageMgnt_dfl",
        "redfish_dfl",
        "Dft_dfl",
        "net_nat_dfl",
        "PcieSwitch_dfl",
        "MaintDebug_dfl",
        "linux_kernel_log",
        "dmesg",
        "app_debug",
        "maintenance_log",
        "md_so_maintenance_log",
        "md_so_operate_log",
        "md_so_strategy_log",
        "dfm_debug_log",
        "dfm.log",
        "raid",
        "lsi",
    ]

    all_files: list[Path] = []
    for p in dump_info.rglob("*"):
        if p.is_file():
            ext = "." + p.suffix.lower().lstrip(".")
            if ext in _SKIP_SCAN_EXTS or p.name.endswith(".sha256") or p.name.endswith(".bak"):
                continue
            all_files.append(p)

    if not all_files:
        return []

    def score_path(p: Path) -> int:
        ext = "." + p.suffix.lower().lstrip(".")
        if ext in _SKIP_SCAN_EXTS or p.name.endswith(".sha256"):
            return 0
        try:
            if p.stat().st_size > 20 * 1024 * 1024:
                return 0
            # Read only first 1MB to avoid OOM
            with p.open("rb") as f:
                text = f.read(1024 * 1024).decode("utf-8", errors="replace")
            return len(_KEYWORD_PATTERN.findall(text))
        except OSError:
            return 0

    # Split into priority and others
    priority_files: list[tuple[int, Path]] = []
    other_files: list[tuple[int, Path]] = []

    for p in all_files:
        score = score_path(p)
        if score == 0:
            continue
        name_lower = p.name.lower()
        is_priority = any(pat in name_lower for pat in priority_pats)
        if is_priority:
            priority_files.append((score, p))
        else:
            other_files.append((score, p))

    # Sort descending by score
    priority_files.sort(key=lambda x: x[0], reverse=True)
    other_files.sort(key=lambda x: x[0], reverse=True)

    # Deduplicate by base name, prefer priority
    seen: set[str] = set()
    result: list[Path] = []

    for score, p in priority_files:
        base = re.sub(r"\.\d+$", "", p.name)
        if base not in seen:
            seen.add(base)
            result.append(p)

    for score, p in other_files:
        base = re.sub(r"\.\d+$", "", p.name)
        if base not in seen:
            seen.add(base)
            result.append(p)

    return result[:top_n]


def _parse_multi(file_paths: list[Path], original_filename: str) -> tuple[str, list, int]:
    """Parse multiple log files, aggregate entries, merge parse_errors.

    Returns (format_type, all_entries, total_parse_errors).
    Each entry's source_file is set to the filename it came from.
    """
    all_entries: list = []
    total_errors = 0
    format_type = "multi"

    for path in file_paths:
        try:
            ft, entries, errs = _route_parse(path.name, path)
            # Tag each entry with its source file
            for e in entries:
                e.source_file = path.name
                # Enrich with Huawei ALM alarm code metadata
                enrich_entry_with_alm(e)
            all_entries.extend(entries)
            total_errors += errs
            if len(entries) > 0:
                format_type = ft
        except Exception:
            total_errors += 1

    # Sort by timestamp if available
    all_entries.sort(key=lambda e: e.timestamp or dt.min)
    return format_type, all_entries, total_errors


def _route_parse(filename: str, path: Path):
    # If path is a directory (decompressed tar.gz), pick the primary log file
    if path.is_dir():
        # Sort by size desc, pick the largest file as primary
        try:
            candidates = sorted(path.rglob("*"), key=lambda p: p.stat().st_size if p.is_file() else -1, reverse=True)
            # Skip very small files (<1KB) and hidden files
            for p in candidates:
                if p.is_file() and p.stat().st_size > 1024 and not p.name.startswith("."):
                    path = p
                    break
            else:
                raise HTTPException(status_code=422, detail=f"无法在解压目录中找到有效的日志文件")
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(status_code=422, detail=f"解压目录扫描失败: {e}")

    # Registry lookup — discovers all registered parsers via __init__.py
    parse_fn, format_name = get_parser(filename if path.is_file() else path.name)
    if parse_fn is not None:
        return parse_fn(path)

    # Fallback for unregistered filenames: try app_debug as catch-all
    return parse_app_debug_log(path)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, factory=True)