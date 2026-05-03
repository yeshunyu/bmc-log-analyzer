import shutil
import tarfile
import uuid
import gzip
import time
from pathlib import Path
from fastapi import FastAPI, UploadFile, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from starlette.templating import Jinja2Templates
import threading

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
from app.parsers import get_parser
from app.detectors.rule_based import detect_rule_anomalies
from app.detectors.statistical import detect_statistical_anomalies
from app.routers.llm import router as llm_router

app = FastAPI(title="BMC Log Analyzer")
app.include_router(llm_router)

STATIC_DIR = Path(__file__).parent / "static"
STATIC_DIR.mkdir(exist_ok=True)
UPLOAD_DIR = Path(__file__).parent / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)

# Files older than this many seconds are candidates for deletion
TTL_SECONDS = 24 * 3600  # 24 hours

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
    return deleted


def _cleanup_loop():
    """Background thread: clean up old uploads every 30 minutes."""
    while True:
        time.sleep(1800)  # 30 minutes
        n = _cleanup_old_files()
        if n:
            print(f"[cleanup] Removed {n} stale upload(s)")


# Start background cleanup thread
_cleanup_thread = threading.Thread(target=_cleanup_loop, daemon=True)
_cleanup_thread.start()
# Also clean any stale files left from previous runs on startup
n = _cleanup_old_files()
if n:
    print(f"[cleanup] Removed {n} stale upload(s) on startup")


@app.get("/", response_class=HTMLResponse)
async def index():
    return templates.get_template("index.html").render()


@app.post("/api/upload")
async def upload_log(file: UploadFile) -> AnalysisResult:
    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided")

    suffix = Path(file.filename).suffix.lower()
    if suffix not in (".log", ".txt", ".gz", ".tar.gz", "") and not suffix.startswith("."):
        raise HTTPException(status_code=400, detail="Unsupported file type")

    # Save uploaded file
    job_id = uuid.uuid4().hex
    save_path = UPLOAD_DIR / f"{job_id}_{file.filename}"
    with save_path.open("wb") as f:
        shutil.copyfileobj(file.file, f)

    # Decompress .tar.gz if needed
    decompressed_path, all_files = _decompress_if_needed(save_path, job_id)

    # For tar.gz, find the best log file
    parse_path = decompressed_path
    if decompressed_path != save_path and decompressed_path.is_dir():
        best = _find_best_log_file(decompressed_path, file.filename)
        if best:
            parse_path = best

    # Parse based on filename hint
    format_type, entries, parse_errors = _route_parse(file.filename, parse_path)

    parsed_log = {
        "format_type": format_type,
        "total_lines": len(entries),
        "entries": entries,
        "parse_errors": parse_errors,
    }

    # Run anomaly detection
    rule_anomalies = detect_rule_anomalies(entries)
    stat_anomalies = detect_statistical_anomalies(entries)

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
        "top_modules": sorted(module_counts.items(), key=lambda x: -x[1])[:5],
        "rule_anomaly_count": len(rule_anomalies),
        "stat_anomaly_count": len(stat_anomalies),
    }

    return AnalysisResult(
        parsed_log=parsed_log,
        rule_anomalies=rule_anomalies,
        statistical_anomalies=stat_anomalies,
        summary=summary,
    )
    # NOTE: uploaded files are NOT deleted here — the background cleanup
    # thread handles 24-hour TTL deletion instead.


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
            extract_dir.mkdir(exist_ok=True)
            with tarfile.open(path, "r:gz") as tar:
                tar.extractall(extract_dir)
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


def _extract_inner_archives(extract_dir: Path, job_id: str) -> list[Path]:
    """Find and extract any .tar / .tar.gz members inside an extracted directory.

    One level of recursion only (no deep nesting).
    Returns flat list of all extracted file paths.
    """
    all_files: list[Path] = []
    for p in extract_dir.rglob("*"):
        if not p.is_file():
            continue
        if p.suffix == ".tar":
            sub_dir = extract_dir / f"{job_id}_inner_{p.stem}"
            sub_dir.mkdir(exist_ok=True)
            with tarfile.open(p, "r:") as tar:
                tar.extractall(sub_dir)
            all_files.extend(p for p in sub_dir.rglob("*") if p.is_file())
            all_files.append(p)
        elif p.suffix == ".gz" and p.stem.endswith(".tar"):
            sub_dir = extract_dir / f"{job_id}_inner_{p.stem}"
            sub_dir.mkdir(exist_ok=True)
            with tarfile.open(p, "r:gz") as tar:
                tar.extractall(sub_dir)
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


def _find_best_log_file(extract_dir: Path, filename: str) -> Path | None:
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

    def find_best(pat: str) -> Path | None:
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

    def _has_rotated_suffix(name: str, pat: str) -> bool:
        """Check if name has a rotation suffix like .1, .2, .3 or .1.gz, .2.gz."""
        base = name[len(pat):]  # everything after the pattern
        import re
        return bool(re.match(r'^\.(\d+)(\.gz)?$', base))

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


def _route_parse(filename: str, path: Path):
    # Try registry first (auto-discovers all FORMAT_NAME+FILE_PATTERNS parsers)
    parse_fn, format_name = get_parser(filename)
    if parse_fn is not None:
        return parse_fn(path)

    # Fallback: explicit routing for special cases
    name = filename.lower()
    if "app_debug" in name or "debug_log" in name:
        return parse_app_debug_log(path)
    elif "agentless" in name:
        return parse_agentless_log(path)
    elif "fdm" in name:
        return parse_fdm_output(path)
    elif "raid" in name or "lsi" in name:
        return parse_raid_log(path)
    elif "ipmi" in name or "sel" in name:
        return parse_ipmi_log(path)
    elif "linux_kernel" in name or "kernel_log" in name:
        return parse_syslog(path)
    elif "imu" in name or "cpu" in name or "m7" in name:
        return parse_m7_log(path)
    elif "maintenance" in name or "operate_log" in name:
        return parse_maintenance_log(path)
    elif "nginx" in name or "access_log" in name:
        return parse_nginx_access_log(path)
    else:
        # Final fallback: try app_debug
        return parse_app_debug_log(path)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
