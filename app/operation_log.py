"""
Operation logger: appends structured JSON logs to a daily file.
Keeps 7 days of history, auto-purges on startup.
"""
import json
import time
from pathlib import Path
from datetime import datetime, timedelta

LOG_DIR = Path(__file__).parent.parent / "logs"
LOG_DIR.mkdir(exist_ok=True)
LOG_TTL_DAYS = 7


def _log_file() -> Path:
    return LOG_DIR / f"operation_{datetime.now().strftime('%Y%m%d')}.jsonl"


def _purge_old():
    """Delete log files older than LOG_TTL_DAYS on startup."""
    cutoff = time.time() - LOG_TTL_DAYS * 86400
    for p in LOG_DIR.glob("operation_*.jsonl"):
        try:
            if p.stat().st_mtime < cutoff:
                p.unlink()
        except Exception:
            pass


# Purge on import
_purge_old()


def log_operation(
    operation: str,
    detail: str = "",
    file_name: str = "",
    result: str = "ok",
    error: str = "",
    extra: dict = None,
):
    """
    Append a structured operation record.

    - operation: upload | reanalyze | delete_history | llm_analysis | llm_analysis_single | clear_history
    - detail: human-readable summary
    - file_name: original uploaded filename (if applicable)
    - result: ok | error
    - error: error message if result=error
    - extra: extra key-value pairs
    """
    record = {
        "timestamp": datetime.now().isoformat(),
        "operation": operation,
        "detail": detail,
        "file_name": file_name,
        "result": result,
        "error": error,
    }
    if extra:
        record["extra"] = extra

    try:
        with open(_log_file(), "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    except Exception:
        pass  # Never let logging crash the app


def read_logs(days: int = 7) -> list[dict]:
    """Read operation logs for the last N days, newest first."""
    cutoff = datetime.now() - timedelta(days=days)
    records = []
    for p in sorted(LOG_DIR.glob("operation_*.jsonl"), reverse=True):
        date_str = p.stem.replace("operation_", "")
        try:
            file_date = datetime.strptime(date_str, "%Y%m%d")
        except ValueError:
            continue
        if file_date < cutoff:
            continue
        try:
            with open(p, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        except Exception:
            continue
    return records
