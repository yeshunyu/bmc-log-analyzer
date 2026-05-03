"""Parsers registry.

Each parser module must expose:
  FORMAT_NAME   — human-readable name (str)
  FILE_PATTERNS — list of substrings to match against filename (list[str])
  parse(path)   — (Path) -> (format_name, list[LogEntry], parse_errors)

Auto-discovery in main.py: for each parser module, check if any pattern
matches the upload filename (case-insensitive). First match wins.
"""

from importlib import import_module
from pathlib import Path

from app.schemas import LogEntry

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------
MAX_FILE_READ_SIZE = 1 * 1024 * 1024  # 1 MB — max bytes read per file for scoring


def read_file_sample(path: Path, max_bytes: int = MAX_FILE_READ_SIZE) -> str:
    """Read at most max_bytes from a file, returning as UTF-8 text.

    For large files this avoids OOM while still capturing enough content
    for keyword-based scoring and format detection.
    """
    try:
        with path.open("rb") as f:
            data = f.read(max_bytes)
        return data.decode("utf-8", errors="replace")
    except OSError:
        return ""


def read_file_sample_lines(path: Path, max_bytes: int = MAX_FILE_READ_SIZE) -> list[str]:
    """Read file sample, split into lines, preserving line structure.

    Only reads max_bytes from the start of the file.  This is intentional:
    we sample from the head because log files are append-only and the most
    recent entries are at the end.  A scanner can call this multiple times
    (head + tail) if needed.
    """
    text = read_file_sample(path, max_bytes)
    return text.splitlines()

# ---------------------------------------------------------------------------
# Discover all parser modules
# ---------------------------------------------------------------------------
_PARSER_MODULES = [
    "app_debug",
    "syslog",
    "ipmi",
    "sel",
    "agentless",
    "raid",
    "fdm",
    "maintenance",
    "m7_imu",
    "nginx_access",
]

_parsers: list[dict] = []


def _load():
    import logging
    logger = logging.getLogger(__name__)
    global _parsers
    _parsers = []
    for mod_name in _PARSER_MODULES:
        try:
            mod = import_module(f"app.parsers.{mod_name}")
        except ImportError as exc:
            logger.warning("Parser module '%s' skipped (import failed): %s", mod_name, exc)
            continue
        fmt = getattr(mod, "FORMAT_NAME", mod_name)
        patterns: list[str] = getattr(mod, "FILE_PATTERNS", [])
        parse_fn = getattr(mod, "parse", None)
        if parse_fn is None:
            logger.debug("Parser module '%s' has no 'parse' fn — skipped", mod_name)
            continue
        _parsers.append({
            "name": fmt,
            "patterns": patterns,
            "parse": parse_fn,
        })


_load()


def get_parser(filename: str):
    """Return (parse_fn, format_name) for the first matching pattern, or None."""
    name_lower = filename.lower()
    for p in _parsers:
        for pat in p["patterns"]:
            if pat.lower() in name_lower:
                return p["parse"], p["name"]
    return None, None
