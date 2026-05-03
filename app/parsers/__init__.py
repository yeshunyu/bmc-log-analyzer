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
    global _parsers
    _parsers = []
    for mod_name in _PARSER_MODULES:
        try:
            mod = import_module(f"app.parsers.{mod_name}")
        except ImportError:
            continue
        fmt = getattr(mod, "FORMAT_NAME", mod_name)
        patterns: list[str] = getattr(mod, "FILE_PATTERNS", [])
        parse_fn = getattr(mod, "parse", None)
        if parse_fn is None:
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
