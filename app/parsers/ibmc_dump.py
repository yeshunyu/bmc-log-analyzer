"""Huawei iBMC Dump archive parser.

Handles .tar / .tar.gz / .zip dump archives produced by iBMC 一键收集.
Instead of parsing the archive itself (which is handled by _decompress_if_needed
in main.py), this parser provides FILE_PATTERNS so that a standalone dump file
(e.g. BMC_dump.gz, core_dump.gz) can be routed to a sensible parser, and
provides _scan_dump_dir() for multi-file dump analysis.
"""

from pathlib import Path
import re

from app.schemas import LogEntry
from app.parsers import read_file_sample_lines
from app.data.log_priority import LOG_PRIORITY_PATTERNS

FORMAT_NAME = "ibmc_dump"
FILE_PATTERNS = [
    "ibmc_dump",
    "BMC_dump",
    "core_dump",
    "dump_info",
    "dump_",
    "ibmc_",
]


def parse(path: Path):
    """Parse a dump archive or dump directory.

    For compressed archives (.gz, .tar.gz) the caller should decompress first.
    For directories, scans the dump_info subdirectory for all log files.

    Returns (format_name, list[LogEntry], parse_errors).
    """
    errors = []

    # If it's a directory, scan recursively
    if path.is_dir():
        entries, scan_errors = _scan_dump_dir(path)
        return FORMAT_NAME, entries, scan_errors

    # Single file — try to detect content type from filename
    entries, file_errors = _parse_single_dump_file(path)
    return FORMAT_NAME, entries, file_errors


def _scan_dump_dir(dump_dir: Path):
    """Scan a dump directory for all log files, parse each, return combined entries.

    High-value files are scanned first; large files are sampled rather than
    fully read to avoid OOM.
    """
    all_entries = []
    errors = []

    dump_info = dump_dir / "dump_info"
    if not dump_info.exists():
        dump_info = dump_dir

    # Priority patterns — ordered by diagnostic value (shared with main.py / log_scanner.py)
    # Collect all matching files
    seen_files = []
    for pat in LOG_PRIORITY_PATTERNS:
        for p in dump_info.rglob(f"{pat}*"):
            if p.is_file() and p not in seen_files:
                seen_files.append(p)

    # Also add any remaining log/txt files not yet included
    for p in dump_info.rglob("*"):
        if p.is_file() and p.suffix in {".log", ".txt", ".dfl"} and p not in seen_files:
            seen_files.append(p)

    # Parse each file (lazy import to avoid circular)
    from app.parsers import get_parser

    for p in seen_files[:20]:  # Cap at 20 files to avoid OOM
        try:
            # Try to use a specific parser first
            parser_fn, fmt = get_parser(p.name)
            if parser_fn:
                _, entries, parse_errors = parser_fn(p)
                all_entries.extend(entries)
                errors.extend(parse_errors)
            else:
                # Fall back to raw text parsing
                raw_entries, raw_errors = _parse_raw_log(p)
                all_entries.extend(raw_entries)
                errors.extend(raw_errors)
        except Exception as e:
            errors.append(f"Error scanning {p.name}: {e}")

    # Sort by timestamp if available
    all_entries.sort(key=lambda e: e.timestamp if e.timestamp else e.raw)

    return all_entries, errors


def _parse_single_dump_file(path: Path):
    """Parse a single dump file (often gzipped or tar archive)."""
    errors = []

    # Check if it's gzipped
    if path.suffix == ".gz":
        import gzip
        try:
            with gzip.open(path, "rt", errors="replace") as f:
                lines = f.readlines()[:5000]  # Sample first 5000 lines
        except Exception as e:
            return [], [f"Failed to decompress {path.name}: {e}"]
    else:
        lines = read_file_sample_lines(path, max_bytes=5 * 1024 * 1024)[:5000]

    entries = []
    timestamp_re = re.compile(
        r"(\d{4}[-/]\d{2}[-/]\d{2}[T\s]\d{2}:\d{2}:\d{2})"
    )

    for i, line in enumerate(lines):
        line = line.rstrip()
        if not line:
            continue

        ts_match = timestamp_re.search(line)
        entry = LogEntry(
            raw=line,
            message=line,
            timestamp=ts_match.group(1) if ts_match else None,
            source_file=str(path),
            line_number=i + 1,
            module=_guess_module_from_path(path),
        )
        entries.append(entry)

    return entries, errors


def _parse_raw_log(path: Path):
    """Parse a raw text log file that has no known parser."""
    errors = []
    lines = read_file_sample_lines(path, max_bytes=5 * 1024 * 1024)[:10000]
    entries = []
    timestamp_re = re.compile(
        r"(\d{4}[-/]\d{2}[-/]\d{2}[T\s]\d{2}:\d{2}:\d{2})"
    )

    for i, line in enumerate(lines):
        line = line.rstrip()
        if not line:
            continue
        ts_match = timestamp_re.search(line)
        entry = LogEntry(
            raw=line,
            message=line,
            timestamp=ts_match.group(1) if ts_match else None,
            source_file=str(path),
            line_number=i + 1,
            module=_guess_module_from_path(path),
        )
        entries.append(entry)

    return entries, errors


def _guess_module_from_path(path: Path) -> str:
    """Guess module name from file path or name."""
    name = path.name.lower()
    if "app_debug" in name:
        return "app_debug"
    if "ipmi" in name:
        return "ipmi"
    if "sensor" in name or "alarm" in name:
        return "sensor"
    if "fan" in name:
        return "cooling"
    if "power" in name:
        return "power"
    if "bios" in name:
        return "bios"
    if "raid" in name or "lsi" in name:
        return "raid"
    if "maintenance" in name or "operate" in name:
        return "maintenance"
    if "security" in name:
        return "security"
    if "kernel" in name or "linux" in name or "dmesg" in name:
        return "linux"
    if "dfl" in name:
        return "dflt"
    return "dump"
