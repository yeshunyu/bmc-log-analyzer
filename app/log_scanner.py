"""Log file discovery and scoring for iBMC dump directories.

Finds the most valuable log files within an extracted dump archive,
using priority patterns and keyword scoring.
"""

from pathlib import Path
from typing import Optional
import re
from app.data.log_priority import LOG_PRIORITY_PATTERNS


# Keywords that indicate high-value diagnostic content (ordered by importance)
# Used to score and prioritize log files during multi-file scanning
_KEYWORD_PATTERN = re.compile(
    r"(?i)(error|fail|fault|critical|major|minor|warning|asserted|deasserted|"
    r"power|fan|thermal|memory|disk|cpu|bios|reboot|restart|poweroff|shutdown|"
    r"power cycle|hang|hung|unresponsive|lockup|reset|oom|out of memory|panic|"
    r"oops|bug|watchdog|mce|machine.check|correctable|uncorrectable|power loss|"
    r"ac loss|segfault|core.dump)",
    re.IGNORECASE,
)

# Skip scanning these file extensions when scoring
_SKIP_SCAN_EXTS = {
    ".gz", ".bin", ".db", ".json", ".csv", ".txt", ".bak",
    ".sha256", ".ini", ".conf",
}

# Max top log files to parse in multi-file mode
_MAX_LOG_FILES = 5


def _has_rotated_suffix(name: str, pat: str) -> bool:
    """Check if name has a rotation suffix like .1, .2, .3 or .1.gz, .2.gz."""
    base = name[len(pat):]  # everything after the pattern
    return bool(re.match(r'^\.(\d+)(\.gz)?$', base))


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


def find_best_log_file(extract_dir: Path) -> Optional[Path]:
    """Find the single best log file from an extracted dump directory.

    Searches dump_info subdirectories (AppDump/BMC, LogDump, etc.) for
    the most relevant log file, preferring non-rotated, non-gzipped originals.
    """
    for pat in LOG_PRIORITY_PATTERNS:
        result = _find_best_matching(pat, extract_dir)
        if result is not None:
            return result
    return None


def _find_best_matching(pat: str, extract_dir: Path):
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


def find_top_log_files(extract_dir: Path, top_n: int = _MAX_LOG_FILES) -> list[Path]:
    """Find top-N log files, preferring known log types scored by keyword matches.

    Two-tier selection:
    1. Priority files matching known log patterns — sorted by keyword match count.
    2. If fewer than top_n found, fill with other scored files.
    """
    dump_info = extract_dir / "dump_info"
    if not dump_info.exists():
        return []

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
        is_priority = any(pat in name_lower for pat in LOG_PRIORITY_PATTERNS)
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
