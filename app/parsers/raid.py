import re
from datetime import datetime
from pathlib import Path
from typing import Optional
from app.schemas import LogEntry

FORMAT_NAME = "raid"
FILE_PATTERNS = ["raid", "lsi"]

# Multi-block LSI RAID log format:
# Controller ID : 0
# Virtual Drive : 0 (Target Id: 0)
# ...event fields...
# Description of the event : <text>

FIELD_PATTERNS = {
    "controller":   re.compile(r"^Controller ID\s+:\s*(\S+)", re.IGNORECASE),
    "vd":           re.compile(r"^Virtual Drive\s+:\s*(\S+)", re.IGNORECASE),
    "pd":           re.compile(r'^\"Physical Drive\s+:\s*(\S+)', re.IGNORECASE),
    "timestamp":    re.compile(r"^Message Timestamp\s+:\s*(.+)", re.IGNORECASE),
    "event_code":   re.compile(r"^Event code\s+:\s*(\S+)", re.IGNORECASE),
    "class":        re.compile(r"^Class\s+:\s*(\S+)", re.IGNORECASE),
    "description":  re.compile(r"^Description of the event\s+:\s*(.+)", re.IGNORECASE),
}

CLASS_SEVERITY = {
    "critical":  "ERROR",
    "error":     "ERROR",
    "warning":   "WARNING",
    "informational": "INFO",
}

MAX_RAID_READ = 10 * 1024 * 1024  # 10 MB — RAID logs are text, 10MB covers most cases


def _read_bounded(path: Path, max_bytes: int = MAX_RAID_READ) -> str:
    try:
        with path.open("rb") as f:
            data = f.read(max_bytes)
        return data.decode("utf-8", errors="replace")
    except OSError:
        return ""


def _parse_ts(ts_str: str) -> Optional[datetime]:
    m = re.search(r"(\d{1,2})/(\d{1,2})/(\d{4})\s*;\s*(\d{1,2}):(\d{2}):(\d{2})", ts_str)
    if m:
        month, day, year, hour, minute, second = m.groups()
        try:
            return datetime(int(year), int(month), int(day), int(hour), int(minute), int(second))
        except ValueError:
            pass
    return None


def _class_to_level(event_class: str) -> str:
    return CLASS_SEVERITY.get(event_class.lower(), "INFO")


def parse(path: Path):
    """Parse LSI MegaRAID multi-block event logs."""
    entries = []
    parse_errors = 0
    content = _read_bounded(path)

    raw_blocks = re.split(r"\n(?=Controller ID\s+:)", content)

    for raw_block in raw_blocks:
        if not raw_block.strip():
            continue

        block: dict[str, str] = {}
        for line in raw_block.splitlines():
            line = line.strip()
            for key, pattern in FIELD_PATTERNS.items():
                m = pattern.match(line)
                if m:
                    block[key] = m.group(1).strip()

        # Multi-line description continuation
        lines = raw_block.splitlines()
        for i, line in enumerate(lines):
            if "Description of the event" in line and ":" in line:
                parts = line.split(":", 1)
                if len(parts) == 2:
                    block.setdefault("description", parts[1].strip())
                for j in range(i + 1, len(lines)):
                    nxt = lines[j].strip()
                    if not nxt:
                        break
                    if re.match(r"^(Controller ID|Virtual Drive|Physical Drive|Message Timestamp|Event code|Class|Description)\s+:", nxt, re.IGNORECASE):
                        break
                    block["description"] = (block.get("description") or "") + " " + nxt
                break

        if not block.get("description"):
            parse_errors += 1
            continue

        ts = _parse_ts(block.get("timestamp", "")) if block.get("timestamp") else None
        event_class = block.get("class", "")
        level = _class_to_level(event_class)

        entries.append(LogEntry(
            timestamp=ts,
            module=f"RAID:{block.get('controller', '?')}",
            level=level,
            source_file=f"event_{block.get('event_code', '?')}",
            message=block["description"].strip(),
            raw=raw_block[:300],
        ))

    return FORMAT_NAME, entries, parse_errors


# Aliases for backward compatibility
parse_raid_log = parse
