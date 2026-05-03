import re
from datetime import datetime
from pathlib import Path
from app.schemas import LogEntry

# Generic timestamped key=value or message log
# Format: 2024-12-07 03:02:21 INFO : SVR-0000000,[OOB] Physical drive Disk4 patrol read - In-Progress
GENERIC_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(INFO|WARN|WARNING|ERROR|DEBUG|CRITICAL):?\s*(?:SVR-\d+,)?\s*(?:\[([^\]]+)\])?\s*(.*)$"
)


FORMAT_NAME = "maintenance"
FILE_PATTERNS = ["maintenance", "operate_log", "security_log", "strategy_log"]


def parse(path: Path):
    entries = []
    parse_errors = 0
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            m = GENERIC_RE.match(line)
            if m:
                ts_str, level, module, message = m.groups()
                try:
                    ts = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
                except ValueError:
                    ts = None
                entries.append(LogEntry(
                    timestamp=ts,
                    module=module or "maintenance",
                    level=level.replace("WARNING", "WARNING").replace("CRITICAL", "ERROR"),
                    message=message.strip(),
                    raw=line,
                ))
            else:
                parse_errors += 1
    return FORMAT_NAME, entries, parse_errors


parse_maintenance_log = parse
