import re
from datetime import datetime
from pathlib import Path
from app.schemas import LogEntry

# Format: 2022-12-24 06:23:14 UTC: BMC detected system power off.
FDM_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC):\s+(.+)$"
)

FORMAT_NAME = "fdm"
FILE_PATTERNS = ["fdm"]


def parse(path: Path):
    entries = []
    parse_errors = 0
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            m = FDM_RE.match(line)
            if m:
                ts_str, message = m.groups()
                try:
                    ts = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S UTC")
                except ValueError:
                    ts = None
                # Determine level
                msg_upper = message.upper()
                if "ERROR" in msg_upper or "FAIL" in msg_upper:
                    level = "ERROR"
                elif "WARN" in msg_upper:
                    level = "WARNING"
                else:
                    level = "INFO"
                entries.append(LogEntry(
                    timestamp=ts,
                    module="FDM",
                    level=level,
                    message=message.strip(),
                    raw=line,
                ))
            else:
                parse_errors += 1
    return FORMAT_NAME, entries, parse_errors


parse_fdm_output = parse
