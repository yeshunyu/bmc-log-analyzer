import re
from datetime import datetime
from pathlib import Path
from app.schemas import LogEntry

# Generic syslog: 2024-03-05T23:42:24+00:00 2102313NNLP0NC100035 kernel: [16396065.873833] message
SYSLOG_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2})\s+\S+\s+\w+:\s+\[[\d.]+\]\s+(.+)$"
)

SYSLOG_FORMAT = "syslog"
SYSLOG_PATTERNS = ["linux_kernel", "kernel_log"]

FORMAT_NAME = SYSLOG_FORMAT
FILE_PATTERNS = SYSLOG_PATTERNS


def parse(path: Path):
    entries = []
    parse_errors = 0
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            m = SYSLOG_RE.match(line)
            if m:
                ts_str, message = m.groups()
                try:
                    ts = datetime.strptime(ts_str, "%Y-%m-%dT%H:%M:%S%z")
                    ts = ts.replace(tzinfo=None)
                except ValueError:
                    ts = None
                # Infer level from message content
                msg_upper = message.upper()
                if "ERROR" in msg_upper or "FAIL" in msg_upper:
                    level = "ERROR"
                elif "WARN" in msg_upper:
                    level = "WARNING"
                else:
                    level = "INFO"
                entries.append(LogEntry(
                    timestamp=ts,
                    module="kernel",
                    level=level,
                    message=message.strip(),
                    raw=line,
                ))
            else:
                parse_errors += 1
    return FORMAT_NAME, entries, parse_errors


# Backward-compat aliases
parse_syslog = parse
