import re
from datetime import datetime
from pathlib import Path
from app.schemas import LogEntry

# M7/IMU log format:
# [    187.425][CHIP 0][      0]IMP report mac 0 link status 1, event 0
# [      0.000][CHIP 0][      0]imu_cmd_queue_init:ddr_base = 0x44080000,g_sq_base = 0x44081000
M7_RE = re.compile(
    r"^\[\s*([\d.]+)\]\[([^\]]+)\]\[([^\]]*)\]\s*(.+)$"
)


FORMAT_NAME = "m7_imu"
FILE_PATTERNS = ["imu", "cpu", "m7"]


def parse(path: Path):
    entries = []
    parse_errors = 0
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            m = M7_RE.match(line)
            if m:
                uptime_str, chip, thread, message = m.groups()
                # Determine severity
                msg_upper = message.upper()
                if any(kw in msg_upper for kw in ["ERR", "FAIL", "WARN"]):
                    level = "ERROR" if "ERR" in msg_upper or "FAIL" in msg_upper else "WARNING"
                else:
                    level = "INFO"
                entries.append(LogEntry(
                    timestamp=None,  # Relative uptime, not absolute
                    module=f"m7:{chip}",
                    level=level,
                    message=message.strip(),
                    raw=line,
                ))
            else:
                parse_errors += 1
    return FORMAT_NAME, entries, parse_errors


parse_m7_log = parse
