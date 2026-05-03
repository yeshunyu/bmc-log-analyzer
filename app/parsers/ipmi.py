import re
from datetime import datetime
from pathlib import Path
from app.schemas import LogEntry

# IPMI operate log:
# 2022-12-24 06:19:59 IPMI,N/A@HOST,Dft,Enable DFT command successfully
# 2022-12-24 06:22:52 IPMI,N/A@HOST,sensor_alarm,Set SysHealLed to (overstate on) color (GREEN) successfully
IPMI_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+IPMI,[^,]*,(\w+),(.*)$"
)

FORMAT_NAME = "ipmi"
FILE_PATTERNS = ["ipmi"]


def parse(path: Path):
    entries = []
    parse_errors = 0
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            m = IPMI_RE.match(line)
            if m:
                ts_str, module, message = m.groups()
                try:
                    ts = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
                except ValueError:
                    ts = None
                level = "ERROR" if "fail" in message.lower() else "INFO"
                entries.append(LogEntry(
                    timestamp=ts,
                    module=f"ipmi:{module}",
                    level=level,
                    message=message.strip(),
                    raw=line,
                ))
            else:
                parse_errors += 1
    return FORMAT_NAME, entries, parse_errors


# Backward-compat alias
parse_ipmi_log = parse
