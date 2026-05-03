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

# Remote log (sensor_alarm):
# 2022-12-24T06:22:52+00:00 2102313NNLP0NC100035 sensor_alarm:    19,2022-12-24 06:23:20,Normal,0x2C00000B,Asserted,ACPI is in the soft-off state.
REMOTE_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2})\s+\S+\s+(\w+):\s+\d+,([^,]*),([^,]*),(.*)$"
)

IPMI_FORMAT = "ipmi"
IPMI_PATTERNS = ["ipmi"]

FORMAT_NAME = IPMI_FORMAT
FILE_PATTERNS = IPMI_PATTERNS


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


# Alias for registry (same as parse above)
parse_ipmi_log = parse


def parse_remote(path: Path):
    entries = []
    parse_errors = 0
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            m = REMOTE_RE.match(line)
            if m:
                ts_str, module, inner_ts, severity, message = m.groups()
                try:
                    ts = datetime.strptime(ts_str, "%Y-%m-%dT%H:%M:%S%z")
                    ts = ts.replace(tzinfo=None)
                except ValueError:
                    ts = None
                entries.append(LogEntry(
                    timestamp=ts,
                    module=f"remote:{module}",
                    level="ERROR" if "assert" in severity.lower() or "error" in severity.lower() else "INFO",
                    message=message.strip(),
                    raw=line,
                ))
            else:
                parse_errors += 1
    return "remote", entries, parse_errors
