import re
from datetime import datetime
from pathlib import Path
from app.schemas import LogEntry

# Format: 2022-12-24T06:23:27+00:00 2102313NNLP0NC100035 kernel: [  731.296955] edma: 1732, host is lost.
AGENTLESS_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2})\s+\S+\s+\w+:\s+\[\s*([\d.]+)\]\s+(.+)$"
)

# Keywords for severity inference (case-insensitive)
_ERROR_KW = (
    r"error|fail|critical|fatal|panic|oom|out of memory"
    r"|lost|absent|missing|degraded|故障|丢失|异常"
)
_WARN_KW = r"warn|warning|alert|注意|警告"
_INFO_KW = r"info|start|init|enable|disable|success"


def _infer_level(message: str) -> str:
    m = message.lower()
    if re.search(_ERROR_KW, m):
        return "ERROR"
    if re.search(_WARN_KW, m):
        return "WARNING"
    if re.search(_INFO_KW, m):
        return "INFO"
    return "INFO"


FORMAT_NAME = "agentless"
FILE_PATTERNS = ["agentless"]


def parse(path: Path):
    entries = []
    parse_errors = 0
    from app.parsers import read_file_sample_lines
    for line in read_file_sample_lines(path):
        line = line.rstrip("\n")
        m = AGENTLESS_RE.match(line)
        if m:
            ts_str, uptime, message = m.groups()
            try:
                ts = datetime.strptime(ts_str, "%Y-%m-%dT%H:%M:%S%z")
                ts = ts.replace(tzinfo=None)
            except ValueError:
                ts = None
            level = _infer_level(message)
            entries.append(LogEntry(
                timestamp=ts,
                module="agentless",
                level=level,
                message=message.strip(),
                raw=line,
            ))
        else:
            parse_errors += 1
    return FORMAT_NAME, entries, parse_errors


parse_agentless_log = parse
