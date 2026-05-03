import re
from datetime import datetime
from pathlib import Path
from app.schemas import LogEntry

# Nginx combined log format:
# 192.168.1.1 - - [10/Oct/2023:13:55:36 +0000] "GET /api HTTP/1.1" 200 1234 "http://referrer.com" "Mozilla/5.0"
NGINX_ACCESS_RE = re.compile(
    r"^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+\"([^\"]*)\"\s+(\d+)\s+(\d+|-)\s+\"([^\"]*)\"\s+\"([^\"]*)"
)

# Nginx error log:
# 2023/10/10 13:55:36 [error] 1234#0: *1 connect() failed (111: Connection refused) while connecting to upstream
NGINX_ERROR_RE = re.compile(
    r"^(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+\[(\w+)\]\s+(\d+)#\d+.*?:\s+(.+)$"
)

FORMAT_NAME = "nginx_access"
FILE_PATTERNS = ["nginx", "access_log"]


def parse_nginx_access_log(path: Path):
    entries = []
    parse_errors = 0
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            m = NGINX_ACCESS_RE.match(line)
            if m:
                ip, ts_str, request, status, size, referrer, ua = m.groups()
                try:
                    ts = datetime.strptime(ts_str, "%d/%b/%Y:%H:%M:%S %z")
                    ts = ts.replace(tzinfo=None)
                except ValueError:
                    ts = None
                level = "ERROR" if status.startswith(("4", "5")) else "INFO"
                # Extract URL path from "GET /path HTTP/1.1" — split safely
                parts = request.split(" ", 2)
                method = parts[0] if len(parts) > 0 else "?"
                path_part = parts[1] if len(parts) > 1 else "?"
                source_file = path_part
                entries.append(LogEntry(
                    timestamp=ts,
                    module=f"nginx:{ip}",
                    level=level,
                    source_file=source_file,
                    message=f"{method} {path_part} -> {status}",
                    raw=line,
                ))
            else:
                parse_errors += 1
    return FORMAT_NAME, entries, parse_errors


def parse_nginx_error_log(path: Path):
    entries = []
    parse_errors = 0
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            m = NGINX_ERROR_RE.match(line)
            if m:
                ts_str, level, pid, message = m.groups()
                try:
                    ts = datetime.strptime(ts_str, "%Y/%m/%d %H:%M:%S")
                except ValueError:
                    ts = None
                entries.append(LogEntry(
                    timestamp=ts,
                    module=f"nginx:{pid}",
                    level=level.upper(),
                    message=message.strip(),
                    raw=line,
                ))
            else:
                parse_errors += 1
    return "nginx_error", entries, parse_errors


def parse(path: Path):
    # Auto-detect: peek first 200 bytes to decide format
    try:
        header = path.open("rb").read(200).decode("utf-8", errors="replace")
    except OSError:
        return parse_nginx_access_log(path)

    if NGINX_ERROR_RE.match(header.splitlines()[0] if header else ""):
        return parse_nginx_error_log(path)
    return parse_nginx_access_log(path)


# Backward-compat alias
parse_nginx_access_log_internal = parse_nginx_access_log
