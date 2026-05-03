import re
from datetime import datetime
from pathlib import Path
from app.schemas import LogEntry

# Format: 2025-06-23 11:03:20.644848 kvm_vmm ERROR: comm.c(329): Pre-read ssl failed.
# Also: 2025-06-24 10:19:33.950528 kvm_vmm : ERROR: comm.c(329): Pre-read ssl failed.  (repeated 42 times)
APP_DEBUG_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)\s+(\S+)\s*(?:\s+:\s*)?(ERROR|WARN|WARNING|INFO|DEBUG):\s*(.+)$"
)

FORMAT_NAME = "app_debug"
FILE_PATTERNS = ["app_debug", "debug_log"]


def parse(path: Path):
    entries = []
    parse_errors = 0
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            m = APP_DEBUG_RE.match(line)
            if m:
                ts_str, module, level, rest = m.groups()
                repeat_count = 1
                # Parse (repeated N times)
                rep_m = re.search(r"\(repeated (\d+) times?\)", rest)
                if rep_m:
                    repeat_count = int(rep_m.group(1))
                    rest = re.sub(r"\s*\(repeated \d+ times?\)\s*$", "", rest)
                # Parse source file and line number: comm.c(329)
                src_m = re.match(r"(\S+\.c)\((\d+)\):\s*(.*)", rest)
                if src_m:
                    src_file, line_num, message = src_m.groups()
                else:
                    src_file, line_num, message = None, None, rest.strip()

                try:
                    ts = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S.%f")
                except ValueError:
                    ts = None

                entries.append(LogEntry(
                    timestamp=ts,
                    module=module,
                    level=level,
                    source_file=src_file,
                    line_number=int(line_num) if line_num else None,
                    message=message.strip(),
                    raw=line,
                    repeat_count=repeat_count,
                ))
            else:
                parse_errors += 1

    return FORMAT_NAME, entries, parse_errors


# Backward-compat aliases (used by main.py fallback routing)
parse_app_debug_log = parse
