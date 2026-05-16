import re
from dataclasses import dataclass
from os_log_analyzer.app.parsers.base import LogLine

@dataclass
class FaultMatch:
    category: str
    severity: str
    first_seen: str
    last_seen: str
    count: int
    sample_lines: list[str]

# Pre-compiled at module load (avoid re-compiling on every detect_faults call)
_PATTERNS = [
    {
        "category": "panic",
        "severity": "critical",
        "patterns": [
            re.compile(r"kernel panic", re.IGNORECASE),
            re.compile(r"NULL pointer", re.IGNORECASE),
            re.compile(r"BUG\("),
            re.compile(r"Kernel panic"),
            re.compile(r"Oops:"),
            re.compile(r"Bug:"),
        ]
    },
    {
        "category": "oom",
        "severity": "critical",
        "patterns": [
            re.compile(r"Out of memory", re.IGNORECASE),
            re.compile(r"oom-kill", re.IGNORECASE),
            re.compile(r"oom_adj"),
            re.compile(r"Memory cgroup"),
        ]
    },
    {
        "category": "io_error",
        "severity": "warning",
        "patterns": [
            re.compile(r"I/O error"),
            re.compile(r"EXT4-fs error"),
            re.compile(r"SCSI error"),
            re.compile(r"NOSPC"),
            re.compile(r"Buffer I/O error"),
        ]
    },
    {
        "category": "shutdown",
        "severity": "warning",
        "patterns": [
            re.compile(r"shutdown", re.IGNORECASE),
            re.compile(r"power off", re.IGNORECASE),
            re.compile(r"reboot: System halted"),
        ]
    },
    {
        "category": "resource",
        "severity": "warning",
        "patterns": [
            re.compile(r"No space"),
            re.compile(r"disk full", re.IGNORECASE),
            re.compile(r"inode exhaustion", re.IGNORECASE),
            re.compile(r"Socket backlog"),
            re.compile(r"failed to accept"),
        ]
    },
]

def detect_faults(lines: list[LogLine]) -> list[FaultMatch]:
    matches_by_cat: dict[str, FaultMatch] = {}

    for line in lines:
        for rule in _PATTERNS:
            for pat in rule["patterns"]:
                if pat.search(line.raw):
                    cat = rule["category"]
                    if cat not in matches_by_cat:
                        matches_by_cat[cat] = FaultMatch(
                            category=cat,
                            severity=rule["severity"],
                            first_seen=line.timestamp or line.raw[:40],
                            last_seen=line.timestamp or line.raw[:40],
                            count=1,
                            sample_lines=[line.raw[:200]]
                        )
                    else:
                        m = matches_by_cat[cat]
                        m.count += 1
                        m.last_seen = line.timestamp or line.raw[:40]
                        if len(m.sample_lines) < 5:
                            m.sample_lines.append(line.raw[:200])
                    break

    # Upgrade io_error to critical if count >= 3
    for m in matches_by_cat.values():
        if m.category == "io_error" and m.count >= 3:
            m.severity = "critical"

    return list(matches_by_cat.values())
