"""Huawei iBMC ALM alarm code parser.

This module acts as a thin parser wrapper around the alarm code data in
app.data.huawei_alm_data. It is registered with the parser registry so that
other parsers (app_debug, syslog) can call enrich_entry_with_alm to post-process
their entries.

Alarm code format: ALM-0xNNXXXXXX
  NN     = subsystem byte (01=Memory, 02=Voltage, 04=Fan, ...)
  XXXXXX = alarm ID within that subsystem

Re-exports from app.data.huawei_alm_data:
  SUBSYSTEM, SEVERITY_NN, ALARM_DB,
  AlarmCodeInfo, decode_alm, extract_alm_codes, is_alm_code
"""

# Re-export data layer
from app.data.huawei_alm_data import (
    SUBSYSTEM,
    SEVERITY_NN,
    ALARM_DB,
    ALM_RE,
    AlarmCodeInfo,
    decode_alm,
    extract_alm_codes,
    is_alm_code,
)

from app.schemas import LogEntry

FORMAT_NAME = "huawei_alm"
FILE_PATTERNS: list[str] = []  # not file-based; called by other parsers


# --------------------------------------------------------------------------+
# Parser helper — used by app_debug / syslog parsers to post-process entries  |
# --------------------------------------------------------------------------+

def enrich_entry_with_alm(entry: LogEntry) -> LogEntry:
    """Check if entry.message contains an ALM code; if so, annotate it.

    Returns the same entry object (mutated) with extra fields added:
      - alm_code: str or None
      - alm_subsystem: str or None
      - alm_severity: str or None (CRITICAL/MAJOR/MINOR/INFO)
      - alm_severity_zh: str or None
      - alm_description: str or None
    """
    codes = extract_alm_codes(entry.message)
    if not codes:
        return entry
    # Use the first (most significant) alarm code
    info = codes[0]
    entry.alm_code = info.code          # type: ignore[attr-defined]
    entry.alm_subsystem = info.subsystem  # type: ignore[attr-defined]
    entry.alm_severity = info.severity  # type: ignore[attr-defined]
    entry.alm_severity_zh = info.severity_zh  # type: ignore[attr-defined]
    entry.alm_description = info.description  # type: ignore[attr-defined]
    # Override level based on alarm severity
    entry.level = info.to_level()
    return entry
