"""SEL (System Event Log) binary parser.

Handles:
  - sensor_alarm_sel.bin  — raw IPMI SEL binary records
  - sel.tar               — tar archive; members are parsed as SEL text format
  - sel.db                — SQLite SEL database (Huawei iBMC format)

IPMI SEL record format (16-byte header + variable data):
  - Bytes 0-1: Record ID (LE)
  - Byte  2:   Record Type (0x00-0xFF, 0x02=System Event, 0xC0+=OEM)
  - Bytes 3-9: Timestamp (LE seconds since epoch) / 0xFFFFFFFF if not set
  - Bytes 10-15: Manufacturer ID (LE, 3 bytes, patched to 4-byte LE)
  - Byte  16+:  Event data (up to 13 bytes)

Decoding steps:
  1. Read record ID (2 bytes LE) → offset += 2
  2. Read record type (1 byte)   → offset += 1
  3. Read timestamp (4 bytes LE) → offset += 4
  4. Read manufacturer ID (3 bytes LE, swap to 4-byte LE) → offset += 3
  5. Read event direction (1 byte: 0x20=Assert, 0x00=Deassert) → offset += 1
  6. Read event data (remaining bytes in record, up to 13)
  7. Record length found in SEL header at byte 1 of first record (usually 0x10)

SEL types we handle:
  0x02  System Event
  0xC0–0xCF  OEM Huawei events (drive, fan, power, etc.)
"""

import struct
import tarfile
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO, Optional

from app.schemas import LogEntry

FORMAT_NAME = "sel"
FILE_PATTERNS = ["sel", "sensor_alarm_sel"]


def _read_in_chunks(f: BinaryIO, max_size: int) -> bytes:
    """Read file in chunks up to max_size bytes to prevent unbounded memory use."""
    data = b""
    chunk_size = 64 * 1024
    while len(data) < max_size:
        chunk = f.read(min(chunk_size, max_size - len(data)))
        if not chunk:
            break
        data += chunk
    return data


# ---------------------------------------------------------------------
# IPMI SEL record types
# ---------------------------------------------------------------------
SEL_TYPE_STR = {
    0x00: "System Boot",
    0x01: "System Restart",
    0x02: "System Event",
    0x03: "Watchdog2 Event",
    0x04: "OEM System Event",
    0x05: "PICMG Event",
    0x06: "LCD Event",
    0x07: "Phone Event",
    0x08: "Power Cycle Event",
    0x09: "Slot/Connector Event",
    0x0A: "System Restart (base)",
    0x0B: "FRU Manufacturing",
    0x0C: "FRU Install",
    0x0D: "FRU Removal",
    0x0E: "FRU Config",
    0x0F: "FRU Relocation",
    0x10: "FRU Active",
    0x11: "FRU Inactive",
    0x12: "FRU Discovery",
    0x13: "FRU Check",
    0xC0: "OEM Huawei Drive",
    0xC1: "OEM Huawei Fan",
    0xC2: "OEM Huawei Power",
    0xC3: "OEM Huawei Temperature",
    0xC4: "OEM Huawei Voltage",
    0xC5: "OEM Huawei Memory",
    0xC6: "OEM Huawei CPU",
    0xC7: "OEM Huawei PCIe",
    0xC8: "OEM Huawei Network",
    0xC9: "OEM Huawei Storage",
    0xCA: "OEM Huawei FC",
    0xCB: "OEM Huawei USB",
    0xCC: "OEM Huawei Sensor",
    0xCD: "OEM Huawei BIOS",
    0xCE: "OEM Huawei BMC",
    0xCF: "OEM Huawei Platform",
}

# ----------------------------------------------------------------------
# Severity mapping for IPMI SEL events.
# Maps sensor type + event type → severity.
# Assert/Deassert is NOT the severity determinant — the sensor/event is.
# ----------------------------------------------------------------------

# Sensor types that are always ERROR when asserted (critical hardware failure)
_ALWAYS_ERROR_SENSORS = {
    0x03,  # Current
    0x05,  # Physical Security (chassis intrusion)
    0x07,  # Processor (CPU error)
    0x0B,  # Memory (ECC error)
    0x10,  # Watchdog1
    0x12,  # Critical Interrupt
    0x18,  # Chip Set
    0x1D,  # OS Critical Stop
    0x24,  # OS Critical Stop
    0x2C,  # Physical Security
    0x2D,  # Processor
    0x31,  # Memory
    0x35,  # System Event
    0x36,  # Critical Interrupt
    0x42,  # Fan (some fan failures)
    0x46,  # CPU
    0x68,  # Health Event
    0x69,  # Run-Time HA
    0x6B,  # BIOS/Startup
    0x6C,  # GPU
    0x6D,  # NVMe
}

# Sensor types that are WARNING when asserted (threshold/predictive)
_THRESHOLD_WARN_SENSORS = {
    0x01,  # Temperature (over-temp warning)
    0x02,  # Voltage (over/under voltage)
    0x04,  # Fan (fan slow/missing)
    0x06,  # Platform Security
    0x09,  # Power Unit
    0x0A,  # Cooling Device
    0x0C,  # Drive Bay
    0x13,  # Button
    0x14,  # Module/Board
    0x19,  # Other FRU
    0x1A,  # LAN
    0x1C,  # Battery
    0x1F,  # Version Change
    0x25,  # Slot/Connector
    0x28,  # Platform Alert
    0x29,  # Entity Presence
    0x2A,  # Monitor ASIC
    0x2B,  # LAN
    0x2E,  # Power Supply
    0x2F,  # Power Unit
    0x30,  # Cooling Device
    0x32,  # Drive Bay
    0x38,  # Module/Board
    0x39,  # Microcontroller
    0x3A,  # Add-in Card
    0x3B,  # Chassis
    0x3C,  # Chip Set
    0x3D,  # Other FRU
    0x3E,  # Non-critical
    0x3F,  # Display
    0x40,  # Disk
    0x41,  # Disk Array
    0x45,  # Fan
    0x47,  # Power Unit
    0x48,  # Fan
    0x49,  # DC Voltage
    0x4A,  # Current
    0x4B,  # Current
    0x4D,  # Power Cap
    0x4E,  # Performance
    0x57,  # IPMB
    0x58,  # Mailbox
    0x59,  # Bridge
    0x5A,  # Management Subsystem
    0x5B,  # Battery
    0x5C,  # Management Subsystem
    0x61,  # Platform Alert
    0x62,  # Sensor
    0x63,  # Battery
    0x65,  # TPM
    0x66,  # Storage
    0x67,  # PCI
}

# Event types (event_type byte) that indicate a real fault
_FAULT_EVENT_TYPES = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}


def _sel_severity(record: dict) -> str:
    """Determine severity for an IPMI SEL record.

    Priority:
    1. OEM records (type >= 0xC0) → ERROR if direction=Assert, INFO if Deassert
    2. Sensor in _ALWAYS_ERROR_SENSORS → ERROR
    3. Sensor in _THRESHOLD_WARN_SENSORS + fault event type → ERROR
    4. Sensor in _THRESHOLD_WARN_SENSORS + assertion → WARNING
    5. Otherwise → INFO
    """
    rtype = record.get("record_type", 0)
    sensor_type = record.get("sensor_type")
    event_type = record.get("event_type")
    direction = record.get("event_dir", 0)
    is_asserted = direction == 0x20

    # OEM Huawei events — type >= 0xC0
    if rtype >= 0xC0:
        # OEM events always indicate hardware-level issues
        return "ERROR" if is_asserted else "INFO"

    # Always-error sensor types
    if sensor_type in _ALWAYS_ERROR_SENSORS:
        # Watchdog timeout, critical interrupt, CPU/memory error, etc.
        return "ERROR"

    # Threshold/predictive sensors
    if sensor_type in _THRESHOLD_WARN_SENSORS:
        if is_asserted:
            # Fault event types (transition to fault state)
            if event_type in _FAULT_EVENT_TYPES:
                return "ERROR"
            return "WARNING"
        else:
            # Deassert = condition cleared = INFO (recovery)
            return "INFO"

    # System boot/restart events — usually INFO
    if rtype in (0x00, 0x01, 0x0A):
        return "INFO"

    # Default: INFO (informational events)
    return "INFO"


# Event direction
DIRECTION = {0x20: "Asserted", 0x00: "Deasserted"}

# Sensor type codes (IPMI v1.5)
SENSOR_TYPE = {
    0x01: "Temperature",
    0x02: "Voltage",
    0x03: "Current",
    0x04: "Fan",
    0x05: "Physical Security",
    0x06: "Platform Security",
    0x07: "Processor",
    0x08: "Power Supply",
    0x09: "Power Unit",
    0x0A: "Cooling Device",
    0x0B: "Memory",
    0x0C: "Drive Bay",
    0x0D: "POST Memory Resize",
    0x0E: "System Firmware",
    0x0F: "Event Logging Disabled",
    0x10: "Watchdog1",
    0x11: "System Event",
    0x12: "Critical Interrupt",
    0x13: "Button",
    0x14: "Module/Board",
    0x15: "Microcontroller",
    0x16: "Add-in Card",
    0x17: "Chassis",
    0x18: "Chip Set",
    0x19: "Other FRU",
    0x1A: "LAN",
    0x1B: "Management Subsystem",
    0x1C: "Battery",
    0x1D: "Operating System",
    0x1E: "Power Rail",
    0x1F: "Version Change",
    0x20: "Calibration",
    0x21: "Boot Error",
    0x22: "Base OS",
    0x23: "OS Boot",
    0x24: "OS Critical Stop",
    0x25: "Slot/Connector",
    0x26: "System ACPI",
    0x27: "Watchdog2",
    0x28: "Platform Alert",
    0x29: "Entity Presence",
    0x2A: "Monitor ASIC",
    0x2B: "LAN",
    0x2C: "Physical Security",
    0x2D: "Processor",
    0x2E: "Power Supply",
    0x2F: "Power Unit",
    0x30: "Cooling Device",
    0x31: "Memory",
    0x32: "Drive Bay",
    0x33: "System Firmware",
    0x34: "Watchdog1",
    0x35: "System Event",
    0x36: "Critical Interrupt",
    0x37: "Button",
    0x38: "Module/Board",
    0x39: "Microcontroller",
    0x3A: "Add-in Card",
    0x3B: "Chassis",
    0x3C: "Chip Set",
    0x3D: "Other FRU",
    0x3E: "Non-critical",
    0x3F: "Display",
    0x40: "Disk",
    0x41: "Disk Array",
    0x42: "风扇",
    0x43: "OS Graceful Stop",
    0x44: "Module/Board",
    0x45: "风扇",
    0x46: "CPU",
    0x47: "Power Unit",
    0x48: "风扇",
    0x49: "DC Voltage",
    0x4A: "Current",
    0x4B: "Current",
    0x4C: "OS",
    0x4D: "Power Cap",
    0x4E: "Performance",
    0x4F: "Entropy",
    0x50: "Firmware",
    0x51: "Version Change",
    0x52: "Secondary BIOS",
    0x53: "Base OS Boot",
    0x54: "Base OS",
    0x55: "OS",
    0x56: "OS",
    0x57: "IPMB",
    0x58: "Mailbox",
    0x59: "Bridge",
    0x5A: "Management Subsystem",
    0x5B: "Battery",
    0x5C: "Management Subsystem",
    0x5D: "Boot",
    0x5E: "Boot",
    0x5F: "Base OS",
    0x60: "Watchdog",
    0x61: "Platform Alert",
    0x62: "Sensor",
    0x63: "Battery",
    0x64: "Global Election",
    0x65: "TPM",
    0x66: "Storage",
    0x67: "PCI",
    0x68: "Health Event",
    0x69: "Run-Time HA",
    0x6A: "SEL Device",
    0x6B: "BIOS/Startup",
    0x6C: "GPU",
    0x6D: "NVMe",
}


def _decode_sel_record(data: bytes) -> Optional[dict]:
    """Decode a single IPMI SEL record from raw bytes.

    Returns a dict with keys: record_id, record_type, timestamp,
    manufacturer_id, event_dir, event_data, sensor_type, sensor_num,
    event_type, direction_str, or None on error.
    """
    if len(data) < 16:
        return None

    record_id = struct.unpack_from("<H", data, 0)[0]
    record_type = data[2]

    # Timestamp: bytes 3-6 (LE), 0xFFFFFFFF means "not set"
    ts_val = struct.unpack_from("<I", data, 3)[0]
    if ts_val == 0xFFFFFFFF:
        timestamp = None
    else:
        try:
            timestamp = datetime.fromtimestamp(ts_val, tz=timezone.utc)
            timestamp = timestamp.replace(tzinfo=None)
        except (ValueError, OSError):
            timestamp = None

    # Manufacturer ID: bytes 7-9 (3 bytes LE, patch to 4 bytes LE)
    mfg_raw = data[7:10]
    mfg_val = mfg_raw[0] | (mfg_raw[1] << 8) | (mfg_raw[2] << 16)

    # Event direction: byte 10 (0x20=Assert, 0x00=Deassert)
    event_dir = data[10]
    direction_str = DIRECTION.get(event_dir, f"unknown(0x{event_dir:02x})")

    # Event data: everything after byte 11, up to 13 bytes max
    event_data = data[11 : 11 + 13]

    sensor_type = None
    sensor_num = None
    event_type = None

    if len(event_data) >= 3:
        sensor_type = event_data[0]
        sensor_num = event_data[1]
        event_type = event_data[2]

    return {
        "record_id": record_id,
        "record_type": record_type,
        "timestamp": timestamp,
        "manufacturer_id": mfg_val,
        "event_dir": event_dir,
        "direction_str": direction_str,
        "event_data": event_data,
        "sensor_type": sensor_type,
        "sensor_num": sensor_num,
        "event_type": event_type,
    }


def _format_sel_entry(record: dict) -> str:
    """Format a decoded SEL record into a human-readable message string."""
    parts = []
    parts.append(f"RecordID=0x{record['record_id']:04X}")

    rtype = record["record_type"]
    rtype_key = f"type_{rtype}" if rtype not in SEL_TYPE_STR else SEL_TYPE_STR[rtype]
    parts.append(rtype_key)

    sensor_type = record["sensor_type"]
    if sensor_type is not None:
        stype_str = SENSOR_TYPE.get(sensor_type, f"SensorType=0x{sensor_type:02X}")
        parts.append(f"{stype_str}(#{record['sensor_num']})")

    event_type = record["event_type"]
    if event_type is not None:
        parts.append(f"EvtType=0x{event_type:02X}")

    if record["event_data"]:
        hex_data = " ".join(f"{b:02X}" for b in record["event_data"])
        parts.append(f"Data=[{hex_data}]")

    parts.append(record["direction_str"])
    return " | ".join(str(p) for p in parts)


def _parse_sel_binary(path: Path):
    """Parse a binary SEL file (sensor_alarm_sel.bin)."""
    entries = []
    parse_errors = 0

    # Stream file in chunks to prevent OOM on pathological inputs
    MAX_SEL_SIZE = 500 * 1024 * 1024  # 500 MB cap
    with path.open("rb") as f:
        data = _read_in_chunks(f, MAX_SEL_SIZE)

    # First byte may be header (0x00 means standard header)
    # Second byte is record size (usually 0x10 = 16 bytes minimum)
    record_size = 16
    if len(data) >= 2:
        candidate = data[1]
        if 8 <= candidate <= 64:
            record_size = candidate

    offset = 0
    while offset + record_size <= len(data):
        record_data = data[offset : offset + record_size]
        record = _decode_sel_record(record_data)

        if record and record["timestamp"]:
            message = _format_sel_entry(record)
            rtype = record["record_type"]
            rtype_str = SEL_TYPE_STR.get(rtype, f"type_{rtype}")
            entries.append(LogEntry(
                timestamp=record["timestamp"],
                module=f"sel:{rtype_str}",
                level=_sel_severity(record),
                message=message,
                raw=record_data.hex(),
            ))
        else:
            parse_errors += 1

        offset += record_size

        # Guard against infinite loop (record_size 0)
        if record_size == 0:
            break

    # If parsing failed entirely, fall back to raw hex dump
    if not entries and parse_errors > 0:
        for i in range(0, len(data), 16):
            chunk = data[i : i + 16]
            ts = datetime.utcfromtimestamp(
                struct.unpack_from("<I", chunk, 3)[0]
            ) if len(chunk) >= 7 and struct.unpack_from("<I", chunk, 3)[0] != 0xFFFFFFFF else None
            entries.append(LogEntry(
                timestamp=ts,
                module="sel",
                level="INFO",
                message=f"Raw: {chunk.hex()}",
                raw=chunk.hex(),
            ))

    return entries, parse_errors


def _parse_sel_tar(path: Path):
    """Parse a sel.tar archive — members are text SEL records."""
    entries = []
    parse_errors = 0

    # 100 MB per-member limit to prevent OOM from malicious/ anomalous archives
    MAX_MEMBER_SIZE = 100 * 1024 * 1024

    with tarfile.open(path, "r:*") as tar:
        for member in tar.getmembers():
            if not member.isfile():
                continue
            if member.size > MAX_MEMBER_SIZE:
                # Skip oversized members rather than OOM-ing
                continue
            f = tar.extractfile(member)
            if f is None:
                continue
            # Try UTF-8 first, fall back to latin-1
            raw = _read_in_chunks(f, MAX_MEMBER_SIZE)
            try:
                content = raw.decode("utf-8", errors="strict")
            except UnicodeDecodeError:
                content = raw.decode("latin-1", errors="replace")

            for line in content.splitlines():
                line = line.strip()
                if not line:
                    continue
                # Try IPMI SEL text format: "0x01 | 0x02 | Timestamp |..."
                parts = [p.strip() for p in line.split("|")]
                if len(parts) >= 4:
                    try:
                        record_id = int(parts[0], 16)
                        record_type = int(parts[1], 16)
                        # Try parse timestamp
                        ts = None
                        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
                            try:
                                ts = datetime.strptime(parts[2][:19], fmt)
                                break
                            except (ValueError, IndexError):
                                pass
                        # Sanitize member name to prevent path traversal in module field
                        safe_name = member.name.replace("/", "_").replace("..", "_")
                        msg = " | ".join(parts[3:])
                        level = "ERROR" if record_type >= 0xC0 else "INFO"
                        # Upgrade to ERROR if message contains fault keywords
                        if any(k in msg.upper() for k in ("FAIL", "ERROR", "CRITICAL", "FATAL", "FAULT")):
                            level = "ERROR"
                        elif any(k in msg.upper() for k in ("WARN", "DEGRADED", "PREDICTIVE", "SLOW", "MISSING")):
                            level = "WARNING"
                        entries.append(LogEntry(
                            timestamp=ts,
                            module=f"sel:tar:{safe_name}",
                            level=level,
                            message=msg,
                            raw=line,
                        ))
                    except (ValueError, IndexError):
                        parse_errors += 1
                else:
                    parse_errors += 1

    return entries, parse_errors


def _parse_sel_db(path: Path):
    """Parse a sel.db SQLite database (Huawei iBMC format).

    The database typically contains a table with event records indexed by time.
    """
    entries = []
    parse_errors = 0

    try:
        conn = sqlite3.connect(str(path))
        cur = conn.cursor()

        # Try to find the event table
        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cur.fetchall()]

        # White-list only known SEL table names — prevents SQL injection
        _SAFE_TABLES = {"sel", "event", "system_event", "sensor_event"}
        for table in tables:
            if table.lower() not in _SAFE_TABLES:
                continue
            try:
                # Get column names (table name already validated above)
                cur.execute(f"PRAGMA table_info({table})")
                cols = [row[1] for row in cur.fetchall()]
                col_str = ", ".join(cols)

                cur.execute(f"SELECT * FROM {table} LIMIT 10000")
                rows = cur.fetchall()

                for row in rows:
                    row_dict = dict(zip(cols, row))
                    # Look for timestamp, level, message columns
                    ts = None
                    for ts_col in ("timestamp", "time", "datetime", "event_time"):
                        if ts_col in row_dict and row_dict[ts_col]:
                            try:
                                ts = datetime.strptime(str(row_dict[ts_col])[:19], "%Y-%m-%d %H:%M:%S")
                                break
                            except (ValueError, TypeError):
                                try:
                                    ts = datetime.fromtimestamp(int(row_dict[ts_col]), tz=timezone.utc)
                                    ts = ts.replace(tzinfo=None)
                                    break
                                except (ValueError, TypeError, OSError):
                                    pass

                    level = "INFO"
                    for lvl_col in ("level", "severity", "type"):
                        if lvl_col in row_dict and row_dict[lvl_col]:
                            lvl = str(row_dict[lvl_col]).upper()
                            if "ERR" in lvl or "CRIT" in lvl or "FAIL" in lvl:
                                level = "ERROR"
                            elif "WARN" in lvl:
                                level = "WARNING"
                            break

                    message = ""
                    for msg_col in ("message", "msg", "description", "event", "data"):
                        if msg_col in row_dict and row_dict[msg_col]:
                            message = str(row_dict[msg_col])
                            break
                    if not message:
                        message = str(row_dict)

                    entries.append(LogEntry(
                        timestamp=ts,
                        module=f"sel:db:{table}",
                        level=level,
                        message=message[:500],
                        raw=str(row_dict)[:200],
                    ))
            except sqlite3.Error as e:
                parse_errors += 1
            break

        conn.close()
    except Exception:
        parse_errors += 1

    return entries, parse_errors


def parse(path: Path):
    """Main entry point — auto-detect format from file extension."""
    entries = []
    parse_errors = 0

    if path.suffix == ".tar":
        # Could be sel.tar — peek at first member name
        try:
            with tarfile.open(path, "r:*") as tar:
                members = tar.getnames()
            if any("sel" in m.lower() or "event" in m.lower() for m in members):
                entries, parse_errors = _parse_sel_tar(path)
            else:
                # Not a SEL tar; delegate to generic tar handler
                parse_errors = 1
        except Exception:
            parse_errors = 1
    elif path.suffix == ".bin":
        # Guard against oversized binary SEL files (read_bytes is unbounded)
        try:
            bin_size = path.stat().st_size
            MAX_BIN_SIZE = 200 * 1024 * 1024  # 200 MB
            if bin_size > MAX_BIN_SIZE:
                return [], 1
        except OSError:
            pass
        entries, parse_errors = _parse_sel_binary(path)
    elif path.suffix == ".db":
        # Guard against oversized SQLite databases (keep memory bounded)
        try:
            db_size = path.stat().st_size
            MAX_DB_SIZE = 500 * 1024 * 1024  # 500 MB
            if db_size > MAX_DB_SIZE:
                return [], 1  # Signal "unsupported/too large"
        except OSError:
            pass
        entries, parse_errors = _parse_sel_db(path)
    else:
        # Try as text — guard against huge files (cap at 100 MB)
        MAX_TEXT_SIZE = 100 * 1024 * 1024
        try:
            file_size = path.stat().st_size
            if file_size > MAX_TEXT_SIZE:
                return [], 1  # Signal "unsupported/too large"
            content = path.read_text(encoding="utf-8", errors="replace")
            lines = content.splitlines()
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                parts = [p.strip() for p in line.split("|")]
                if len(parts) >= 4:
                    try:
                        ts = None
                        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
                            try:
                                ts = datetime.strptime(parts[2][:19], fmt)
                                break
                            except (ValueError, IndexError):
                                pass
                        entries.append(LogEntry(
                            timestamp=ts,
                            module="sel:text",
                            level="INFO",
                            message=" | ".join(parts[3:]),
                            raw=line,
                        ))
                    except (ValueError, IndexError):
                        parse_errors += 1
                else:
                    parse_errors += 1
        except Exception:
            parse_errors = 1

    return FORMAT_NAME, entries, parse_errors
