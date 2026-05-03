"""Tests for all log parsers."""

import pytest
from pathlib import Path
import tempfile
import os

from app.schemas import LogEntry
from app.parsers import get_parser


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def tmp_path(content: str, suffix: str = ".log") -> Path:
    f = tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False)
    f.write(content)
    f.flush()
    return Path(f.name)


def cleanup(path: Path):
    os.unlink(path)


# ---------------------------------------------------------------------------
# Parser registry
# ---------------------------------------------------------------------------

class TestRegistry:
    def test_get_parser_finds_app_debug(self):
        fn, name = get_parser("app_debug_log_all")
        assert fn is not None
        assert name == "app_debug"

    def test_get_parser_finds_syslog(self):
        fn, name = get_parser("linux_kernel_log")
        assert fn is not None
        assert name == "syslog"

    def test_get_parser_finds_ipmi(self):
        fn, name = get_parser("ipmi_sel_log")
        assert fn is not None
        assert name == "ipmi"

    def test_get_parser_finds_agentless(self):
        fn, name = get_parser("agentless_log")
        assert fn is not None
        assert name == "agentless"

    def test_get_parser_finds_raid(self):
        fn, name = get_parser("raid_log")
        assert fn is not None
        assert name == "raid"

    def test_get_parser_finds_fdm(self):
        fn, name = get_parser("fdm_log")
        assert fn is not None
        assert name == "fdm"

    def test_get_parser_finds_maintenance(self):
        fn, name = get_parser("maintenance_log")
        assert fn is not None
        assert name == "maintenance"

    def test_get_parser_finds_m7(self):
        fn, name = get_parser("m7_imu_log")
        assert fn is not None
        assert name == "m7_imu"

    def test_get_parser_finds_nginx(self):
        fn, name = get_parser("nginx_access_log")
        assert fn is not None
        assert name == "nginx_access"

    def test_get_parser_returns_none_for_unknown(self):
        fn, name = get_parser("totally_unknown_file")
        assert fn is None
        assert name is None


# ---------------------------------------------------------------------------
# app_debug parser
# ---------------------------------------------------------------------------

class TestAppDebug:
    SAMPLE = (
        "2025-06-23 11:03:20.644848 kvm_vmm ERROR: comm.c(329): Pre-read ssl failed.\n"
        "2025-06-24 10:19:33.950528 kvm_vmm : ERROR: comm.c(329): Pre-read ssl failed.  (repeated 42 times)\n"
        "2025-06-25 08:00:01.000000 host_mgr INFO: host is registered.\n"
    )

    def test_parses_basic_line(self):
        path = tmp_path(self.SAMPLE)
        try:
            from app.parsers.app_debug import parse
            fmt, entries, errors = parse(path)
            assert fmt == "app_debug"
            assert len(entries) == 3
            assert entries[0].level == "ERROR"
            assert entries[0].module == "kvm_vmm"
            assert "ssl failed" in entries[0].message
            assert entries[1].repeat_count == 42
            assert entries[2].level == "INFO"
        finally:
            cleanup(path)

    def test_parse_errors_count(self):
        path = tmp_path("not a valid log line\n2025-06-23 11:03:20.644848 kvm_vmm ERROR: ok\n")
        try:
            from app.parsers.app_debug import parse
            fmt, entries, errors = parse(path)
            assert errors == 1
        finally:
            cleanup(path)


# ---------------------------------------------------------------------------
# syslog parser
# ---------------------------------------------------------------------------

class TestSyslog:
    SAMPLE = (
        "2025-06-23T11:03:20+00:00 2102313NNLP0NC100035 kernel: [16396065.873833] EDMA host is lost\n"
        "2025-06-23T11:04:00+00:00 2102313NNLP0NC100035 kernel: [16396065.873833] system FAIL detected\n"
    )

    def test_parses_syslog(self):
        path = tmp_path(self.SAMPLE)
        try:
            from app.parsers.syslog import parse
            fmt, entries, errors = parse(path)
            assert fmt == "syslog"
            assert len(entries) == 2
            assert entries[0].level == "INFO"   # "lost" doesn't trigger ERROR/FAIL/WARN keywords
            assert entries[1].level == "ERROR"  # "FAIL" triggers ERROR
        finally:
            cleanup(path)


# ---------------------------------------------------------------------------
# IPMI parser
# ---------------------------------------------------------------------------

class TestIPMI:
    SAMPLE = (
        "2022-12-24 06:19:59 IPMI,N/A@HOST,Dft,Enable DFT command successfully\n"
        "2022-12-24 06:22:52 IPMI,N/A@HOST,sensor_alarm,Set SysHealLed to (overstate on) color (GREEN) successfully\n"
    )

    def test_parses_ipmi(self):
        path = tmp_path(self.SAMPLE)
        try:
            from app.parsers.ipmi import parse
            fmt, entries, errors = parse(path)
            assert fmt == "ipmi"
            assert len(entries) == 2
            assert entries[0].module == "ipmi:Dft"
            assert entries[1].module == "ipmi:sensor_alarm"
        finally:
            cleanup(path)


# ---------------------------------------------------------------------------
# agentless parser
# ---------------------------------------------------------------------------

class TestAgentless:
    SAMPLE = (
        "2022-12-24T06:23:27+00:00 2102313NNLP0NC100035 kernel: [  731.296955] edma: 1732, host is lost.\n"
        "2022-12-24T06:24:00+00:00 2102313NNLP0NC100035 kernel: [  731.296955] normal event\n"
    )

    def test_parses_agentless(self):
        path = tmp_path(self.SAMPLE)
        try:
            from app.parsers.agentless import parse
            fmt, entries, errors = parse(path)
            assert fmt == "agentless"
            assert len(entries) == 2
            assert entries[0].level == "ERROR"
            assert entries[1].level == "INFO"
        finally:
            cleanup(path)


# ---------------------------------------------------------------------------
# FDM parser
# ---------------------------------------------------------------------------

class TestFDM:
    SAMPLE = (
        "2022-12-24 06:23:14 UTC: BMC detected system power off.\n"
        "2022-12-24 06:24:00 UTC: ERROR: FDM process failed.\n"
    )

    def test_parses_fdm(self):
        path = tmp_path(self.SAMPLE)
        try:
            from app.parsers.fdm import parse
            fmt, entries, errors = parse(path)
            assert fmt == "fdm"
            assert len(entries) == 2
            # "power off" doesn't contain ERROR/FAIL/WARN → INFO
            assert entries[0].level == "INFO"
            # "ERROR:" → ERROR
            assert entries[1].level == "ERROR"
        finally:
            cleanup(path)


# ---------------------------------------------------------------------------
# RAID parser
# ---------------------------------------------------------------------------

class TestRAID:
    SAMPLE = """Controller ID : 0
Virtual Drive : 0 (Target Id: 0)
Message Timestamp : 12/24/2022  06:23:14
Event code : 0x00
Class : Critical
Description of the event : Logical drive is failed

Controller ID : 1
Virtual Drive : 1 (Target Id: 1)
Message Timestamp : 12/25/2022  10:00:00
Event code : 0x01
Class : Warning
Description of the event : Patrol read error
"""

    def test_parses_raid(self):
        path = tmp_path(self.SAMPLE)
        try:
            from app.parsers.raid import parse
            fmt, entries, errors = parse(path)
            assert fmt == "raid"
            assert len(entries) == 2
            assert entries[0].level == "ERROR"
            assert entries[0].module == "RAID:0"
            assert "failed" in entries[0].message.lower()
            assert entries[1].level == "WARNING"
            assert entries[1].module == "RAID:1"
        finally:
            cleanup(path)


# ---------------------------------------------------------------------------
# maintenance parser
# ---------------------------------------------------------------------------

class TestMaintenance:
    SAMPLE = (
        "2024-12-07 03:02:21 INFO : SVR-0000000,[OOB] Physical drive Disk4 patrol read - In-Progress\n"
        "2024-12-07 03:05:00 ERROR : SVR-0000000,[OOB] Physical drive Disk4 patrol read - Critical\n"
    )

    def test_parses_maintenance(self):
        path = tmp_path(self.SAMPLE)
        try:
            from app.parsers.maintenance import parse
            fmt, entries, errors = parse(path)
            assert fmt == "maintenance"
            assert len(entries) == 2
            assert entries[0].level == "INFO"
            assert entries[1].level == "ERROR"
        finally:
            cleanup(path)


# ---------------------------------------------------------------------------
# M7/IMU parser
# ---------------------------------------------------------------------------

class TestM7IMU:
    SAMPLE = (
        "[    187.425][CHIP 0][      0]IMP report mac 0 link status 1, event 0\n"
        "[      0.000][CHIP 0][      0]imu_cmd_queue_init:ddr_base = 0x44080000\n"
        "[    100.000][CHIP 1][      0]ERR: dma transfer failed\n"
    )

    def test_parses_m7(self):
        path = tmp_path(self.SAMPLE)
        try:
            from app.parsers.m7_imu import parse
            fmt, entries, errors = parse(path)
            assert fmt == "m7_imu"
            assert len(entries) == 3
            assert entries[0].level == "INFO"
            assert entries[2].level == "ERROR"
            assert entries[2].module == "m7:CHIP 1"
        finally:
            cleanup(path)


# ---------------------------------------------------------------------------
# nginx_access parser
# ---------------------------------------------------------------------------

class TestNginxAccess:
    SAMPLE = (
        '192.168.1.1 - - [10/Oct/2023:13:55:36 +0000] "GET /api HTTP/1.1" 200 1234 "-" "Mozilla/5.0"\n'
        '192.168.1.2 - - [10/Oct/2023:13:56:00 +0000] "POST /login HTTP/1.1" 500 5123 "-" "curl"\n'
    )

    def test_parses_nginx(self):
        path = tmp_path(self.SAMPLE)
        try:
            from app.parsers.nginx_access import parse
            fmt, entries, errors = parse(path)
            assert fmt == "nginx_access"
            assert len(entries) == 2
            assert entries[0].level == "INFO"
            assert entries[1].level == "ERROR"
        finally:
            cleanup(path)


# ---------------------------------------------------------------------------
# rule-based detector
# ---------------------------------------------------------------------------

class TestRuleDetector:
    def test_detects_ssl_failed(self):
        from app.detectors.rule_based import detect_rule_anomalies
        from app.schemas import LogEntry
        from datetime import datetime

        entries = [
            LogEntry(timestamp=datetime.now(), module="kvm_vmm", level="ERROR",
                     message="Pre-read ssl failed", raw="test")
        ]
        anomalies = detect_rule_anomalies(entries)
        assert any(a.rule_id == "ssl_failed" for a in anomalies)

    def test_detects_host_lost(self):
        from app.detectors.rule_based import detect_rule_anomalies
        from app.schemas import LogEntry
        from datetime import datetime

        entries = [
            LogEntry(timestamp=datetime.now(), module="edma", level="ERROR",
                     message="host is lost", raw="test")
        ]
        anomalies = detect_rule_anomalies(entries)
        assert any(a.rule_id == "host_lost" for a in anomalies)

    def test_ignores_info_recovery_events(self):
        from app.detectors.rule_based import detect_rule_anomalies
        from app.schemas import LogEntry
        from datetime import datetime

        # host_registered is INFO but very common — should be skipped
        entries = [
            LogEntry(timestamp=datetime.now(), module="edma", level="INFO",
                     message="host is registered", raw="test")
        ]
        anomalies = detect_rule_anomalies(entries)
        # host_registered is filtered out even when it matches
        assert not any(a.rule_id == "host_registered" for a in anomalies)


# ---------------------------------------------------------------------------
# statistical detector
# ---------------------------------------------------------------------------

class TestStatDetector:
    def test_no_anomaly_for_normal_entries(self):
        from app.detectors.statistical import detect_statistical_anomalies
        from app.schemas import LogEntry
        from datetime import datetime, timedelta

        base = datetime(2025, 1, 1, 12, 0, 0)
        entries = [
            LogEntry(timestamp=base + timedelta(minutes=i), module="test", level="ERROR",
                     message="normal error", raw="test")
            for i in range(10)
        ]
        # 1 per minute is not a burst
        anomalies = detect_statistical_anomalies(entries)
        assert not any(a.metric == "error_burst" for a in anomalies)
