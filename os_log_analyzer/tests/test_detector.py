import pytest
from os_log_analyzer.app.parsers.detector import detect_faults
from os_log_analyzer.app.parsers.base import LogLine

def test_detect_panic():
    lines = [
        LogLine(raw="Kernel panic - not syncing: VFS", timestamp="2026-03-15 04:02:01", message="Kernel panic"),
    ]
    faults = detect_faults(lines)
    assert len(faults) == 1
    assert faults[0].category == "panic"
    assert faults[0].severity == "critical"

def test_detect_oom():
    lines = [
        LogLine(raw="Out of memory: Killed process 12345", timestamp="2026-03-15 04:02:01", message="Out of memory"),
    ]
    faults = detect_faults(lines)
    assert any(f.category == "oom" for f in faults)

def test_detect_io_error_multiple():
    lines = [
        LogLine(raw="I/O error", timestamp="2026-03-15 04:02:01", message="I/O error"),
        LogLine(raw="I/O error", timestamp="2026-03-15 04:02:02", message="I/O error"),
        LogLine(raw="I/O error", timestamp="2026-03-15 04:02:03", message="I/O error"),
    ]
    faults = detect_faults(lines)
    io_fault = next((f for f in faults if f.category == "io_error"), None)
    assert io_fault is not None
    assert io_fault.severity == "critical"  # upgraded from warning when count >= 3
    assert io_fault.count == 3

def test_no_fault():
    lines = [
        LogLine(raw="System startup complete", timestamp="2026-03-15 04:02:01", message=" startup"),
    ]
    faults = detect_faults(lines)
    assert len(faults) == 0
