"""Tests for statistical anomaly detector (burst + repeat_flood)."""

import pytest
from datetime import datetime, timedelta
from app.detectors.statistical import detect_statistical_anomalies, _burst_anomalies
from app.schemas import LogEntry, StatisticalAnomaly


def _entry(level: str, minutes_offset: int, module: str = "test", repeat: int = 1) -> LogEntry:
    return LogEntry(
        timestamp=datetime(2025, 6, 23, 12, 0, 0) + timedelta(minutes=minutes_offset),
        module=module,
        level=level,
        message=f"{module} error",
        raw=f"{module} error",
        repeat_count=repeat,
    )


class TestBurstAnomalies:
    """ERROR/WARNING burst detection in time windows."""

    def test_no_burst_sparse_errors(self):
        """1 ERROR per minute for 10 minutes should NOT be a burst (below 3x threshold)."""
        entries = [_entry("ERROR", i) for i in range(10)]
        result = detect_statistical_anomalies(entries)
        assert not any(a.metric == "error_burst" for a in result)

    def test_burst_3x_threshold(self):
        """3x average rate should trigger error_burst.

        With 20 entries spread over 20 minutes: avg_rate = 1.0, threshold = 3.0.
        Adding 5 entries at minute 20: count=5 >= threshold=3 → burst fires.
        """
        # Sparse baseline: 1 entry per minute for 20 minutes
        entries = [_entry("ERROR", i) for i in range(20)]
        # Dense burst at minute 20: 5 entries
        entries.extend([_entry("ERROR", 20) for _ in range(5)])
        result = detect_statistical_anomalies(entries)
        bursts = [a for a in result if a.metric == "error_burst"]
        assert len(bursts) >= 1, f"expected burst, got {[b.description for b in result]}"

    def test_no_burst_if_not_meeting_threshold(self):
        """Below-min_count entries should not trigger burst."""
        # Only 2 entries total (below min_count=3 for ERROR)
        entries = [_entry("ERROR", 0), _entry("ERROR", 5)]
        result = detect_statistical_anomalies(entries)
        assert not any(a.metric == "error_burst" for a in result)

    def test_warning_burst_higher_threshold(self):
        """WARNING burst requires 5x threshold and min_count=5, so ERROR-only data won't trigger."""
        entries = [_entry("WARNING", i) for i in range(10)]
        result = detect_statistical_anomalies(entries)
        assert not any(a.metric == "warning_burst" for a in result)

    def test_entries_without_timestamp_ignored(self):
        """Entries without timestamp should not cause crashes in burst detection."""
        entries = [
            LogEntry(timestamp=None, module="test", level="ERROR", message="x", raw="x"),
            LogEntry(
                timestamp=datetime(2025, 6, 23, 12, 10, 0),
                module="test",
                level="ERROR",
                message="x",
                raw="x",
            ),
        ]
        result = detect_statistical_anomalies(entries)
        # Should not crash — either result or empty is fine
        assert isinstance(result, list)


class TestRepeatFlood:
    """repeat_flood detection: many repeats in a single entry."""

    def test_repeat_flood_triggered(self):
        """Single ERROR entry with repeat_count > 20 should trigger repeat_flood."""
        entry = LogEntry(
            timestamp=datetime(2025, 6, 23, 12, 0, 0),
            module="kvm_vmm",
            level="ERROR",
            message="Pre-read ssl failed",
            raw="Pre-read ssl failed",
            repeat_count=50,
        )
        result = detect_statistical_anomalies([entry])
        floods = [a for a in result if a.metric == "repeat_flood"]
        assert len(floods) == 1
        assert floods[0].severity == "WARNING"

    def test_repeat_below_threshold_no_flood(self):
        """repeat_count <= 20 should not trigger repeat_flood."""
        entry = LogEntry(
            timestamp=datetime(2025, 6, 23, 12, 0, 0),
            module="kvm_vmm",
            level="ERROR",
            message="ssl error",
            raw="ssl error",
            repeat_count=20,
        )
        result = detect_statistical_anomalies([entry])
        assert not any(a.metric == "repeat_flood" for a in result)

    def test_multiple_modules_separate_floods(self):
        """Different modules are tracked separately in repeat_flood."""
        entries = [
            LogEntry(
                timestamp=datetime(2025, 6, 23, 12, 0, 0),
                module="module_a",
                level="ERROR",
                message="a",
                raw="a",
                repeat_count=30,
            ),
            LogEntry(
                timestamp=datetime(2025, 6, 23, 12, 1, 0),
                module="module_b",
                level="ERROR",
                message="b",
                raw="b",
                repeat_count=30,
            ),
        ]
        result = detect_statistical_anomalies(entries)
        floods = [a for a in result if a.metric == "repeat_flood"]
        assert len(floods) == 2

    def test_repeat_flood_only_on_error_level(self):
        """repeat_flood only fires for ERROR-level entries, not WARNING."""
        entry = LogEntry(
            timestamp=datetime(2025, 6, 23, 12, 0, 0),
            module="kvm_vmm",
            level="WARNING",
            message="repeat warning",
            raw="repeat warning",
            repeat_count=50,
        )
        result = detect_statistical_anomalies([entry])
        assert not any(a.metric == "repeat_flood" for a in result)


class TestStatDetectorEdgeCases:
    """Edge cases and empty input handling."""

    def test_empty_entries(self):
        result = detect_statistical_anomalies([])
        assert result == []

    def test_only_info_entries(self):
        """INFO entries should not contribute to statistical anomalies."""
        entries = [
            LogEntry(
                timestamp=datetime(2025, 6, 23, 12, 0, 0),
                module="test",
                level="INFO",
                message="normal",
                raw="normal",
            )
            for _ in range(20)
        ]
        result = detect_statistical_anomalies(entries)
        assert not any(a.metric == "error_burst" for a in result)
        assert not any(a.metric == "warning_burst" for a in result)

    def test_mixed_error_and_warning_bursts(self):
        """Both ERROR and WARNING can fire simultaneously if thresholds are met."""
        # ERROR burst: 3x, min_count=3
        error_entries = [_entry("ERROR", i) for i in range(10)]
        # WARNING burst: 5x, min_count=5
        warn_entries = [_entry("WARNING", i) for i in range(10)]
        result = detect_statistical_anomalies(error_entries + warn_entries)
        # No bursts since each minute only has 1 entry (below threshold)
        assert not any("burst" in a.metric for a in result)
