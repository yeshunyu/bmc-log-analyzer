import re
from collections import defaultdict
from datetime import datetime, timedelta
from app.schemas import LogEntry, StatisticalAnomaly

# Detect bursts: unusually high event frequency in short time windows
MINUTES_BUCKETS = [5, 15, 30]

def _burst_anomalies(entries_by_level: dict[str, list[LogEntry]], threshold_multiplier: float = 3.0, min_count: int = 3) -> list[StatisticalAnomaly]:
    """Detect burst anomalies for each severity level."""
    results = []
    for level, level_entries in entries_by_level.items():
        if not level_entries:
            continue
        buckets = defaultdict(list)
        for e in level_entries:
            if e.timestamp:
                key = e.timestamp.replace(second=0, microsecond=0)
                buckets[key].append(e)
        if not buckets:
            continue
        counts = [len(v) for v in buckets.values()]
        avg_rate = sum(counts) / len(counts) if counts else 0
        threshold = max(min_count, avg_rate * threshold_multiplier)
        for minute, bucket_entries in buckets.items():
            count = len(bucket_entries)
            if count >= threshold:
                window_start = minute
                window_end = minute + timedelta(minutes=1)
                context_start = minute - timedelta(minutes=2)
                context_end = window_end + timedelta(minutes=2)
                context_entries = [e for e in level_entries
                                   if e.timestamp and context_start <= e.timestamp < context_end]
                module_breakdown = defaultdict(int)
                for e in bucket_entries:
                    module_breakdown[e.module] += 1
                top_module = max(module_breakdown, key=module_breakdown.get) if module_breakdown else "unknown"
                results.append(StatisticalAnomaly(
                    metric=f"{level.lower()}_burst",
                    description=f"{level}事件突增：{count}条/分钟（阈值={threshold:.1f}），主要集中在 {top_module}",
                    severity=level,
                    window_start=window_start,
                    window_end=window_end,
                    event_count=count,
                    threshold=threshold,
                    entries=context_entries[:10],
                ))
    return results

def detect_statistical_anomalies(entries: list[LogEntry]) -> list[StatisticalAnomaly]:
    results = []

    # Build minute-level buckets per severity level
    by_level: dict[str, list[LogEntry]] = defaultdict(list)
    for e in entries:
        if e.timestamp and e.level in ("ERROR", "WARNING"):
            by_level[e.level].append(e)

    # ERROR burst: 3x average
    results.extend(_burst_anomalies(by_level, threshold_multiplier=3.0, min_count=3))

    # WARNING burst: higher multiplier (5x) to avoid noise
    results.extend(_burst_anomalies(by_level, threshold_multiplier=5.0, min_count=5))

    # Also detect rapid repeated patterns (many repeats in a single entry)
    repeat_anomalies = [e for e in entries if e.repeat_count > 10 and e.level == "ERROR"]
    if repeat_anomalies:
        module_breakdown = defaultdict(list)
        for e in repeat_anomalies:
            module_breakdown[e.module].append(e)

        for module, module_entries in module_breakdown.items():
            total_repeats = sum(e.repeat_count for e in module_entries)
            if total_repeats > 20:
                results.append(StatisticalAnomaly(
                    metric="repeat_flood",
                    description=f"模块 {module} 重复事件 flood：{total_repeats}次重复（去重后{len(module_entries)}种）",
                    severity="WARNING",
                    window_start=module_entries[0].timestamp or datetime.min,
                    window_end=module_entries[-1].timestamp or datetime.max,
                    event_count=total_repeats,
                    threshold=20,
                    entries=module_entries[:5],
                ))

    return results
