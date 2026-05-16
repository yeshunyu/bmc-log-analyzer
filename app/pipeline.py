"""Log analysis pipeline — unified upload and reanalyze logic.

Both upload and reanalyze follow the same pipeline:
  1. Decompress archive if needed
  2. Scan and select log files
  3. Parse selected files
  4. Enrich with Huawei ALM alarm codes
  5. Detect anomalies
  6. Build summary stats

Single class with two factory methods (from_upload vs from_disk)
keeps the two endpoints DRY while preserving their distinct FastAPI
interface signatures.
"""

from pathlib import Path
from datetime import datetime as dt

from app.schemas import AnalysisResult, LogEntry
from app.archive import decompress_if_needed
from app.log_scanner import find_best_log_file, find_top_log_files
from app.parsers import get_parser
from app.parsers.app_debug import parse_app_debug_log
from app.parsers.huawei_alm import enrich_entry_with_alm
from app.detectors.rule_based import detect_rule_anomalies, detect_alm_anomalies
from app.detectors.statistical import detect_statistical_anomalies
from app.operation_log import log_operation


class LogAnalysisPipeline:
    """Reusable analysis pipeline for upload and reanalyze."""

    def __init__(self, file_path: Path, original_filename: str, job_id: str):
        self.file_path = file_path
        self.original_filename = original_filename
        self.job_id = job_id

    # -------------------------------------------------------------------------
    # Factory methods — one per entry point
    # -------------------------------------------------------------------------

    @classmethod
    def from_upload(cls, file_path: Path, original_filename: str, job_id: str) -> "LogAnalysisPipeline":
        return cls(file_path, original_filename, job_id)

    @classmethod
    def from_disk(cls, file_path: Path, original_filename: str, job_id: str) -> "LogAnalysisPipeline":
        """Reanalyze path: touch file to reset its TTL timer."""
        import os
        os.utime(file_path)
        return cls(file_path, original_filename, job_id)

    # -------------------------------------------------------------------------
    # Pipeline steps
    # -------------------------------------------------------------------------

    def run(self) -> AnalysisResult:
        """Execute full analysis pipeline. Returns AnalysisResult."""
        # 1. Decompress
        decompressed_path, all_files = decompress_if_needed(self.file_path, self.job_id)

        # 2. Parse
        if decompressed_path != self.file_path and decompressed_path.is_dir():
            top_files = find_top_log_files(decompressed_path)
            if top_files:
                format_type, entries, parse_errors = self._parse_multi(top_files)
            elif all_files:
                format_type, entries, parse_errors = self._route_parse(all_files[0])
            else:
                format_type, entries, parse_errors = "unknown", [], 0
        else:
            format_type, entries, parse_errors = self._route_parse(decompressed_path)

        # 3. Huawei ALM enrichment — done once, here, in the pipeline
        for e in entries:
            enrich_entry_with_alm(e)

        # 4. Time range
        ts_list = [e.timestamp for e in entries if e.timestamp]
        time_range = []
        if ts_list:
            ts_list.sort()
            time_range = [
                _format_ts(ts_list[0]),
                _format_ts(ts_list[-1]),
            ]

        parsed_log = {
            "format_type": format_type,
            "total_lines": len(entries),
            "entries": entries,
            "parse_errors": parse_errors,
            "file_name": self.original_filename,
            "time_range": time_range,
        }

        # 5. Detect anomalies
        rule_anomalies = detect_rule_anomalies(entries)
        stat_anomalies = detect_statistical_anomalies(entries)
        alm_anomalies = detect_alm_anomalies(entries)

        # 6. Summary stats
        level_counts, module_counts = _build_counts(entries)
        summary = {
            "total_entries": len(entries),
            "error_count": level_counts.get("ERROR", 0),
            "warning_count": level_counts.get("WARNING", 0),
            "level_counts": level_counts,
            "top_modules": sorted(module_counts.items(), key=lambda x: -x[1])[:5],
            "rule_anomaly_count": len(rule_anomalies),
            "alm_anomaly_count": sum(1 for a in alm_anomalies if a.severity == "ERROR"),
            "stat_anomaly_count": len(stat_anomalies),
            "parsers_used": {format_type: len(entries)},
        }

        # 7. Log operation
        log_operation(
            operation="upload" if self.job_id else "reanalyze",
            detail=f"{'上传' if self.job_id else '重新分析'}文件 {self.original_filename}，"
                   f"解析格式 {format_type}，{len(entries)} 条日志",
            file_name=self.original_filename,
            result="ok",
            extra={
                "format": format_type,
                "entries": len(entries),
                "errors": parse_errors,
                "rule_anomalies": len(rule_anomalies),
                "alm_anomalies": sum(1 for a in alm_anomalies if a.severity == "ERROR"),
                "stat_anomalies": len(stat_anomalies),
            },
        )

        return AnalysisResult(
            parsed_log=parsed_log,
            rule_anomalies=rule_anomalies,
            alm_anomalies=alm_anomalies,
            statistical_anomalies=stat_anomalies,
            summary=summary,
        )

    # -------------------------------------------------------------------------
    # Internal helpers
    # -------------------------------------------------------------------------

    def _route_parse(self, path: Path):
        """Route to the appropriate parser for a single file."""
        if path.is_dir():
            # Pick the largest file as primary
            try:
                candidates = sorted(
                    path.rglob("*"),
                    key=lambda p: p.stat().st_size if p.is_file() else -1,
                    reverse=True,
                )
                for p in candidates:
                    if p.is_file() and p.stat().st_size > 1024 and not p.name.startswith("."):
                        path = p
                        break
                else:
                    from fastapi import HTTPException
                    raise HTTPException(status_code=422, detail="无法在解压目录中找到有效的日志文件")
            except Exception as e:
                from fastapi import HTTPException
                raise HTTPException(status_code=422, detail=f"解压目录扫描失败: {e}")

        parse_fn, format_name = get_parser(
            self.original_filename if path.is_file() else path.name
        )
        if parse_fn is not None:
            return parse_fn(path)

        # Fallback: app_debug catch-all
        return parse_app_debug_log(path)

    def _parse_multi(self, file_paths: list[Path]):
        """Parse multiple files, aggregate entries, merge parse_errors."""
        all_entries: list = []
        total_errors = 0
        format_type = "multi"

        for path in file_paths:
            try:
                ft, entries, errs = self._route_parse(path)
                for e in entries:
                    e.source_file = path.name
                all_entries.extend(entries)
                total_errors += errs
                if entries:
                    format_type = ft
            except Exception:
                total_errors += 1

        # Sort by timestamp if available — but do NOT enrich here
        all_entries.sort(key=lambda e: e.timestamp or dt.min)
        return format_type, all_entries, total_errors


# ---------------------------------------------------------------------------
# Pure helpers (no pipeline state)
# ---------------------------------------------------------------------------

def _format_ts(ts):
    return ts.strftime("%Y-%m-%d %H:%M:%S") if hasattr(ts, "strftime") else str(ts)


def _build_counts(entries: list[LogEntry]):
    level_counts: dict[str, int] = {}
    module_counts: dict[str, int] = {}
    for e in entries:
        level_counts[e.level] = level_counts.get(e.level, 0) + 1
        if e.module:
            module_counts[e.module] = module_counts.get(e.module, 0) + 1
    return level_counts, module_counts
