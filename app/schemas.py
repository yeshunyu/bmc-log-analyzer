from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime


class LogEntry(BaseModel):
    timestamp: Optional[datetime] = None
    module: str = ""
    level: str = "INFO"
    source_file: Optional[str] = None
    line_number: Optional[int] = None
    message: str
    raw: str
    repeat_count: int = 1


class ParsedLog(BaseModel):
    format_type: str
    total_lines: int
    entries: list[LogEntry]
    parse_errors: int = 0


class AnomalyRule(BaseModel):
    id: str
    pattern: str
    description: str
    severity: str = "ERROR"  # ERROR, WARNING, INFO
    module: Optional[str] = None


class AnomalyDetection(BaseModel):
    rule_id: str
    rule_description: str
    severity: str
    count: int
    entries: list[LogEntry] = Field(default_factory=list, max_length=20)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None


class StatisticalAnomaly(BaseModel):
    metric: str
    description: str
    severity: str
    window_start: datetime
    window_end: datetime
    event_count: int
    threshold: float
    entries: list[LogEntry] = Field(default_factory=list, max_length=10)


class AnalysisResult(BaseModel):
    parsed_log: ParsedLog
    rule_anomalies: list[AnomalyDetection]
    statistical_anomalies: list[StatisticalAnomaly]
    summary: dict


class LLMAnalysisRequest(BaseModel):
    anomalies: list[AnomalyDetection]
    statistical_anomalies: list[StatisticalAnomaly]
    top_entries: list[LogEntry] = Field(default_factory=list, max_length=50)
