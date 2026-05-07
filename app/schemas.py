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
    # Huawei ALM alarm code fields (populated by huawei_alm.enrich_entry_with_alm)
    alm_code: Optional[str] = None
    alm_subsystem: Optional[str] = None
    alm_severity: Optional[str] = None   # CRITICAL/MAJOR/MINOR/INFO
    alm_severity_zh: Optional[str] = None
    alm_description: Optional[str] = None


class ParsedLog(BaseModel):
    format_type: str
    total_lines: int
    entries: list[LogEntry]
    parse_errors: int = 0
    file_name: Optional[str] = None
    time_range: list[Optional[str]] = Field(default_factory=lambda: [None, None])


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
    alm_anomalies: list[AnomalyDetection] = Field(default_factory=list)  # Huawei ALM alarm codes
    statistical_anomalies: list[StatisticalAnomaly]
    summary: dict


class ChatMessage(BaseModel):
    role: str  # "user" | "assistant" | "system"
    content: str

class ChatRequest(BaseModel):
    messages: list[ChatMessage]
    system_prompt: str = ""

class LLMAnalysisRequest(BaseModel):
    anomalies: list[AnomalyDetection]
    statistical_anomalies: list[StatisticalAnomaly]
    top_entries: list[LogEntry] = Field(default_factory=list, max_length=50)
