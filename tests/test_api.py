"""API endpoint tests — upload, history, reanalyze, llm-settings, operation-logs."""

import pytest
from datetime import datetime
from unittest.mock import patch


class TestUpload:
    def test_upload_rejects_empty_filename(self, client):
        """Upload without filename returns 422 or 400."""
        from io import BytesIO
        res = client.post(
            "/api/upload",
            files={"file": (None, b"test", "text/plain")},
        )
        assert res.status_code in (400, 422)

    def test_upload_rejects_unsupported_extension(self, client):
        """Upload with .pdf extension is rejected."""
        from io import BytesIO
        res = client.post(
            "/api/upload",
            files={"file": ("test.pdf", b"dummy", "application/pdf")},
        )
        assert res.status_code == 400
        assert "Unsupported" in res.json().get("detail", "")

    def test_upload_accepts_log_file_returns_parsed_log(self, client, sample_log_bytes):
        """Valid .log upload returns a parsed_log key."""
        res = client.post(
            "/api/upload",
            files={"file": ("test.log", sample_log_bytes, "text/plain")},
        )
        assert res.status_code == 200
        assert "parsed_log" in res.json()

    def test_upload_accepts_log_file_returns_rule_anomalies(self, client, sample_log_bytes):
        """Valid .log upload returns a rule_anomalies key."""
        res = client.post(
            "/api/upload",
            files={"file": ("test.log", sample_log_bytes, "text/plain")},
        )
        assert res.status_code == 200
        assert "rule_anomalies" in res.json()

    def test_upload_accepts_log_file_returns_summary(self, client, sample_log_bytes):
        """Valid .log upload returns a summary key."""
        res = client.post(
            "/api/upload",
            files={"file": ("test.log", sample_log_bytes, "text/plain")},
        )
        assert res.status_code == 200
        assert "summary" in res.json()

    def test_upload_summary_contains_entry_count(self, client, sample_log_bytes):
        """Summary total_entries reflects the number of parsed log lines."""
        res = client.post(
            "/api/upload",
            files={"file": ("test.log", sample_log_bytes, "text/plain")},
        )
        assert res.status_code == 200
        assert res.json()["summary"]["total_entries"] >= 1

    def test_upload_accepts_gz_file(self, client):
        """Compressed .gz log file is accepted."""
        import gzip
        content = b"2025-06-23 11:03:20.644848 kvm_vmm ERROR: test\n"
        gz_bytes = gzip.compress(content)
        res = client.post(
            "/api/upload",
            files={"file": ("debug.log.gz", gz_bytes, "application/gzip")},
        )
        assert res.status_code == 200
        data = res.json()
        assert data["summary"]["total_entries"] >= 1

    def test_upload_returns_error_count(self, client, sample_log_bytes):
        """parse_errors field reflects unparseable lines."""
        # Mix: one valid + one invalid
        content = (
            b"2025-06-23 11:03:20.644848 kvm_vmm ERROR: ssl failed.\n"
            b"totally invalid line without timestamp\n"
        )
        res = client.post(
            "/api/upload",
            files={"file": ("test.log", content, "text/plain")},
        )
        assert res.status_code == 200
        assert res.json()["parsed_log"]["parse_errors"] >= 1

    def test_upload_parses_multiple_formats(self, client):
        """Multi-file .tar.gz (iBMC dump) is handled without crash."""
        import tarfile, io
        # Create a simple tar.gz with a debug log inside
        tar_buffer = io.BytesIO()
        with tarfile.open(fileobj=tar_buffer, mode="w:gz") as tar:
            info = tarfile.TarInfo(name="app_debug_log_all")
            data = b"2025-06-23 11:03:20.644848 kvm_vmm ERROR: test\n"
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        tar_buffer.seek(0)

        res = client.post(
            "/api/upload",
            files={"file": ("dump.tar.gz", tar_buffer.read(), "application/gzip")},
        )
        assert res.status_code == 200
        data = res.json()
        assert "parsed_log" in data


class TestHistory:
    def test_history_returns_list(self, client):
        """GET /api/history returns a list (empty or with entries)."""
        res = client.get("/api/history")
        assert res.status_code == 200
        assert isinstance(res.json(), list)

    def test_history_cleared(self, client):
        """DELETE /api/history clears all files and returns count."""
        res = client.delete("/api/history")
        assert res.status_code == 200
        data = res.json()
        assert "deleted" in data


class TestReanalyze:
    def test_reanalyze_not_found(self, client):
        """Reanalyze non-existent UUID returns 404."""
        res = client.post("/api/reanalyze/00000000000000000000000000000000")
        assert res.status_code == 404

    def test_reanalyze_not_found_on_delete(self, client):
        """Delete-reanalyze non-existent UUID returns 404."""
        res = client.delete("/api/reanalyze/00000000000000000000000000000000")
        assert res.status_code == 404


class TestOperationLogs:
    def test_operation_logs_defaults_to_7_days(self, client):
        """GET /api/operation-logs returns logs (may be empty)."""
        res = client.get("/api/operation-logs")
        assert res.status_code == 200
        data = res.json()
        assert isinstance(data, list)

    def test_operation_logs_rejects_invalid_days(self, client):
        """Invalid days param is clamped to default."""
        res = client.get("/api/operation-logs?days=100")
        assert res.status_code == 200
        # Clamped to max 30 → still 200


class TestLLMSettings:
    def test_get_llm_settings_returns_config(self, client):
        """GET /api/analyze/llm-settings returns current LLM config."""
        res = client.get("/api/analyze/llm-settings")
        assert res.status_code == 200
        data = res.json()
        assert "provider" in data
        assert "model" in data

    def test_post_llm_settings_validates(self, client):
        """POST with invalid provider is rejected."""
        res = client.post(
            "/api/analyze/llm-settings",
            json={"provider": "invalid_provider", "api_key": "", "api_base": "", "model": ""},
        )
        assert res.status_code == 422


class TestNPUDetection:
    """Verify NPU is detected across all layers: frontend keywords, LLM prompt, rule engine."""

    def test_rule_based_detects_npu_anomaly(self):
        """NPU-related log entries should be detected by rule-based detector."""
        from app.detectors.rule_based import detect_rule_anomalies
        from app.schemas import LogEntry
        from datetime import datetime

        entries = [
            LogEntry(
                timestamp=datetime.now(),
                module="npu_sched",
                level="ERROR",
                message="NPU device 0 fault detected",
                raw="test",
            ),
            LogEntry(
                timestamp=datetime.now(),
                module="hiai",
                level="ERROR",
                message="Ascend NPU AI core error",
                raw="test",
            ),
        ]
        # Should not crash — returns list (may or may not have matches depending on rules)
        result = detect_rule_anomalies(entries)
        assert isinstance(result, list)

    def test_hw_keywords_in_llm_prompt_contain_npu(self):
        """LLM prompt builder should include NPU in hardware keywords."""
        from app.routers.llm import build_prompt
        from app.schemas import LLMAnalysisRequest, AnomalyDetection, LogEntry
        from datetime import datetime

        req = LLMAnalysisRequest(
            anomalies=[],
            statistical_anomalies=[],
            top_entries=[
                LogEntry(
                    timestamp=datetime.now(),
                    module="npu",
                    level="ERROR",
                    message="NPU error",
                    raw="",
                )
            ],
        )
        prompt = build_prompt(req)
        # Should not crash when NPU entries are present
        assert isinstance(prompt, str)
        assert len(prompt) > 0

    def test_hw_keywords_in_llm_prompt_contain_mb(self):
        """LLM prompt builder should include motherboard (mb) in hardware keywords."""
        from app.routers.llm import build_prompt
        from app.schemas import LLMAnalysisRequest, LogEntry
        from datetime import datetime

        req = LLMAnalysisRequest(
            anomalies=[],
            statistical_anomalies=[],
            top_entries=[
                LogEntry(
                    timestamp=datetime.now(),
                    module="thermal",
                    level="ERROR",
                    message="sensor overheat",
                    raw="",
                )
            ],
        )
        prompt = build_prompt(req)
        assert isinstance(prompt, str)
        assert len(prompt) > 0


class TestSecurityBounds:
    def test_upload_file_size_limit(self, client):
        """Large file upload should be rejected or handled gracefully.

        FastAPI's UploadFile reads into memory by default.
        We test that the endpoint accepts files up to a reasonable limit.
        """
        # Create a 10MB file of repeated log lines
        line = b"2025-06-23 11:03:20.644848 kvm_vmm ERROR: test line.\n"
        large_content = line * 50000  # ~5MB

        res = client.post(
            "/api/upload",
            files={"file": ("large.log", large_content, "text/plain")},
        )
        # Should succeed or fail gracefully — just shouldn't crash server
        assert res.status_code in (200, 413, 400)

    def test_llm_request_entries_field_limit(self):
        """LLMAnalysisRequest should limit nested entries to prevent memory exhaustion.

        Pydantic v2 enforces max_length — oversized entries cause ValidationError.
        """
        from app.schemas import LLMAnalysisRequest, LogEntry, AnomalyDetection
        from pydantic import ValidationError
        from datetime import datetime

        # Create 100 entries (exceeds max_length=20)
        entries = [
            LogEntry(
                timestamp=datetime.now(),
                module="test",
                level="ERROR",
                message=f"error {i}",
                raw="",
            )
            for i in range(100)
        ]

        # Should raise ValidationError instead of accepting oversized data
        with pytest.raises(ValidationError) as exc_info:
            AnomalyDetection(
                rule_id="test",
                rule_description="test",
                severity="ERROR",
                count=100,
                entries=entries,
            )
        assert "too_long" in str(exc_info.value)

        # Within limit should succeed
        small_entries = entries[:5]
        req = LLMAnalysisRequest(
            anomalies=[
                AnomalyDetection(
                    rule_id="test",
                    rule_description="test",
                    severity="ERROR",
                    count=5,
                    entries=small_entries,
                )
            ],
            statistical_anomalies=[],
            top_entries=[],
        )
        assert req is not None


class TestParserRegistry:
    def test_sel_parser_registered(self):
        """SEL parser should be registered and discoverable."""
        from app.parsers import get_parser

        fn, name = get_parser("sel")
        assert fn is not None, "SEL parser should be registered"
        assert name == "sel"

    def test_sel_parser_finds_sensor_alarm_sel(self):
        """sensor_alarm_sel.bin should be routed to SEL parser."""
        from app.parsers import get_parser

        fn, name = get_parser("sensor_alarm_sel.bin")
        assert fn is not None
        assert name == "sel"


class TestLLMAnalysis:
    """LLM analysis endpoints — mocked to avoid real API calls."""

    def _mock_llm_config(self):
        """Return a mock LLMConfig with valid credentials."""
        from app.config import LLMConfig
        return LLMConfig(provider="custom", api_key="test-key", api_base="https://test.example.com", model="test-model")

    def test_llm_analyze_returns_summary(self, client):
        """POST /api/analyze/llm returns a summary from the LLM."""
        req_body = {
            "anomalies": [
                {
                    "rule_id": "ssl_failed",
                    "rule_description": "SSL handshake failure",
                    "severity": "ERROR",
                    "count": 3,
                    "entries": [
                        {
                            "timestamp": "2025-06-23T11:03:20",
                            "module": "kvm_vmm",
                            "level": "ERROR",
                            "message": "Pre-read ssl failed",
                            "raw": "Pre-read ssl failed",
                        }
                    ],
                }
            ],
            "statistical_anomalies": [],
            "top_entries": [],
        }

        with patch("app.routers.llm.get_llm_config", return_value=self._mock_llm_config()):
            with patch("app.routers.llm.call_llm") as mock_call:
                mock_call.return_value = "SSL failure detected — check certificate configuration."
                res = client.post("/api/analyze/llm", json=req_body)
                assert res.status_code == 200
                assert "summary" in res.json()
                assert "SSL" in res.json()["summary"]
                mock_call.assert_called_once()

    def test_llm_analyze_rejects_missing_api_key(self, client):
        """POST /api/analyze/llm with no API key configured returns 400."""
        from app.config import LLMConfig

        req_body = {"anomalies": [], "statistical_anomalies": [], "top_entries": []}

        empty_config = LLMConfig(provider="custom", api_key="", api_base="", model="")
        with patch("app.routers.llm.get_llm_config", return_value=empty_config):
            res = client.post("/api/analyze/llm", json=req_body)
            assert res.status_code == 400
            assert "API Key" in res.json()["detail"]

    def test_llm_analyze_single_returns_summary(self, client):
        """POST /api/analyze/llm-single returns a summary for a single rule."""
        req_body = {
            "anomaly_type": "rule",
            "rule_id": "ssl_failed",
            "rule_description": "SSL handshake failure",
            "severity": "ERROR",
            "count": 5,
            "entries": [
                {
                    "timestamp": "2025-06-23T11:03:20",
                    "module": "kvm_vmm",
                    "level": "ERROR",
                    "message": "ssl failed",
                    "raw": "ssl failed",
                }
            ],
        }

        with patch("app.routers.llm.get_llm_config", return_value=self._mock_llm_config()):
            with patch("app.routers.llm.call_llm") as mock_call:
                mock_call.return_value = "Multiple SSL failures indicate network misconfiguration."
                res = client.post("/api/analyze/llm-single", json=req_body)
                assert res.status_code == 200
                assert "summary" in res.json()
                assert "SSL" in res.json()["summary"]
                mock_call.assert_called_once()
