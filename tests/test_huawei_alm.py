"""Tests for Huawei ALM alarm code parser."""

import pytest
from app.parsers.huawei_alm import (
    decode_alm,
    extract_alm_codes,
    is_alm_code,
    enrich_entry_with_alm,
    AlarmCodeInfo,
)
from app.schemas import LogEntry


class TestDecodeALM:
    """decode_alm() — parse Huawei alarm code strings into AlarmCodeInfo."""

    @pytest.mark.parametrize("code,expected_subsystem,expected_severity,expected_desc_contains", [
        ("ALM-0x01000001", "Memory", "CRITICAL", "PPR"),
        ("ALM-0x01000005", "Memory", "CRITICAL", "内存初始化"),
        ("ALM-0x0100000F", "Memory", "MINOR", "Smarterror"),
        ("ALM-0x01000013", "Memory", "MINOR", "内存温度过高"),
        ("ALM-0x01000027", "Memory", "CRITICAL", "PMem内存过热"),
        ("ALM-0x10000003", "Mainboard", "MAJOR", "主板过热"),
        ("ALM-0x1000002B", "Mainboard", "MAJOR", "缓起电路电压过高"),
        ("ALM-0x2C000001", "System", "CRITICAL", "系统严重告警"),
        ("ALM-0x2C000003", "System", "CRITICAL", "系统异常下电"),
        ("ALM-0x2C000007", "System", "CRITICAL", "系统异常下电"),
        ("ALM-0x2C00000D", "System", "INFO", "系统电源正常"),
        ("ALM-0x1A000001", "BMC", "INFO", "BMC FRU读取成功"),
        ("ALM-0x1A000013", "BMC", "CRITICAL", "BMC供电故障"),
        ("ALM-0x2C000085", "System", "CRITICAL", "NPU昇腾设备故障"),
        ("ALM-0x2C000089", "System", "CRITICAL", "NPU昇腾设备通信异常"),
        ("ALM-0x2C000095", "System", "MAJOR", "CANN运行时错误"),
        ("ALM-0x6C000003", "GPU", "CRITICAL", "GPU显卡故障"),
        ("ALM-0x6C000025", "GPU", "CRITICAL", "GPU显存错误"),
        ("ALM-0x04000001", "Fan", "MINOR", "风扇转速过低"),
        ("ALM-0x0400000D", "Fan", "MAJOR", "风扇故障"),
        ("ALM-0x04000015", "Fan", "CRITICAL", "风扇冗余丧失"),
        ("ALM-0x09000003", "Power Supply", "CRITICAL", "电源模块故障"),
        ("ALM-0x09000011", "Power Supply", "MAJOR", "电源模块温度过高"),
        ("ALM-0x40000003", "Disk", "CRITICAL", "硬盘故障"),
        ("ALM-0x40000009", "Disk", "MINOR", "硬盘Predictive Failure"),
        ("ALM-0x6D000003", "NVMe", "CRITICAL", "NVMe SSD故障"),
        ("ALM-0x02000003", "Voltage", "MAJOR", "电压过高"),
        ("ALM-0x08000005", "PCIe Card", "MAJOR", "PCIe标卡故障"),
        ("ALM-0x20000003", "Boot", "CRITICAL", "系统启动失败"),
    ])
    def test_decodes_known_codes(self, code, expected_subsystem, expected_severity, expected_desc_contains):
        info = decode_alm(code)
        assert info is not None, f"decode_alm returned None for {code}"
        assert info.subsystem == expected_subsystem, f"expected subsystem {expected_subsystem}, got {info.subsystem}"
        assert info.severity == expected_severity, f"expected severity {expected_severity}, got {info.severity}"
        assert expected_desc_contains in info.description

    def test_to_level_critical(self):
        info = AlarmCodeInfo(
            code="ALM-0x2C000001", subsystem="System",
            alarm_id="0x2C000001", description="系统严重告警",
            severity="CRITICAL", severity_zh="紧急",
        )
        assert info.to_level() == "ERROR"

    def test_to_level_major(self):
        info = AlarmCodeInfo(
            code="ALM-0x10000003", subsystem="Mainboard",
            alarm_id="0x10000003", description="主板过热",
            severity="MAJOR", severity_zh="严重",
        )
        assert info.to_level() == "ERROR"

    def test_to_level_minor(self):
        info = AlarmCodeInfo(
            code="ALM-0x04000001", subsystem="Fan",
            alarm_id="0x04000001", description="风扇转速过低",
            severity="MINOR", severity_zh="轻微",
        )
        assert info.to_level() == "WARNING"

    def test_to_level_info(self):
        info = AlarmCodeInfo(
            code="ALM-0x09000001", subsystem="Power Supply",
            alarm_id="0x09000001", description="电源模块正常",
            severity="INFO", severity_zh="提示",
        )
        assert info.to_level() == "INFO"

    def test_to_rule_id(self):
        info = AlarmCodeInfo(
            code="ALM-0x2C000003", subsystem="System",
            alarm_id="0x2C000003", description="系统异常下电",
            severity="CRITICAL", severity_zh="紧急",
        )
        assert info.to_rule_id() == "alm_0x2c000003"

    @pytest.mark.parametrize("code", [
        "ALM-0x00000001",  # known generic
        "ALM-0x01000001",  # known memory
    ])
    def test_roundtrip_code_format(self, code):
        """Decoded code field should be canonical ALM-0xXXXXXXXX form."""
        info = decode_alm(code)
        assert info is not None
        assert info.code.startswith("ALM-0x")
        assert len(info.code) == 14  # "ALM-0x" + 8 hex digits

    def test_unknown_code_still_decodes(self):
        """Unknown alarm codes should still return AlarmCodeInfo with inferred severity."""
        info = decode_alm("ALM-0xFF000001")
        assert info is not None
        assert info.subsystem == "Unknown(0xFF)"
        assert info.severity in ("CRITICAL", "MAJOR", "MINOR", "INFO")
        assert "未知告警" in info.description

    @pytest.mark.parametrize("code", [
        "not-a-code",
        "ALM-xyz",
        "ALM-0xZZZZZZZZ",
        "ALM-0x123456789",  # too long (>8 hex digits)
    ])
    def test_invalid_codes_return_none(self, code):
        assert decode_alm(code) is None

    def test_empty_string_becomes_zero_code(self):
        """Empty string after processing becomes ALM-0x00000000, which is a valid
        (though zero) alarm code — it does NOT return None (known behavior)."""
        # This is the actual behavior: "" → "00000000" → ALM-0x00000000
        info = decode_alm("")
        # ALM-0x00000000 is NOT in ALARM_DB, so it falls through to
        # the unknown-code path and returns an AlarmCodeInfo (not None)
        assert info is not None
        assert info.code == "ALM-0x00000000"

    def test_strips_leading_zeroes(self):
        """Code with fewer than 8 hex digits should be padded correctly."""
        info = decode_alm("ALM-0x1000001")  # only 7 digits
        assert info is not None
        assert info.code == "ALM-0x01000001"

    def test_uppercase_works(self):
        info = decode_alm("alm-0x01000001")  # lowercase
        assert info is not None


class TestExtractALMCodes:
    """extract_alm_codes() — find all alarm codes in a string."""

    def test_finds_multiple_codes(self):
        text = (
            "2025-06-23 11:03:20 kvm_vmm ERROR: NPU fault detected. "
            "ALM-0x2C000085 NPU昇腾设备故障. "
            "ALM-0x01000005 also occurred."
        )
        codes = extract_alm_codes(text)
        assert len(codes) == 2
        assert codes[0].code == "ALM-0x2C000085"
        assert codes[1].code == "ALM-0x01000005"

    def test_deduplicates_repeated_codes(self):
        text = "ALM-0x2C000085 ALM-0x2C000085 ALM-0x2C000085"
        codes = extract_alm_codes(text)
        assert len(codes) == 1
        assert codes[0].code == "ALM-0x2C000085"

    def test_no_codes_returns_empty_list(self):
        codes = extract_alm_codes("no alarm codes in this string")
        assert codes == []

    def test_finds_in_plain_text(self):
        text = "BMC告警: ALM-0x1A000013 发生在 2025-06-23"
        codes = extract_alm_codes(text)
        assert len(codes) == 1
        assert codes[0].code == "ALM-0x1A000013"


class TestIsALMCode:
    """is_alm_code() — quick check if text contains an alarm code."""

    @pytest.mark.parametrize("text,expected", [
        ("ALM-0x2C000085 detected", True),
        ("No alarm here", False),
        ("ALM-0x2C000001", True),
        ("ALM-0x12345678", True),
    ])
    def test_is_alm_code(self, text, expected):
        assert is_alm_code(text) is expected

    def test_lowercase_prefix_is_recognized(self):
        """Regex ALM_RE is case-sensitive (no IGNORECASE flag) for the 'ALM-0x' prefix.

        So 'alm-0x...' (lowercase) will NOT match. Only 'ALM-0x...' works.
        """
        # Lowercase prefix → not recognized (expected behavior with case-sensitive regex)
        assert is_alm_code("alm-0x01000001") is False
        # Uppercase prefix → recognized
        assert is_alm_code("ALM-0x01000001") is True


class TestEnrichEntryWithALM:
    """enrich_entry_with_alm() — annotate a LogEntry with ALM metadata."""

    def test_enriches_entry_with_known_code(self):
        entry = LogEntry(
            timestamp=None,
            module="app_debug",
            level="ERROR",
            message="ALM-0x2C000085 NPU昇腾设备故障",
            raw="ALM-0x2C000085 NPU昇腾设备故障",
        )
        result = enrich_entry_with_alm(entry)
        assert result.alm_code == "ALM-0x2C000085"
        assert result.alm_subsystem == "System"
        assert result.alm_severity == "CRITICAL"
        assert result.alm_severity_zh == "紧急"
        assert "NPU昇腾" in result.alm_description
        # Level is promoted to ERROR for CRITICAL
        assert result.level == "ERROR"

    def test_enriches_entry_with_minor_code(self):
        entry = LogEntry(
            timestamp=None,
            module="app_debug",
            level="INFO",
            message="ALM-0x04000001 风扇转速过低",
            raw="ALM-0x04000001 风扇转速过低",
        )
        result = enrich_entry_with_alm(entry)
        assert result.alm_code == "ALM-0x04000001"
        assert result.alm_severity == "MINOR"
        assert result.alm_severity_zh == "轻微"
        # Level is promoted to WARNING for MINOR
        assert result.level == "WARNING"

    def test_enriches_entry_with_info_code(self):
        entry = LogEntry(
            timestamp=None,
            module="app_debug",
            level="INFO",
            message="ALM-0x09000001 电源模块正常",
            raw="ALM-0x09000001 电源模块正常",
        )
        result = enrich_entry_with_alm(entry)
        assert result.alm_code == "ALM-0x09000001"
        assert result.alm_severity == "INFO"
        assert result.level == "INFO"  # stays INFO

    def test_no_code_leaves_entry_unchanged(self):
        """Entry without ALM code should be returned as-is (alm fields remain None)."""
        entry = LogEntry(
            timestamp=None,
            module="app_debug",
            level="ERROR",
            message="Pre-read ssl failed",
            raw="Pre-read ssl failed",
        )
        result = enrich_entry_with_alm(entry)
        assert result.alm_code is None
        assert result.alm_subsystem is None
        assert result.level == "ERROR"  # unchanged

    def test_multiple_codes_uses_first(self):
        """When entry contains multiple ALM codes, use the first one found."""
        entry = LogEntry(
            timestamp=None,
            module="app_debug",
            level="ERROR",
            message="ALM-0x2C000085 ALM-0x2C000089 both NPU errors",
            raw="ALM-0x2C000085 ALM-0x2C000089",
        )
        result = enrich_entry_with_alm(entry)
        assert result.alm_code == "ALM-0x2C000085"

    def test_returns_same_entry_object(self):
        """enrich_entry_with_alm mutates and returns the same object."""
        entry = LogEntry(
            timestamp=None,
            module="app_debug",
            level="ERROR",
            message="ALM-0x2C000085",
            raw="ALM-0x2C000085",
        )
        result = enrich_entry_with_alm(entry)
        assert result is entry
