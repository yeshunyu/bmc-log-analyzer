import json
import os
import urllib.error
import urllib.request
from datetime import datetime
from typing import Any
from fastapi import APIRouter, HTTPException, Request, Depends
from pydantic import BaseModel
from app.schemas import LLMAnalysisRequest
from app.config import get_llm_config, update_llm_config, LLMProvider
from app.operation_log import log_operation
from app.auth import require_api_key
from app.limiters import llm_limiter

router = APIRouter(prefix="/api/analyze", tags=["analysis"])


def _get_entry(e: Any, field: str, default: Any = None) -> Any:
    """Get field from a LogEntry dict or Pydantic model."""
    if isinstance(e, dict):
        return e.get(field, default)
    return getattr(e, field, default)


def _fmt_ts(ts: Any) -> str:
    """Safely format a timestamp (datetime object or ISO string) to Y-m-d H:M:S."""
    if ts is None:
        return "N/A"
    if isinstance(ts, datetime):
        return ts.strftime("%Y-%m-%d %H:%M:%S")
    if isinstance(ts, str) and ts:
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            return ts[:19] if len(ts) >= 19 else ts
    return str(ts)


# ---------------------------------------------------------------------------
# Settings model
# ---------------------------------------------------------------------------
class LLMSettingsRequest(BaseModel):
    provider: LLMProvider
    api_key: str
    api_base: str
    model: str


class LLMSingleRequest(BaseModel):
    anomaly_type: str   # "rule" or "stat"
    rule_id: str
    rule_description: str
    severity: str
    count: int
    entries: list  # list of LogEntry dicts


class LLMSettingsResponse(BaseModel):
    provider: LLMProvider
    api_base: str
    model: str
    api_key: str = ""


# ---------------------------------------------------------------------------
# Settings endpoints
# ---------------------------------------------------------------------------
@router.get("/llm-settings", response_model=LLMSettingsResponse)
async def get_settings(req: Request):
    cfg = get_llm_config()
    return LLMSettingsResponse(
        provider=cfg.provider,
        api_base=cfg.api_base,
        model=cfg.model,
        api_key=cfg.api_key,
    )


@router.post("/llm-settings", response_model=LLMSettingsResponse)
async def post_settings(req: LLMSettingsRequest):
    if not req.api_key:
        raise HTTPException(status_code=400, detail="API Key 不能为空")
    # SSRF protection: validate api_base URL
    import ipaddress
    from urllib.parse import urlparse
    parsed = urlparse(req.api_base or "")
    if parsed.scheme not in ("https", "http") or not parsed.netloc:
        raise HTTPException(status_code=400, detail="api_base 必须是有效的 HTTP/HTTPS URL")
    # Block private/internal IP ranges using ipaddress module
    try:
        host_ip = ipaddress.ip_address(parsed.hostname)
        if host_ip.is_private or host_ip.is_loopback or host_ip.is_reserved or host_ip.is_multicast:
            raise HTTPException(status_code=400, detail="api_base 不能使用内网地址")
    except ValueError:
        # Not an IP address, check if it's a blocked hostname
        blocked_hosts = {"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"}
        if parsed.hostname.lower() in blocked_hosts:
            raise HTTPException(status_code=400, detail="api_base 不能使用内网地址")
    cfg = update_llm_config(req.provider, req.api_key, req.api_base, req.model)
    return LLMSettingsResponse(provider=cfg.provider, api_base=cfg.api_base, model=cfg.model, api_key=cfg.api_key)


@router.post("/llm-settings/reset")
async def reset_settings():
    """Reset LLM config to defaults."""
    cfg = update_llm_config("custom", "", "https://api.deepseek.com", "")
    return LLMSettingsResponse(provider=cfg.provider, api_base=cfg.api_base, model=cfg.model)


# ---------------------------------------------------------------------------
# Prompt builder (shared by full + single)
# ---------------------------------------------------------------------------
def build_prompt(req: LLMAnalysisRequest) -> str:
    lines = ["# BMC 日志异常分析报告", ""]

    # ── Hardware taxonomy for Huawei iBMC / standard IPMI ──────────────────
    HW_KW = {
        'mb':    ['sensor', 'thermal', 'overheat', 'fan', 'voltage', 'psu',
                  'chassis', 'bios', 'boot', 'intrusion', 'sel ',
                  'system event', 'power on', 'power off', 'reset'],
        'cpu':   ['cpu', 'core', 'processor', 'core_temp', 'package_temp',
                  'processor', 'p-state', 'c-state'],
        'mem':   ['mem', 'memory', 'dram', 'ecc', 'ram', 'corrected', 'uncorrectable'],
        'disk':  ['disk', 'nvme', 'ssd', 'hdd', 'sata', 'pcie', 'block',
                  'media', 'media error', 'pcie error', 'drive', 'hdd fault'],
        'raid':  ['raid', 'lsi', 'megaraid', 'perc', 'hba', '阵列',
                  'logical drive', 'physical drive', 'vd ', 'pd ', 'bbu',
                  'rebuild', 'patrol', 'consistency'],
        'net':   ['eth', 'nic', 'network', 'ethernet', 'port', 'link',
                  'tcp', 'udp', 'mac', 'arp', 'lldp', 'mlag', 'bond'],
        'npu':   ['npu', 'ascend', 'hiai', 'dvpp', 'aicore', 'aicpu',
                  'devicecore', 'npu_ex', 'npuinfo', 'npusched', 'ai_core',
                  'ai_cpu', 'cann', 'him_config', 'hicama', 'hdc'],
        'bmc':   ['ipmi', 'sel', 'sensor', 'fru', 'sdr', 'pef', 'bmc watch',
                  'watchdog', 'webui', 'kvm', 'vmm', 'firmware', 'bmc'],
        'agent': ['agentless', 'hardware', 'signature', 'maintenance',
                  'diag', 'diagnosis', 'ism', 'ibmc', 'imanager'],
    }

    # Severity keyword map (for entries without parsed level)
    ERR_KW = ['fail', 'error', 'critical', 'fault', 'lost', 'miss', 'timeout',
              'abort', 'unable', 'incorrect', 'critical', 'emergency', 'alert']
    WARN_KW = ['warn', 'notice', 'info recovery', 'degraded']

    def detect_hw_type(msg):
        if not msg:
            return None
        lower = msg.lower()
        for hw, kws in HW_KW.items():
            for kw in kws:
                if kw in lower:
                    return hw
        return None

    def entry_level(e):
        """Return ERROR/WARNING/INFO based on raw message content."""
        raw = ((e.message or '') + ' ' + (e.module or '')).lower()
        if any(k in raw for k in ERR_KW):
            return 'ERROR'
        if any(k in raw for k in WARN_KW):
            return 'WARNING'
        lvl = (e.level or '').upper()
        if 'ERR' in lvl or 'CRIT' in lvl or 'FAIL' in lvl:
            return 'ERROR'
        if 'WARN' in lvl:
            return 'WARNING'
        return 'INFO'

    # ── Hardware summary ───────────────────────────────────────────────────
    hw_counts = {k: 0 for k in HW_KW}
    hw_entries = {k: [] for k in HW_KW}
    for e in (req.top_entries or []):
        msg = (e.message or '') + ' ' + (e.module or '')
        ht = detect_hw_type(msg)
        if ht:
            hw_counts[ht] += 1
            if len(hw_entries[ht]) < 2:
                hw_entries[ht].append(e)

    hw_total = sum(hw_counts.values())
    if hw_total > 0:
        hw_labels = {
            'mb': '主板/传感器', 'cpu': 'CPU', 'mem': '内存',
            'disk': '硬盘/NVMe', 'raid': 'RAID/存储', 'net': '网卡/网络',
            'npu': 'NPU/昇腾', 'bmc': 'BMC/iBMC', 'agent': 'Agentless',
        }
        lines.append("## 硬件相关事件概览")
        for hw, cnt in sorted(hw_counts.items(), key=lambda x: -x[1]):
            if cnt > 0:
                lines.append(f"- **{hw_labels[hw]}**：{cnt} 条")
                for e in hw_entries[hw][:2]:
                    ts = _fmt_ts(e.timestamp)
                    lvl = entry_level(e)
                    lines.append(f"  - `[{lvl}]` [{ts}] [{e.module}] {e.message[:100]}")
        lines.append("")

    # ── Anomaly patterns ──────────────────────────────────────────────────
    if req.anomalies:
        lines.append("## 检测到的异常模式")
        for a in req.anomalies[:10]:
            lines.append(f"### [{a.severity}] {a.rule_description}")
            lines.append(f"- 出现次数：{a.count}")
            if a.first_seen:
                lines.append(f"- 首次发生：{a.first_seen}")
            if a.last_seen:
                lines.append(f"- 最后发生：{a.last_seen}")
            lines.append("- 示例日志：")
            for e in a.entries[:3]:
                ts = _fmt_ts(e.timestamp)
                lvl = entry_level(e)
                lines.append(f"  - `[{lvl}]` [{ts}] [{e.module}] {e.message}")
            lines.append("")

    # ── Statistical anomalies ──────────────────────────────────────────────
    if req.statistical_anomalies:
        lines.append("## 统计异常")
        for a in req.statistical_anomalies[:5]:
            lines.append(f"- **{a.description}**")
            lines.append(f"  时间窗口：{a.window_start} ~ {a.window_end}")
            lines.append("")

    # ── Raw ERROR log ──────────────────────────────────────────────────────
    if req.top_entries:
        err_entries = [e for e in req.top_entries if entry_level(e) == 'ERROR']
        if err_entries:
            lines.append(f"## ERROR 日志（共 {len(err_entries)} 条，取前 20）")
            for e in err_entries[:20]:
                ts = _fmt_ts(e.timestamp)
                lines.append(f"[{ts}] [{e.module}] {e.message}")
            lines.append("")

    lines.append("""---
【重要指令】请根据以上日志中的**硬件底层故障特征**，而不是上层管理接口（如 PowerMgnt/API）的异常，分析以下三点。

**1. 根因判断（需要更加具体）**
*   **故障部件**：请明确判断是 物理硬盘(HDD/SSD)、RAID卡、背板(Backplane) 还是 SAS/PCIe 链路。
*   **故障位置**：请**务必提取具体的故障槽位号（如 SlotId=4）、Enclosure ID、物理驱动器编号、或 PCIe 地址**。如果无法识别准确位置，请指出推测的故障域。
*   **错误码/关键日志**：提取核心错误码（如 GetPDInfo failed 0x1001）或 S.M.A.R.T 错误详情。请忽略 `[PowerMgnt]`、`[portal]` 等管理层面的 pull 数据错误，因为它们可能是定期轮询的超时，而非物理故障本源。

**2. 优先级建议（业务导向，而非仅看温度/电源）**
*   请基于**对业务连续性和数据安全的影响**来划分优先级。
*   **P0/P1（最高优先）**：涉及数据丢失风险、盘阵降级、硬盘即将离线、业务读写中断、核心部件掉电。
*   **P2（中优先）**：风扇转速过高，温度超过阈值、硬盘预警但未完全掉线、RAID 组成员降级。
*   **P3（低优先）**：日志报错但业务无感、传感器轻微偏移、BMC 自身管理接口报错。
*   **特别说明**：硬盘故障/RAID 成员失效的优先级**不应低于**风扇或电源模块异常。

**3. 解决步骤（给出可执行的命令行与工单建议）**
请按以下结构编写操作指南，包含**诊断命令 + 物理操作 + 兜底方案**：
*   **命令级诊断**：给出具体的排查命令，例如 `storcli64 /c0 /eall /sall show` 或对应厂商工具查询故障盘状态。
*   **物理操作**：明确指出具体操作（如"加固背板及 SAS 线缆连接"、或"尝试重新插拔 SlotId=4 的硬盘"）。
*   **系统/固件修复**：如果物理操作无效，建议执行哪些操作（如"更新 RAID 卡固件"或"更换特定 SlotId 的硬盘"）。
*   **兜底方案**：如问题持续导致业务受损，建议联系对应服务器厂商（如华为、超聚变等）提供完整日志进行固件/驱动升级或 RMA 换件。

---
**回答要求（精简调整版）：**
- 中文，专业，语言**明确**。使用 Markdown 加粗关键信息，例如 `**SlotId=4**`。
- 根因判断请**直接定位到具体的 Slot 或 PCIe 位置**，避免笼统描述。
- 解决步骤请参考对应厂商（华为/超聚变等）的现有运维工具与手段。
- 必须**先排除 `PowerMgnt`、`[portal]` 等管理接口偶发超时层面的干扰**，聚焦底层硬件报错。""")

    return "\n".join(lines)


def build_single_prompt(anomaly_type: str, rule_id: str, rule_description: str,
                         severity: str, count: int, entries) -> str:
    """Build prompt for a single anomaly card analysis."""
    ERR_KW = ['fail', 'error', 'critical', 'fault', 'lost', 'miss',
              'timeout', 'abort', 'unable', 'incorrect', 'emergency', 'alert']
    WARN_KW = ['warn', 'notice', 'info recovery', 'degraded']

    def entry_level(e):
        raw = ((_get_entry(e, 'message') or '') + ' ' + (_get_entry(e, 'module') or '')).lower()
        if any(k in raw for k in ERR_KW):
            return 'ERROR'
        if any(k in raw for k in WARN_KW):
            return 'WARNING'
        lvl = (_get_entry(e, 'level') or '').upper()
        if 'ERR' in lvl or 'CRIT' in lvl or 'FAIL' in lvl:
            return 'ERROR'
        if 'WARN' in lvl:
            return 'WARNING'
        return 'INFO'

    lines = [
        "# 单条异常根因分析",
        "",
        f"## 异常类型：{anomaly_type}",
        f"### [{severity}] {rule_description}",
        f"- 出现次数：{count}",
        "",
        "## 关联日志（采样最多5条）：",
    ]
    for e in entries[:5]:
        ts = _fmt_ts(_get_entry(e, 'timestamp'))
        lvl = entry_level(e)
        lines.append(f"- `[{lvl}]` [{ts}] [{_get_entry(e, 'module')}] {_get_entry(e, 'message')}")
    lines.append("")
    lines.append("""【重要指令】请根据这条异常的**硬件底层故障特征**进行分析。

**1. 根因判断**
*   **故障部件**：判断是物理硬盘、RAID卡、背板还是 SAS/PCIe 链路故障。
*   **故障位置**：提取具体的故障槽位号（如 SlotId=4）、Enclosure ID 或 PCIe 地址。
*   **错误码/关键日志**：提取核心错误码（如 GetPDInfo failed 0x1001）或 S.M.A.R.T 错误。请忽略 `PowerMgnt`、`portal` 等管理接口超时，它们可能是轮询超时而非物理故障本源。

**2. 优先级建议**
*   **P0/P1**：数据丢失风险、盘阵降级、硬盘即将离线、业务中断 → 最高优先
*   **P2**：硬盘预警未掉线、RAID 成员降级 → 中优先
*   **P3**：业务无感的日志报错 → 低优先

**3. 解决步骤**
*   **命令诊断**：`storcli64 /c0 /eall /sall show` 或厂商工具
*   **物理操作**：如"加固背板 SAS 线缆"或"重新插拔 SlotId=X 硬盘"
*   **固件修复**：更新 RAID 卡固件或更换故障硬盘
*   **兜底方案**：联系华为/超聚变厂商进行固件升级或 RMA 换件

**回答要求**：中文回答，使用 Markdown 加粗关键位置（如 `**SlotId=4**`），直接定位到具体槽位，避免笼统描述。""")
    return "\n".join(lines)


# --------------------------------------------------------------------------
# Generic OpenAI-compatible custom API driver (auto-detects Anthropic vs OpenAI by URL)
# ---------------------------------------------------------------------------
def _call_custom(prompt: str, api_key: str, api_base: str, model: str) -> str:
    """Try OpenAI-compatible first, fall back to Anthropic-compatible.

    Attempts both interfaces with the same prompt and returns whichever
    responds with a valid structure — no need to guess from URL path.
    """
    # Try OpenAI /chat/completions
    try:
        result = _call_openai_compatible(prompt, api_key, api_base, model)
        return result
    except (KeyError, IndexError, RuntimeError):
        pass

    # Fall back to Anthropic /messages
    try:
        return _call_anthropic_compatible(prompt, api_key, api_base, model)
    except (KeyError, IndexError, RuntimeError) as e:
        raise RuntimeError(
            f"API 接口响应格式错误（尝试了 OpenAI 和 Anthropic 两种接口），"
            f"请检查 api_base 是否正确。底层错误: {e}"
        )


def _call_openai_compatible(prompt: str, api_key: str, api_base: str, model: str) -> str:
    import urllib.request
    import urllib.error

    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.3,
    }
    body = json.dumps(payload).encode("utf-8")

    req = urllib.request.Request(
        f"{api_base.rstrip('/')}/chat/completions",
        data=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data["choices"][0]["message"]["content"].strip()
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8")
        raise RuntimeError(f"API 错误 {e.code}: {body[:500]}")
    except (KeyError, IndexError) as e:
        raise RuntimeError(f"响应格式错误: {e}")


def _call_anthropic_compatible(prompt: str, api_key: str, api_base: str, model: str) -> str:
    """Anthropic Messages API compatible driver (e.g. DeepSeek Anthropic endpoint)."""
    import urllib.request
    import urllib.error

    # Don't auto-prepend claude- for non-Anthropic models like MiniMax-M2.7
    anthropic_model = model if model.startswith("claude-") or model.startswith("anthropic") else model

    payload = {
        "model": anthropic_model,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": 4096,
        "temperature": 0.3,
    }
    body = json.dumps(payload).encode("utf-8")

    # Anthropic-compatible base already contains /anthropic, just append /messages
    # MiniMax/DeepSeek use Authorization: Bearer like OpenAI, not x-api-key like standard Anthropic
    is_special = "minimax" in api_base.lower() or "deepseek" in api_base.lower()
    auth_header = f"Bearer {api_key}" if is_special else api_key
    headers = {
        "Content-Type": "application/json",
        "Authorization": auth_header,
        "anthropic-version": "2023-06-01",
    }
    if not is_special:
        headers["x-api-key"] = api_key

    req = urllib.request.Request(
        f"{api_base.rstrip('/')}/v1/messages",
        data=body,
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            # Anthropic-compatible returns content as [{"type": "text", "text": "..."}]
            # or [{"type": "thinking", ...}, {"type": "text", "text": "..."}]
            # Some providers like MiniMax may return simpler formats
            content = data.get("content") or []
            if isinstance(content, list):
                for item in content:
                    if isinstance(item, dict) and item.get("type") == "text":
                        return item["text"].strip()
            # MiniMax may return content directly as a string
            if isinstance(content, str) and content:
                return content.strip()
            # Fallback: try common response structures
            if data.get("text"):
                return data["text"].strip()
            raise RuntimeError("响应中未找到 text 类型的 content")
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8")
        raise RuntimeError(f"API 错误 {e.code}: {body[:500]}")
    except (KeyError, IndexError) as e:
        raise RuntimeError(f"响应格式错误: {e}")


# ---------------------------------------------------------------------------
# Main analysis endpoint (rate limited: 10/min per IP)
# ---------------------------------------------------------------------------
@llm_limiter.limit("10/minute")
@router.post("/llm")
async def llm_analyze(request: Request, data: LLMAnalysisRequest):
    prompt = build_prompt(data)
    cfg = get_llm_config()

    try:
        if not cfg.api_key:
            raise HTTPException(
                status_code=400,
                detail="LLM API Key 未设置，请在页面右上角「LLM 配置」中进行配置。",
            )
        result_text = _call_custom(prompt, cfg.api_key, cfg.api_base, cfg.model)

        log_operation(
            operation="llm_analysis",
            detail=f"LLM 全文分析，provider={cfg.provider}，model={cfg.model}",
            result="ok",
            extra={"provider": cfg.provider, "model": cfg.model, "prompt_chars": len(prompt)},
        )
        return {"summary": result_text}
    except HTTPException:
        raise  # Re-raise HTTPException without wrapping it
    except Exception as e:
        log_operation(operation="llm_analysis", detail=f"LLM 分析失败: {e}", result="error", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@llm_limiter.limit("10/minute")
@router.post("/llm-single")
async def llm_analyze_single(request: Request, data: LLMSingleRequest):
    prompt = build_single_prompt(
        anomaly_type=data.anomaly_type,
        rule_id=data.rule_id,
        rule_description=data.rule_description,
        severity=data.severity,
        count=data.count,
        entries=data.entries,
    )
    cfg = get_llm_config()

    try:
        if not cfg.api_key:
            raise HTTPException(
                status_code=400,
                detail="LLM API Key 未设置，请在页面右上角「LLM 配置」中进行配置。",
            )
        result_text = _call_custom(prompt, cfg.api_key, cfg.api_base, cfg.model)

        log_operation(
            operation="llm_analysis_single",
            detail=f"LLM 单规则分析，provider={cfg.provider}，model={cfg.model}，rule={data.rule_id}",
            result="ok",
            extra={"provider": cfg.provider, "model": cfg.model, "rule_id": data.rule_id, "severity": data.severity},
        )
        return {"summary": result_text}
    except HTTPException:
        raise
    except Exception as e:
        log_operation(operation="llm_analysis_single", detail=f"LLM 单规则分析失败: {e}", result="error", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))
