import json
import subprocess
from datetime import datetime
from typing import Any
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from app.schemas import LLMAnalysisRequest
from app.config import get_llm_config, update_llm_config, LLMProvider
from app.operation_log import log_operation

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


# ---------------------------------------------------------------------------
# Settings endpoints
# ---------------------------------------------------------------------------
@router.get("/llm-settings", response_model=LLMSettingsResponse)
async def get_settings():
    cfg = get_llm_config()
    return LLMSettingsResponse(provider=cfg.provider, api_base=cfg.api_base, model=cfg.model)


@router.post("/llm-settings", response_model=LLMSettingsResponse)
async def post_settings(req: LLMSettingsRequest):
    # Require api_key for custom provider
    if req.provider == "custom" and not req.api_key:
        raise HTTPException(status_code=400, detail="自定义 API 需要提供 api_key")
    cfg = update_llm_config(req.provider, req.api_key, req.api_base, req.model)
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

    lines.append("""请分析以上日志，回答以下三点：
1. **根因判断**：这些异常最可能的根本原因是什么？（是否涉及 CPU/内存/硬盘/RAID/网卡/NPU 等硬件？是否是固件/配置问题？）
2. **优先级建议**：哪些异常需要优先处理？（特别是电源、风扇、温度、过载类异常应最高优先级）
3. **解决步骤**：建议的解决步骤或进一步调查方向？（如检查硬件健康状态、更新固件、联系华为技术支持等）

**回答要求**：
- 用中文回答，简洁专业，突出重点，每点 2-4 句话
- 重点关注 CPU、内存、硬盘/RAID、网络等硬件问题
- 如果异常具有时间相关性（如每次重启后出现），请特别指出""")

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
    lines.append("""请分析这条异常，回答：
1. **根因判断**：最可能的根本原因是什么？（是否涉及 CPU/内存/硬盘/RAID/网卡/NPU 等硬件？是否是固件/配置/BMC 问题？）
2. **解决步骤**：建议的解决步骤或进一步调查方向？（如检查硬件健康状态命令、固件版本、联系华为技术支持等）

**回答要求**：用中文回答，简洁专业，突出重点，3-5句话为宜。""")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# MiniMax (mmx CLI) driver
# ---------------------------------------------------------------------------
def _call_minimax(prompt: str) -> str:
    result = subprocess.run(
        ["mmx", "text", "chat", "--output", "text", "--message", prompt],
        capture_output=True,
        text=True,
        timeout=120,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "MiniMax CLI 返回非零")
    return result.stdout.strip()


# ---------------------------------------------------------------------------
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

    # Anthropic model names start with claude-*
    anthropic_model = model if model.startswith("claude-") else f"claude-{model}"

    payload = {
        "model": anthropic_model,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": 1024,
        "temperature": 0.3,
    }
    body = json.dumps(payload).encode("utf-8")

    # Anthropic-compatible base already contains /anthropic, just append /messages
    req = urllib.request.Request(
        f"{api_base.rstrip('/')}/v1/messages",
        data=body,
        headers={
            "Content-Type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            # MiniMax Anthropic-compatible returns content as [{"type": "text", "text": "..."}]
            # or [{"type": "thinking", ...}, {"type": "text", "text": "..."}]
            for item in (data.get("content") or []):
                if item.get("type") == "text":
                    return item["text"].strip()
            raise RuntimeError("响应中未找到 text 类型的 content")
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8")
        raise RuntimeError(f"API 错误 {e.code}: {body[:500]}")
    except (KeyError, IndexError) as e:
        raise RuntimeError(f"响应格式错误: {e}")


# ---------------------------------------------------------------------------
# Main analysis endpoint
# ---------------------------------------------------------------------------
@router.post("/llm")
async def llm_analyze(req: LLMAnalysisRequest):
    prompt = build_prompt(req)
    cfg = get_llm_config()

    try:
        if cfg.provider == "minimax":
            result_text = _call_minimax(prompt)
        else:
            if not cfg.api_key:
                raise HTTPException(
                    status_code=400,
                    detail="自定义 API Key 未设置，请先在设置中配置。",
                )
            result_text = _call_custom(prompt, cfg.api_key, cfg.api_base, cfg.model)

        log_operation(
            operation="llm_analysis",
            detail=f"LLM 全文分析，provider={cfg.provider}，model={cfg.model}",
            result="ok",
            extra={"provider": cfg.provider, "model": cfg.model, "prompt_chars": len(prompt)},
        )
        return {"summary": result_text}
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="LLM 分析超时（2分钟）")
    except Exception as e:
        log_operation(operation="llm_analysis", detail=f"LLM 分析失败: {e}", result="error", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/llm-single")
async def llm_analyze_single(req: LLMSingleRequest):
    prompt = build_single_prompt(
        anomaly_type=req.anomaly_type,
        rule_id=req.rule_id,
        rule_description=req.rule_description,
        severity=req.severity,
        count=req.count,
        entries=req.entries,
    )
    cfg = get_llm_config()

    try:
        if cfg.provider == "minimax":
            result_text = _call_minimax(prompt)
        else:
            if not cfg.api_key:
                raise HTTPException(
                    status_code=400,
                    detail="自定义 API Key 未设置，请先在设置中配置。",
                )
            result_text = _call_custom(prompt, cfg.api_key, cfg.api_base, cfg.model)

        log_operation(
            operation="llm_analysis_single",
            detail=f"LLM 单规则分析，provider={cfg.provider}，model={cfg.model}，rule={req.rule_id}",
            result="ok",
            extra={"provider": cfg.provider, "model": cfg.model, "rule_id": req.rule_id, "severity": req.severity},
        )
        return {"summary": result_text}
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="LLM 分析超时（2分钟）")
    except Exception as e:
        log_operation(operation="llm_analysis_single", detail=f"LLM 单规则分析失败: {e}", result="error", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))
