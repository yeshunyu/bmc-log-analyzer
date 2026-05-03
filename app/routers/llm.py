import json
import subprocess
from datetime import datetime
from typing import Any
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from app.schemas import LLMAnalysisRequest
from app.config import get_llm_config, update_llm_config, LLMProvider

router = APIRouter(prefix="/api/analyze", tags=["analysis"])


def _fmt_ts(ts: Any) -> str:
    """Safely format a timestamp (datetime object or ISO string) to Y-m-d H:M:S."""
    if ts is None:
        return "N/A"
    if isinstance(ts, datetime):
        return ts.strftime("%Y-%m-%d %H:%M:%S")
    if isinstance(ts, str) and ts:
        try:
            # Parse ISO format datetime string
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
    cfg = update_llm_config(req.provider, req.api_key, req.api_base, req.model)
    return LLMSettingsResponse(provider=cfg.provider, api_base=cfg.api_base, model=cfg.model)


# ---------------------------------------------------------------------------
# Prompt builder (shared by full + single)
# ---------------------------------------------------------------------------
def build_prompt(req: LLMAnalysisRequest) -> str:
    lines = ["# BMC 日志异常分析报告", ""]

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
                lines.append(f"  [{ts}] [{e.module}] {e.message}")
            lines.append("")

    if req.statistical_anomalies:
        lines.append("## 统计异常")
        for a in req.statistical_anomalies[:5]:
            lines.append(f"- {a.description}")
            lines.append(f"  时间窗口：{a.window_start} ~ {a.window_end}")
            lines.append("")

    if req.top_entries:
        lines.append("## Top ERROR 日志（按时间排序）")
        for e in req.top_entries[:20]:
            ts = _fmt_ts(e.timestamp)
            lines.append(f"[{ts}] [{e.module}] {e.message}")
        lines.append("")

    lines.append("""请分析以上日志，回答：
1. 这些异常最可能的根本原因是什么？
2. 哪些异常需要优先处理？
3. 建议的解决步骤或进一步的调查方向？
请用中文回答，简洁专业，突出重点。""")

    return "\n".join(lines)


def build_single_prompt(anomaly_type: str, rule_id: str, rule_description: str,
                         severity: str, count: int, entries) -> str:
    """Build prompt for a single anomaly card analysis."""
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
        ts = _fmt_ts(e.timestamp)
        lines.append(f"- [{ts}] [{e.module}] {e.message}")
    lines.append("")
    lines.append("""请分析这条异常，回答：
1. 最可能的根本原因是什么？
2. 建议的解决步骤或进一步调查方向？
请用中文回答，简洁专业，突出重点（3-5句话为宜）。""")
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
# Generic OpenAI-compatible custom API driver
# ---------------------------------------------------------------------------
def _call_custom(prompt: str, api_key: str, api_base: str, model: str) -> str:
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

        return {"summary": result_text}
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="LLM 分析超时（2分钟）")
    except Exception as e:
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

        return {"summary": result_text}
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="LLM 分析超时（2分钟）")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
