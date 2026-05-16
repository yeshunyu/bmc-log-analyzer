"""LLM analysis endpoints: settings, full analysis, single anomaly, chat.

Business logic extracted to:
  app/llm/prompts.py  -- prompt builders
  app/llm/driver.py   -- API drivers (OpenAI / Anthropic)
  app/security/ssrf.py -- SSRF + DNS cache
"""
import ipaddress
from typing import Any
from urllib.parse import urlparse

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from app.schemas import LLMAnalysisRequest, ChatRequest
from app.config import get_llm_config, update_llm_config, LLMProvider
from app.operation_log import log_operation
from app.auth import require_api_key
from app.limiters import llm_limiter
from app.llm.prompts import build_prompt, build_single_prompt
from app.llm.driver import call_llm, call_llm_chat

router = APIRouter(prefix="/api/analyze", tags=["analysis"])


# -----------------------------------------------------------------------------
# Settings models
# -----------------------------------------------------------------------------


class LLMSettingsRequest(BaseModel):
    provider: LLMProvider
    api_key: str
    api_base: str
    model: str


class LLMSingleRequest(BaseModel):
    anomaly_type: str  # "rule" or "stat"
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


# -----------------------------------------------------------------------------
# Settings endpoints
# -----------------------------------------------------------------------------


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


# -----------------------------------------------------------------------------
# Main analysis endpoint (rate limited: 10/min per IP)
# -----------------------------------------------------------------------------


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
        result_text = call_llm(prompt, cfg.api_key, cfg.api_base, cfg.model)

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
        result_text = call_llm(prompt, cfg.api_key, cfg.api_base, cfg.model)

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


# -----------------------------------------------------------------------------
# Chat endpoint (multi-turn, rate limited: 20/min per IP)
# -----------------------------------------------------------------------------


@llm_limiter.limit("20/minute")
@router.post("/chat")
async def llm_chat(request: Request, data: ChatRequest):
    cfg = get_llm_config()

    try:
        if not cfg.api_key:
            raise HTTPException(
                status_code=400,
                detail="LLM API Key 未设置，请在页面右上角「LLM 配置」中进行配置。",
            )

        messages = [{"role": m.role, "content": m.content} for m in data.messages]
        result_text = call_llm_chat(
            messages, cfg.api_key, cfg.api_base, cfg.model,
            system_prompt=data.system_prompt,
        )

        return {"reply": result_text}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
