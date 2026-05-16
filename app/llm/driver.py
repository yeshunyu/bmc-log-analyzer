"""OpenAI- and Anthropic-compatible API drivers for LLM calls.

Drivers handle HTTP communication, error parsing, and response normalization.
Auto-detects API style from URL, with explicit provider-specific tweaks.
"""
import json
from typing import Any

from app.security.ssrf import validate_ssrf


# -----------------------------------------------------------------------------
# Core: auto-detecting driver
# -----------------------------------------------------------------------------


def call_llm(prompt: str, api_key: str, api_base: str, model: str) -> str:
    """Try OpenAI-compatible first, fall back to Anthropic-compatible.

    Attempts both interfaces and returns whichever responds with a valid
    structure — no need to guess from URL path.
    """
    try:
        return _call_openai(prompt, api_key, api_base, model)
    except (KeyError, IndexError, RuntimeError):
        pass
    try:
        return _call_anthropic(prompt, api_key, api_base, model)
    except (KeyError, IndexError, RuntimeError) as e:
        raise RuntimeError(
            f"API 接口响应格式错误（尝试了 OpenAI 和 Anthropic 两种接口），"
            f"请检查 api_base 是否正确。底层错误: {e}"
        )


def call_llm_chat(
    messages: list[dict[str, str]],
    api_key: str,
    api_base: str,
    model: str,
    system_prompt: str = "",
) -> str:
    """Multi-turn version of call_llm. Tries OpenAI first, then Anthropic."""
    try:
        return _call_openai_chat(messages, api_key, api_base, model, system_prompt)
    except (KeyError, IndexError, RuntimeError):
        pass
    try:
        return _call_anthropic_chat(messages, api_key, api_base, model, system_prompt)
    except (KeyError, IndexError, RuntimeError) as e:
        raise RuntimeError(
            f"API 接口响应格式错误（尝试了 OpenAI 和 Anthropic 两种接口），"
            f"请检查 api_base 是否正确。底层错误: {e}"
        )


# -----------------------------------------------------------------------------
# OpenAI-compatible
# -----------------------------------------------------------------------------


def _call_openai(prompt: str, api_key: str, api_base: str, model: str) -> str:
    """OpenAI /chat/completions driver."""
    import urllib.error
    import urllib.request

    validate_ssrf(api_base)

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
        body_str = e.read().decode("utf-8")
        raise RuntimeError(f"API 错误 {e.code}: {body_str[:500]}")
    except (KeyError, IndexError) as e:
        raise RuntimeError(f"响应格式错误: {e}")


def _call_openai_chat(
    messages: list[dict[str, str]],
    api_key: str,
    api_base: str,
    model: str,
    system_prompt: str = "",
) -> str:
    """OpenAI-compatible multi-turn chat."""
    import urllib.error
    import urllib.request

    validate_ssrf(api_base)

    api_messages = []
    if system_prompt:
        api_messages.append({"role": "system", "content": system_prompt})
    api_messages.extend(messages)

    payload = {
        "model": model,
        "messages": api_messages,
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
        err_body = e.read().decode("utf-8")
        raise RuntimeError(f"API 错误 {e.code}: {err_body[:500]}")
    except (KeyError, IndexError) as e:
        raise RuntimeError(f"响应格式错误: {e}")


# -----------------------------------------------------------------------------
# Anthropic-compatible
# -----------------------------------------------------------------------------


def _call_anthropic(prompt: str, api_key: str, api_base: str, model: str) -> str:
    """Anthropic Messages API compatible driver (e.g. MiniMax, DeepSeek)."""
    import urllib.error
    import urllib.request

    validate_ssrf(api_base)

    anthropic_model = (
        model
        if model.startswith("claude-") or model.startswith("anthropic")
        else model
    )

    payload = {
        "model": anthropic_model,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": 4096,
        "temperature": 0.3,
    }
    body = json.dumps(payload).encode("utf-8")

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
            content = data.get("content") or []
            if isinstance(content, list):
                for item in content:
                    if isinstance(item, dict) and item.get("type") == "text":
                        return item["text"].strip()
            if isinstance(content, str) and content:
                return content.strip()
            if data.get("text"):
                return data["text"].strip()
            raise RuntimeError("响应中未找到 text 类型的 content")
    except urllib.error.HTTPError as e:
        body_str = e.read().decode("utf-8")
        raise RuntimeError(f"API 错误 {e.code}: {body_str[:500]}")
    except (KeyError, IndexError) as e:
        raise RuntimeError(f"响应格式错误: {e}")


def _call_anthropic_chat(
    messages: list[dict[str, str]],
    api_key: str,
    api_base: str,
    model: str,
    system_prompt: str = "",
) -> str:
    """Anthropic-compatible multi-turn chat."""
    import urllib.error
    import urllib.request

    validate_ssrf(api_base)

    anthropic_model = (
        model
        if model.startswith("claude-") or model.startswith("anthropic")
        else model
    )

    payload: dict[str, Any] = {
        "model": anthropic_model,
        "messages": messages,
        "max_tokens": 4096,
        "temperature": 0.3,
    }
    if system_prompt:
        payload["system"] = system_prompt
    body = json.dumps(payload).encode("utf-8")

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
            content = data.get("content") or []
            if isinstance(content, list):
                for item in content:
                    if isinstance(item, dict) and item.get("type") == "text":
                        return item["text"].strip()
            if isinstance(content, str) and content:
                return content.strip()
            if data.get("text"):
                return data["text"].strip()
            raise RuntimeError("响应中未找到 text 类型的 content")
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8")
        raise RuntimeError(f"API 错误 {e.code}: {err_body[:500]}")
    except (KeyError, IndexError) as e:
        raise RuntimeError(f"响应格式错误: {e}")
