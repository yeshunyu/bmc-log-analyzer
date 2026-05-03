"""In-memory LLM configuration, updated by the user via settings UI.

Can be overridden at startup via environment variables:
  LLM_PROVIDER  -- "minimax" or "custom"  (default: minimax)
  LLM_API_KEY   -- API key for custom provider
  LLM_API_BASE  -- API base URL for custom provider
  LLM_MODEL     -- Model name (default: MiniMax-Text-01)
"""

import os
from typing import Literal
from dataclasses import dataclass

# Provider types
LLMProvider = Literal["minimax", "custom"]


def _env(key: str, default: str) -> str:
    return os.environ.get(key, default)


@dataclass
class LLMConfig:
    provider: LLMProvider = "minimax"
    api_key: str = ""
    api_base: str = "https://api.minimax.chat/v1"
    model: str = "MiniMax-Text-01"

    def to_dict(self) -> dict:
        return {
            "provider": self.provider,
            "api_key": self.api_key,
            "api_base": self.api_base,
            "model": self.model,
        }


def _make_config() -> LLMConfig:
    """Build initial config from environment variables (Docker / production use)."""
    return LLMConfig(
        provider=_env("LLM_PROVIDER", "minimax"),
        api_key=_env("LLM_API_KEY", ""),
        api_base=_env("LLM_API_BASE", "https://api.minimax.chat/v1"),
        model=_env("LLM_MODEL", "MiniMax-Text-01"),
    )


# Global singleton — initialised from env vars at startup
_llm_config = _make_config()


def get_llm_config() -> LLMConfig:
    return _llm_config


def update_llm_config(provider: LLMProvider, api_key: str, api_base: str, model: str) -> LLMConfig:
    global _llm_config
    _llm_config = LLMConfig(provider=provider, api_key=api_key, api_base=api_base, model=model)
    return _llm_config
