"""In-memory LLM configuration, updated by the user via settings UI."""

from typing import Literal
from dataclasses import dataclass, field

# Provider types
LLMProvider = Literal["minimax", "custom"]


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


# Global singleton
_llm_config = LLMConfig()


def get_llm_config() -> LLMConfig:
    return _llm_config


def update_llm_config(provider: LLMProvider, api_key: str, api_base: str, model: str) -> LLMConfig:
    global _llm_config
    _llm_config = LLMConfig(provider=provider, api_key=api_key, api_base=api_base, model=model)
    return _llm_config
