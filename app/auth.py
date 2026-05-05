"""API authentication module."""
import os
import secrets
from fastapi import HTTPException, Security, Request
from fastapi.security import APIKeyHeader

# API key configured via environment variable (optional for local dev)
_api_key = os.environ.get("API_KEY", "")


def is_auth_enabled() -> bool:
    """Check if authentication is enabled (API_KEY is set)."""
    return bool(_api_key)


async def require_api_key(request: Request) -> str:
    """Dependency that enforces API key auth if enabled."""
    if not is_auth_enabled():
        return ""

    auth_header = request.headers.get("X-API-Key", "")
    if not auth_header:
        raise HTTPException(
            status_code=401,
            detail="请提供 API Key (X-API-Key header)",
        )
    if not secrets.compare_digest(auth_header, _api_key):
        raise HTTPException(
            status_code=403,
            detail="API Key 无效",
        )
    return auth_header