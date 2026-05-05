"""API authentication module with anti-brute-force protection."""
import os
import secrets
import time
from collections import defaultdict
from pathlib import Path
from fastapi import HTTPException, Request
from slowapi.util import get_remote_address

# Track failed attempts: {ip: (count, last_attempt_time)}
_failed_attempts: dict[str, tuple[int, float]] = defaultdict(lambda: (0, 0.0))
MAX_FAILURES = 5          # Lock out after 5 failed attempts
LOCKOUT_DURATION = 300    # 5 minute lockout
FAILURE_WINDOW = 900      # 15 minute window to reset failures


def _load_or_generate_key() -> str:
    """Load API key from env, or load from file. Returns empty string if none set."""
    _api_key = os.environ.get("API_KEY", "")
    if _api_key:
        return _api_key
    # Use env-var configurable path, fallback to /app for container or /tmp for dev
    key_path_env = os.environ.get("API_KEY_FILE", "")
    if key_path_env:
        key_file = Path(key_path_env)
    else:
        # Default path - prefer /tmp for dev, /app for container
        # But use /tmp if /app/.api_key is not writable (container running as non-root)
        default_key_file = Path("/app/.api_key")
        if Path("/app").exists() and os.access(default_key_file.parent, os.W_OK):
            key_file = default_key_file
        else:
            key_file = Path("/tmp/.bmc_api_key")
    if key_file.exists():
        return key_file.read_text().strip()
    # No key configured
    return ""


def is_auth_enabled() -> bool:
    """Check if auth is enabled. Returns True only if an API key is configured."""
    return bool(get_api_key())


def get_api_key() -> str:
    """Return the effective API key (env or generated)."""
    return _load_or_generate_key()


async def require_api_key(request: Request) -> str:
    """Dependency that enforces API key auth when configured, otherwise allows all."""
    # Skip auth in test mode
    if os.environ.get("TESTING", "") == "true":
        return "test-key"

    effective_key = get_api_key()

    # If no API key is configured, auth is disabled
    if not effective_key:
        return ""

    client_ip = get_remote_address(request)

    # Check lockout status
    if client_ip in _failed_attempts:
        count, last_attempt = _failed_attempts[client_ip]
        if count >= MAX_FAILURES:
            elapsed = time.time() - last_attempt
            if elapsed < LOCKOUT_DURATION:
                remaining = int(LOCKOUT_DURATION - elapsed)
                raise HTTPException(
                    status_code=429,
                    detail=f"失败次数过多，请在 {remaining} 秒后重试",
                )
            # Lockout expired, reset
            del _failed_attempts[client_ip]

    auth_header = request.headers.get("X-API-Key", "")

    if not auth_header:
        _record_failure(client_ip)
        raise HTTPException(
            status_code=401,
            detail="请提供 API Key (X-API-Key header)",
        )

    if not secrets.compare_digest(auth_header, effective_key):
        _record_failure(client_ip)
        # Log failed attempt
        from app.operation_log import log_operation
        log_operation(
            operation="auth_failed",
            detail=f"无效的 API Key，来源 IP: {client_ip}",
            result="error",
        )
        raise HTTPException(
            status_code=403,
            detail="API Key 无效",
        )

    # Success - clear failure count for this IP
    if client_ip in _failed_attempts:
        del _failed_attempts[client_ip]

    return auth_header


def _record_failure(ip: str) -> None:
    """Record a failed auth attempt with rate limiting."""
    now = time.time()
    count, last_attempt = _failed_attempts[ip]

    # Reset if window expired
    if now - last_attempt > FAILURE_WINDOW:
        count = 0

    _failed_attempts[ip] = (count + 1, now)