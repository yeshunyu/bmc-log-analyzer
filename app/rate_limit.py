"""Rate limiting configuration for the application."""
import os
from slowapi import Limiter
from slowapi.util import get_remote_address

def _real_remote_address(request) -> str:
    """
    Get real client IP, respecting trusted proxy headers.
    Only use X-Forwarded-For when TRUSTED_PROXY_COUNT is set
    (prevents spoofing in non-proxy deployments).
    """
    trusted = int(os.environ.get("TRUSTED_PROXY_COUNT", "0"))
    if trusted > 0:
        # Behind a trusted reverse proxy (nginx/K8s ingress)
        forwarded = request.headers.get("X-Forwarded-For", "")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return get_remote_address(request)

# Rate limiter — 20 requests per minute per IP by default
limiter = Limiter(key_func=_real_remote_address, default_limits=["20/minute"])