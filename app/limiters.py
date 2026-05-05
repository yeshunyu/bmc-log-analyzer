"""Rate limiter singletons for the application.

This module is imported by both app.main and app.routers.llm to avoid circular imports.
"""
import os
from slowapi import Limiter
from slowapi.util import get_remote_address

# Check if running in test mode (rate limiting can be relaxed)
_test_mode = os.environ.get("TESTING", "") == "true"

# General rate limiter — 20 requests per minute per IP (for uploads)
_default_limit = ["200/minute"] if _test_mode else ["20/minute"]
limiter = Limiter(key_func=get_remote_address, default_limits=_default_limit)

# LLM-specific rate limiter — 10 requests per minute per IP (for LLM analysis endpoints)
_llm_default_limit = ["200/minute"] if _test_mode else ["10/minute"]
llm_limiter = Limiter(key_func=get_remote_address, default_limits=_llm_default_limit)

# Reanalyze rate limiter — 5 requests per minute per IP
_reanalyze_default_limit = ["200/minute"] if _test_mode else ["5/minute"]
reanalyze_limiter = Limiter(key_func=get_remote_address, default_limits=_reanalyze_default_limit)