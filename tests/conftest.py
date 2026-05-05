"""Shared pytest fixtures for bmc-log-analyzer tests."""

import os
# Set test mode and API key before importing app
os.environ["TESTING"] = "true"
os.environ["API_KEY"] = "test-secret-key-for-testing-only"

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client():
    """FastAPI test client — shared across all API tests."""
    from app.main import app
    client = TestClient(app)
    # Clear rate limit storage between tests
    from app.limiters import limiter, llm_limiter, reanalyze_limiter
    limiter._storage.reset()
    llm_limiter._storage.reset()
    reanalyze_limiter._storage.reset()
    return client


@pytest.fixture
def sample_log_bytes():
    """Minimal log content used by upload tests."""
    return (
        b"2025-06-23 11:03:20.644848 kvm_vmm ERROR: comm.c(329): Pre-read ssl failed.\n"
        b"2025-06-25 08:00:01.000000 host_mgr INFO: host is registered.\n"
    )
