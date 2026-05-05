"""Shared pytest fixtures for bmc-log-analyzer tests."""

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client():
    """FastAPI test client — shared across all API tests."""
    # Defer import to avoid module-level side effects at collection time
    from app.main import app
    return TestClient(app)


@pytest.fixture
def sample_log_bytes():
    """Minimal log content used by upload tests."""
    return (
        b"2025-06-23 11:03:20.644848 kvm_vmm ERROR: comm.c(329): Pre-read ssl failed.\n"
        b"2025-06-25 08:00:01.000000 host_mgr INFO: host is registered.\n"
    )
