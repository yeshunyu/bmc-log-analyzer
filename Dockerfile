# ===== Stage 1: Builder =====
FROM python:3.11-slim AS builder

WORKDIR /app

# Install uv (fast package manager)
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Copy only dependency files first for caching
COPY pyproject.toml uv.lock* ./

# Install dependencies into local venv
RUN uv venv /app/.venv && \
    uv pip install --python /app/.venv --no-cache

# Copy source code
COPY . .

# ===== Stage 2: Runtime =====
FROM python:3.11-slim

WORKDIR /app

# Install runtime dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*

# Copy venv from builder
COPY --from=builder /app/.venv /app/.venv

# Set PATH
ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1

# Expose port
EXPOSE 8000

# Run
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
