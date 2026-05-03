# ===== Stage 1: Builder =====
FROM python:3.11-slim AS builder

WORKDIR /app

# Install build dependencies for compiled Python packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for caching
COPY requirements.txt ./

# Install into venv (no compiled deps needed for plain uvicorn)
RUN python -m venv /app/.venv && \
    /app/.venv/bin/pip install --no-cache -r requirements.txt

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
