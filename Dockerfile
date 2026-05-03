# ===== Stage 1: Builder =====
FROM python:3.11-alpine AS builder

WORKDIR /app

# Install build dependencies for compiled Python packages
RUN apk add --no-cache \
    gcc \
    musl-dev \
    libffi-dev \
    openssl-dev \
    cargo \
    rust

# Upgrade pip first so wheel gets a newer version
RUN pip install --user --upgrade pip wheel

# Copy source code
COPY . .

# Remove any pre-existing venv/dist that may contain old vulnerable packages
RUN rm -rf /app/.venv /app/dist

# Copy requirements and install (after clean to avoid old cached packages)
COPY requirements.txt /tmp/
RUN pip install --user -r /tmp/requirements.txt

# ===== Stage 2: Runtime =====
FROM python:3.11-alpine

WORKDIR /app

# Install runtime dependencies only
RUN apk add --no-cache musl

# Copy installed packages from builder
COPY --from=builder /root/.local /root/.local
COPY --from=builder /app /app

# Set PATH so .local/bin takes priority
ENV PATH="/root/.local/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH="/root/.local/lib/python3.11/site-packages:$PYTHONPATH"

# Expose port
EXPOSE 8000

# Run
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
