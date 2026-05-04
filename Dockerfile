# ===== Stage 1: Builder =====
FROM python:3.11-alpine AS builder

WORKDIR /app

# Install build dependencies (compilers, etc.)
RUN apk add --no-cache \
    gcc \
    musl-dev \
    libffi-dev \
    openssl-dev \
    cargo \
    rust

# Create venv and install all deps into it (no external download at runtime)
RUN python -m venv /app/venv
ENV PATH="/app/venv/bin:$PATH"

# Upgrade pip/wheel/setuptools in venv (must come after ENV PATH)
RUN pip install --upgrade pip wheel setuptools

# Copy deps and source, then install
COPY requirements.txt /tmp/
RUN pip install -r /tmp/requirements.txt
COPY app /app/app

# ===== Stage 2: Runtime (fully offline, no network) =====
FROM python:3.11-alpine

WORKDIR /app

# Remove base image's pip/setuptools/wheel (not needed at runtime, avoids trivy scanning them)
RUN apk add --no-cache musl \
    && cd /usr/local/lib/python3.11/site-packages \
    && rm -rf pip* setuptools* wheel* \
              autocommand* backports* importlib_metadata* inflect* \
              jaraco* more_itertools* packaging* platformdirs* \
              typeguard* typing_extensions* zipp* \
    && rm -rf /root/.local

# Copy pre-built venv from builder (only venv, no base /usr/local/lib)
COPY --from=builder /app/venv /app/venv

# Activate venv — override PYTHONPATH to prevent base image's site-packages from being loaded
ENV PATH="/app/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH="/app/venv/lib/python3.11/site-packages" \
    PYTHONHOME=""

# Copy application source
COPY --from=builder /app /app

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
