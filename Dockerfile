# ===== Stage 1: Builder =====
FROM python:3.11-alpine AS builder
ARG APP_VERSION=dev

WORKDIR /app

# Write version file (consumed by FastAPI at runtime)
RUN echo "{\"version\": \"$APP_VERSION\"}" > /tmp/app_version.json

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

# Copy app version (injected at build time)
COPY --from=builder /tmp/app_version.json /app/app_version.json

# Activate venv — override PYTHONPATH to prevent base image's site-packages from being loaded
ENV PATH="/app/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH="/app/venv/lib/python3.11/site-packages" \
    PYTHONHOME=""

# Copy application source and entrypoint
COPY --from=builder /app /app
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 8000
ENTRYPOINT ["/entrypoint.sh"]
