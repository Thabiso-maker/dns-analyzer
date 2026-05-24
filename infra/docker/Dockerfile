# ==============================================================================
# DNS Security Analyzer — Production Dockerfile
# ==============================================================================
# Multi-stage build:
#   Stage 1 (builder): Install dependencies into a virtual environment
#   Stage 2 (runtime): Copy only the venv — no build tools in final image
#
# Build:  docker build -f infra/docker/Dockerfile -t dns-analyzer:latest .
# Run:    docker run -p 8000:8000 --env-file .env dns-analyzer:latest
# ==============================================================================

# ── Stage 1: Dependency builder ───────────────────────────────────────────────
FROM python:3.11-slim AS builder

# Install system dependencies needed to build Python packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    libpq-dev \
    libffi-dev \
    libssl-dev \
    # WeasyPrint system dependencies
    libcairo2-dev \
    libpango1.0-dev \
    libgdk-pixbuf2.0-dev \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Poetry
RUN pip install --no-cache-dir poetry==1.8.3

WORKDIR /build

# Copy dependency manifests first (maximise Docker layer cache hits)
COPY pyproject.toml poetry.lock* ./

# Create virtualenv inside project for easy copying to runtime stage
RUN poetry config virtualenvs.in-project true \
    && poetry install --only main --no-interaction --no-ansi --no-root

# Copy source and install the package itself
COPY src/ ./src/
COPY cli/ ./cli/
RUN poetry install --only main --no-interaction --no-ansi


# ── Stage 2: Runtime image ────────────────────────────────────────────────────
FROM python:3.11-slim AS runtime

LABEL maintainer="DNS Security Analyzer"
LABEL description="Enterprise DNS Security Analyzer API"
LABEL version="0.1.0"

# Install only runtime system dependencies (no build tools)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    libcairo2 \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf2.0-0 \
    libffi8 \
    # DNS tools for debugging
    dnsutils \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create non-root user for security
RUN groupadd --gid 1001 analyzer \
    && useradd --uid 1001 --gid analyzer --shell /bin/bash --create-home analyzer

WORKDIR /app

# Copy virtual environment from builder stage
COPY --from=builder /build/.venv /app/.venv

# Copy application source
COPY --chown=analyzer:analyzer src/     ./src/
COPY --chown=analyzer:analyzer cli/     ./cli/
COPY --chown=analyzer:analyzer wordlists/ ./wordlists/
COPY --chown=analyzer:analyzer alembic.ini ./

# Create directories with correct permissions
RUN mkdir -p /app/reports/output /app/logs \
    && chown -R analyzer:analyzer /app

# Switch to non-root user
USER analyzer

# Add venv to PATH
ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONPATH="/app/src" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    # Prevent Python from buffering stdout/stderr
    PYTHONUTF8=1

# Expose API port
EXPOSE 8000

# Health check — uses the /health/ping endpoint (minimal, no DB check)
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8000/api/v1/health/ping || exit 1

# Default command — production Uvicorn with multiple workers
CMD ["uvicorn", \
     "dns_analyzer.api.app:create_app", \
     "--factory", \
     "--host", "0.0.0.0", \
     "--port", "8000", \
     "--workers", "4", \
     "--loop", "uvloop", \
     "--http", "httptools", \
     "--proxy-headers", \
     "--forwarded-allow-ips", "*"]