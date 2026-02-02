# SPECTRE Dockerfile
# Multi-stage build for minimal image size and security

# ============================================
# Stage 1: Builder
# ============================================
FROM python:3.12-slim as builder

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install Python dependencies
COPY pyproject.toml ./
RUN pip install --upgrade pip && \
    pip install build && \
    pip install .

# ============================================
# Stage 2: Runtime
# ============================================
FROM python:3.12-slim as runtime

# Labels
LABEL org.opencontainers.image.title="SPECTRE" \
    org.opencontainers.image.description="Security Platform for Enrichment, Collection, Threat Research & Evaluation" \
    org.opencontainers.image.version="0.1.0" \
    org.opencontainers.image.source="https://github.com/spectre-osint/spectre"

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONFAULTHANDLER=1 \
    PATH="/opt/venv/bin:$PATH" \
    # SPECTRE configuration
    SPECTRE_HOME="/app" \
    SPECTRE_DATA="/data" \
    SPECTRE_CONFIG="/config"

# Create non-root user for security
RUN groupadd --gid 1000 spectre && \
    useradd --uid 1000 --gid spectre --shell /bin/bash --create-home spectre

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    # DNS utilities (for nslookup debugging)
    dnsutils \
    # WHOIS client
    whois \
    # Network utilities
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv

# Create application directories
RUN mkdir -p /app /data /config && \
    chown -R spectre:spectre /app /data /config

WORKDIR /app

# Copy application code
COPY --chown=spectre:spectre spectre/ ./spectre/

# Set up volumes for persistent data
VOLUME ["/data", "/config"]

# Switch to non-root user
USER spectre

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD spectre plugins health || exit 1

# Default command
ENTRYPOINT ["spectre"]
CMD ["--help"]
