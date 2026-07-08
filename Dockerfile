# W3BSP1D3R — Enterprise Web Vulnerability Scanner
# Multi-stage build for minimal image size

FROM python:3.12-slim AS builder

WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ---------------------------------------------------------------------------
FROM python:3.12-slim

LABEL maintainer="S1YOL"
LABEL description="W3BSP1D3R — Enterprise Web Vulnerability Scanner"
LABEL version="3.0.0-beta"

# Security: run as non-root
RUN groupadd -r scanner && useradd -r -g scanner -m scanner

WORKDIR /app
COPY --from=builder /install /usr/local
COPY . .

# Create directories for outputs
RUN mkdir -p /app/reports /app/.w3bsp1d3r && \
    chown -R scanner:scanner /app

USER scanner

# Default: show help. Override CMD to run scans.
ENTRYPOINT ["python", "main.py"]
CMD ["--help"]

# Health check for API server mode
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:8888/api/v1/health')" || exit 1
