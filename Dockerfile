# Phoenix DFIR - Multi-stage Docker build
FROM node:20-alpine AS frontend-build

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY . .
RUN npm run build

# Backend
FROM python:3.11-slim

LABEL maintainer="Phoenix DFIR Team"
LABEL description="Phoenix DFIR - Forensic Investigation Platform"

ENV PYTHONUNBUFFERED=1 \
    PHOENIX_DEBUG=false \
    PHOENIX_PORT=5000 \
    PHOENIX_FRONTEND_DIR=/app/frontend

WORKDIR /app

# System deps
RUN apt-get update && \
    apt-get install -y --no-install-recommends tini curl unzip ca-certificates sleuthkit && \
    rm -rf /var/lib/apt/lists/* && \
    groupadd -r phoenix && useradd -r -g phoenix -d /app phoenix

# Optional DFIR tools (Volatility 3 + Hayabusa), enabled by
# docker-compose (INSTALL_DFIR_TOOLS=true). Best-effort install: on network
# failure the image still works (falls back to the native parsers
# and the 29 built-in Sigma rules).
ARG INSTALL_DFIR_TOOLS=false
ARG VOLATILITY_VERSION=2.28.2
ARG HAYABUSA_VERSION=latest
RUN if [ "$INSTALL_DFIR_TOOLS" = "true" ]; then \
      pip install --no-cache-dir "volatility3==${VOLATILITY_VERSION}" yara-python || \
        echo "WARNING: Volatility 3 not installed"; \
      ( set -e; \
        if [ "$HAYABUSA_VERSION" = "latest" ]; then \
          tag=$(curl -fsSLI -o /dev/null -w '%{url_effective}' https://github.com/Yamato-Security/hayabusa/releases/latest); \
          ver="${tag##*/v}"; \
        else ver="$HAYABUSA_VERSION"; fi; \
        curl -fsSL "https://github.com/Yamato-Security/hayabusa/releases/download/v${ver}/hayabusa-${ver}-lin-x64-musl.zip" -o /tmp/hayabusa.zip; \
        mkdir -p /opt/hayabusa && unzip -q /tmp/hayabusa.zip -d /opt/hayabusa; \
        bin=$(find /opt/hayabusa -maxdepth 1 -type f -name 'hayabusa-*' ! -name '*.zip' | head -n1); \
        chmod +x "$bin" && ln -sf "$bin" /opt/hayabusa/hayabusa && ln -sf /opt/hayabusa/hayabusa /usr/local/bin/hayabusa; \
        rm -f /tmp/hayabusa.zip; \
        echo "Hayabusa ${ver} installed" ) || echo "WARNING: Hayabusa not installed"; \
    fi

# Python deps (optional ones are best-effort: python-evtx/hexdump do not
# build everywhere, the platform works without them)
COPY backend/requirements.txt backend/requirements-optional.txt /app/backend/
RUN pip install --no-cache-dir -r /app/backend/requirements.txt && \
    pip install --no-cache-dir -r /app/backend/requirements-optional.txt || \
    echo "Optional dependencies skipped (hexdump/python-evtx build unavailable)"

# Application code (+ autonomous investigator MCP toolkit and legacy CLI)
COPY backend/ /app/backend/
COPY mcp-server/ /app/mcp-server/
COPY legacy/ /app/legacy/
# Marks /app as a source tree: data stays in /app/backend (mounted volumes)
COPY pyproject.toml /app/pyproject.toml

# Built frontend
COPY --from=frontend-build /app/dist /app/frontend

# Data volume
RUN mkdir -p /app/data /app/backend/uploads /app/backend/reports /app/backend/evidence_inbox /mnt/evidence /opt/hayabusa && \
    chown -R phoenix:phoenix /app /opt/hayabusa

VOLUME ["/app/data", "/app/backend/uploads", "/app/backend/evidence_inbox"]

# Evidence vault: mount the host folder READ-ONLY at /mnt/evidence
ENV PHOENIX_EVIDENCE_VAULT=/mnt/evidence

USER phoenix

EXPOSE 5000

WORKDIR /app/backend

# Built-in image healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request,sys; urllib.request.urlopen('http://localhost:5000/livez', timeout=3).read(); sys.exit(0)" || exit 1

ENTRYPOINT ["tini", "--"]
# gunicorn, gthread worker (1 process, PHOENIX_THREADS threads), Flask-SocketIO
# in threading mode: same server in the single container and the production
# stack (docker-compose.prod.yml adds nginx + Redis).
CMD ["gunicorn", "--config", "/app/backend/gunicorn.conf.py", "app:app"]
