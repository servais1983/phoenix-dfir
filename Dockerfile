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
LABEL description="Phoenix DFIR - Plateforme d'Investigation Forensique"

ENV PYTHONUNBUFFERED=1 \
    PHOENIX_DEBUG=false \
    PHOENIX_PORT=5000 \
    PHOENIX_FRONTEND_DIR=/app/frontend

WORKDIR /app

# System deps
RUN apt-get update && \
    apt-get install -y --no-install-recommends tini curl unzip ca-certificates && \
    rm -rf /var/lib/apt/lists/* && \
    groupadd -r phoenix && useradd -r -g phoenix -d /app phoenix

# Outils DFIR optionnels (Volatility 3 + Hayabusa) - actives par
# docker-compose (INSTALL_DFIR_TOOLS=true). Installation best-effort : en cas
# d'echec reseau l'image reste fonctionnelle (repli sur les parsers natifs
# et les 26 regles Sigma integrees).
ARG INSTALL_DFIR_TOOLS=false
ARG VOLATILITY_VERSION=2.28.2
ARG HAYABUSA_VERSION=latest
RUN if [ "$INSTALL_DFIR_TOOLS" = "true" ]; then \
      pip install --no-cache-dir "volatility3==${VOLATILITY_VERSION}" yara-python || \
        echo "AVERTISSEMENT: Volatility 3 non installe"; \
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
        echo "Hayabusa ${ver} installe" ) || echo "AVERTISSEMENT: Hayabusa non installe"; \
    fi

# Python deps (les optionnelles sont best-effort : python-evtx/hexdump ne
# compile pas partout, la plateforme fonctionne sans)
COPY backend/requirements.txt backend/requirements-optional.txt /app/backend/
RUN pip install --no-cache-dir -r /app/backend/requirements.txt && \
    pip install --no-cache-dir -r /app/backend/requirements-optional.txt || \
    echo "Dependances optionnelles ignorees (build hexdump/python-evtx indisponible)"

# Application code (+ boite a outils MCP de l'enqueteur autonome et CLI legacy)
COPY backend/ /app/backend/
COPY mcp-server/ /app/mcp-server/
COPY legacy/ /app/legacy/

# Built frontend
COPY --from=frontend-build /app/dist /app/frontend

# Data volume
RUN mkdir -p /app/data /app/backend/uploads /app/backend/reports /app/backend/evidence_inbox /mnt/evidence /opt/hayabusa && \
    chown -R phoenix:phoenix /app /opt/hayabusa

VOLUME ["/app/data", "/app/backend/uploads", "/app/backend/evidence_inbox"]

# Coffre de preuves : monter le dossier hote en LECTURE SEULE sur /mnt/evidence
ENV PHOENIX_EVIDENCE_VAULT=/mnt/evidence

USER phoenix

EXPOSE 5000

WORKDIR /app/backend

# Healthcheck integre a l'image
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request,sys; urllib.request.urlopen('http://localhost:5000/livez', timeout=3).read(); sys.exit(0)" || exit 1

ENTRYPOINT ["tini", "--"]
# Mono-conteneur : Flask-SocketIO dev server (suffisant pour single-user/POC).
# En production, utiliser docker-compose.prod.yml qui passe a gunicorn+eventlet.
CMD ["python", "app.py"]
