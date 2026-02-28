# Phoenix DFIR - Multi-stage Docker build
# Stage 1: Frontend build
FROM node:20-alpine AS frontend-build

WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci --production=false
COPY . .
RUN npm run build

# ============================================================================
# Stage 2: Production backend
# ============================================================================
FROM python:3.11-slim

LABEL maintainer="Phoenix DFIR Team"
LABEL description="Phoenix DFIR - Plateforme d'Investigation Forensique"
LABEL version="3.1"

# Variables d'environnement de build
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONHASHSEED=random \
    PHOENIX_DEBUG=false \
    PHOENIX_PORT=5000 \
    PHOENIX_LOG_FORMAT=json \
    PHOENIX_LOG_LEVEL=INFO \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Installer les dependances systeme
# libmagic1 est requis par python-magic pour la validation des types de fichiers
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        tini \
        libmagic1 \
        curl && \
    rm -rf /var/lib/apt/lists/* && \
    # Creer l'utilisateur non-root
    groupadd -r phoenix && \
    useradd -r -g phoenix -d /app -s /sbin/nologin phoenix

# Installer les dependances Python
COPY backend/requirements.txt /app/backend/
RUN pip install --no-cache-dir -r /app/backend/requirements.txt

# Copier le code de l'application
COPY backend/ /app/backend/

# Copier le frontend buildé
COPY --from=frontend-build /app/dist /app/frontend

# Creer les repertoires de donnees et attribuer les permissions
RUN mkdir -p /app/data /app/backend/uploads /app/backend/reports && \
    chown -R phoenix:phoenix /app && \
    chmod 750 /app/backend && \
    chmod 700 /app/backend/uploads && \
    chmod 700 /app/backend/reports

# Volumes pour la persistance des donnees
VOLUME ["/app/data", "/app/backend/uploads", "/app/backend/reports"]

# Port expose
EXPOSE 5000

# Passer a l'utilisateur non-root
USER phoenix

# Utiliser tini comme PID 1 pour une gestion correcte des signaux
ENTRYPOINT ["tini", "--"]

# Demarrer avec Gunicorn en production
# - app:socketio.wsgi_app: expose le WSGI app de Flask-SocketIO
# - gunicorn.conf.py: configuration complete (workers, timeouts, logging)
CMD ["gunicorn", \
     "--config", "/app/backend/gunicorn.conf.py", \
     "--chdir", "/app/backend", \
     "app:socketio.wsgi_app"]

# Health check via curl (plus robuste que urllib)
HEALTHCHECK --interval=30s --timeout=10s --retries=3 --start-period=15s \
    CMD curl -f http://localhost:5000/api/health || exit 1
