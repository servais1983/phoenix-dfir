# Phoenix DFIR - Multi-stage Docker build
FROM node:20-alpine AS frontend-build

WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci --production=false
COPY . .
RUN npm run build

# Backend
FROM python:3.11-slim

LABEL maintainer="Phoenix DFIR Team"
LABEL description="Phoenix DFIR - Plateforme d'Investigation Forensique"

ENV PYTHONUNBUFFERED=1 \
    PHOENIX_DEBUG=false \
    PHOENIX_PORT=5000

WORKDIR /app

# System deps
RUN apt-get update && \
    apt-get install -y --no-install-recommends tini && \
    rm -rf /var/lib/apt/lists/* && \
    groupadd -r phoenix && useradd -r -g phoenix -d /app phoenix

# Python deps
COPY backend/requirements.txt /app/backend/
RUN pip install --no-cache-dir -r /app/backend/requirements.txt

# Application code
COPY backend/ /app/backend/

# Built frontend
COPY --from=frontend-build /app/dist /app/frontend

# Data volume
RUN mkdir -p /app/data /app/backend/uploads /app/backend/reports && \
    chown -R phoenix:phoenix /app

VOLUME ["/app/data", "/app/backend/uploads"]

USER phoenix

EXPOSE 5000

ENTRYPOINT ["tini", "--"]
CMD ["python", "/app/backend/app.py"]
