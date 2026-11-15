# SentinelGraph AI, single image.
#
# One process serves the SPA and the API on the same port, so the image is the
# whole product: build the frontend, install the backend, run it.
#
#   docker build -t sentinelgraph-ai .
#   docker run -p 8088:8088 -e SG_AUTH_TOKEN=<token> -v sg-data:/data sentinelgraph-ai
#
# SG_AUTH_TOKEN is not optional when binding off-host: the server refuses to
# start on a non-loopback address without it, on purpose. See docs/SECURITY.md.

# --- stage 1: build the SPA ------------------------------------------------
FROM node:22-alpine AS web
WORKDIR /web
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

# --- stage 2: runtime ------------------------------------------------------
FROM python:3.11-slim AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app/backend \
    SG_HOST=0.0.0.0 \
    SG_PORT=8088 \
    SG_DB_PATH=/data/sentinelgraph.db \
    SG_ARTIFACT_DIR=/data/artifacts

WORKDIR /app

COPY backend/requirements.txt ./backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt

COPY backend/ ./backend/
COPY tools/ ./tools/
COPY --from=web /web/dist ./frontend/dist

# The database, artifacts and master key all live under /data so a single
# volume keeps the deployment's state across restarts.
RUN useradd --create-home --uid 10001 sg \
    && mkdir -p /data \
    && chown -R sg:sg /data /app
USER sg
VOLUME ["/data"]

EXPOSE 8088

# /api/health is the one route exempt from the bearer token, so this needs none.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import sys,urllib.request; \
sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8088/api/health', timeout=4).status == 200 else 1)"

CMD ["python", "-m", "sentinelgraph", "serve"]
