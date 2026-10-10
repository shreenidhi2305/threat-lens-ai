# syntax=docker/dockerfile:1
#
# All-in-one image for single-container hosts such as Hugging Face Spaces: the API serves the
# built UI itself, so there is one process and one port (7860).
# `python deploy/huggingface/prepare.py` assembles the folder this file is built from.

# ---- 1. build the React app ---------------------------------------------------------------------
FROM node:22-alpine AS web
WORKDIR /web
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
ARG VITE_API_BASE_URL=/api/v1
ENV VITE_API_BASE_URL=$VITE_API_BASE_URL
RUN npm run build

# ---- 2. install the backend dependencies ----------------------------------------------------------
FROM python:3.11-slim AS builder
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential libssl-dev \
    && rm -rf /var/lib/apt/lists/*
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
COPY backend/requirements.txt ./
RUN pip install -r requirements.txt

# ---- 3. runtime ---------------------------------------------------------------------------------------
FROM python:3.11-slim

# libgomp1 is LightGBM's OpenMP runtime; without it the ML model silently fails to load.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libgomp1 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 1000 user

COPY --from=builder /opt/venv /opt/venv

# Public demo defaults. Set JWT_SECRET_KEY and DEV_LOGIN_PASSWORD (12+ characters) as secrets on the
# host; the app refuses to start in production without them.
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    APP_ENV=production \
    ALLOW_DEV_LOGIN=true \
    TRUST_PROXY_HEADERS=true \
    SERVE_FRONTEND_DIR=/app/static \
    SEED_DEMO_DATA=true \
    DEMO_SAMPLES_DIR=/app/demo_samples \
    FRAME_ANCESTORS="https://huggingface.co https://*.hf.space"

WORKDIR /app
COPY --chown=user backend/app ./app
COPY --from=web --chown=user /web/dist ./static
COPY --chown=user demo/samples ./demo_samples
RUN mkdir -p /app/var && chown -R user:user /app/var
USER user

EXPOSE 7860

HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:7860/health', timeout=4)"

# One worker on purpose: alerts, notifications and rate limits are held in this process.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "7860"]
