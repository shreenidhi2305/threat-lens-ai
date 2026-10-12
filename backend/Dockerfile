# syntax=docker/dockerfile:1

# ---- build stage: install dependencies into a virtualenv ---------------------------------
FROM python:3.11-slim AS builder

ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1

# Compilers live only in this stage, in case a dependency has no prebuilt wheel for the platform.
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential libssl-dev \
    && rm -rf /var/lib/apt/lists/*

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt ./
RUN pip install -r requirements.txt

# ---- runtime stage --------------------------------------------------------------------------
FROM python:3.11-slim

# libgomp1 is LightGBM's OpenMP runtime. Without it `import lightgbm` fails and the ML model
# silently disappears (every verdict would fall back to rules only).
RUN apt-get update \
    && apt-get install -y --no-install-recommends libgomp1 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --create-home threatlens

COPY --from=builder /opt/venv /opt/venv

# Secure by default: production mode refuses to start with the default JWT secret or an
# unconfigured sign-in (see app/core/startup_checks.py). Set the real values via the environment.
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    APP_ENV=production

WORKDIR /app
COPY app ./app

# Uploaded samples and saved admin settings live here; mount a volume to keep them.
RUN mkdir -p /app/var && chown -R threatlens:threatlens /app/var
USER threatlens

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=4)"

# One worker on purpose: alerts, notifications and rate limits are held in this process.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
