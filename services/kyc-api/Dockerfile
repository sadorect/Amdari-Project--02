# Fix for HARDEN-RUNTIME: slim base image (smaller attack surface than the
# full python:3.11 image), runs as a non-root user, and declares a
# HEALTHCHECK so an unhealthy container is visible to the orchestrator
# instead of silently serving errors.
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt requirements-dev.txt ./
# Patch base-image findings Trivy reports as fixed upstream: zlib1g (OS) and the
# wheel/setuptools build tooling (setuptools vendors jaraco.context).
# hadolint ignore=DL3008,DL3013
RUN apt-get update \
    && apt-get install -y --no-install-recommends --only-upgrade zlib1g \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir --upgrade pip setuptools wheel

RUN pip install --no-cache-dir -r requirements.txt -r requirements-dev.txt

COPY . .

RUN groupadd --system app && useradd --system --gid app --no-create-home app \
    && chown -R app:app /app
USER app

EXPOSE 8002

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8002/health', timeout=3)" || exit 1

CMD ["python", "-m", "app.main"]
