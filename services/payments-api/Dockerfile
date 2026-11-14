# Fix for HARDEN-RUNTIME: slim base image (smaller attack surface than the
# full python:3.11 image), runs as a non-root user, and declares a
# HEALTHCHECK so an unhealthy container is visible to the orchestrator
# instead of silently serving errors.
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt requirements-dev.txt ./
# Patch base-image findings Trivy reports as fixed upstream: zlib1g (OS). The
# wheel/setuptools build tooling is removed after the install below instead.
# hadolint ignore=DL3008,DL3013
RUN apt-get update \
    && apt-get install -y --no-install-recommends --only-upgrade zlib1g \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir --upgrade pip

RUN pip install --no-cache-dir -r requirements.txt -r requirements-dev.txt \
    && pip uninstall -y setuptools wheel \
    && rm -rf /usr/local/lib/python3.11/site-packages/setuptools /usr/local/lib/python3.11/site-packages/pkg_resources /usr/local/lib/python3.11/site-packages/_distutils_hack

COPY . .

RUN groupadd --system app && useradd --system --gid app --no-create-home app \
    && chown -R app:app /app
USER app

EXPOSE 8001

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8001/health', timeout=3)" || exit 1

CMD ["python", "-m", "app.main"]
