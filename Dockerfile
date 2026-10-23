# syntax=docker/dockerfile:1.7
# Sentinel API / worker image. One image serves both roles:
#   API    (default CMD)  -> docker/entrypoint.sh api
#   worker                -> docker/entrypoint.sh worker   (or: python -m app.worker)
#
# Build args:
#   EXTRAS=1       also install requirements-optional.txt (cloud SDKs, OpenTelemetry)
#   APP_VERSION    OCI version label

ARG PYTHON_VERSION=3.12

# ---------------------------------------------------------------- build stage
FROM python:${PYTHON_VERSION}-slim AS build
ARG EXTRAS=0
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1 PYTHONDONTWRITEBYTECODE=1
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential libpq-dev \
 && rm -rf /var/lib/apt/lists/*
RUN python -m venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH
WORKDIR /build
COPY requirements.txt requirements-optional.txt ./
RUN pip install --upgrade pip wheel \
 && pip install -r requirements.txt \
 && if [ "$EXTRAS" = "1" ]; then pip install -r requirements-optional.txt; fi

# ---------------------------------------------------------------- runtime stage
FROM python:${PYTHON_VERSION}-slim AS runtime
ARG APP_VERSION=dev
LABEL org.opencontainers.image.title="Sentinel" \
      org.opencontainers.image.description="Agentic security operations platform (API + worker)" \
      org.opencontainers.image.version="${APP_VERSION}" \
      org.opencontainers.image.source="https://github.com/eekosystems/sentinel-agentic-security" \
      org.opencontainers.image.licenses="MIT"
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PATH=/opt/venv/bin:$PATH \
    DATABASE_URL=sqlite:////app/data/sentinel.db SCAN_ROOT=/app/targets \
    RUN_MIGRATIONS=false UVICORN_WORKERS=1 FORWARDED_ALLOW_IPS=127.0.0.1
RUN apt-get update \
 && apt-get install -y --no-install-recommends libpq5 ca-certificates tini curl \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd -r -g 10001 sentinel \
 && useradd -r -u 10001 -g sentinel -d /app -s /usr/sbin/nologin sentinel
WORKDIR /app
COPY --from=build /opt/venv /opt/venv
# .dockerignore keeps tests, docs, infra, data and env files out of the context, so this
# copies app/, scripts/, alembic/ (when present), alembic.ini, requirements*.txt, LICENSE.
COPY --chown=sentinel:sentinel . .
RUN install -m 0755 docker/entrypoint.sh /usr/local/bin/sentinel-entrypoint \
 && rm -rf docker \
 && mkdir -p /app/data /app/targets \
 && chown -R sentinel:sentinel /app/data /app/targets
USER 10001:10001
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8080/health || exit 1
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/sentinel-entrypoint"]
CMD ["api"]
