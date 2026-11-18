# syntax=docker/dockerfile:1.7
# Argus API / worker image. One image serves both roles:
#   API    (default CMD)  -> docker/entrypoint.sh api
#   worker                -> docker/entrypoint.sh worker   (or: python -m app.worker)
#
# Build args:
#   EXTRAS=1       also install requirements-optional.txt (cloud SDKs, OpenTelemetry)
#   APP_VERSION    OCI version label

ARG PYTHON_VERSION=3.12
ARG PYTHON_DIGEST=sha256:6b2152a5c30cb97e3f98f09c3b82d5e8780992f3194e1c4a98f462739dc4c109

# ---------------------------------------------------------------- build stage
FROM python:${PYTHON_VERSION}-slim@${PYTHON_DIGEST} AS build
ARG EXTRAS=0
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1 PYTHONDONTWRITEBYTECODE=1
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential libpq-dev \
 && rm -rf /var/lib/apt/lists/*
RUN python -m venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH
WORKDIR /build
COPY requirements.txt requirements.lock.txt requirements-optional.txt ./
# requirements.lock.txt pins every transitive runtime dependency (generated on linux/py3.12, see
# its header). Installing requirements.txt under that constraint makes every build resolve to the
# same audited set (pip-audit runs against the lock in CI). Test tooling lives in
# requirements-dev.txt and is never installed in the image.
RUN pip install --upgrade "pip==$(sed -n 's/^pip==//p' requirements.lock.txt)" wheel \
 && pip install -r requirements.txt -c requirements.lock.txt \
 && if [ "$EXTRAS" = "1" ]; then pip install -r requirements-optional.txt -c requirements.lock.txt; fi

# ---------------------------------------------------------------- runtime stage
FROM python:${PYTHON_VERSION}-slim@${PYTHON_DIGEST} AS runtime
ARG APP_VERSION=dev
ARG INCLUDE_OFFENSIVE=0
LABEL org.opencontainers.image.title="Argus" \
      org.opencontainers.image.description="Agentic security operations platform (API + worker)" \
      org.opencontainers.image.version="${APP_VERSION}" \
      org.opencontainers.image.source="https://github.com/thomasunise/argus" \
      org.opencontainers.image.licenses="MIT"
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PATH=/opt/venv/bin:$PATH \
    HOME=/tmp XDG_CACHE_HOME=/tmp/.cache \
    DATABASE_URL=sqlite:////app/data/argus.db SCAN_ROOT=/app/targets \
    RUN_MIGRATIONS=false UVICORN_WORKERS=1 TRUSTED_PROXY_HOPS=0 \
    CORE_ONLY_BUILD=true
RUN apt-get update \
 && apt-get install -y --no-install-recommends libpq5 ca-certificates tini curl \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd -r -g 10001 argus \
 && useradd -r -u 10001 -g argus -d /app -s /usr/sbin/nologin argus
WORKDIR /app
COPY --from=build /opt/venv /opt/venv
# .dockerignore keeps tests, docs, infra, data and env files out of the context, so this
# copies app/, scripts/, alembic/ (when present), alembic.ini, requirements*.txt, LICENSE.
COPY --chown=argus:argus . .
RUN install -m 0755 docker/entrypoint.sh /usr/local/bin/argus-entrypoint \
 && rm -rf docker \
 && if [ "$INCLUDE_OFFENSIVE" != "1" ]; then \
      rm -rf app/pentest app/discovery app/exploit \
             app/api/pentest.py app/api/discovery.py app/api/exploits.py app/api/autopilot.py \
             app/testing/autopilot.py app/testing/adapters/strix.py \
             app/agents/tools/exploit.py app/agents/tools/pentest_tool.py \
             app/agents/specialists/poc_author.py app/agents/specialists/offensive_pentest.py \
             app/agents/specialists/redteam_plan.py; \
    fi \
 && mkdir -p /app/data /app/targets \
 && chown -R argus:argus /app/data /app/targets
USER 10001:10001
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8080/health || exit 1
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/argus-entrypoint"]
CMD ["api"]
