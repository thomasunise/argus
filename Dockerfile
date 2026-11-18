# syntax=docker/dockerfile:1.7
# Argus API / worker image. One image serves both roles:
#   API    (default CMD)  -> docker/entrypoint.sh api
#   worker                -> docker/entrypoint.sh worker   (or: python -m app.worker)
#
# Build args:
#   EXTRAS=1       also install requirements-optional.txt (cloud SDKs, OpenTelemetry)
#   APP_VERSION    OCI version label

ARG PYTHON_VERSION=3.12
ARG PYTHON_DIGEST=sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b

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
COPY requirements.txt requirements.lock.txt requirements.hashes.txt requirements-optional.txt ./
# requirements.lock.txt pins every transitive runtime dependency (generated on linux/py3.12, see
# its header) and requirements.hashes.txt carries the sha256 of every published file for each pin
# (scripts/lock_hashes.py). --require-hashes makes the build fail if the index serves anything
# else; `pip check` then confirms the pinned set is complete and consistent. pip-audit runs
# against the lock in CI. Test tooling lives in requirements-dev.txt and is never installed here.
RUN pip install --upgrade "pip==$(sed -n 's/^pip==//p' requirements.lock.txt | tr -d '\r')" setuptools wheel \
 && pip install --require-hashes --no-deps -r requirements.hashes.txt \
 && pip check \
 && if [ "$EXTRAS" = "1" ]; then pip install -r requirements-optional.txt -c requirements.lock.txt; fi

# ---------------------------------------------------------------- source stage
# The application tree is assembled here and copied into the runtime image as one layer. Files left
# out of the core build (the offensive modules, by default) are removed before that copy, so they
# are not present in any layer of the published image, not just hidden by a later one.
FROM python:${PYTHON_VERSION}-slim@${PYTHON_DIGEST} AS source
ARG INCLUDE_OFFENSIVE=0
WORKDIR /src
# .dockerignore keeps tests, docs, infra, data and env files out of the context, so this
# copies app/, scripts/, alembic/ (when present), alembic.ini, requirements*.txt, LICENSE.
COPY . .
RUN install -D -m 0755 docker/entrypoint.sh /out/argus-entrypoint \
 && rm -rf docker \
 && if [ "$INCLUDE_OFFENSIVE" != "1" ]; then \
      rm -rf app/pentest app/discovery app/exploit \
             app/api/pentest.py app/api/discovery.py app/api/exploits.py app/api/autopilot.py \
             app/testing/autopilot.py app/testing/adapters/strix.py \
             app/agents/tools/exploit.py app/agents/tools/pentest_tool.py \
             app/agents/specialists/poc_author.py app/agents/specialists/offensive_pentest.py \
             app/agents/specialists/redteam_plan.py; \
    fi

# ---------------------------------------------------------------- runtime stage
FROM python:${PYTHON_VERSION}-slim@${PYTHON_DIGEST} AS runtime
ARG APP_VERSION=dev
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
 && apt-get upgrade -y \
 && apt-get install -y --no-install-recommends libpq5 ca-certificates tini curl \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd -r -g 10001 argus \
 && useradd -r -u 10001 -g argus -d /app -s /usr/sbin/nologin argus
WORKDIR /app
COPY --from=build /opt/venv /opt/venv
COPY --from=source --chown=argus:argus /src /app
COPY --from=source /out/argus-entrypoint /usr/local/bin/argus-entrypoint
RUN mkdir -p /app/data /app/targets \
 && chown -R argus:argus /app/data /app/targets
USER 10001:10001
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8080/health || exit 1
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/argus-entrypoint"]
CMD ["api"]
