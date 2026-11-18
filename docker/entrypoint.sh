#!/bin/sh
# Entrypoint for the Argus image.
#   api     run migrations (if RUN_MIGRATIONS=true) then uvicorn behind a reverse proxy
#   worker  run migrations (if RUN_MIGRATIONS=true) then the standalone queue worker
#   migrate run migrations once and exit
#   <anything else> is exec'd verbatim (e.g. python scripts/seed_demo.py)
set -eu

ROLE="${1:-api}"
if [ $# -gt 0 ]; then shift; fi

run_migrations() {
  if [ "${RUN_MIGRATIONS:-false}" = "true" ]; then
    echo "[entrypoint] running database migrations"
    python scripts/migrate.py
  fi
}

case "$ROLE" in
  api)
    run_migrations
    # Client IP resolution from X-Forwarded-For is handled inside the app by TRUSTED_PROXY_HOPS
    # (taking the Nth address from the right). Do not let uvicorn take the leftmost X-Forwarded-For.
    exec uvicorn app.main:app \
      --host "${UVICORN_HOST:-0.0.0.0}" \
      --port "${UVICORN_PORT:-8080}" \
      --workers "${UVICORN_WORKERS:-1}" \
      --no-server-header \
      --timeout-graceful-shutdown "${UVICORN_GRACEFUL_TIMEOUT:-25}"
    ;;
  worker)
    run_migrations
    exec python -m app.worker
    ;;
  migrate)
    exec python scripts/migrate.py
    ;;
  *)
    exec "$ROLE" "$@"
    ;;
esac
