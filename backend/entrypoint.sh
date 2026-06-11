#!/usr/bin/env bash
# Entrypoint for the backend API container.
# Waits for Postgres, applies migrations, seeds demo data, then starts uvicorn.
set -euo pipefail

echo "[entrypoint] waiting for postgres..."
python - <<'PY'
import time, sys
import psycopg2
from app.config import settings

url = settings.database_url.replace("postgresql://", "postgres://")
for attempt in range(30):
    try:
        psycopg2.connect(settings.database_url).close()
        print("[entrypoint] postgres is ready")
        break
    except Exception as exc:
        print(f"[entrypoint] postgres not ready ({attempt+1}/30): {exc}")
        time.sleep(2)
else:
    print("[entrypoint] postgres never became ready")
    sys.exit(1)
PY

echo "[entrypoint] running migrations..."
alembic upgrade head || echo "[entrypoint] alembic failed; falling back to create_all at startup"

echo "[entrypoint] seeding demo data..."
python -m app.seed || echo "[entrypoint] seed skipped"

echo "[entrypoint] starting API..."
exec uvicorn app.main:app --host 0.0.0.0 --port 8000
