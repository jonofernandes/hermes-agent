#!/bin/bash
set -e

mkdir -p "${HERMES_HOME:-/data/.hermes}"

exec uvicorn server:app \
    --host 0.0.0.0 \
    --port "${PORT:-8080}" \
    --log-level info
