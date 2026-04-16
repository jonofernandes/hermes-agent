#!/bin/bash
# Railway entrypoint: create required data directories, then start the server.
set -e

DATA_DIR="${HERMES_HOME:-/data/.hermes}"

# Create necessary runtime directories under the data volume
mkdir -p \
    "${DATA_DIR}/sessions" \
    "${DATA_DIR}/skills" \
    "${DATA_DIR}/workspace" \
    "${DATA_DIR}/pairing"

# Resolve the directory that contains this script so server.py is found
# regardless of whether the repo is mounted at /app or /opt/hermes.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Execute the Python management server (replaces this shell process)
exec python "${SCRIPT_DIR}/server.py"
