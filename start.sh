#!/bin/bash
set -e

INSTALL_DIR="/opt/hermes"
HERMES_HOME="${HERMES_HOME:-/opt/data}"

source "${INSTALL_DIR}/.venv/bin/activate"

mkdir -p "$HERMES_HOME"/{cron,sessions,logs,hooks,memories,skills,skins,plans,workspace,home}

# .env
if [ ! -f "$HERMES_HOME/.env" ]; then
    cp "$INSTALL_DIR/.env.example" "$HERMES_HOME/.env"
fi

# config.yaml
if [ ! -f "$HERMES_HOME/config.yaml" ]; then
    cp "$INSTALL_DIR/cli-config.yaml.example" "$HERMES_HOME/config.yaml"
fi

# SOUL.md
if [ ! -f "$HERMES_HOME/SOUL.md" ]; then
    cp "$INSTALL_DIR/docker/SOUL.md" "$HERMES_HOME/SOUL.md"
fi

# Sync bundled skills
if [ -d "$INSTALL_DIR/skills" ]; then
    python3 "$INSTALL_DIR/tools/skills_sync.py"
fi

# Railway expects an HTTP server for healthchecks.
# Run the gateway in foreground mode with the API server on PORT (default 8080).
# Bind to 0.0.0.0 so Railway can reach the /health endpoint.
export API_SERVER_PORT="${PORT:-8080}"
export API_SERVER_HOST="${API_SERVER_HOST:-0.0.0.0}"

exec hermes gateway run "$@"
