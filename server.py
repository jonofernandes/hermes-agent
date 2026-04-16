#!/usr/bin/env python3
"""
Hermes Agent — Railway management server.

Manages the hermes gateway process and the hermes web UI, provides HTTP Basic
auth + session-cookie authentication, reverse-proxies the web UI, and exposes
control endpoints for gateway lifecycle and pairing management.

Environment variables:
    ADMIN_USER          Basic-auth username (default: admin)
    ADMIN_PASSWORD      Basic-auth password (required in production)
    SECRET_KEY          HMAC secret for signing session cookies (auto-generated
                        if not set, meaning sessions are lost on restart)
    PORT                Port this server listens on (default: 8080)
    HERMES_HOME         Hermes data directory (default: /data/.hermes)
    OPENAI_API_KEY      Passed through to hermes processes
    ANTHROPIC_API_KEY   Passed through to hermes processes
    OPENROUTER_API_KEY  Passed through to hermes processes
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("hermes.server")

# ---------------------------------------------------------------------------
# Configuration from environment
# ---------------------------------------------------------------------------
ADMIN_USER: str = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASSWORD: str = os.environ.get("ADMIN_PASSWORD", "")
SECRET_KEY: str = os.environ.get("SECRET_KEY", secrets.token_hex(32))
PORT: int = int(os.environ.get("PORT", "8080"))
HERMES_HOME: str = os.environ.get("HERMES_HOME", "/data/.hermes")

# Internal hermes web UI address (started by this server)
_WEB_HOST = "127.0.0.1"
_WEB_PORT = 9119
_WEB_BASE = f"http://{_WEB_HOST}:{_WEB_PORT}"

# Cookie name for the session token
_COOKIE_NAME = "hermes_session"
# Session TTL in seconds (8 hours)
_SESSION_TTL = 8 * 3600

# ---------------------------------------------------------------------------
# Starlette / httpx imports (available via hermes-agent[web] extra)
# ---------------------------------------------------------------------------
try:
    import httpx
    from starlette.applications import Starlette
    from starlette.middleware import Middleware
    from starlette.middleware.sessions import SessionMiddleware
    from starlette.requests import Request
    from starlette.responses import (
        HTMLResponse,
        JSONResponse,
        PlainTextResponse,
        RedirectResponse,
        Response,
        StreamingResponse,
    )
    from starlette.routing import Mount, Route
except ImportError as exc:
    sys.exit(
        f"Missing dependency: {exc}\n"
        "Install with: pip install starlette httpx uvicorn"
    )

# ---------------------------------------------------------------------------
# Hermes install directory (resolved relative to this file so it works
# whether the repo is mounted at /app, /opt/hermes, or anywhere else)
# ---------------------------------------------------------------------------
_HERMES_DIR = str(Path(__file__).parent.resolve())


def _ensure_hermes_on_path() -> None:
    """Add the hermes install directory to sys.path if not already present."""
    if _HERMES_DIR not in sys.path:
        sys.path.insert(0, _HERMES_DIR)


# ---------------------------------------------------------------------------
# Managed child processes
# ---------------------------------------------------------------------------
_gateway_proc: Optional[asyncio.subprocess.Process] = None
_web_proc: Optional[asyncio.subprocess.Process] = None

# Lock to serialise gateway start/stop/restart operations
_gateway_lock = asyncio.Lock()


def _hermes_env() -> dict:
    """Build the environment for child hermes processes."""
    env = {**os.environ, "HERMES_HOME": HERMES_HOME, "PYTHONUNBUFFERED": "1"}
    return env


async def _start_web_ui() -> None:
    """Start the hermes web UI on the internal port."""
    global _web_proc
    if _web_proc is not None and _web_proc.returncode is None:
        return  # already running

    log.info("Starting hermes web UI on %s:%d", _WEB_HOST, _WEB_PORT)
    _web_proc = await asyncio.create_subprocess_exec(
        sys.executable,
        "-m",
        "hermes_cli.main",
        "dashboard",
        "--host",
        _WEB_HOST,
        "--port",
        str(_WEB_PORT),
        "--no-open",
        env=_hermes_env(),
        cwd=_HERMES_DIR,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    # Drain output in background so the pipe buffer never fills
    asyncio.ensure_future(_drain(_web_proc, "web-ui"))


async def _start_gateway() -> None:
    """Start the hermes gateway in the foreground (non-service mode)."""
    global _gateway_proc
    async with _gateway_lock:
        if _gateway_proc is not None and _gateway_proc.returncode is None:
            log.info("Gateway already running (pid=%d)", _gateway_proc.pid)
            return

        log.info("Starting hermes gateway")
        _gateway_proc = await asyncio.create_subprocess_exec(
            sys.executable,
            "-m",
            "hermes_cli.main",
            "gateway",
            "run",
            env=_hermes_env(),
            cwd=_HERMES_DIR,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        asyncio.ensure_future(_drain(_gateway_proc, "gateway"))
        log.info("Gateway started (pid=%d)", _gateway_proc.pid)


async def _stop_gateway() -> None:
    """Gracefully stop the gateway process."""
    global _gateway_proc
    async with _gateway_lock:
        if _gateway_proc is None or _gateway_proc.returncode is not None:
            log.info("Gateway is not running")
            return

        pid = _gateway_proc.pid
        log.info("Stopping gateway (pid=%d)", pid)
        try:
            _gateway_proc.send_signal(signal.SIGTERM)
            try:
                await asyncio.wait_for(_gateway_proc.wait(), timeout=10)
            except asyncio.TimeoutError:
                log.warning("Gateway did not exit in 10 s, sending SIGKILL")
                _gateway_proc.kill()
                await _gateway_proc.wait()
        except ProcessLookupError:
            pass
        log.info("Gateway stopped (pid=%d)", pid)
        _gateway_proc = None


async def _drain(proc: asyncio.subprocess.Process, label: str) -> None:
    """Read and log stdout from a child process until it exits."""
    if proc.stdout is None:
        return
    try:
        async for line in proc.stdout:
            text = line.decode(errors="replace").rstrip()
            if text:
                log.info("[%s] %s", label, text)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Authentication helpers
# ---------------------------------------------------------------------------

def _make_session_token(username: str) -> str:
    """Create a signed, time-stamped session token."""
    expires = int(time.time()) + _SESSION_TTL
    payload = f"{username}:{expires}"
    sig = hmac.new(SECRET_KEY.encode(), payload.encode(), hashlib.sha256).hexdigest()
    raw = f"{payload}:{sig}"
    return base64.urlsafe_b64encode(raw.encode()).decode()


def _verify_session_token(token: str) -> Optional[str]:
    """Verify a session token. Returns the username on success, None on failure."""
    try:
        raw = base64.urlsafe_b64decode(token.encode()).decode()
        username, expires_str, sig = raw.rsplit(":", 2)
        expires = int(expires_str)
        if time.time() > expires:
            return None
        expected_payload = f"{username}:{expires_str}"
        expected_sig = hmac.new(
            SECRET_KEY.encode(), expected_payload.encode(), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(sig, expected_sig):
            return None
        return username
    except Exception:
        return None


def _check_basic_auth(request: Request) -> bool:
    """Return True if the request carries valid HTTP Basic credentials."""
    if not ADMIN_PASSWORD:
        # No password configured — allow all (development mode)
        return True
    auth_header = request.headers.get("authorization", "")
    if not auth_header.lower().startswith("basic "):
        return False
    try:
        decoded = base64.b64decode(auth_header[6:]).decode()
        user, _, password = decoded.partition(":")
        return hmac.compare_digest(user, ADMIN_USER) and hmac.compare_digest(
            password, ADMIN_PASSWORD
        )
    except Exception:
        return False


def _is_authenticated(request: Request) -> bool:
    """Return True if the request is authenticated via cookie or Basic auth."""
    # Cookie-based session
    cookie = request.cookies.get(_COOKIE_NAME, "")
    if cookie and _verify_session_token(cookie):
        return True
    # HTTP Basic auth
    return _check_basic_auth(request)


def _login_response(request: Request) -> Response:
    """Return a 401 response that prompts for Basic auth credentials."""
    return Response(
        content="Authentication required",
        status_code=401,
        headers={"WWW-Authenticate": 'Basic realm="Hermes Agent"'},
    )


# ---------------------------------------------------------------------------
# Login / logout endpoints
# ---------------------------------------------------------------------------

async def login(request: Request) -> Response:
    """POST /login — exchange Basic credentials for a session cookie."""
    if not _check_basic_auth(request):
        return _login_response(request)
    token = _make_session_token(ADMIN_USER)
    response = RedirectResponse(url="/", status_code=303)
    response.set_cookie(
        _COOKIE_NAME,
        token,
        max_age=_SESSION_TTL,
        httponly=True,
        samesite="lax",
    )
    return response


async def logout(request: Request) -> Response:
    """POST /logout — clear the session cookie."""
    response = RedirectResponse(url="/", status_code=303)
    response.delete_cookie(_COOKIE_NAME)
    return response


# ---------------------------------------------------------------------------
# Health check (public — no auth required)
# ---------------------------------------------------------------------------

async def health(request: Request) -> JSONResponse:
    """GET /health — liveness probe for Railway."""
    gateway_running = (
        _gateway_proc is not None and _gateway_proc.returncode is None
    )
    web_running = _web_proc is not None and _web_proc.returncode is None
    return JSONResponse(
        {
            "status": "ok",
            "gateway_running": gateway_running,
            "web_ui_running": web_running,
            "hermes_home": HERMES_HOME,
        }
    )


# ---------------------------------------------------------------------------
# Gateway control endpoints
# ---------------------------------------------------------------------------

async def gateway_start(request: Request) -> JSONResponse:
    """POST /api/gateway/start — start the gateway."""
    if not _is_authenticated(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    await _start_gateway()
    return JSONResponse({"ok": True, "action": "start"})


async def gateway_stop(request: Request) -> JSONResponse:
    """POST /api/gateway/stop — stop the gateway."""
    if not _is_authenticated(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    await _stop_gateway()
    return JSONResponse({"ok": True, "action": "stop"})


async def gateway_restart(request: Request) -> JSONResponse:
    """POST /api/gateway/restart — restart the gateway."""
    if not _is_authenticated(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    await _stop_gateway()
    await asyncio.sleep(1)
    await _start_gateway()
    return JSONResponse({"ok": True, "action": "restart"})


async def gateway_status(request: Request) -> JSONResponse:
    """GET /api/gateway/status — return gateway process status."""
    if not _is_authenticated(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    running = _gateway_proc is not None and _gateway_proc.returncode is None
    pid = _gateway_proc.pid if running else None
    return JSONResponse({"running": running, "pid": pid})


# ---------------------------------------------------------------------------
# Pairing management endpoints
# ---------------------------------------------------------------------------

async def pairing_list(request: Request) -> JSONResponse:
    """GET /api/pairing — list pending and approved pairing entries."""
    if not _is_authenticated(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    try:
        _ensure_hermes_on_path()
        from gateway.pairing import PairingStore

        store = PairingStore()
        return JSONResponse(
            {
                "pending": store.list_pending(),
                "approved": store.list_approved(),
            }
        )
    except Exception as exc:
        log.exception("pairing_list failed")
        return JSONResponse({"error": str(exc)}, status_code=500)


async def pairing_approve(request: Request) -> JSONResponse:
    """POST /api/pairing/approve — approve a pairing code."""
    if not _is_authenticated(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    try:
        body = await request.json()
        platform = body.get("platform", "")
        code = body.get("code", "")
        if not platform or not code:
            return JSONResponse(
                {"error": "platform and code are required"}, status_code=400
            )
        _ensure_hermes_on_path()
        from gateway.pairing import PairingStore

        store = PairingStore()
        result = store.approve_code(platform, code)
        if result is None:
            return JSONResponse(
                {"error": "Invalid or expired code"}, status_code=400
            )
        return JSONResponse({"ok": True, "approved": result})
    except Exception as exc:
        log.exception("pairing_approve failed")
        return JSONResponse({"error": str(exc)}, status_code=500)


async def pairing_revoke(request: Request) -> JSONResponse:
    """POST /api/pairing/revoke — revoke an approved user."""
    if not _is_authenticated(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    try:
        body = await request.json()
        platform = body.get("platform", "")
        user_id = body.get("user_id", "")
        if not platform or not user_id:
            return JSONResponse(
                {"error": "platform and user_id are required"}, status_code=400
            )
        _ensure_hermes_on_path()
        from gateway.pairing import PairingStore

        store = PairingStore()
        removed = store.revoke(platform, user_id)
        return JSONResponse({"ok": True, "removed": removed})
    except Exception as exc:
        log.exception("pairing_revoke failed")
        return JSONResponse({"error": str(exc)}, status_code=500)


# ---------------------------------------------------------------------------
# Reverse proxy to the hermes web UI
# ---------------------------------------------------------------------------

# Shared async HTTP client (connection-pooled)
_http_client: Optional[httpx.AsyncClient] = None


def _get_http_client() -> httpx.AsyncClient:
    global _http_client
    if _http_client is None or _http_client.is_closed:
        _http_client = httpx.AsyncClient(
            base_url=_WEB_BASE,
            timeout=httpx.Timeout(30.0),
            follow_redirects=False,
        )
    return _http_client


async def proxy(request: Request) -> Response:
    """Reverse-proxy all other requests to the hermes web UI."""
    if not _is_authenticated(request):
        # For browser requests, redirect to a Basic-auth challenge
        accept = request.headers.get("accept", "")
        if "text/html" in accept:
            return _login_response(request)
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    client = _get_http_client()
    path = request.url.path
    query = request.url.query
    url = path + (f"?{query}" if query else "")

    # Forward the request body
    body = await request.body()

    # Strip hop-by-hop headers before forwarding
    _hop_by_hop = {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailers",
        "transfer-encoding",
        "upgrade",
        "host",
    }
    headers = {
        k: v
        for k, v in request.headers.items()
        if k.lower() not in _hop_by_hop
    }

    try:
        upstream = await client.request(
            method=request.method,
            url=url,
            headers=headers,
            content=body,
        )
    except httpx.ConnectError:
        return HTMLResponse(
            "<h2>Hermes web UI is starting…</h2>"
            "<p>Please refresh in a few seconds.</p>",
            status_code=503,
        )
    except Exception as exc:
        log.error("Proxy error: %s", exc)
        return PlainTextResponse(f"Proxy error: {exc}", status_code=502)

    # Strip hop-by-hop headers from the upstream response
    response_headers = {
        k: v
        for k, v in upstream.headers.items()
        if k.lower() not in _hop_by_hop
    }

    return Response(
        content=upstream.content,
        status_code=upstream.status_code,
        headers=response_headers,
    )


# ---------------------------------------------------------------------------
# Application startup / shutdown
# ---------------------------------------------------------------------------

async def on_startup() -> None:
    """Start managed child processes when the server starts."""
    log.info("Hermes management server starting (port=%d)", PORT)
    log.info("HERMES_HOME=%s", HERMES_HOME)

    # Ensure data directories exist
    for subdir in ("sessions", "skills", "workspace", "pairing"):
        Path(HERMES_HOME, subdir).mkdir(parents=True, exist_ok=True)

    # Start the hermes web UI
    await _start_web_ui()

    # Start the gateway (best-effort — may not be configured yet)
    try:
        await _start_gateway()
    except Exception as exc:
        log.warning("Gateway did not start on boot: %s", exc)


async def on_shutdown() -> None:
    """Stop managed child processes on server shutdown."""
    log.info("Shutting down managed processes")
    await _stop_gateway()

    global _web_proc
    if _web_proc is not None and _web_proc.returncode is None:
        _web_proc.terminate()
        try:
            await asyncio.wait_for(_web_proc.wait(), timeout=5)
        except asyncio.TimeoutError:
            _web_proc.kill()

    global _http_client
    if _http_client is not None and not _http_client.is_closed:
        await _http_client.aclose()


# ---------------------------------------------------------------------------
# Starlette application
# ---------------------------------------------------------------------------

routes = [
    # Public endpoints
    Route("/health", health, methods=["GET"]),
    # Auth
    Route("/login", login, methods=["POST"]),
    Route("/logout", logout, methods=["POST"]),
    # Gateway control
    Route("/api/gateway/start", gateway_start, methods=["POST"]),
    Route("/api/gateway/stop", gateway_stop, methods=["POST"]),
    Route("/api/gateway/restart", gateway_restart, methods=["POST"]),
    Route("/api/gateway/status", gateway_status, methods=["GET"]),
    # Pairing management
    Route("/api/pairing", pairing_list, methods=["GET"]),
    Route("/api/pairing/approve", pairing_approve, methods=["POST"]),
    Route("/api/pairing/revoke", pairing_revoke, methods=["POST"]),
    # Catch-all reverse proxy to hermes web UI
    Route("/{path:path}", proxy, methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]),
    Route("/", proxy, methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]),
]

app = Starlette(
    routes=routes,
    on_startup=[on_startup],
    on_shutdown=[on_shutdown],
)

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    try:
        import uvicorn
    except ImportError:
        sys.exit("uvicorn is required: pip install uvicorn")

    if not ADMIN_PASSWORD:
        log.warning(
            "ADMIN_PASSWORD is not set — authentication is disabled. "
            "Set ADMIN_PASSWORD in your Railway environment variables."
        )

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=PORT,
        log_level="info",
        access_log=True,
    )
