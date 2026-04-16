import asyncio
import base64
import hashlib
import hmac
import os
import re
import secrets
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
from itsdangerous import BadSignature, SignatureExpired, TimestampSigner
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, Response
from starlette.routing import Route

ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")
HERMES_HOME = os.environ.get("HERMES_HOME", "/data/.hermes")
PORT = int(os.environ.get("PORT", "8080"))
WEB_PORT = int(os.environ.get("WEB_PORT", "9119"))
PAIRING_DIR = Path(HERMES_HOME) / "pairing"
CODE_TTL_SECONDS = 3600

# ---------------------------------------------------------------------------
# Session cookie auth
# ---------------------------------------------------------------------------

COOKIE_NAME = "hermes_session"
COOKIE_MAX_AGE = 86400 * 7  # 7 days
SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_hex(32))
_signer = TimestampSigner(SECRET_KEY)


def _make_session_token(username: str) -> str:
    return _signer.sign(username).decode()


def _verify_session_token(token: str) -> str | None:
    try:
        return _signer.unsign(token, max_age=COOKIE_MAX_AGE).decode()
    except (BadSignature, SignatureExpired):
        return None


def _is_authenticated(request: Request) -> bool:
    token = request.cookies.get(COOKIE_NAME)
    if token and _verify_session_token(token):
        return True
    return False


def _auth_response() -> Response:
    return Response(
        status_code=401,
        headers={"WWW-Authenticate": 'Basic realm="Hermes Agent"'},
    )


def _check_basic_auth(request: Request) -> bool:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Basic "):
        return False
    try:
        decoded = base64.b64decode(auth[6:]).decode("utf-8")
    except Exception:
        return False
    username, _, password = decoded.partition(":")
    return secrets.compare_digest(username, ADMIN_USERNAME) and secrets.compare_digest(
        password, ADMIN_PASSWORD
    )


# ---------------------------------------------------------------------------
# Gateway manager
# ---------------------------------------------------------------------------


class GatewayManager:
    def __init__(self):
        self.process: asyncio.subprocess.Process | None = None
        self._lock = asyncio.Lock()
        self._state = "stopped"
        self._read_tasks: list[asyncio.Task] = []

    @property
    def state(self) -> str:
        if self.process is None:
            return "stopped"
        if self.process.returncode is None:
            return "running"
        return "stopped"

    async def start(self) -> dict:
        async with self._lock:
            if self.state == "running":
                return {"ok": False, "error": "Already running"}
            env = os.environ.copy()
            env["HERMES_HOME"] = HERMES_HOME
            try:
                self.process = await asyncio.create_subprocess_exec(
                    "hermes", "gateway", "start",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.STDOUT,
                    env=env,
                )
                self._state = "running"
                task = asyncio.create_task(self._drain_output())
                self._read_tasks = [t for t in self._read_tasks if not t.done()]
                self._read_tasks.append(task)
                return {"ok": True}
            except Exception as e:
                return {"ok": False, "error": str(e)}

    async def stop(self) -> dict:
        async with self._lock:
            if self.process is None or self.process.returncode is not None:
                return {"ok": False, "error": "Not running"}
            self.process.terminate()
            try:
                await asyncio.wait_for(self.process.wait(), timeout=10.0)
            except asyncio.TimeoutError:
                self.process.kill()
            self.process = None
            return {"ok": True}

    async def restart(self) -> dict:
        await self.stop()
        return await self.start()

    async def _drain_output(self):
        try:
            while self.process and self.process.stdout:
                line = await self.process.stdout.readline()
                if not line:
                    break
                print(f"[hermes gateway] {line.decode('utf-8', errors='replace').rstrip()}", flush=True)
        except asyncio.CancelledError:
            return


gateway = GatewayManager()


# ---------------------------------------------------------------------------
# Web manager (hermes web React SPA)
# ---------------------------------------------------------------------------


class WebManager:
    def __init__(self):
        self.process: asyncio.subprocess.Process | None = None
        self._monitor_task: asyncio.Task | None = None

    async def start(self):
        env = os.environ.copy()
        env["HERMES_HOME"] = HERMES_HOME

        # Call start_server() directly to bypass the `hermes dashboard`
        # CLI wrapper which runs _build_web_ui() and requires Node.js.
        # Node is only available in the Docker build stage, not at runtime.
        self.process = await asyncio.create_subprocess_exec(
            "python", "-c",
            (
                "from hermes_cli.web_server import start_server; "
                f"start_server(port={WEB_PORT}, open_browser=False)"
            ),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            env=env,
        )
        self._monitor_task = asyncio.create_task(self._monitor())

    async def stop(self):
        if self._monitor_task:
            self._monitor_task.cancel()
            try:
                await self._monitor_task
            except asyncio.CancelledError:
                pass
        if self.process and self.process.returncode is None:
            self.process.terminate()
            try:
                await asyncio.wait_for(self.process.wait(), timeout=10.0)
            except asyncio.TimeoutError:
                self.process.kill()

    async def _monitor(self):
        try:
            while self.process and self.process.stdout:
                line = await self.process.stdout.readline()
                if not line:
                    break
                print(f"[hermes web] {line.decode('utf-8', errors='replace').rstrip()}", flush=True)
        except asyncio.CancelledError:
            return
        if self.process and self.process.returncode is not None:
            print(f"[hermes web] exited with code {self.process.returncode}", flush=True)

    async def wait_ready(self, timeout: float = 30.0) -> bool:
        """Poll WEB_PORT until hermes web is accepting TCP connections."""
        loop = asyncio.get_event_loop()
        deadline = loop.time() + timeout
        print(f"[hermes web] waiting for port {WEB_PORT}…", flush=True)
        while loop.time() < deadline:
            if self.process and self.process.returncode is not None:
                print("[hermes web] process exited before becoming ready", flush=True)
                return False
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection("127.0.0.1", WEB_PORT), timeout=1.0
                )
                writer.close()
                await writer.wait_closed()
                print(f"[hermes web] ready on port {WEB_PORT}", flush=True)
                return True
            except (OSError, asyncio.TimeoutError):
                await asyncio.sleep(1)
        print(f"[hermes web] timed out waiting for port {WEB_PORT}", flush=True)
        return False


web_manager = WebManager()

# ---------------------------------------------------------------------------
# Proxy handler
# ---------------------------------------------------------------------------

_proxy_client: httpx.AsyncClient | None = None

_HOP_BY_HOP = frozenset(
    [
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailers",
        "transfer-encoding",
        "upgrade",
        "content-encoding",
        "content-length",
    ]
)


async def _proxy_request(request: Request) -> Response:
    assert _proxy_client is not None
    url = f"http://127.0.0.1:{WEB_PORT}{request.url.path}"
    if request.url.query:
        url += f"?{request.url.query}"

    headers = {
        k: v
        for k, v in request.headers.items()
        if k.lower() not in _HOP_BY_HOP and k.lower() != "host"
    }
    headers["accept-encoding"] = "identity"

    body = await request.body()

    try:
        upstream = await _proxy_client.request(
            method=request.method,
            url=url,
            headers=headers,
            content=body,
            follow_redirects=False,
        )
    except (httpx.ConnectError, httpx.ConnectTimeout):
        return Response(
            content=(
                "<!doctype html><html><head>"
                "<meta http-equiv='refresh' content='3'>"
                "<title>Starting…</title>"
                "<style>body{font-family:sans-serif;display:flex;align-items:center;"
                "justify-content:center;height:100vh;margin:0;background:#0f172a;color:#94a3b8}"
                "p{font-size:1.2rem}</style></head>"
                "<body><p>Hermes dashboard is starting, please wait…</p></body></html>"
            ),
            status_code=503,
            media_type="text/html",
        )
    except Exception as e:
        return PlainTextResponse(f"Proxy error: {e}", status_code=502)

    resp_headers = {
        k: v
        for k, v in upstream.headers.items()
        if k.lower() not in _HOP_BY_HOP
    }

    return Response(
        content=upstream.content,
        status_code=upstream.status_code,
        headers=resp_headers,
        media_type=upstream.headers.get("content-type"),
    )


# ---------------------------------------------------------------------------
# Auth endpoint
# ---------------------------------------------------------------------------


async def login(request: Request) -> Response:
    if _is_authenticated(request):
        return Response(status_code=302, headers={"location": "/"})

    if not _check_basic_auth(request):
        return _auth_response()

    token = _make_session_token(ADMIN_USERNAME)
    response = Response(status_code=302, headers={"location": "/"})
    response.set_cookie(
        COOKIE_NAME,
        token,
        max_age=COOKIE_MAX_AGE,
        httponly=True,
        samesite="lax",
    )
    return response


async def logout(request: Request) -> Response:
    response = Response(status_code=302, headers={"location": "/"})
    response.delete_cookie(COOKIE_NAME)
    return response


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------


async def health(request: Request) -> JSONResponse:
    return JSONResponse(
        {
            "ok": True,
            "gateway": gateway.state,
            "web": "running" if (web_manager.process and web_manager.process.returncode is None) else "stopped",
        }
    )


# ---------------------------------------------------------------------------
# Gateway API
# ---------------------------------------------------------------------------


async def api_gateway_start(request: Request) -> JSONResponse:
    if not _is_authenticated(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    result = await gateway.start()
    return JSONResponse(result)


async def api_gateway_stop(request: Request) -> JSONResponse:
    if not _is_authenticated(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    result = await gateway.stop()
    return JSONResponse(result)


async def api_gateway_restart(request: Request) -> JSONResponse:
    if not _is_authenticated(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    result = await gateway.restart()
    return JSONResponse(result)


async def api_status(request: Request) -> JSONResponse:
    if not _is_authenticated(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    return JSONResponse(
        {
            "gateway": {"state": gateway.state},
            "web": {
                "state": "running"
                if (web_manager.process and web_manager.process.returncode is None)
                else "stopped"
            },
        }
    )


# ---------------------------------------------------------------------------
# Pairing API
# ---------------------------------------------------------------------------


def _sanitize_platform(platform: str) -> str:
    """Sanitize platform name to prevent path traversal."""
    return re.sub(r"[^a-zA-Z0-9_-]", "", platform)


async def api_pairing_code(request: Request) -> JSONResponse:
    if not _is_authenticated(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    platform = _sanitize_platform(request.query_params.get("platform", ""))
    if not platform:
        return JSONResponse({"error": "Missing platform"}, status_code=400)
    code_file = PAIRING_DIR / f"{platform}.code"
    if not code_file.exists():
        return JSONResponse({"code": None})
    try:
        code = code_file.read_text().strip()
        return JSONResponse({"code": code})
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


async def api_pairing_approve(request: Request) -> JSONResponse:
    if not _is_authenticated(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)
    platform = _sanitize_platform(body.get("platform", ""))
    if not platform:
        return JSONResponse({"error": "Missing platform"}, status_code=400)
    approve_file = PAIRING_DIR / f"{platform}.approved"
    PAIRING_DIR.mkdir(parents=True, exist_ok=True)
    approve_file.touch()
    return JSONResponse({"ok": True})


async def api_pairing_deny(request: Request) -> JSONResponse:
    if not _is_authenticated(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)
    platform = _sanitize_platform(body.get("platform", ""))
    if not platform:
        return JSONResponse({"error": "Missing platform"}, status_code=400)
    code_file = PAIRING_DIR / f"{platform}.code"
    approve_file = PAIRING_DIR / f"{platform}.approved"
    for f in (code_file, approve_file):
        if f.exists():
            f.unlink()
    return JSONResponse({"ok": True})


async def api_pairing_approved(request: Request) -> JSONResponse:
    if not _is_authenticated(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    platform = _sanitize_platform(request.query_params.get("platform", ""))
    if not platform:
        return JSONResponse({"error": "Missing platform"}, status_code=400)
    approve_file = PAIRING_DIR / f"{platform}.approved"
    return JSONResponse({"approved": approve_file.exists()})


async def api_pairing_revoke(request: Request) -> JSONResponse:
    if not _is_authenticated(request):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)
    platform = _sanitize_platform(body.get("platform", ""))
    if not platform:
        return JSONResponse({"error": "Missing platform"}, status_code=400)
    approve_file = PAIRING_DIR / f"{platform}.approved"
    if approve_file.exists():
        approve_file.unlink()
    return JSONResponse({"ok": True})


# ---------------------------------------------------------------------------
# Proxy catch-all (auth-gated)
# ---------------------------------------------------------------------------


async def proxy_handler(request: Request) -> Response:
    if not _is_authenticated(request):
        # Allow Bearer token requests through (React SPA API calls)
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return _auth_response()
    return await _proxy_request(request)


# ---------------------------------------------------------------------------
# Auto-start
# ---------------------------------------------------------------------------


async def auto_start_gateway():
    await asyncio.sleep(2)
    await gateway.start()


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(app):
    global _proxy_client
    _proxy_client = httpx.AsyncClient(timeout=30.0)

    await web_manager.start()
    await web_manager.wait_ready()

    asyncio.create_task(auto_start_gateway())

    try:
        yield
    finally:
        await web_manager.stop()
        await gateway.stop()
        await _proxy_client.aclose()


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

routes = [
    Route("/health", health),
    Route("/login", login, methods=["GET", "POST"]),
    Route("/logout", logout, methods=["GET", "POST"]),
    Route("/api/status", api_status),
    Route("/api/gateway/start", api_gateway_start, methods=["POST"]),
    Route("/api/gateway/stop", api_gateway_stop, methods=["POST"]),
    Route("/api/gateway/restart", api_gateway_restart, methods=["POST"]),
    Route("/api/pairing/code", api_pairing_code),
    Route("/api/pairing/approve", api_pairing_approve, methods=["POST"]),
    Route("/api/pairing/deny", api_pairing_deny, methods=["POST"]),
    Route("/api/pairing/approved", api_pairing_approved),
    Route("/api/pairing/revoke", api_pairing_revoke, methods=["POST"]),
    # Everything else → hermes web (React SPA + upstream API)
    Route("/{path:path}", proxy_handler, methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]),
    Route("/", proxy_handler),
]

app = Starlette(routes=routes, lifespan=lifespan)
