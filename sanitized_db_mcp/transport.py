"""
SSE transport for the sanitizing MCP server.

Provides a Starlette ASGI application with:
  - GET /sse          SSE connection endpoint (MCP session)
  - POST /messages/   Client-to-server message endpoint
  - GET /health       Health check for load balancers / Render

Requires the [sse] optional extra:
    pip install 'sanitized-db-mcp[sse]'
"""

from __future__ import annotations

import asyncio
import hmac
import logging
import time

from anyio import BrokenResourceError, ClosedResourceError
from mcp.server import Server
from mcp.server.sse import SseServerTransport

try:
    from starlette.applications import Starlette
    from starlette.requests import Request
    from starlette.responses import JSONResponse, Response
    from starlette.routing import Mount, Route
except ImportError:
    raise ImportError(
        "SSE transport requires the 'sse' extra. "
        "Install with: pip install 'sanitized-db-mcp[sse]'"
    )

logger = logging.getLogger("sanitized_db_mcp")

_EXPECTED_DISCONNECT = (ClosedResourceError, BrokenResourceError, ConnectionError)


def _is_expected_disconnect(exc: BaseException) -> bool:
    """Return True if *exc* (or all sub-exceptions in a group) are expected."""
    if isinstance(exc, _EXPECTED_DISCONNECT):
        return True
    if isinstance(exc, BaseExceptionGroup):
        return all(_is_expected_disconnect(e) for e in exc.exceptions)
    return False


def _contains_timeout(exc: BaseException) -> bool:
    """Return True if *exc* (or any sub-exception in a group) is a TimeoutError."""
    if isinstance(exc, TimeoutError):
        return True
    if isinstance(exc, BaseExceptionGroup):
        return any(_contains_timeout(e) for e in exc.exceptions)
    return False


# ---------------------------------------------------------------------------
# Auth middleware
# ---------------------------------------------------------------------------


class BearerAuthMiddleware:
    """Pure ASGI middleware for bearer-token authentication.

    Skips auth for /health and non-HTTP scopes (lifespan).
    Uses hmac.compare_digest for constant-time comparison.
    """

    def __init__(self, app, api_key: str) -> None:
        self.app = app
        self._expected = f"Bearer {api_key}".encode()
        self._fail_count = 0
        self._last_fail_summary = 0.0

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        if scope["path"] in ("/health", "/health/"):
            await self.app(scope, receive, send)
            return

        auth = b""
        for key, val in scope.get("headers", []):
            if key == b"authorization":
                auth = val
                break

        if not hmac.compare_digest(auth, self._expected):
            self._fail_count += 1
            now = time.monotonic()
            if now - self._last_fail_summary >= 60:
                logger.warning(
                    "Authentication failed: %d attempt(s) in last 60s",
                    self._fail_count,
                )
                self._fail_count = 0
                self._last_fail_summary = now
            logger.debug(
                "Authentication failed for %s %s",
                scope.get("method", "?"),
                scope["path"][:200],
            )
            response = JSONResponse(
                {"error": "Unauthorized"},
                status_code=401,
                headers={"WWW-Authenticate": "Bearer"},
            )
            await response(scope, receive, send)
            return

        await self.app(scope, receive, send)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


async def health_check(request: Request) -> JSONResponse:
    """Shallow health check for Render / load balancers."""
    return JSONResponse({"status": "ok"})


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------


def create_sse_app(
    server: Server,
    *,
    api_key: str | None = None,
    session_timeout: int | None = None,
) -> Starlette | BearerAuthMiddleware:
    """Build the Starlette ASGI app for SSE transport.

    Returns the app wrapped with BearerAuthMiddleware when *api_key* is provided.
    """
    sse_transport = SseServerTransport("/messages/")
    init_options = server.create_initialization_options()

    async def handle_sse(request: Request) -> Response:
        # _send is a private attr on starlette Request; connect_sse needs
        # the raw ASGI send callable. This is the canonical MCP SDK pattern.
        try:
            async with sse_transport.connect_sse(
                request.scope, request.receive, request._send
            ) as (read_stream, write_stream):
                if session_timeout is not None:
                    async with asyncio.timeout(session_timeout):
                        await server.run(read_stream, write_stream, init_options)
                else:
                    await server.run(read_stream, write_stream, init_options)
        except BaseException as exc:
            if isinstance(exc, (KeyboardInterrupt, SystemExit, GeneratorExit, asyncio.CancelledError)):
                raise
            if isinstance(exc, TimeoutError) or _contains_timeout(exc):
                logger.info("SSE session closed (timeout after %ds)", session_timeout)
                # Log any unexpected sub-exceptions grouped with the timeout
                if isinstance(exc, BaseExceptionGroup):
                    unexpected = [
                        e for e in exc.exceptions
                        if not isinstance(e, (TimeoutError, *_EXPECTED_DISCONNECT))
                    ]
                    if unexpected:
                        logger.error("Unexpected errors alongside timeout: %r", unexpected)
            elif _is_expected_disconnect(exc):
                logger.debug("SSE session closed (client disconnect)")
            else:
                logger.error("SSE session error (unexpected)", exc_info=True)
        return Response()

    app = Starlette(
        routes=[
            Route("/sse", endpoint=handle_sse, methods=["GET"]),
            Route("/health", endpoint=health_check, methods=["GET"]),
            Mount("/messages/", app=sse_transport.handle_post_message),
        ],
    )

    if api_key:
        logger.info("Bearer token authentication enabled")
        return BearerAuthMiddleware(app, api_key)

    logger.warning(
        "MCP_API_KEY is not set — SSE server has no authentication. "
        "This is unsafe for production deployments."
    )
    return app
