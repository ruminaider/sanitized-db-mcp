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

import hmac
import logging

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

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        if scope["path"] == "/health":
            await self.app(scope, receive, send)
            return

        auth = b""
        for key, val in scope.get("headers", []):
            if key == b"authorization":
                auth = val
                break

        if not hmac.compare_digest(auth, self._expected):
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
    server: Server, *, api_key: str | None = None
) -> Starlette | BearerAuthMiddleware:
    """Build the Starlette ASGI app for SSE transport.

    Returns the app wrapped with BearerAuthMiddleware when *api_key* is provided.
    """
    sse_transport = SseServerTransport("/messages/")
    init_options = server.create_initialization_options()

    async def handle_sse(request: Request) -> Response:
        # _send is a private attr on starlette Request; connect_sse needs
        # the raw ASGI send callable. This is the canonical MCP SDK pattern.
        async with sse_transport.connect_sse(
            request.scope, request.receive, request._send
        ) as (read_stream, write_stream):
            await server.run(read_stream, write_stream, init_options)
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
