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
import os

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
        self.api_key = api_key

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        if scope["path"] == "/health":
            await self.app(scope, receive, send)
            return

        headers = dict(scope.get("headers", []))
        auth = headers.get(b"authorization", b"").decode()
        expected = f"Bearer {self.api_key}"

        if not hmac.compare_digest(auth, expected):
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


def create_sse_app(server: Server) -> Starlette | BearerAuthMiddleware:
    """Build the Starlette ASGI app for SSE transport.

    Returns the app wrapped with BearerAuthMiddleware if MCP_API_KEY is set.
    """
    sse_transport = SseServerTransport("/messages/")

    async def handle_sse(request: Request) -> Response:
        async with sse_transport.connect_sse(
            request.scope, request.receive, request._send
        ) as (read_stream, write_stream):
            await server.run(
                read_stream, write_stream, server.create_initialization_options()
            )
        return Response()

    app = Starlette(
        routes=[
            Route("/sse", endpoint=handle_sse, methods=["GET"]),
            Route("/health", endpoint=health_check, methods=["GET"]),
            Mount("/messages/", app=sse_transport.handle_post_message),
        ],
    )

    api_key = os.environ.get("MCP_API_KEY")
    if api_key:
        logger.info("Bearer token authentication enabled")
        return BearerAuthMiddleware(app, api_key)

    logger.warning(
        "MCP_API_KEY is not set — SSE server has no authentication. "
        "This is unsafe for production deployments."
    )
    return app
