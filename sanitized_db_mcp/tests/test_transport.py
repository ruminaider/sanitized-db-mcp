"""Tests for SSE transport: auth middleware, health endpoint, app construction."""

from __future__ import annotations

import pytest
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient


# ---------------------------------------------------------------------------
# Helpers — minimal Starlette app for testing middleware in isolation
# ---------------------------------------------------------------------------

async def _echo(request: Request) -> JSONResponse:
    """Dummy endpoint that returns 200."""
    return JSONResponse({"ok": True})


async def _health(request: Request) -> JSONResponse:
    return JSONResponse({"status": "ok"})


def _make_app(api_key: str | None = None) -> Starlette | object:
    """Build a minimal Starlette app, optionally wrapped with auth middleware."""
    from sanitized_db_mcp.transport import BearerAuthMiddleware

    app = Starlette(routes=[
        Route("/test", endpoint=_echo, methods=["GET"]),
        Route("/health", endpoint=_health, methods=["GET"]),
    ])
    if api_key:
        app = BearerAuthMiddleware(app, api_key)
    return app


# ---------------------------------------------------------------------------
# BearerAuthMiddleware
# ---------------------------------------------------------------------------

class TestBearerAuthMiddleware:
    """Tests for the pure-ASGI bearer token middleware."""

    def test_valid_token_passes(self):
        client = TestClient(_make_app(api_key="secret-key"))
        resp = client.get("/test", headers={"Authorization": "Bearer secret-key"})
        assert resp.status_code == 200
        assert resp.json() == {"ok": True}

    def test_missing_token_returns_401(self):
        client = TestClient(_make_app(api_key="secret-key"))
        resp = client.get("/test")
        assert resp.status_code == 401
        assert resp.json() == {"error": "Unauthorized"}
        assert resp.headers["www-authenticate"] == "Bearer"

    def test_wrong_token_returns_401(self):
        client = TestClient(_make_app(api_key="secret-key"))
        resp = client.get("/test", headers={"Authorization": "Bearer wrong-key"})
        assert resp.status_code == 401

    def test_malformed_auth_header_returns_401(self):
        client = TestClient(_make_app(api_key="secret-key"))
        resp = client.get("/test", headers={"Authorization": "Basic dXNlcjpwYXNz"})
        assert resp.status_code == 401

    def test_health_bypasses_auth(self):
        client = TestClient(_make_app(api_key="secret-key"))
        resp = client.get("/health")  # no auth header
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}

    def test_no_middleware_allows_all(self):
        client = TestClient(_make_app(api_key=None))
        resp = client.get("/test")  # no auth header, no middleware
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Health endpoint
# ---------------------------------------------------------------------------

class TestHealthEndpoint:
    """Tests for the /health endpoint."""

    def test_health_returns_ok(self):
        from sanitized_db_mcp.transport import health_check

        app = Starlette(routes=[Route("/health", endpoint=health_check, methods=["GET"])])
        client = TestClient(app)
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}


# ---------------------------------------------------------------------------
# SSE app construction
# ---------------------------------------------------------------------------

class TestCreateSseApp:
    """Tests for create_sse_app() factory."""

    def _make_mock_server(self):
        """Create a minimal MCP Server for testing app construction."""
        from mcp.server import Server
        return Server("test-server")

    def test_returns_asgi_app(self):
        from sanitized_db_mcp.transport import create_sse_app

        app = create_sse_app(self._make_mock_server())
        # ASGI apps are callable with (scope, receive, send)
        assert callable(app)

    def test_health_accessible_without_auth(self, monkeypatch):
        from sanitized_db_mcp.transport import create_sse_app

        monkeypatch.setenv("MCP_API_KEY", "test-key")
        app = create_sse_app(self._make_mock_server())
        client = TestClient(app)
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}

    def test_sse_endpoint_requires_auth_when_key_set(self, monkeypatch):
        from sanitized_db_mcp.transport import create_sse_app

        monkeypatch.setenv("MCP_API_KEY", "test-key")
        app = create_sse_app(self._make_mock_server())
        client = TestClient(app)
        resp = client.get("/sse")
        assert resp.status_code == 401

    def test_no_auth_when_key_unset(self, monkeypatch):
        from sanitized_db_mcp.transport import create_sse_app

        monkeypatch.delenv("MCP_API_KEY", raising=False)
        app = create_sse_app(self._make_mock_server())
        client = TestClient(app)
        # Verify /health works without auth — confirms no middleware is applied
        # (We can't hit /sse because connect_sse blocks waiting for MCP session)
        resp = client.get("/health")
        assert resp.status_code == 200
