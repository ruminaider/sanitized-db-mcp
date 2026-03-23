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
