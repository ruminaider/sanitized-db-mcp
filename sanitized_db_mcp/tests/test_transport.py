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

    def test_non_utf8_auth_header_returns_401(self):
        """Non-UTF-8 bytes in Authorization header should produce 401, not 500."""
        import asyncio
        from sanitized_db_mcp.transport import BearerAuthMiddleware

        async def inner_app(scope, receive, send):
            response = JSONResponse({"ok": True})
            await response(scope, receive, send)

        middleware = BearerAuthMiddleware(inner_app, "secret-key")

        async def run():
            status_codes = []

            async def receive():
                return {"type": "http.request", "body": b""}

            async def send(message):
                if message["type"] == "http.response.start":
                    status_codes.append(message["status"])

            scope = {
                "type": "http",
                "path": "/test",
                "headers": [(b"authorization", b"\xff\xfe\xfd")],
                "method": "GET",
            }
            await middleware(scope, receive, send)
            return status_codes[0]

        status = asyncio.run(run())
        assert status == 401

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
        assert callable(app)

    def test_health_accessible_without_auth(self):
        from sanitized_db_mcp.transport import create_sse_app

        app = create_sse_app(self._make_mock_server(), api_key="test-key")
        client = TestClient(app)
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}

    def test_sse_endpoint_requires_auth_when_key_set(self):
        from sanitized_db_mcp.transport import create_sse_app

        app = create_sse_app(self._make_mock_server(), api_key="test-key")
        client = TestClient(app)
        resp = client.get("/sse")
        assert resp.status_code == 401

    def test_messages_endpoint_requires_auth_when_key_set(self):
        from sanitized_db_mcp.transport import create_sse_app

        app = create_sse_app(self._make_mock_server(), api_key="test-key")
        client = TestClient(app)
        resp = client.post("/messages/")
        assert resp.status_code == 401

    def test_no_auth_when_key_unset(self):
        from sanitized_db_mcp.transport import create_sse_app

        app = create_sse_app(self._make_mock_server())
        client = TestClient(app)
        resp = client.get("/health")
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# SSE error handling
# ---------------------------------------------------------------------------

class TestHandleSseErrorHandling:
    """Tests that SSE connection errors are handled gracefully."""

    def _make_mock_server(self):
        from mcp.server import Server
        return Server("test-server")

    def _make_app_with_failing_server(self, exc_to_raise):
        """Build an SSE app whose server.run() raises *exc_to_raise*."""
        from unittest.mock import AsyncMock, patch
        from sanitized_db_mcp.transport import create_sse_app

        server = self._make_mock_server()
        app = create_sse_app(server)

        # Patch server.run on the instance so the handler's try/except is exercised.
        server.run = AsyncMock(side_effect=exc_to_raise)
        return app

    def test_expected_disconnect_does_not_500(self):
        """ClosedResourceError (client disconnect) should not produce a 500."""
        from anyio import ClosedResourceError

        app = self._make_app_with_failing_server(ClosedResourceError())
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.get("/sse")
        assert resp.status_code < 500

    def test_expected_disconnect_logs_debug(self, caplog):
        """ClosedResourceError should log at DEBUG level."""
        import logging
        from anyio import ClosedResourceError

        app = self._make_app_with_failing_server(ClosedResourceError())
        client = TestClient(app, raise_server_exceptions=False)

        with caplog.at_level(logging.DEBUG, logger="sanitized_db_mcp"):
            client.get("/sse")

        sse_records = [r for r in caplog.records if "SSE session" in r.message]
        assert len(sse_records) >= 1
        assert sse_records[0].levelno == logging.DEBUG

    def test_unexpected_error_does_not_500(self):
        """Unexpected errors should be caught, not produce unhandled 500s."""
        app = self._make_app_with_failing_server(RuntimeError("boom"))
        client = TestClient(app, raise_server_exceptions=False)

        resp = client.get("/sse")
        assert resp.status_code < 500

    def test_unexpected_error_logs_error(self, caplog):
        """Unexpected errors should log at ERROR level with traceback."""
        import logging

        app = self._make_app_with_failing_server(RuntimeError("boom"))
        client = TestClient(app, raise_server_exceptions=False)

        with caplog.at_level(logging.DEBUG, logger="sanitized_db_mcp"):
            client.get("/sse")

        sse_records = [r for r in caplog.records if "SSE session" in r.message]
        assert len(sse_records) >= 1
        assert sse_records[0].levelno == logging.ERROR

    def test_connection_error_logs_debug(self, caplog):
        """ConnectionError (network flap) should log at DEBUG, not ERROR."""
        import logging

        app = self._make_app_with_failing_server(ConnectionError("reset"))
        client = TestClient(app, raise_server_exceptions=False)

        with caplog.at_level(logging.DEBUG, logger="sanitized_db_mcp"):
            client.get("/sse")

        sse_records = [r for r in caplog.records if "SSE session" in r.message]
        assert len(sse_records) >= 1
        assert sse_records[0].levelno == logging.DEBUG


# ---------------------------------------------------------------------------
# Transport dispatch (server.py main)
# ---------------------------------------------------------------------------

_MINIMAL_ALLOWLIST_YAML = (
    "tables:\n  test_table:\n    id:\n      type: integer\n      placeholder: '0'\n"
    "allowed_functions:\n  - COUNT\n"
)


@pytest.fixture()
def allowlist_env(monkeypatch, tmp_path):
    """Write a minimal allowlist and set ALLOWLIST_PATH."""
    f = tmp_path / "allowlist.yaml"
    f.write_text(_MINIMAL_ALLOWLIST_YAML)
    monkeypatch.setenv("ALLOWLIST_PATH", str(f))


class TestTransportDispatch:
    """Tests for MCP_TRANSPORT parsing and dispatch in server.main()."""

    def test_unknown_transport_raises(self, monkeypatch, allowlist_env):
        """Unknown MCP_TRANSPORT value raises ConfigurationError."""
        from sanitized_db_mcp.errors import ConfigurationError

        monkeypatch.setenv("MCP_TRANSPORT", "bogus")

        from sanitized_db_mcp.server import main

        with pytest.raises(ConfigurationError, match="Unknown MCP_TRANSPORT"):
            main()

    def test_transport_case_insensitive(self, monkeypatch, allowlist_env):
        """MCP_TRANSPORT=SSE (uppercase) should be accepted."""
        monkeypatch.setenv("MCP_TRANSPORT", "SSE")
        monkeypatch.setenv("MCP_API_KEY", "test")

        from sanitized_db_mcp.server import main
        from unittest.mock import patch, MagicMock

        # uvicorn is lazy-imported inside _run_sse(), so patch sys.modules
        mock_uvicorn = MagicMock()
        with patch.dict("sys.modules", {"uvicorn": mock_uvicorn}):
            main()  # should not raise

    def test_default_transport_is_stdio(self, monkeypatch, allowlist_env):
        """Unset MCP_TRANSPORT defaults to stdio."""
        monkeypatch.delenv("MCP_TRANSPORT", raising=False)

        from sanitized_db_mcp.server import main
        from unittest.mock import patch

        with patch("sanitized_db_mcp.server.asyncio") as mock_asyncio:
            mock_asyncio.run = lambda coro: coro.close()
            main()

    def test_invalid_port_raises_configuration_error(self, monkeypatch, allowlist_env):
        """PORT='abc' should raise ConfigurationError."""
        from sanitized_db_mcp.errors import ConfigurationError

        monkeypatch.setenv("MCP_TRANSPORT", "sse")
        monkeypatch.setenv("MCP_API_KEY", "test-key-long-enough")
        monkeypatch.setenv("PORT", "abc")

        from sanitized_db_mcp.server import main

        with pytest.raises(ConfigurationError, match="PORT"):
            main()

    def test_port_out_of_range_raises(self, monkeypatch, allowlist_env):
        """PORT='99999' should raise ConfigurationError."""
        from sanitized_db_mcp.errors import ConfigurationError

        monkeypatch.setenv("MCP_TRANSPORT", "sse")
        monkeypatch.setenv("MCP_API_KEY", "test-key-long-enough")
        monkeypatch.setenv("PORT", "99999")

        from sanitized_db_mcp.server import main

        with pytest.raises(ConfigurationError, match="PORT"):
            main()

    def test_port_zero_raises(self, monkeypatch, allowlist_env):
        """PORT='0' should raise ConfigurationError."""
        from sanitized_db_mcp.errors import ConfigurationError

        monkeypatch.setenv("MCP_TRANSPORT", "sse")
        monkeypatch.setenv("MCP_API_KEY", "test-key-long-enough")
        monkeypatch.setenv("PORT", "0")

        from sanitized_db_mcp.server import main

        with pytest.raises(ConfigurationError, match="PORT"):
            main()
