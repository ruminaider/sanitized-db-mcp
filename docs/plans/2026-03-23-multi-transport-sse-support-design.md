# Multi-Transport SSE Support

**Date:** 2026-03-23
**Status:** Proposed

## 1. Problem Statement

The sanitized-db-mcp server only supports stdio transport. It works well when run locally alongside Claude Code, but cannot be deployed as a shared service. To deploy on Render as a private web service accessible by multiple dev machines running Claude Code, the server needs SSE (Server-Sent Events) transport with bearer-token authentication.

## 2. Transport Selection

A new `MCP_TRANSPORT` environment variable selects the transport at startup:

- **`stdio`** (default) — current behavior, no changes. Backwards-compatible with all existing installations (pip, uvx, Docker).
- **`sse`** — starts an HTTP server with SSE transport for remote deployment.
- **`http`** — reserved for future streamable HTTP transport (not implemented in this PR).

The default remains `stdio` so existing users experience zero breaking changes.

## 3. SSE Implementation

Use the official `mcp.server.sse.SseServerTransport` class from the `mcp` library, mounted on a Starlette ASGI app served by uvicorn.

The `main()` function in `server.py` will branch on `MCP_TRANSPORT`:

```
if transport == "stdio":
    # existing path: stdio_server() context manager
elif transport == "sse":
    # new path: Starlette + uvicorn
```

SSE path setup:
1. Create the `Server` and `Allowlist` via existing `create_server()`.
2. Instantiate `SseServerTransport("/messages/")`.
3. Mount two routes on the Starlette app:
   - `GET /sse` — SSE connection endpoint (handled by `sse.handle_sse_request`)
   - `POST /messages/` — client-to-server message endpoint (handled by `sse.handle_post_message`)
   - `GET /health` — returns 200 OK with `{"status": "ok"}` for Render health checks
4. Run via `uvicorn.run(app, host="0.0.0.0", port=PORT)`.

Port is configurable via the `PORT` env var (default `8000`). Render sets `PORT` automatically for web services.

## 4. Authentication Middleware

A new env var `MCP_API_KEY` enables bearer-token authentication:

- When set, all HTTP requests (except `GET /health`) must include `Authorization: Bearer <key>`.
- Missing or invalid tokens return `401 Unauthorized`.
- When unset, authentication is skipped (local dev, stdio mode).

Implemented as Starlette middleware so it applies uniformly to `/sse` and `/messages/` routes without modifying the MCP handler code.

```python
class BearerAuthMiddleware:
    def __init__(self, app, api_key: str):
        self.app = app
        self.api_key = api_key

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http" and scope["path"] != "/health":
            headers = dict(scope.get("headers", []))
            auth = headers.get(b"authorization", b"").decode()
            if auth != f"Bearer {self.api_key}":
                # return 401
                ...
        await self.app(scope, receive, send)
```

## 5. Dependencies

Add `starlette` and `uvicorn` as optional dependencies under an `sse` extra:

```toml
[project.optional-dependencies]
sse = [
    "starlette>=0.36",
    "uvicorn>=0.27",
]
dev = [
    "pytest>=8.0",
    "pytest-asyncio>=0.23",
]
```

- `pip install sanitized-db-mcp` — stdio only, lightweight.
- `pip install sanitized-db-mcp[sse]` — includes starlette + uvicorn for SSE transport.

At startup, if `MCP_TRANSPORT=sse` but starlette/uvicorn are not installed, raise a clear error: `"SSE transport requires the 'sse' extra. Install with: pip install sanitized-db-mcp[sse]"`.

## 6. Dockerfile Changes

The Docker image should support both transports, since Docker deployments will typically use SSE:

```dockerfile
RUN pip install --no-cache-dir .[sse]
```

The entrypoint remains `python -m sanitized_db_mcp.server`. Transport is selected at runtime via `MCP_TRANSPORT`. This keeps the image usable for both stdio (default) and SSE without rebuilding.

## 7. Configuration Summary

| Env Var | Required | Default | Description |
|---|---|---|---|
| `MCP_TRANSPORT` | No | `stdio` | Transport mode: `stdio` or `sse` |
| `PORT` | No (SSE only) | `8000` | HTTP port for SSE server |
| `MCP_API_KEY` | No (SSE recommended) | None | Bearer token for HTTP auth |
| `ALLOWLIST_PATH` | Yes | — | Path to allowlist.yaml |
| `DATABASE_URL` | Conditional | — | Postgres connection string |
| `RENDER_POSTGRES_ID` | Conditional | — | Render Postgres instance ID |
| `RENDER_API_KEY` | Conditional | — | Render API key (for Render Postgres connection) |

## 8. Non-Goals

- **IP allowlisting** — handled at the Render infrastructure level (private service + internal network), not in the application.
- **Allowlist generation at build time** — the consuming project (e.g., Evvy) bakes its own `allowlist.yaml` into its Docker image or mounts it as a volume. This server just reads it.
- **Streamable HTTP transport** — the MCP spec defines this as a future transport. We reserve the `http` value for `MCP_TRANSPORT` but do not implement it in this PR.
- **Multi-tenant / per-user allowlists** — all connections share the same allowlist. Scoping is a future concern.
