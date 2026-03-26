#!/usr/bin/env python3
"""
Sanitizing MCP server for PII/PHI-safe database queries.

This server receives SQL queries from LLM agents, rewrites them using
pglast to replace non-allowlisted column references with type-preserving
placeholders, then executes the rewritten SQL against the database.

Usage:
    python -m sanitized_db_mcp.server

Environment variables:
    ALLOWLIST_PATH      Path to allowlist.yaml (required)
    RENDER_POSTGRES_ID  Render Postgres instance ID (optional)
    RENDER_API_KEY      Render API key (optional)
    DATABASE_URL        Static connection string fallback (optional)
    MCP_TRANSPORT       Transport mode: stdio (default) or sse
    PORT                HTTP port for SSE server (default 8000)
    MCP_API_KEY         Bearer token for SSE authentication (recommended)
    MCP_MAX_CONNECTIONS Max concurrent connections for SSE (default: unlimited)
    MCP_SESSION_TIMEOUT Max SSE session duration in seconds (default: unlimited)
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
import time

from mcp.server import Server
from mcp.server.lowlevel.server import request_ctx
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

from .allowlist import Allowlist
from .audit import AuditEntry, extract_client_ip, log_query
from .connection import execute_query
from .errors import ConfigurationError, SanitizationError, sanitize_pg_error
from .sanitizer import sanitize_query


def _parse_positive_int_env(name: str, *, default: str | None = None) -> int | None:
    """Parse an optional env var as a positive integer, or raise ConfigurationError."""
    raw = os.environ.get(name, default) if default else os.environ.get(name)
    if raw is None:
        return None
    try:
        value = int(raw)
    except ValueError:
        raise ConfigurationError(f"{name} must be an integer, got {raw!r}") from None
    if value < 1:
        raise ConfigurationError(f"{name} must be positive, got {value}")
    return value


# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("sanitized_db_mcp")


# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------


def create_server() -> tuple[Server, Allowlist]:
    """Create and configure the MCP server."""
    allowlist_path = os.environ.get("ALLOWLIST_PATH")
    if not allowlist_path:
        raise ConfigurationError("ALLOWLIST_PATH environment variable is required")

    logger.info("Loading allowlist from %s", allowlist_path)
    allowlist = Allowlist.from_yaml(allowlist_path)
    logger.info(
        "Loaded allowlist: %d tables, %d allowed functions",
        len(allowlist.all_tables),
        len(allowlist.allowed_functions),
    )

    server = Server(os.environ.get("MCP_SERVER_NAME", "sanitized-db"))

    @server.list_tools()
    async def list_tools() -> list[Tool]:
        return [
            Tool(
                name="query",
                description=(
                    "Execute a read-only SQL query against the database. "
                    "PII/PHI columns are automatically redacted with type-preserving "
                    "placeholders. Only SELECT statements are allowed. "
                    "Returns results as a JSON array of row objects."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "sql": {
                            "type": "string",
                            "description": "The SQL SELECT query to execute",
                        }
                    },
                    "required": ["sql"],
                },
            )
        ]

    @server.call_tool()
    async def call_tool(name: str, arguments: dict) -> list[TextContent]:
        if name != "query":
            return [TextContent(type="text", text=f"Unknown tool: {name}")]

        sql = arguments.get("sql", "").strip()
        if not sql:
            return [TextContent(type="text", text="Error: empty SQL query")]

        audit = AuditEntry(original_sql=sql)

        # Enrich audit with client identity from MCP request context
        try:
            ctx = request_ctx.get()
            audit.request_id = str(ctx.request_id) if ctx.request_id else None
            if ctx.request is not None and hasattr(ctx.request, "headers"):
                audit.client_ip = extract_client_ip(ctx.request)
                audit.user_agent = ctx.request.headers.get("user-agent")
                audit.session_id = getattr(
                    ctx.request, "query_params", {}
                ).get("session_id")
            audit.transport = "sse"
        except LookupError:
            audit.transport = "stdio"

        start = time.time()

        try:
            # Sanitize
            result = sanitize_query(sql, allowlist)
            audit.rewritten_sql = result.rewritten_sql
            audit.tables_accessed = result.tables_accessed
            audit.columns_accessed = result.columns_accessed
            audit.columns_redacted = result.columns_redacted

            if result.was_rewritten:
                audit.outcome = "redacted"
                logger.info("Query rewritten: %d columns redacted", len(result.columns_redacted))
            else:
                audit.outcome = "allowed"

            # Execute
            rows = execute_query(result.rewritten_sql)
            audit.row_count = len(rows)
            audit.execution_time_ms = (time.time() - start) * 1000

            # Format response
            response = json.dumps(rows, default=str, indent=2)

            # Add metadata header
            header_parts = [f"{len(rows)} rows returned"]
            if result.columns_redacted:
                header_parts.append(f"{len(result.columns_redacted)} columns redacted")
            header = " | ".join(header_parts)

            return [TextContent(type="text", text=f"/* {header} */\n{response}")]

        except SanitizationError as e:
            e.log()
            audit.outcome = "blocked"
            audit.rejection_reason = e.agent_message
            audit.execution_time_ms = (time.time() - start) * 1000
            return [TextContent(type="text", text=f"Error: {e.agent_message}")]

        except Exception as e:
            logger.error("Unexpected error: %s", e, exc_info=True)
            audit.outcome = "error"
            audit.rejection_reason = sanitize_pg_error(e)
            audit.execution_time_ms = (time.time() - start) * 1000
            return [TextContent(type="text", text=f"Error: {sanitize_pg_error(e)}")]

        finally:
            log_query(audit)

    return server, allowlist


async def _run_stdio(server: Server) -> None:
    """Run the server with stdio transport."""
    init_options = server.create_initialization_options()
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, init_options)


def _run_sse(server: Server) -> None:
    """Run the server with SSE transport over HTTP."""
    from .transport import create_sse_app

    try:
        import uvicorn
    except ImportError:
        raise ImportError(
            "SSE transport requires uvicorn. "
            "Install with: pip install 'sanitized-db-mcp[sse]'"
        ) from None

    port = _parse_positive_int_env("PORT", default="8000")
    if port > 65535:
        raise ConfigurationError(f"PORT must be between 1 and 65535, got {port}")
    api_key_raw = os.environ.get("MCP_API_KEY")
    if api_key_raw is not None:
        if not api_key_raw.strip():
            raise ConfigurationError(
                "MCP_API_KEY is set but empty. Provide a real key or unset it entirely."
            )
        if api_key_raw != api_key_raw.strip():
            raise ConfigurationError(
                "MCP_API_KEY has leading/trailing whitespace. "
                "Remove the whitespace or set the key without it."
            )
    api_key = api_key_raw  # None if unset, validated non-empty above

    max_connections = _parse_positive_int_env("MCP_MAX_CONNECTIONS")
    session_timeout = _parse_positive_int_env("MCP_SESSION_TIMEOUT")

    app = create_sse_app(server, api_key=api_key, session_timeout=session_timeout)

    logger.info("Starting SSE server on 0.0.0.0:%d", port)
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=port,
        log_level="info",
        timeout_graceful_shutdown=20,
        limit_concurrency=max_connections,
    )


def main() -> None:
    """Run the MCP server.

    Dispatches to stdio or SSE transport based on MCP_TRANSPORT env var.
    """
    transport = os.environ.get("MCP_TRANSPORT", "stdio").lower().strip()

    server, _allowlist = create_server()

    if transport == "stdio":
        asyncio.run(_run_stdio(server))
    elif transport == "sse":
        _run_sse(server)
    else:
        raise ConfigurationError(
            f"Unknown MCP_TRANSPORT: {transport!r}. Valid options: stdio, sse"
        )


if __name__ == "__main__":
    main()
