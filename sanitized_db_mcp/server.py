#!/usr/bin/env python3
"""
Sanitizing MCP server for PII/PHI-safe database queries.

This server receives SQL queries from LLM agents, rewrites them using
pglast to replace non-allowlisted column references with type-preserving
placeholders, then executes the rewritten SQL against the database.

Usage:
    python tools/sanitized_db_mcp/server.py

Environment variables:
    ALLOWLIST_PATH      Path to allowlist.yaml (required)
    RENDER_POSTGRES_ID  Render Postgres instance ID (optional)
    RENDER_API_KEY      Render API key (optional)
    DATABASE_URL        Static connection string fallback (optional)
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

from .allowlist import Allowlist
from .audit import AuditEntry, log_query
from .connection import execute_query
from .errors import ConfigurationError, SanitizationError, sanitize_pg_error
from .sanitizer import sanitize_query


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

    server = Server("sanitized-db")

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


async def main():
    """Run the MCP server."""
    server, _allowlist = create_server()
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    import asyncio

    asyncio.run(main())
