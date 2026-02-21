"""
Dual-mode database connection management.

Supports:
  1. Render API: dynamically resolves connection string from Render
  2. Static DATABASE_URL: for local Docker or future AWS migration
"""

from __future__ import annotations

import logging
import os
import time

import httpx
import psycopg

from .errors import ConfigurationError, QueryExecutionError, QueryTimeoutError


logger = logging.getLogger(__name__)

# Cache Render API connection string for 5 minutes
_RENDER_CACHE_TTL = 300
_render_cache: dict[str, tuple[str, float]] = {}


def _fetch_render_connection_string(postgres_id: str, api_key: str) -> str:
    """Resolve a connection string from the Render API."""
    cache_key = postgres_id
    now = time.time()

    # Check cache
    if cache_key in _render_cache:
        cached_url, cached_at = _render_cache[cache_key]
        if now - cached_at < _RENDER_CACHE_TTL:
            return cached_url

    url = f"https://api.render.com/v1/postgres/{postgres_id}/connection-info"
    headers = {"Authorization": f"Bearer {api_key}"}

    try:
        resp = httpx.get(url, headers=headers, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        conn_string = data.get("externalConnectionString", "")
        if not conn_string:
            raise ConfigurationError(f"Render API returned no connection string for {postgres_id}")

        # Cache it
        _render_cache[cache_key] = (conn_string, now)
        logger.info("Fetched connection string from Render API (cached for %ds)", _RENDER_CACHE_TTL)
        return conn_string

    except httpx.HTTPStatusError as e:
        raise ConfigurationError(
            f"Render API returned {e.response.status_code} for postgres {postgres_id}"
        )
    except httpx.RequestError as e:
        raise ConfigurationError(f"Render API request failed: {e}")


def get_connection_string() -> str:
    """Resolve the database connection string.

    Prefers Render API when configured, falls back to DATABASE_URL.
    """
    render_postgres_id = os.environ.get("RENDER_POSTGRES_ID")
    render_api_key = os.environ.get("RENDER_API_KEY")
    database_url = os.environ.get("DATABASE_URL")

    if render_postgres_id and render_api_key:
        return _fetch_render_connection_string(render_postgres_id, render_api_key)

    if database_url:
        return database_url

    raise ConfigurationError(
        "No database connection configured. "
        "Set RENDER_POSTGRES_ID + RENDER_API_KEY, or DATABASE_URL."
    )


def execute_query(sql: str, connection_string: str | None = None) -> list[dict]:
    """Execute a read-only SQL query and return rows as dicts.

    Enforces:
      - Read-only transaction
      - 5-second statement timeout
      - SSL required (when not localhost)
    """
    if connection_string is None:
        connection_string = get_connection_string()

    # Determine if we need SSL (not for localhost)
    use_ssl = "localhost" not in connection_string and "127.0.0.1" not in connection_string

    try:
        conn_params = {"autocommit": True}
        if use_ssl:
            conn_params["sslmode"] = "require"

        with psycopg.connect(connection_string, **conn_params) as conn:
            conn.execute("SET statement_timeout = '5s'")
            conn.execute("SET default_transaction_read_only = 'on'")

            with conn.cursor() as cur:
                cur.execute(sql)

                if cur.description is None:
                    return []

                columns = [desc.name for desc in cur.description]
                rows = cur.fetchall()

                return [dict(zip(columns, row, strict=True)) for row in rows]

    except psycopg.errors.QueryCanceled:
        raise QueryTimeoutError("Query exceeded 5-second timeout")
    except psycopg.errors.ReadOnlySqlTransaction:
        raise QueryExecutionError("Write operations are not permitted")
    except psycopg.errors.InsufficientPrivilege:
        raise QueryExecutionError("Insufficient privileges for this query")
    except psycopg.Error as e:
        # Log the full error server-side, return sanitized message
        logger.error("Database error: %s", e)
        raise QueryExecutionError(f"Database error: {type(e).__name__}")
