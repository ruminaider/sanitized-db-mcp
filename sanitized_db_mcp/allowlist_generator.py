"""
Standalone allowlist generator for the sanitized-db-mcp server.

Introspects a PostgreSQL database via ``information_schema.columns`` and
produces an ``allowlist.yaml`` scaffold where **no columns are visible by
default**.  Users uncomment the columns they wish to expose.

Separated from the CLI entry-point for testability.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any


# ======================================================================
# Type-preserving placeholder map (PostgreSQL data types)
# ======================================================================

_PLACEHOLDER_MAP: dict[str, str] = {
    "varchar": "'[REDACTED]'",
    "text": "'[REDACTED]'",
    "char": "'[REDACTED]'",
    "character varying": "'[REDACTED]'",
    "character": "'[REDACTED]'",
    "serial": "0",
    "bigserial": "0",
    "smallserial": "0",
    "integer": "0",
    "bigint": "0",
    "smallint": "0",
    "boolean": "false",
    "timestamp without time zone": "'1900-01-01T00:00:00Z'",
    "timestamp with time zone": "'1900-01-01T00:00:00Z'",
    "timestamp": "'1900-01-01T00:00:00Z'",
    "date": "'1900-01-01'",
    "time without time zone": "'00:00:00'",
    "time": "'00:00:00'",
    "interval": "'0 seconds'",
    "double precision": "0.0",
    "numeric": "0.0",
    "real": "0.0",
    "uuid": "'00000000-0000-0000-0000-000000000000'",
    "jsonb": "'null'::jsonb",
    "json": "'null'::json",
    "bytea": "'\\x00'::bytea",
    "inet": "'0.0.0.0'::inet",
    "ARRAY": "'{}'",
    "array": "'{}'",
}


# ======================================================================
# Default allowed SQL functions
# ======================================================================

DEFAULT_ALLOWED_FUNCTIONS: list[str] = [
    "COUNT", "SUM", "AVG", "MIN", "MAX", "BOOL_AND", "BOOL_OR",
    "ARRAY_AGG", "ARRAY_LENGTH", "STRING_AGG",
    "COALESCE", "NULLIF", "GREATEST", "LEAST",
    "NOW", "CURRENT_DATE", "CURRENT_TIMESTAMP", "DATE_TRUNC", "EXTRACT", "AGE", "DATE_PART",
    "UPPER", "LOWER", "LENGTH", "TRIM", "LTRIM", "RTRIM", "LEFT", "RIGHT",
    "REPLACE", "SUBSTRING", "POSITION", "CONCAT", "CONCAT_WS",
    "ROUND", "CEIL", "CEILING", "FLOOR", "ABS", "MOD", "POWER", "SQRT", "SIGN",
    "CAST", "GENERATE_SERIES",
]


# ======================================================================
# PII / PHI detection patterns
# ======================================================================

PII_PATTERNS: list[str] = [
    r"^e?_?mail$", r"email", r"password", r"passwd", r"pass_hash",
    r"^phone", r"mobile", r"^first_name$", r"^last_name$", r"^full_name$",
    r"^name$",  # bare "name" is likely PII
    r"ssn", r"social_security",
    r"^address", r"street", r"^city$", r"^zip", r"postal",
    r"date_of_birth", r"^dob$", r"birthday", r"birth_date",
    r"ip_address", r"^ip$",
]

_compiled_pii_patterns: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE) for p in PII_PATTERNS
]


def is_pii_column(column_name: str) -> bool:
    """Return True if *column_name* matches any PII heuristic pattern."""
    return any(pat.search(column_name) for pat in _compiled_pii_patterns)


# ======================================================================
# Column metadata
# ======================================================================


@dataclass
class ColumnInfo:
    """Metadata for a single database column."""

    table_schema: str
    table_name: str
    column_name: str
    data_type: str
    udt_name: str


# ======================================================================
# Type normalisation helpers
# ======================================================================

# Mapping of verbose ``information_schema`` types to short canonical forms
# used as keys into ``_PLACEHOLDER_MAP``.
_TYPE_ALIASES: dict[str, str] = {
    "character varying": "varchar",
    "character": "char",
    "timestamp without time zone": "timestamp",
    "timestamp with time zone": "timestamp",
    "time without time zone": "time",
}

# Regex to strip parenthesised qualifiers, e.g. ``numeric(10,2)`` -> ``numeric``
_PAREN_RE = re.compile(r"\(.*\)")


def _base_type(data_type: str) -> str:
    """Normalise an ``information_schema.columns.data_type`` value to the
    short canonical name used in allowlist YAML files.

    Examples::

        "character varying"           -> "varchar"
        "timestamp without time zone" -> "timestamp"
        "integer"                     -> "integer"
        "numeric(10,2)"               -> "numeric"
        "USER-DEFINED"                -> falls through (handled by caller)
    """
    cleaned = _PAREN_RE.sub("", data_type).strip().lower()
    return _TYPE_ALIASES.get(cleaned, cleaned)


def _placeholder_for_type(data_type: str) -> str:
    """Return the type-preserving placeholder for a PostgreSQL data type.

    Falls back to ``'[REDACTED]'`` for unknown types.
    """
    base = _base_type(data_type)
    if base in _PLACEHOLDER_MAP:
        return _PLACEHOLDER_MAP[base]

    # Some user-defined or exotic types fall through — use text placeholder
    return "'[REDACTED]'"


# ======================================================================
# Database introspection
# ======================================================================

_INTROSPECT_SQL = """\
SELECT table_schema, table_name, column_name, data_type, udt_name
FROM information_schema.columns
WHERE table_schema = ANY(%s)
ORDER BY table_schema, table_name, ordinal_position
"""


def introspect_schema(
    database_url: str,
    schemas: list[str] | None = None,
) -> dict[str, list[ColumnInfo]]:
    """Connect to PostgreSQL and return column metadata grouped by table.

    Parameters
    ----------
    database_url:
        A ``postgresql://`` connection string.
    schemas:
        Target schema(s) to introspect. Defaults to ``["public"]``.

    Returns
    -------
    dict mapping ``table_name`` to a list of :class:`ColumnInfo` objects,
    ordered by ``ordinal_position``.
    """
    import psycopg  # import here so the rest of the module is testable without psycopg

    if schemas is None:
        schemas = ["public"]

    result: dict[str, list[ColumnInfo]] = {}

    with psycopg.connect(database_url) as conn:
        with conn.cursor() as cur:
            cur.execute(_INTROSPECT_SQL, [schemas])
            for row in cur.fetchall():
                col = ColumnInfo(
                    table_schema=row[0],
                    table_name=row[1],
                    column_name=row[2],
                    data_type=row[3],
                    udt_name=row[4],
                )
                key = col.table_name
                if col.table_schema != "public":
                    key = f"{col.table_schema}.{col.table_name}"
                result.setdefault(key, []).append(col)

    return result


# ======================================================================
# YAML generation
# ======================================================================

_YAML_HEADER = """\
# Generated by: sanitized-db-mcp generate-allowlist
#
# HOW TO USE:
# - Columns under "columns:" are VISIBLE to agents (currently empty)
# - Commented lines show available columns — uncomment to make visible
# - Lines marked "# PII" were flagged as likely PII/PHI — review carefully
# - After editing, restart the MCP server to apply changes
"""


def generate_allowlist_yaml(
    schema_info: dict[str, list[ColumnInfo]],
    *,
    deny_pii: bool = False,
    include_functions: bool = True,
) -> str:
    """Generate an ``allowlist.yaml`` scaffold from introspected column metadata.

    Every column starts **invisible** (commented out).  The user must
    explicitly uncomment columns to expose them.

    Parameters
    ----------
    schema_info:
        Output of :func:`introspect_schema`.
    deny_pii:
        When ``True``, columns whose names match :data:`PII_PATTERNS`
        are annotated with a ``# PII`` comment.
    include_functions:
        When ``True`` (the default), emit the ``allowed_functions`` section
        with :data:`DEFAULT_ALLOWED_FUNCTIONS`.
    """
    lines: list[str] = [_YAML_HEADER]
    lines.append("tables:")

    for table_name in sorted(schema_info.keys()):
        columns = schema_info[table_name]
        lines.append(f"  {table_name}:")
        lines.append("    columns: {}")
        lines.append("    # Available columns (uncomment to make visible):")

        # Partition columns into non-PII and PII (PII listed last)
        non_pii: list[ColumnInfo] = []
        pii: list[ColumnInfo] = []

        for col in columns:
            if deny_pii and is_pii_column(col.column_name):
                pii.append(col)
            else:
                non_pii.append(col)

        for col in non_pii:
            base = _base_type(col.data_type)
            placeholder = _placeholder_for_type(col.data_type)
            lines.append(
                f"    #   {col.column_name}: "
                f"{{type: {base}, placeholder: {placeholder}}}"
            )

        for col in pii:
            base = _base_type(col.data_type)
            placeholder = _placeholder_for_type(col.data_type)
            lines.append(
                f"    #   {col.column_name}: "
                f"{{type: {base}, placeholder: {placeholder}}}  # PII"
            )

    if include_functions:
        lines.append("")
        lines.append("allowed_functions:")
        for func in DEFAULT_ALLOWED_FUNCTIONS:
            lines.append(f"  - {func}")

    # Ensure trailing newline
    lines.append("")
    return "\n".join(lines)
