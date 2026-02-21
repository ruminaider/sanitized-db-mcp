"""Test fixtures for the sanitizing MCP server."""

import pytest

from sanitized_db_mcp.allowlist import Allowlist


@pytest.fixture
def sample_allowlist() -> Allowlist:
    """A minimal allowlist for testing.

    Simulates two tables:
      - accounts_profile: id, user_id, is_test_user visible; email, phone_number hidden
      - ecomm_order: id, user_id, status, order_number visible; email, payload hidden
      - auth_user: id, is_active visible; email, first_name, last_name, password hidden
    """
    tables = {
        "accounts_profile": {
            "id": {"type": "integer", "placeholder": "0"},
            "user_id": {"type": "integer", "placeholder": "0"},
            "is_test_user": {"type": "boolean", "placeholder": "false"},
        },
        "ecomm_order": {
            "id": {"type": "integer", "placeholder": "0"},
            "user_id": {"type": "integer", "placeholder": "0"},
            "status": {"type": "varchar", "placeholder": "'[REDACTED]'"},
            "order_number": {"type": "varchar", "placeholder": "'[REDACTED]'"},
            "create_date": {"type": "timestamp", "placeholder": "'1900-01-01T00:00:00Z'"},
        },
        "auth_user": {
            "id": {"type": "integer", "placeholder": "0"},
            "is_active": {"type": "boolean", "placeholder": "false"},
        },
    }

    allowed_functions = {
        "COUNT",
        "SUM",
        "AVG",
        "MIN",
        "MAX",
        "COALESCE",
        "NULLIF",
        "GREATEST",
        "LEAST",
        "NOW",
        "CURRENT_DATE",
        "CURRENT_TIMESTAMP",
        "DATE_TRUNC",
        "EXTRACT",
        "UPPER",
        "LOWER",
        "LENGTH",
        "TRIM",
        "ROUND",
        "CEIL",
        "FLOOR",
        "ABS",
        "CONCAT",
        "CONCAT_WS",
        "BOOL_AND",
        "BOOL_OR",
        "GENERATE_SERIES",
        "CAST",
        "LEFT",
        "RIGHT",
        "REPLACE",
        "SUBSTRING",
        "POSITION",
        "STRING_AGG",
        "ARRAY_AGG",
        "ARRAY_LENGTH",
        "AGE",
        "DATE_PART",
        "MOD",
        "POWER",
        "SQRT",
        "SIGN",
        "LTRIM",
        "RTRIM",
        "CEILING",
    }

    return Allowlist(tables=tables, allowed_functions=allowed_functions)
