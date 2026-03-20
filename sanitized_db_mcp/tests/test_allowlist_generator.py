"""Tests for the standalone allowlist generator."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import yaml

from sanitized_db_mcp.allowlist_generator import (
    DEFAULT_ALLOWED_FUNCTIONS,
    PII_PATTERNS,
    ColumnInfo,
    _PLACEHOLDER_MAP,
    _base_type,
    _placeholder_for_type,
    generate_allowlist_yaml,
    introspect_schema,
    is_pii_column,
)


# ======================================================================
# Placeholder mapping
# ======================================================================


class TestPlaceholderMapping:
    def test_placeholder_mapping(self):
        """Every type in _PLACEHOLDER_MAP should resolve to itself."""
        for pg_type, expected_placeholder in _PLACEHOLDER_MAP.items():
            result = _placeholder_for_type(pg_type)
            assert result == expected_placeholder, (
                f"Expected {expected_placeholder!r} for type {pg_type!r}, got {result!r}"
            )

    def test_unknown_type_falls_back_to_redacted(self):
        assert _placeholder_for_type("citext") == "'[REDACTED]'"
        assert _placeholder_for_type("hstore") == "'[REDACTED]'"
        assert _placeholder_for_type("USER-DEFINED") == "'[REDACTED]'"


# ======================================================================
# Type normalisation
# ======================================================================


class TestBaseTypeNormalization:
    def test_character_varying_to_varchar(self):
        assert _base_type("character varying") == "varchar"

    def test_character_to_char(self):
        assert _base_type("character") == "char"

    def test_timestamp_without_timezone(self):
        assert _base_type("timestamp without time zone") == "timestamp"

    def test_timestamp_with_timezone(self):
        assert _base_type("timestamp with time zone") == "timestamp"

    def test_time_without_timezone(self):
        assert _base_type("time without time zone") == "time"

    def test_integer_unchanged(self):
        assert _base_type("integer") == "integer"

    def test_boolean_unchanged(self):
        assert _base_type("boolean") == "boolean"

    def test_strips_parenthesised_qualifiers(self):
        assert _base_type("numeric(10,2)") == "numeric"
        assert _base_type("character varying(255)") == "varchar"

    def test_lowercases_input(self):
        assert _base_type("INTEGER") == "integer"
        assert _base_type("Boolean") == "boolean"

    def test_user_defined_passthrough(self):
        assert _base_type("USER-DEFINED") == "user-defined"


# ======================================================================
# PII pattern detection
# ======================================================================


class TestPiiPatternDetection:
    @pytest.mark.parametrize(
        "column_name",
        [
            "email",
            "user_email",
            "email_address",
            "password",
            "passwd",
            "pass_hash",
            "phone",
            "phone_number",
            "mobile",
            "mobile_phone",
            "first_name",
            "last_name",
            "full_name",
            "name",
            "ssn",
            "social_security",
            "social_security_number",
            "address",
            "address_line_1",
            "street",
            "street_address",
            "city",
            "zip",
            "zip_code",
            "postal",
            "postal_code",
            "date_of_birth",
            "dob",
            "birthday",
            "birth_date",
            "ip_address",
            "ip",
        ],
    )
    def test_pii_columns_detected(self, column_name: str):
        assert is_pii_column(column_name), f"{column_name!r} should be flagged as PII"

    @pytest.mark.parametrize(
        "column_name",
        [
            "id",
            "status",
            "created_at",
            "updated_at",
            "order_id",
            "is_active",
            "quantity",
            "price",
            "description",
            "slug",
            "product_type",
            "user_id",
            "session_id",
            "create_date",
            "modify_date",
            "is_test_user",
            "order_number",
        ],
    )
    def test_pii_no_false_positives(self, column_name: str):
        assert not is_pii_column(column_name), (
            f"{column_name!r} should NOT be flagged as PII"
        )


# ======================================================================
# YAML generation — empty schema
# ======================================================================


class TestGenerateYamlEmptySchema:
    def test_empty_schema_produces_valid_yaml(self):
        result = generate_allowlist_yaml({})
        parsed = yaml.safe_load(result)
        assert parsed is not None
        assert "tables" in parsed

    def test_empty_schema_has_no_tables(self):
        result = generate_allowlist_yaml({})
        parsed = yaml.safe_load(result)
        # "tables:" with nothing beneath it parses as None
        assert parsed["tables"] is None


# ======================================================================
# YAML generation — default (no visible columns)
# ======================================================================


class TestGenerateYamlDefaultNoVisibleColumns:
    @pytest.fixture
    def sample_schema(self) -> dict[str, list[ColumnInfo]]:
        return {
            "auth_user": [
                ColumnInfo("public", "auth_user", "id", "integer", "int4"),
                ColumnInfo("public", "auth_user", "is_active", "boolean", "bool"),
                ColumnInfo("public", "auth_user", "email", "character varying", "varchar"),
            ],
        }

    def test_columns_dict_is_empty(self, sample_schema):
        result = generate_allowlist_yaml(sample_schema)
        parsed = yaml.safe_load(result)
        assert parsed["tables"]["auth_user"]["columns"] == {}

    def test_all_columns_appear_in_comments(self, sample_schema):
        result = generate_allowlist_yaml(sample_schema)
        assert "#   id:" in result
        assert "#   is_active:" in result
        assert "#   email:" in result

    def test_column_types_in_comments(self, sample_schema):
        result = generate_allowlist_yaml(sample_schema)
        # "character varying" should be normalised to "varchar"
        assert "type: varchar" in result
        assert "type: integer" in result
        assert "type: boolean" in result


# ======================================================================
# YAML generation — PII annotations
# ======================================================================


class TestGenerateYamlDenyPiiAnnotations:
    @pytest.fixture
    def schema_with_pii(self) -> dict[str, list[ColumnInfo]]:
        return {
            "auth_user": [
                ColumnInfo("public", "auth_user", "id", "integer", "int4"),
                ColumnInfo("public", "auth_user", "is_active", "boolean", "bool"),
                ColumnInfo("public", "auth_user", "email", "character varying", "varchar"),
                ColumnInfo("public", "auth_user", "first_name", "character varying", "varchar"),
                ColumnInfo("public", "auth_user", "password", "character varying", "varchar"),
            ],
        }

    def test_pii_columns_annotated(self, schema_with_pii):
        result = generate_allowlist_yaml(schema_with_pii, deny_pii=True)
        # PII columns should have the # PII suffix
        for pii_col in ("email", "first_name", "password"):
            # Find the comment line for this column and verify it ends with # PII
            for line in result.splitlines():
                if f"#   {pii_col}:" in line:
                    assert line.rstrip().endswith("# PII"), (
                        f"Column {pii_col!r} should be annotated with # PII, got: {line!r}"
                    )
                    break
            else:
                pytest.fail(f"Column {pii_col!r} not found in output")

    def test_non_pii_columns_not_annotated(self, schema_with_pii):
        result = generate_allowlist_yaml(schema_with_pii, deny_pii=True)
        for line in result.splitlines():
            if "#   id:" in line or "#   is_active:" in line:
                assert "# PII" not in line, f"Non-PII column should not have # PII: {line!r}"

    def test_pii_columns_listed_after_non_pii(self, schema_with_pii):
        """PII columns should appear after non-PII columns within a table."""
        result = generate_allowlist_yaml(schema_with_pii, deny_pii=True)
        lines = result.splitlines()

        # Collect indices of commented column lines for auth_user
        col_lines = [
            (i, line)
            for i, line in enumerate(lines)
            if line.strip().startswith("#   ") and ":" in line
        ]

        non_pii_indices = [i for i, line in col_lines if "# PII" not in line]
        pii_indices = [i for i, line in col_lines if "# PII" in line]

        if non_pii_indices and pii_indices:
            assert max(non_pii_indices) < min(pii_indices), (
                "All non-PII columns should appear before PII columns"
            )

    def test_no_pii_annotations_when_deny_pii_false(self, schema_with_pii):
        result = generate_allowlist_yaml(schema_with_pii, deny_pii=False)
        # Check that no column comment lines have the # PII suffix.
        # (The header text itself mentions "# PII" in instructions, which is fine.)
        column_lines = [
            line for line in result.splitlines()
            if line.strip().startswith("#   ") and ":" in line
        ]
        for line in column_lines:
            assert not line.rstrip().endswith("# PII"), (
                f"Column line should not have PII annotation when deny_pii=False: {line!r}"
            )


# ======================================================================
# YAML generation — functions section
# ======================================================================


class TestGenerateYamlIncludesFunctions:
    def test_allowed_functions_present(self):
        result = generate_allowlist_yaml({}, include_functions=True)
        parsed = yaml.safe_load(result)
        assert "allowed_functions" in parsed
        assert isinstance(parsed["allowed_functions"], list)
        assert "COUNT" in parsed["allowed_functions"]
        assert "SUM" in parsed["allowed_functions"]

    def test_all_default_functions_included(self):
        result = generate_allowlist_yaml({}, include_functions=True)
        parsed = yaml.safe_load(result)
        for func in DEFAULT_ALLOWED_FUNCTIONS:
            assert func in parsed["allowed_functions"], f"{func} missing from allowed_functions"

    def test_functions_omitted_when_disabled(self):
        result = generate_allowlist_yaml({}, include_functions=False)
        parsed = yaml.safe_load(result)
        assert parsed.get("allowed_functions") is None


# ======================================================================
# YAML generation — table ordering
# ======================================================================


class TestGenerateYamlTablesSorted:
    def test_tables_alphabetically_sorted(self):
        schema_info = {
            "zebra_table": [
                ColumnInfo("public", "zebra_table", "id", "integer", "int4"),
            ],
            "alpha_table": [
                ColumnInfo("public", "alpha_table", "id", "integer", "int4"),
            ],
            "middle_table": [
                ColumnInfo("public", "middle_table", "id", "integer", "int4"),
            ],
        }
        result = generate_allowlist_yaml(schema_info)

        # Extract table names in order from the output
        table_names = []
        for line in result.splitlines():
            # Table lines are indented with 2 spaces and end with ":"
            stripped = line.rstrip()
            if stripped.startswith("  ") and stripped.endswith(":") and not stripped.startswith("    "):
                table_names.append(stripped.strip().rstrip(":"))

        assert table_names == ["alpha_table", "middle_table", "zebra_table"]


# ======================================================================
# Database introspection (mocked)
# ======================================================================


class TestIntrospectSchema:
    def test_introspect_groups_by_table(self):
        mock_rows = [
            ("public", "auth_user", "id", "integer", "int4"),
            ("public", "auth_user", "email", "character varying", "varchar"),
            ("public", "ecomm_order", "id", "integer", "int4"),
            ("public", "ecomm_order", "status", "character varying", "varchar"),
        ]

        mock_cursor = MagicMock()
        mock_cursor.fetchall.return_value = mock_rows
        mock_cursor.__enter__ = MagicMock(return_value=mock_cursor)
        mock_cursor.__exit__ = MagicMock(return_value=False)

        mock_conn = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_conn.__enter__ = MagicMock(return_value=mock_conn)
        mock_conn.__exit__ = MagicMock(return_value=False)

        with patch("psycopg.connect", return_value=mock_conn):
            result = introspect_schema("postgresql://test@localhost/testdb")

        assert "auth_user" in result
        assert "ecomm_order" in result
        assert len(result["auth_user"]) == 2
        assert len(result["ecomm_order"]) == 2
        assert result["auth_user"][0].column_name == "id"
        assert result["auth_user"][1].column_name == "email"

    def test_introspect_non_public_schema_uses_qualified_name(self):
        mock_rows = [
            ("analytics", "events", "id", "integer", "int4"),
        ]

        mock_cursor = MagicMock()
        mock_cursor.fetchall.return_value = mock_rows
        mock_cursor.__enter__ = MagicMock(return_value=mock_cursor)
        mock_cursor.__exit__ = MagicMock(return_value=False)

        mock_conn = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_conn.__enter__ = MagicMock(return_value=mock_conn)
        mock_conn.__exit__ = MagicMock(return_value=False)

        with patch("psycopg.connect", return_value=mock_conn):
            result = introspect_schema(
                "postgresql://test@localhost/testdb",
                schemas=["analytics"],
            )

        assert "analytics.events" in result

    def test_introspect_default_schema_is_public(self):
        mock_cursor = MagicMock()
        mock_cursor.fetchall.return_value = []
        mock_cursor.__enter__ = MagicMock(return_value=mock_cursor)
        mock_cursor.__exit__ = MagicMock(return_value=False)

        mock_conn = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_conn.__enter__ = MagicMock(return_value=mock_conn)
        mock_conn.__exit__ = MagicMock(return_value=False)

        with patch("psycopg.connect", return_value=mock_conn):
            introspect_schema("postgresql://test@localhost/testdb")

        # Verify the execute call used ["public"] as the schema parameter
        mock_cursor.execute.assert_called_once()
        call_args = mock_cursor.execute.call_args
        assert call_args[0][1] == [["public"]]
