"""Tests for the SQL sanitizer — core rewriting logic."""

import pytest

from sanitized_db_mcp.errors import (
    DisallowedFunctionError,
    QuerySyntaxError,
    RestrictedColumnError,
    StatementTypeError,
    SystemCatalogError,
)
from sanitized_db_mcp.sanitizer import sanitize_query


class TestBasicSelectRewriting:
    """Tests for basic SELECT column rewriting."""

    def test_visible_columns_pass_through(self, sample_allowlist):
        result = sanitize_query(
            "SELECT id, user_id, is_test_user FROM accounts_profile",
            sample_allowlist,
        )
        assert not result.was_rewritten
        assert "accounts_profile" in result.tables_accessed

    def test_hidden_column_replaced_with_placeholder(self, sample_allowlist):
        result = sanitize_query(
            "SELECT id, email FROM accounts_profile",
            sample_allowlist,
        )
        assert result.was_rewritten
        assert "accounts_profile.email" in result.columns_redacted
        # The rewritten SQL should not contain 'email' as a column reference
        assert (
            "email" not in result.rewritten_sql.lower().split("as")[0]
            or "[REDACTED]" in result.rewritten_sql
        )

    def test_qualified_column_reference(self, sample_allowlist):
        result = sanitize_query(
            "SELECT p.id, p.email FROM accounts_profile p",
            sample_allowlist,
        )
        assert result.was_rewritten
        assert any("email" in col for col in result.columns_redacted)

    def test_mixed_visible_and_hidden(self, sample_allowlist):
        result = sanitize_query(
            "SELECT id, user_id, email, phone_number FROM accounts_profile",
            sample_allowlist,
        )
        assert result.was_rewritten
        assert any("email" in col for col in result.columns_redacted)
        assert any("phone_number" in col for col in result.columns_redacted)


class TestStatementTypeValidation:
    """Only SELECT statements are allowed."""

    def test_insert_rejected(self, sample_allowlist):
        with pytest.raises(StatementTypeError):
            sanitize_query(
                "INSERT INTO accounts_profile (email) VALUES ('test@test.com')",
                sample_allowlist,
            )

    def test_update_rejected(self, sample_allowlist):
        with pytest.raises(StatementTypeError):
            sanitize_query(
                "UPDATE accounts_profile SET email = 'new@test.com' WHERE id = 1",
                sample_allowlist,
            )

    def test_delete_rejected(self, sample_allowlist):
        with pytest.raises(StatementTypeError):
            sanitize_query(
                "DELETE FROM accounts_profile WHERE id = 1",
                sample_allowlist,
            )

    def test_drop_rejected(self, sample_allowlist):
        with pytest.raises(StatementTypeError):
            sanitize_query("DROP TABLE accounts_profile", sample_allowlist)

    def test_create_rejected(self, sample_allowlist):
        with pytest.raises(StatementTypeError):
            sanitize_query("CREATE TABLE test (id int)", sample_allowlist)

    def test_multi_statement_rejected(self, sample_allowlist):
        with pytest.raises(StatementTypeError):
            sanitize_query("SELECT 1; SELECT 2", sample_allowlist)

    def test_empty_query_rejected(self, sample_allowlist):
        with pytest.raises(QuerySyntaxError):
            sanitize_query("", sample_allowlist)

    def test_syntax_error_rejected(self, sample_allowlist):
        with pytest.raises(QuerySyntaxError):
            sanitize_query("SELCT id FORM accounts_profile", sample_allowlist)


class TestTableValidation:
    """Table access control."""

    def test_unknown_table_rejected(self, sample_allowlist):
        with pytest.raises(RestrictedColumnError):
            sanitize_query("SELECT id FROM nonexistent_table", sample_allowlist)

    def test_system_catalog_rejected(self, sample_allowlist):
        with pytest.raises(SystemCatalogError):
            sanitize_query("SELECT * FROM pg_catalog.pg_tables", sample_allowlist)

    def test_information_schema_rejected(self, sample_allowlist):
        with pytest.raises(SystemCatalogError):
            sanitize_query("SELECT * FROM information_schema.columns", sample_allowlist)

    def test_pg_prefix_table_rejected(self, sample_allowlist):
        with pytest.raises(SystemCatalogError):
            sanitize_query("SELECT * FROM pg_stat_activity", sample_allowlist)


class TestFunctionValidation:
    """Function allow/blocklist."""

    def test_allowed_aggregate_functions(self, sample_allowlist):
        result = sanitize_query(
            "SELECT COUNT(*), MAX(id) FROM accounts_profile",
            sample_allowlist,
        )
        assert "count" in result.rewritten_sql.lower() or "COUNT" in result.rewritten_sql

    def test_allowed_date_functions(self, sample_allowlist):
        sanitize_query(
            "SELECT id, NOW() FROM accounts_profile",
            sample_allowlist,
        )
        # Should pass without error

    def test_blocked_row_to_json(self, sample_allowlist):
        with pytest.raises(DisallowedFunctionError):
            sanitize_query(
                "SELECT row_to_json(t) FROM accounts_profile t",
                sample_allowlist,
            )

    def test_blocked_to_json(self, sample_allowlist):
        with pytest.raises(DisallowedFunctionError):
            sanitize_query(
                "SELECT to_json(p) FROM accounts_profile p",
                sample_allowlist,
            )

    def test_blocked_json_agg(self, sample_allowlist):
        with pytest.raises(DisallowedFunctionError):
            sanitize_query(
                "SELECT json_agg(p) FROM accounts_profile p",
                sample_allowlist,
            )

    def test_blocked_dblink(self, sample_allowlist):
        with pytest.raises(DisallowedFunctionError):
            sanitize_query(
                "SELECT * FROM dblink('dbname=other', 'SELECT email FROM users') AS t(email text)",
                sample_allowlist,
            )

    def test_blocked_pg_sleep(self, sample_allowlist):
        with pytest.raises(DisallowedFunctionError):
            sanitize_query("SELECT pg_sleep(5)", sample_allowlist)

    def test_blocked_pg_advisory_lock(self, sample_allowlist):
        with pytest.raises(DisallowedFunctionError):
            sanitize_query("SELECT pg_advisory_lock(1)", sample_allowlist)

    def test_blocked_encode(self, sample_allowlist):
        with pytest.raises(DisallowedFunctionError):
            sanitize_query(
                "SELECT encode(email::bytea, 'hex') FROM accounts_profile",
                sample_allowlist,
            )

    def test_blocked_md5(self, sample_allowlist):
        with pytest.raises(DisallowedFunctionError):
            sanitize_query(
                "SELECT md5(email) FROM accounts_profile",
                sample_allowlist,
            )

    def test_blocked_has_column_privilege(self, sample_allowlist):
        with pytest.raises(DisallowedFunctionError):
            sanitize_query(
                "SELECT has_column_privilege('accounts_profile', 'email', 'SELECT')",
                sample_allowlist,
            )


class TestWhereClauseRestriction:
    """WHERE clause cannot reference non-allowlisted columns."""

    def test_visible_column_in_where_allowed(self, sample_allowlist):
        result = sanitize_query(
            "SELECT id FROM accounts_profile WHERE is_test_user = true",
            sample_allowlist,
        )
        # Should pass without error
        assert not result.was_rewritten

    def test_hidden_column_in_where_rejected(self, sample_allowlist):
        with pytest.raises(RestrictedColumnError):
            sanitize_query(
                "SELECT id FROM accounts_profile WHERE email = 'test@test.com'",
                sample_allowlist,
            )

    def test_hidden_column_in_like_rejected(self, sample_allowlist):
        with pytest.raises(RestrictedColumnError):
            sanitize_query(
                "SELECT id FROM accounts_profile WHERE email LIKE 'a%'",
                sample_allowlist,
            )

    def test_hidden_column_in_join_on_rejected(self, sample_allowlist):
        with pytest.raises(RestrictedColumnError):
            sanitize_query(
                "SELECT p.id FROM accounts_profile p JOIN auth_user u ON u.email = p.email",
                sample_allowlist,
            )

    def test_visible_column_in_join_on_allowed(self, sample_allowlist):
        sanitize_query(
            "SELECT p.id FROM accounts_profile p JOIN auth_user u ON u.id = p.user_id",
            sample_allowlist,
        )
        # Should pass without error


class TestExpressionRewriting:
    """Expressions containing hidden columns should be redacted."""

    def test_concat_with_hidden_column(self, sample_allowlist):
        result = sanitize_query(
            "SELECT CONCAT(email, ' ', status) FROM ecomm_order",
            sample_allowlist,
        )
        assert result.was_rewritten
        assert any("email" in col for col in result.columns_redacted)

    def test_case_referencing_hidden_column(self, sample_allowlist):
        result = sanitize_query(
            "SELECT CASE WHEN email IS NOT NULL THEN 'has_email' ELSE 'no_email' END "
            "FROM accounts_profile",
            sample_allowlist,
        )
        # The CASE expression references email (hidden) — should be redacted
        assert result.was_rewritten


class TestJoinQueries:
    """Multi-table JOIN queries."""

    def test_join_visible_columns(self, sample_allowlist):
        result = sanitize_query(
            "SELECT p.id, p.user_id, o.status "
            "FROM accounts_profile p "
            "JOIN ecomm_order o ON o.user_id = p.user_id",
            sample_allowlist,
        )
        assert not result.was_rewritten

    def test_join_mixed_columns(self, sample_allowlist):
        result = sanitize_query(
            "SELECT p.id, p.email, o.status "
            "FROM accounts_profile p "
            "JOIN ecomm_order o ON o.user_id = p.user_id",
            sample_allowlist,
        )
        assert result.was_rewritten
        assert any("email" in col for col in result.columns_redacted)


class TestSubqueries:
    """Subquery validation."""

    def test_subquery_in_where_validated(self, sample_allowlist):
        sanitize_query(
            "SELECT id FROM accounts_profile "
            "WHERE user_id IN (SELECT id FROM auth_user WHERE is_active = true)",
            sample_allowlist,
        )
        # Should pass — all columns are allowlisted

    def test_subquery_accessing_hidden_column_rejected(self, sample_allowlist):
        with pytest.raises(RestrictedColumnError):
            sanitize_query(
                "SELECT id FROM accounts_profile "
                "WHERE user_id IN (SELECT id FROM auth_user WHERE email = 'test@test.com')",
                sample_allowlist,
            )


class TestUnionQueries:
    """UNION/INTERSECT/EXCEPT validation."""

    def test_union_visible_columns(self, sample_allowlist):
        sanitize_query(
            "SELECT id FROM accounts_profile UNION ALL SELECT id FROM auth_user",
            sample_allowlist,
        )
        # Should pass

    def test_union_with_hidden_column_rejected(self, sample_allowlist):
        with pytest.raises(RestrictedColumnError):
            sanitize_query(
                "SELECT id FROM accounts_profile "
                "UNION ALL "
                "SELECT id FROM auth_user WHERE email = 'test@test.com'",
                sample_allowlist,
            )
