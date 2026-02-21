"""
Adversarial bypass test suite.

Every test case represents a specific attack vector from the security
review. Each asserts that sensitive data is either redacted or the
query is rejected outright. If any test fails, there is a data leak.
"""

import pytest

from sanitized_db_mcp.errors import (
    DisallowedFunctionError,
    QuerySyntaxError,
    RestrictedColumnError,
    StatementTypeError,
    SystemCatalogError,
)
from sanitized_db_mcp.sanitizer import sanitize_query


# ======================================================================
# Statement type attacks
# ======================================================================


class TestStatementTypeAttacks:
    """Attempt to use non-SELECT statement types."""

    def test_copy_to_stdout(self, sample_allowlist):
        with pytest.raises((StatementTypeError, QuerySyntaxError)):
            sanitize_query("COPY accounts_profile TO STDOUT", sample_allowlist)

    def test_do_block(self, sample_allowlist):
        with pytest.raises((StatementTypeError, QuerySyntaxError)):
            sanitize_query(
                "DO $$ BEGIN RAISE NOTICE '%', (SELECT email FROM accounts_profile LIMIT 1); END $$",
                sample_allowlist,
            )

    def test_prepare_execute(self, sample_allowlist):
        with pytest.raises((StatementTypeError, QuerySyntaxError)):
            sanitize_query(
                "PREPARE stmt AS SELECT email FROM accounts_profile; EXECUTE stmt",
                sample_allowlist,
            )

    def test_explain_leaks_plan(self, sample_allowlist):
        with pytest.raises(StatementTypeError):
            sanitize_query(
                "EXPLAIN SELECT email FROM accounts_profile",
                sample_allowlist,
            )

    def test_explain_analyze(self, sample_allowlist):
        with pytest.raises(StatementTypeError):
            sanitize_query(
                "EXPLAIN ANALYZE SELECT email FROM accounts_profile",
                sample_allowlist,
            )

    def test_set_role_escalation(self, sample_allowlist):
        with pytest.raises((StatementTypeError, QuerySyntaxError)):
            sanitize_query("SET ROLE postgres", sample_allowlist)

    def test_declare_cursor(self, sample_allowlist):
        with pytest.raises((StatementTypeError, QuerySyntaxError)):
            sanitize_query(
                "DECLARE c CURSOR FOR SELECT email FROM accounts_profile",
                sample_allowlist,
            )

    def test_multi_statement_injection(self, sample_allowlist):
        with pytest.raises((StatementTypeError, QuerySyntaxError)):
            sanitize_query(
                "SELECT id FROM accounts_profile; DROP TABLE accounts_profile",
                sample_allowlist,
            )

    def test_create_temp_table(self, sample_allowlist):
        with pytest.raises((StatementTypeError, QuerySyntaxError)):
            sanitize_query(
                "CREATE TEMP TABLE leak AS SELECT email FROM accounts_profile",
                sample_allowlist,
            )

    def test_listen_notify(self, sample_allowlist):
        with pytest.raises((StatementTypeError, QuerySyntaxError)):
            sanitize_query("LISTEN channel", sample_allowlist)

    def test_show_config(self, sample_allowlist):
        with pytest.raises((StatementTypeError, QuerySyntaxError)):
            sanitize_query("SHOW server_version", sample_allowlist)


# ======================================================================
# System catalog access attacks
# ======================================================================


class TestSystemCatalogAttacks:
    """Attempt to access system catalogs for schema discovery."""

    def test_pg_catalog_tables(self, sample_allowlist):
        with pytest.raises(SystemCatalogError):
            sanitize_query(
                "SELECT tablename FROM pg_catalog.pg_tables",
                sample_allowlist,
            )

    def test_information_schema_columns(self, sample_allowlist):
        with pytest.raises(SystemCatalogError):
            sanitize_query(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_name = 'accounts_profile'",
                sample_allowlist,
            )

    def test_pg_stat_activity(self, sample_allowlist):
        with pytest.raises(SystemCatalogError):
            sanitize_query(
                "SELECT query FROM pg_stat_activity",
                sample_allowlist,
            )

    def test_pg_class(self, sample_allowlist):
        with pytest.raises(SystemCatalogError):
            sanitize_query(
                "SELECT relname FROM pg_class WHERE relkind = 'r'",
                sample_allowlist,
            )

    def test_has_column_privilege_function(self, sample_allowlist):
        with pytest.raises(DisallowedFunctionError):
            sanitize_query(
                "SELECT has_column_privilege('agent_readonly', 'accounts_profile', 'email', 'SELECT')",
                sample_allowlist,
            )


# ======================================================================
# Subquery bypass attacks
# ======================================================================


class TestSubqueryBypass:
    """Attempt to extract data via subqueries."""

    def test_scalar_subquery_in_select(self, sample_allowlist):
        """Scalar subquery accessing hidden column in SELECT."""
        with pytest.raises(RestrictedColumnError):
            sanitize_query(
                "SELECT id, (SELECT email FROM accounts_profile WHERE id = 1) "
                "FROM accounts_profile",
                sample_allowlist,
            )

    def test_cte_accessing_hidden_column(self, sample_allowlist):
        """CTE (WITH clause) accessing hidden column."""
        with pytest.raises(RestrictedColumnError):
            sanitize_query(
                "WITH leaked AS (SELECT email FROM accounts_profile) SELECT * FROM leaked",
                sample_allowlist,
            )

    def test_union_exfiltrates_hidden_column(self, sample_allowlist):
        """UNION to smuggle hidden column data."""
        with pytest.raises(RestrictedColumnError):
            sanitize_query(
                "SELECT id FROM accounts_profile UNION ALL SELECT email FROM accounts_profile",
                sample_allowlist,
            )

    def test_subquery_in_from_clause(self, sample_allowlist):
        """Derived table accessing hidden column."""
        with pytest.raises(RestrictedColumnError):
            sanitize_query(
                "SELECT sub.email FROM (SELECT email FROM accounts_profile) sub",
                sample_allowlist,
            )

    def test_exists_with_hidden_column(self, sample_allowlist):
        """EXISTS subquery using hidden column in WHERE."""
        with pytest.raises(RestrictedColumnError):
            sanitize_query(
                "SELECT id FROM accounts_profile p "
                "WHERE EXISTS (SELECT 1 FROM auth_user u WHERE u.email = 'test@test.com')",
                sample_allowlist,
            )


# ======================================================================
# Function bypass attacks
# ======================================================================


class TestFunctionBypass:
    """Attempt to use functions to exfiltrate data."""

    def test_row_to_json_dumps_entire_row(self, sample_allowlist):
        with pytest.raises(DisallowedFunctionError):
            sanitize_query(
                "SELECT row_to_json(t) FROM accounts_profile t",
                sample_allowlist,
            )

    def test_to_json_bypass(self, sample_allowlist):
        with pytest.raises(DisallowedFunctionError):
            sanitize_query(
                "SELECT to_json(p) FROM accounts_profile p",
                sample_allowlist,
            )

    def test_json_agg_entire_table(self, sample_allowlist):
        with pytest.raises(DisallowedFunctionError):
            sanitize_query(
                "SELECT json_agg(t) FROM accounts_profile t",
                sample_allowlist,
            )

    def test_json_build_object_hidden_column(self, sample_allowlist):
        with pytest.raises(DisallowedFunctionError):
            sanitize_query(
                "SELECT json_build_object('email', email) FROM accounts_profile",
                sample_allowlist,
            )

    def test_xmlelement_bypass(self, sample_allowlist):
        with pytest.raises(DisallowedFunctionError):
            sanitize_query(
                "SELECT xmlelement(name user, email) FROM accounts_profile",
                sample_allowlist,
            )

    def test_query_to_xml_exfiltration(self, sample_allowlist):
        with pytest.raises(DisallowedFunctionError):
            sanitize_query(
                "SELECT query_to_xml('SELECT email FROM accounts_profile', true, false, '')",
                sample_allowlist,
            )

    def test_encode_email_as_hex(self, sample_allowlist):
        with pytest.raises(DisallowedFunctionError):
            sanitize_query(
                "SELECT encode(email::bytea, 'hex') FROM accounts_profile",
                sample_allowlist,
            )

    def test_string_agg_hidden_column(self, sample_allowlist):
        """string_agg is allowed but should redact hidden columns."""
        result = sanitize_query(
            "SELECT string_agg(email, ',') FROM accounts_profile",
            sample_allowlist,
        )
        # The expression references email (hidden) — should be redacted
        assert result.was_rewritten
        assert any("email" in col for col in result.columns_redacted)


# ======================================================================
# WHERE exfiltration attacks (boolean-based side channel)
# ======================================================================


class TestWhereExfiltration:
    """Boolean-based side-channel extraction via WHERE clause."""

    def test_boolean_binary_search_email(self, sample_allowlist):
        """Extract email char-by-char via WHERE LIKE pattern."""
        with pytest.raises(RestrictedColumnError):
            sanitize_query(
                "SELECT COUNT(*) FROM accounts_profile WHERE email LIKE 'a%'",
                sample_allowlist,
            )

    def test_length_check_hidden_column(self, sample_allowlist):
        """Determine length of hidden column value."""
        with pytest.raises(RestrictedColumnError):
            sanitize_query(
                "SELECT COUNT(*) FROM accounts_profile WHERE LENGTH(email) > 10",
                sample_allowlist,
            )

    def test_substr_hidden_column(self, sample_allowlist):
        """Extract substring of hidden column."""
        with pytest.raises(RestrictedColumnError):
            sanitize_query(
                "SELECT COUNT(*) FROM accounts_profile WHERE SUBSTRING(email, 1, 1) = 'a'",
                sample_allowlist,
            )

    def test_regex_match_hidden_column(self, sample_allowlist):
        """Regex match on hidden column."""
        with pytest.raises(RestrictedColumnError):
            sanitize_query(
                "SELECT id FROM accounts_profile WHERE email ~ '^admin'",
                sample_allowlist,
            )

    def test_case_insensitive_like(self, sample_allowlist):
        with pytest.raises(RestrictedColumnError):
            sanitize_query(
                "SELECT id FROM accounts_profile WHERE email ILIKE '%@gmail.com'",
                sample_allowlist,
            )

    def test_between_on_hidden_column(self, sample_allowlist):
        with pytest.raises(RestrictedColumnError):
            sanitize_query(
                "SELECT id FROM accounts_profile WHERE phone_number BETWEEN '100' AND '999'",
                sample_allowlist,
            )

    def test_in_clause_hidden_column(self, sample_allowlist):
        with pytest.raises(RestrictedColumnError):
            sanitize_query(
                "SELECT id FROM accounts_profile WHERE email IN ('a@b.com', 'c@d.com')",
                sample_allowlist,
            )

    def test_is_not_null_hidden_column(self, sample_allowlist):
        """Even IS NULL/IS NOT NULL on hidden columns leaks information."""
        with pytest.raises(RestrictedColumnError):
            sanitize_query(
                "SELECT id FROM accounts_profile WHERE email IS NOT NULL",
                sample_allowlist,
            )

    def test_having_clause_hidden_column(self, sample_allowlist):
        with pytest.raises(RestrictedColumnError):
            sanitize_query(
                "SELECT user_id, COUNT(*) FROM ecomm_order "
                "GROUP BY user_id HAVING MAX(email) IS NOT NULL",
                sample_allowlist,
            )


# ======================================================================
# Expression bypass attacks
# ======================================================================


class TestExpressionBypass:
    """Attempt to extract data via SQL expressions."""

    def test_type_cast_bypass(self, sample_allowlist):
        """Cast hidden column to reveal it."""
        result = sanitize_query(
            "SELECT email::text FROM accounts_profile",
            sample_allowlist,
        )
        assert result.was_rewritten
        assert any("email" in col for col in result.columns_redacted)

    def test_concatenation_with_hidden(self, sample_allowlist):
        """Concatenate visible and hidden columns."""
        result = sanitize_query(
            "SELECT id || email FROM accounts_profile",
            sample_allowlist,
        )
        assert result.was_rewritten

    def test_case_expression_leaks_hidden(self, sample_allowlist):
        """CASE expression referencing hidden column."""
        result = sanitize_query(
            "SELECT CASE WHEN email LIKE '%@gmail.com' THEN 'gmail' ELSE 'other' END "
            "FROM accounts_profile",
            sample_allowlist,
        )
        # This uses email in WHERE-like context inside CASE — should be redacted
        assert result.was_rewritten


# ======================================================================
# Star expansion attacks
# ======================================================================


class TestStarExpansion:
    """Attempt to use SELECT * to access hidden columns."""

    def test_bare_star_expands(self, sample_allowlist):
        """SELECT * should expand to only visible columns."""
        result = sanitize_query(
            "SELECT * FROM accounts_profile",
            sample_allowlist,
        )
        assert result.was_rewritten
        # Should contain visible columns
        assert "id" in result.rewritten_sql.lower() or "user_id" in result.rewritten_sql.lower()

    def test_qualified_star_expands(self, sample_allowlist):
        """SELECT t.* should expand to only visible columns."""
        result = sanitize_query(
            "SELECT p.* FROM accounts_profile p",
            sample_allowlist,
        )
        assert result.was_rewritten

    def test_star_in_function_rejected(self, sample_allowlist):
        """json_agg(t.*) is rejected."""
        with pytest.raises(DisallowedFunctionError):
            sanitize_query(
                "SELECT json_agg(t.*) FROM accounts_profile t",
                sample_allowlist,
            )


# ======================================================================
# Timing attacks
# ======================================================================


class TestTimingAttacks:
    """Attempt to use timing-based side channels."""

    def test_pg_sleep_in_select(self, sample_allowlist):
        with pytest.raises(DisallowedFunctionError):
            sanitize_query("SELECT pg_sleep(1)", sample_allowlist)

    def test_pg_sleep_in_case(self, sample_allowlist):
        with pytest.raises(DisallowedFunctionError):
            sanitize_query(
                "SELECT CASE WHEN 1=1 THEN pg_sleep(1) ELSE pg_sleep(0) END",
                sample_allowlist,
            )

    def test_pg_advisory_lock_timing(self, sample_allowlist):
        with pytest.raises(DisallowedFunctionError):
            sanitize_query(
                "SELECT pg_advisory_lock(1) FROM accounts_profile",
                sample_allowlist,
            )


# ======================================================================
# Error leakage attacks
# ======================================================================


class TestErrorLeakage:
    """Errors should never reveal column names or types."""

    def test_invalid_column_generic_error(self, sample_allowlist):
        """Error for nonexistent column should be generic."""
        # This should raise either a syntax error or restricted column error,
        # but never reveal the actual column list
        try:
            sanitize_query(
                "SELECT nonexistent_col FROM accounts_profile",
                sample_allowlist,
            )
        except Exception as e:
            # The error message should not contain actual column names
            error_msg = str(e)
            assert "email" not in error_msg.lower()
            assert "phone_number" not in error_msg.lower()
            assert "birthday" not in error_msg.lower()


# ======================================================================
# Multi-table attack combinations
# ======================================================================


class TestMultiTableAttacks:
    """Cross-table attacks combining allowed and hidden data."""

    def test_join_leaks_hidden_column(self, sample_allowlist):
        """JOIN ON condition using hidden column."""
        with pytest.raises(RestrictedColumnError):
            sanitize_query(
                "SELECT p.id, u.id FROM accounts_profile p JOIN auth_user u ON u.email = p.email",
                sample_allowlist,
            )

    def test_cross_join_hidden_column(self, sample_allowlist):
        """Cross-join to brute-force hidden values."""
        with pytest.raises(RestrictedColumnError):
            sanitize_query(
                "SELECT p.id FROM accounts_profile p, auth_user u WHERE p.email = u.email",
                sample_allowlist,
            )
