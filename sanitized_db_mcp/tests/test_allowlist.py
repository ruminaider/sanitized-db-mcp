"""Tests for allowlist loading and querying."""

import pytest

from sanitized_db_mcp.allowlist import Allowlist


class TestAllowlistLoading:
    def test_load_from_yaml(self, tmp_path):
        yaml_content = """\
tables:
  accounts_profile:
    columns:
      id: {type: integer, placeholder: "0"}
      user_id: {type: integer, placeholder: "0"}
allowed_functions:
  - COUNT
  - SUM
"""
        yaml_file = tmp_path / "allowlist.yaml"
        yaml_file.write_text(yaml_content)

        al = Allowlist.from_yaml(yaml_file)
        assert al.has_table("accounts_profile")
        assert al.is_column_visible("accounts_profile", "id")
        assert al.is_column_visible("accounts_profile", "user_id")
        assert al.is_function_allowed("COUNT")
        assert al.is_function_allowed("SUM")

    def test_missing_file_raises(self):
        with pytest.raises(FileNotFoundError):
            Allowlist.from_yaml("/nonexistent/path.yaml")

    def test_empty_yaml_raises(self, tmp_path):
        yaml_file = tmp_path / "empty.yaml"
        yaml_file.write_text("")
        with pytest.raises(ValueError, match="missing 'tables' key"):
            Allowlist.from_yaml(yaml_file)

    def test_no_tables_key_raises(self, tmp_path):
        yaml_file = tmp_path / "bad.yaml"
        yaml_file.write_text("allowed_functions:\n  - COUNT\n")
        with pytest.raises(ValueError, match="missing 'tables' key"):
            Allowlist.from_yaml(yaml_file)


class TestAllowlistQuerying:
    def test_has_table(self, sample_allowlist):
        assert sample_allowlist.has_table("accounts_profile")
        assert sample_allowlist.has_table("ecomm_order")
        assert not sample_allowlist.has_table("nonexistent_table")

    def test_is_column_visible(self, sample_allowlist):
        assert sample_allowlist.is_column_visible("accounts_profile", "id")
        assert sample_allowlist.is_column_visible("accounts_profile", "user_id")
        assert sample_allowlist.is_column_visible("accounts_profile", "is_test_user")
        # Hidden columns
        assert not sample_allowlist.is_column_visible("accounts_profile", "email")
        assert not sample_allowlist.is_column_visible("accounts_profile", "phone_number")

    def test_get_placeholder(self, sample_allowlist):
        # Known visible column returns its placeholder
        assert sample_allowlist.get_placeholder("accounts_profile", "id") == "0"
        # Unknown column gets default
        assert sample_allowlist.get_placeholder("accounts_profile", "email") == "'[REDACTED]'"

    def test_get_visible_columns(self, sample_allowlist):
        visible = sample_allowlist.get_visible_columns("accounts_profile")
        assert visible == {"id", "user_id", "is_test_user"}

    def test_is_function_allowed(self, sample_allowlist):
        assert sample_allowlist.is_function_allowed("COUNT")
        assert sample_allowlist.is_function_allowed("count")  # case insensitive
        assert not sample_allowlist.is_function_allowed("ROW_TO_JSON")
        assert not sample_allowlist.is_function_allowed("PG_SLEEP")

    def test_case_insensitive_table(self, sample_allowlist):
        assert sample_allowlist.has_table("Accounts_Profile")
        assert sample_allowlist.is_column_visible("ACCOUNTS_PROFILE", "id")

    def test_all_tables(self, sample_allowlist):
        assert "accounts_profile" in sample_allowlist.all_tables
        assert "ecomm_order" in sample_allowlist.all_tables
        assert "auth_user" in sample_allowlist.all_tables
