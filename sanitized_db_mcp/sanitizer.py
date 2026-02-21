"""
SQL sanitizer using pglast (PostgreSQL's C parser) for AST-level rewriting.

Pipeline:
  1.  Parse SQL → AST
  2.  Validate: exactly one SELECT statement
  3.  Reject: SELECT INTO (intoClause) and FOR UPDATE/SHARE (lockingClause)
  4.  Validate: no system catalogs
  5.  Validate: only allowed functions
  6.  Validate: FILTER (WHERE ...) on aggregates (agg_filter)
  7.  Validate: inline OVER clauses on window functions (FuncCall.over)
  8.  Reject: WHERE/HAVING/JOIN ON conditions referencing hidden columns
  9.  Reject: ORDER BY / GROUP BY / DISTINCT ON / WINDOW referencing hidden columns
  10. Validate: CTE and subquery SELECT targets for hidden columns
  11. Rewrite: replace hidden column refs in outer SELECT with placeholders
  12. Expand: SELECT * → explicit visible columns + redacted marker
  13. Serialize: AST → rewritten SQL string
"""

from __future__ import annotations

from dataclasses import dataclass, field
import logging

import pglast
from pglast import parse_sql
from pglast.stream import RawStream

from .allowlist import Allowlist
from .errors import (
    DisallowedFunctionError,
    QuerySyntaxError,
    RestrictedColumnError,
    StatementTypeError,
    SystemCatalogError,
)


logger = logging.getLogger(__name__)

# System schemas that must never be accessed
BLOCKED_SCHEMAS = frozenset(
    {
        "pg_catalog",
        "information_schema",
        "pg_temp",
        "pg_toast",
    }
)

# System table prefixes to block
BLOCKED_TABLE_PREFIXES = frozenset(
    {
        "pg_",
        "sql_",
    }
)

# Functions that can dump entire rows or exfiltrate data
# (blocked even if they appear to take allowlisted args)
ALWAYS_BLOCKED_FUNCTIONS = frozenset(
    {
        "ROW_TO_JSON",
        "TO_JSON",
        "TO_JSONB",
        "JSON_AGG",
        "JSONB_AGG",
        "JSON_OBJECT_AGG",
        "JSONB_OBJECT_AGG",
        "JSON_BUILD_OBJECT",
        "JSONB_BUILD_OBJECT",
        "JSON_POPULATE_RECORD",
        "JSONB_POPULATE_RECORD",
        "JSON_POPULATE_RECORDSET",
        "JSONB_POPULATE_RECORDSET",
        "XMLELEMENT",
        "XMLFOREST",
        "XMLAGG",
        "QUERY_TO_XML",
        "TABLE_TO_XML",
        "CURSOR_TO_XML",
        "DBLINK",
        "DBLINK_EXEC",
        "PG_SLEEP",
        "PG_ADVISORY_LOCK",
        "PG_ADVISORY_UNLOCK",
        "SET_CONFIG",
        "CURRENT_SETTING",
        "HAS_TABLE_PRIVILEGE",
        "HAS_COLUMN_PRIVILEGE",
        "HAS_SCHEMA_PRIVILEGE",
        "HAS_DATABASE_PRIVILEGE",
        "PG_READ_FILE",
        "PG_READ_BINARY_FILE",
        "PG_LS_DIR",
        "PG_STAT_FILE",
        "ENCODE",
        "DECODE",
        "MD5",
        "SHA256",
        "SHA512",
        "DIGEST",
        "CRYPT",
        "LO_IMPORT",
        "LO_EXPORT",
        "LO_GET",
        "COPY",
    }
)


@dataclass
class SanitizeResult:
    """Result of sanitizing a SQL query."""

    original_sql: str
    rewritten_sql: str
    tables_accessed: list[str] = field(default_factory=list)
    columns_accessed: list[str] = field(default_factory=list)
    columns_redacted: list[str] = field(default_factory=list)
    was_rewritten: bool = False


def sanitize_query(sql: str, allowlist: Allowlist) -> SanitizeResult:
    """Sanitize a SQL query according to the allowlist.

    Returns a SanitizeResult with the rewritten SQL, or raises
    a SanitizationError subclass if the query is rejected.
    """
    # ------------------------------------------------------------------
    # 1. Parse
    # ------------------------------------------------------------------
    try:
        stmts = parse_sql(sql)
    except pglast.parser.ParseError as e:
        raise QuerySyntaxError(f"Parse error: {e}")

    if not stmts:
        raise QuerySyntaxError("Empty query")

    # ------------------------------------------------------------------
    # 2. Validate: exactly one SELECT statement
    # ------------------------------------------------------------------
    if len(stmts) > 1:
        raise StatementTypeError("Multiple statements are not allowed")

    stmt = stmts[0].stmt

    # pglast wraps in a RawStmt; get the inner statement
    if not isinstance(stmt, pglast.ast.SelectStmt):
        raise StatementTypeError(f"Only SELECT statements are allowed, got {type(stmt).__name__}")

    # ------------------------------------------------------------------
    # 3. Build table alias map from FROM clause
    # ------------------------------------------------------------------
    table_aliases = _extract_table_aliases(stmt)
    tables_accessed = list(table_aliases.values())

    # ------------------------------------------------------------------
    # 4. Validate tables
    # ------------------------------------------------------------------
    _validate_tables(tables_accessed, allowlist)

    # ------------------------------------------------------------------
    # 5. Validate the full AST
    # ------------------------------------------------------------------
    columns_accessed = []
    columns_redacted = []

    # Walk the AST to validate functions, WHERE/JOIN columns
    _validate_ast(stmt, allowlist, table_aliases)

    # ------------------------------------------------------------------
    # 6. Rewrite SELECT columns
    # ------------------------------------------------------------------
    was_rewritten = _rewrite_select_targets(
        stmt, allowlist, table_aliases, columns_accessed, columns_redacted
    )

    # ------------------------------------------------------------------
    # 7. Serialize back to SQL
    # ------------------------------------------------------------------
    rewritten_sql = RawStream()(stmts[0])

    return SanitizeResult(
        original_sql=sql,
        rewritten_sql=rewritten_sql,
        tables_accessed=tables_accessed,
        columns_accessed=columns_accessed,
        columns_redacted=columns_redacted,
        was_rewritten=was_rewritten,
    )


# ======================================================================
# AST helpers
# ======================================================================


def _extract_table_aliases(stmt) -> dict[str, str]:
    """Extract a mapping of alias → real table name from FROM clause.

    If no alias, the table name maps to itself.
    """
    aliases: dict[str, str] = {}
    _walk_from_clause(stmt.fromClause, aliases)
    return aliases


def _walk_from_clause(from_list, aliases: dict[str, str]):
    """Recursively walk FROM clause items to extract table references."""
    if from_list is None:
        return

    for item in from_list:
        if isinstance(item, pglast.ast.RangeVar):
            table_name = item.relname
            if item.schemaname:
                # Check for blocked schemas
                if item.schemaname.lower() in BLOCKED_SCHEMAS:
                    raise SystemCatalogError(f"Access to schema {item.schemaname} is blocked")
                table_name = f"{item.schemaname}.{item.relname}"

            alias = item.alias.aliasname if item.alias else item.relname
            aliases[alias] = table_name

        elif isinstance(item, pglast.ast.JoinExpr):
            # Recurse into JOIN
            _walk_join(item, aliases)

        elif isinstance(item, pglast.ast.RangeSubselect):
            # Subquery in FROM — validate it recursively
            if item.subquery and isinstance(item.subquery, pglast.ast.SelectStmt):
                sub_aliases = _extract_table_aliases(item.subquery)
                # Validate subquery tables
                for tbl in sub_aliases.values():
                    _check_table_name(tbl)
                # The subquery's alias becomes a "virtual table" — we don't
                # add its inner tables to the outer scope
                if item.alias:
                    aliases[item.alias.aliasname] = f"__subquery_{item.alias.aliasname}"

        elif isinstance(item, pglast.ast.RangeFunction):
            # Table-returning function (e.g., generate_series)
            if item.alias:
                aliases[item.alias.aliasname] = f"__func_{item.alias.aliasname}"

        elif isinstance(item, pglast.ast.RangeTableSample):
            # TABLESAMPLE wraps a RangeVar — extract the underlying table
            if item.relation:
                _walk_from_clause([item.relation], aliases)


def _walk_join(join_expr, aliases: dict[str, str]):
    """Walk a JoinExpr to extract table references."""
    # Left side
    if isinstance(join_expr.larg, pglast.ast.RangeVar):
        _walk_from_clause([join_expr.larg], aliases)
    elif isinstance(join_expr.larg, pglast.ast.JoinExpr):
        _walk_join(join_expr.larg, aliases)
    elif isinstance(join_expr.larg, pglast.ast.RangeSubselect):
        _walk_from_clause([join_expr.larg], aliases)

    # Right side
    if isinstance(join_expr.rarg, pglast.ast.RangeVar):
        _walk_from_clause([join_expr.rarg], aliases)
    elif isinstance(join_expr.rarg, pglast.ast.JoinExpr):
        _walk_join(join_expr.rarg, aliases)
    elif isinstance(join_expr.rarg, pglast.ast.RangeSubselect):
        _walk_from_clause([join_expr.rarg], aliases)


def _check_table_name(table_name: str):
    """Raise if the table name matches blocked patterns."""
    lower = table_name.lower()
    for prefix in BLOCKED_TABLE_PREFIXES:
        if lower.startswith(prefix):
            raise SystemCatalogError(f"Access to table {table_name} is blocked")


def _validate_tables(tables: list[str], allowlist: Allowlist):
    """Validate that all referenced tables are in the allowlist."""
    for table in tables:
        # Skip virtual tables (subqueries, functions)
        if table.startswith("__subquery_") or table.startswith("__func_"):
            continue

        _check_table_name(table)

        if not allowlist.has_table(table):
            raise RestrictedColumnError(f"Table {table} is not in the allowlist")


# ======================================================================
# Function validation
# ======================================================================


def _validate_ast(stmt, allowlist: Allowlist, table_aliases: dict[str, str]):
    """Walk the full AST to validate functions and WHERE/JOIN column refs."""
    _walk_node(stmt, allowlist, table_aliases, in_where=False)


def _walk_node(node, allowlist: Allowlist, table_aliases: dict[str, str], in_where: bool):
    """Recursively walk an AST node for validation."""
    if node is None:
        return

    if isinstance(node, pglast.ast.FuncCall):
        _validate_function(node, allowlist)
        # Walk FILTER (WHERE ...) clause — semantically a WHERE condition
        if node.agg_filter:
            _walk_node(node.agg_filter, allowlist, table_aliases, in_where=True)
        # Walk inline OVER clause — PARTITION BY / ORDER BY leak hidden column info
        if node.over:
            _walk_node(node.over, allowlist, table_aliases, in_where=True)

    if isinstance(node, pglast.ast.XmlExpr):
        raise DisallowedFunctionError("XML functions are not allowed")

    if isinstance(node, pglast.ast.ColumnRef):
        if in_where:
            _validate_where_column(node, allowlist, table_aliases)

    # Check WHERE clause
    if isinstance(node, pglast.ast.SelectStmt):
        if node.whereClause:
            _walk_node(node.whereClause, allowlist, table_aliases, in_where=True)
        if node.havingClause:
            _walk_node(node.havingClause, allowlist, table_aliases, in_where=True)
        # Validate FROM clause JOINs (ON conditions), table-returning functions,
        # and subqueries in FROM
        if node.fromClause:
            for item in node.fromClause:
                if isinstance(item, pglast.ast.JoinExpr):
                    _validate_join_condition(item, allowlist, table_aliases)
                if isinstance(item, pglast.ast.RangeFunction):
                    _validate_range_function(item, allowlist)
                if isinstance(item, pglast.ast.RangeSubselect):
                    if item.subquery and isinstance(item.subquery, pglast.ast.SelectStmt):
                        sub_aliases = _extract_table_aliases(item.subquery)
                        _validate_tables(list(sub_aliases.values()), allowlist)
                        _validate_ast(item.subquery, allowlist, sub_aliases)
                        _validate_select_targets(item.subquery, allowlist, sub_aliases)

        # Validate subqueries in target list
        if node.targetList:
            for target in node.targetList:
                if isinstance(target, pglast.ast.ResTarget) and target.val:
                    _walk_node(target.val, allowlist, table_aliases, in_where=False)

        # Validate CTEs
        if node.withClause and node.withClause.ctes:
            for cte in node.withClause.ctes:
                if isinstance(cte, pglast.ast.CommonTableExpr) and cte.ctequery:
                    if isinstance(cte.ctequery, pglast.ast.SelectStmt):
                        cte_aliases = _extract_table_aliases(cte.ctequery)
                        _validate_ast(cte.ctequery, allowlist, cte_aliases)
                        _validate_select_targets(cte.ctequery, allowlist, cte_aliases)

        # Validate UNION/INTERSECT/EXCEPT
        if node.larg:
            if isinstance(node.larg, pglast.ast.SelectStmt):
                larg_aliases = _extract_table_aliases(node.larg)
                _validate_ast(node.larg, allowlist, larg_aliases)
                _validate_select_targets(node.larg, allowlist, larg_aliases)
        if node.rarg:
            if isinstance(node.rarg, pglast.ast.SelectStmt):
                rarg_aliases = _extract_table_aliases(node.rarg)
                _validate_ast(node.rarg, allowlist, rarg_aliases)
                _validate_select_targets(node.rarg, allowlist, rarg_aliases)

        # Reject locking clauses (FOR UPDATE, FOR SHARE, etc.)
        if node.lockingClause:
            raise StatementTypeError("Locking clauses (FOR UPDATE, FOR SHARE) are not allowed")

        # Reject SELECT INTO (creates a table)
        if node.intoClause:
            raise StatementTypeError("SELECT INTO is not allowed")

        # Validate ORDER BY — hidden columns leak sort order
        if node.sortClause:
            for sort_item in node.sortClause:
                _walk_node(sort_item, allowlist, table_aliases, in_where=True)

        # Validate GROUP BY — hidden columns leak grouping
        if node.groupClause:
            for group_item in node.groupClause:
                _walk_node(group_item, allowlist, table_aliases, in_where=True)

        # Validate DISTINCT ON — hidden columns leak uniqueness
        if node.distinctClause:
            for distinct_item in node.distinctClause:
                _walk_node(distinct_item, allowlist, table_aliases, in_where=True)

        # Validate WINDOW definitions — hidden columns in PARTITION BY / ORDER BY
        if node.windowClause:
            for window_def in node.windowClause:
                _walk_node(window_def, allowlist, table_aliases, in_where=True)

        return  # Don't recurse further — we handled sub-parts above

    if isinstance(node, pglast.ast.SubLink):
        # Subquery in expression (EXISTS, IN, scalar subquery)
        if node.subselect and isinstance(node.subselect, pglast.ast.SelectStmt):
            sub_aliases = _extract_table_aliases(node.subselect)
            _validate_tables(list(sub_aliases.values()), allowlist)
            _validate_ast(node.subselect, allowlist, sub_aliases)
            _validate_select_targets(node.subselect, allowlist, sub_aliases)
        return

    # Generic recursion for other node types
    if isinstance(node, pglast.ast.Node):
        for attr_name in node.__slots__:  # type: ignore[attr-defined]
            attr = getattr(node, attr_name, None)
            if attr is None:
                continue
            if isinstance(attr, pglast.ast.Node):
                _walk_node(attr, allowlist, table_aliases, in_where=in_where)
            elif isinstance(attr, tuple):
                for item in attr:
                    if isinstance(item, pglast.ast.Node):
                        _walk_node(item, allowlist, table_aliases, in_where=in_where)


def _validate_select_targets(stmt, allowlist: Allowlist, table_aliases: dict[str, str]):
    """Validate that SELECT targets don't reference hidden columns.

    Used for subqueries where we reject rather than rewrite.
    """
    if stmt.targetList is None:
        return

    for target in stmt.targetList:
        if not isinstance(target, pglast.ast.ResTarget):
            continue
        val = target.val

        # Check direct column references
        if isinstance(val, pglast.ast.ColumnRef):
            table, column = _resolve_column_ref(val, table_aliases)
            if table and column and not table.startswith("__"):
                if allowlist.has_table(table) and not allowlist.is_column_visible(table, column):
                    raise RestrictedColumnError("Hidden column in subquery SELECT is not allowed")

        # Check expressions containing hidden column refs
        expr_columns = _extract_column_refs(val, table_aliases)
        for tbl, col in expr_columns:
            if tbl and not tbl.startswith("__") and allowlist.has_table(tbl):
                if not allowlist.is_column_visible(tbl, col):
                    raise RestrictedColumnError(
                        "Hidden column in subquery expression is not allowed"
                    )


def _validate_range_function(range_func, allowlist: Allowlist):
    """Validate function calls in FROM clause (e.g., dblink)."""
    if range_func.functions:
        for func_tuple in range_func.functions:
            if isinstance(func_tuple, tuple):
                for func_item in func_tuple:
                    if isinstance(func_item, pglast.ast.FuncCall):
                        _validate_function(func_item, allowlist)


def _validate_function(func_call, allowlist: Allowlist):
    """Validate that a function call is on the allowed list."""
    if not func_call.funcname:
        return

    func_parts = []
    for part in func_call.funcname:
        if isinstance(part, pglast.ast.String):
            func_parts.append(part.sval)

    if not func_parts:
        return

    func_name = func_parts[-1].upper()

    # Check always-blocked list first
    if func_name in ALWAYS_BLOCKED_FUNCTIONS:
        raise DisallowedFunctionError(f"Function {func_name} is not allowed")

    # Check schema-qualified functions (block pg_catalog.* etc.)
    if len(func_parts) > 1:
        schema = func_parts[0].lower()
        if schema in BLOCKED_SCHEMAS:
            raise SystemCatalogError(f"Function in schema {schema} is not allowed")

    # Check against allowlist
    if not allowlist.is_function_allowed(func_name):
        raise DisallowedFunctionError(f"Function {func_name} is not on the allowed list")

    # Check for star in function args (e.g., json_agg(t.*))
    # COUNT(*) is safe — it just counts rows, no data exposure
    if func_call.agg_star and func_name != "COUNT":
        raise DisallowedFunctionError(
            f"Star (*) in function arguments is not allowed: {func_name}(*)"
        )


def _validate_where_column(col_ref, allowlist: Allowlist, table_aliases: dict[str, str]):
    """Validate that a column reference in WHERE/JOIN is allowlisted."""
    table, column = _resolve_column_ref(col_ref, table_aliases)
    if table and column:
        # Skip virtual tables
        if table.startswith("__subquery_") or table.startswith("__func_"):
            return
        if not allowlist.is_column_visible(table, column):
            raise RestrictedColumnError(
                f"Column {table}.{column} cannot be used in WHERE/JOIN conditions"
            )


def _validate_join_condition(join_expr, allowlist: Allowlist, table_aliases: dict[str, str]):
    """Validate ON condition of a JOIN."""
    if join_expr.quals:
        _walk_node(join_expr.quals, allowlist, table_aliases, in_where=True)

    # Recurse into nested joins
    if isinstance(join_expr.larg, pglast.ast.JoinExpr):
        _validate_join_condition(join_expr.larg, allowlist, table_aliases)
    if isinstance(join_expr.rarg, pglast.ast.JoinExpr):
        _validate_join_condition(join_expr.rarg, allowlist, table_aliases)


def _resolve_column_ref(col_ref, table_aliases: dict[str, str]) -> tuple[str | None, str | None]:
    """Resolve a ColumnRef to (table_name, column_name).

    Returns (None, None) for unresolvable references (e.g., standalone *).
    """
    if not col_ref.fields:
        return None, None

    fields = []
    for f in col_ref.fields:
        if isinstance(f, pglast.ast.String):
            fields.append(f.sval)
        elif isinstance(f, pglast.ast.A_Star):
            fields.append("*")

    if len(fields) == 1:
        # Unqualified column — try to resolve from single table
        col = fields[0]
        if col == "*":
            return None, None
        if len(table_aliases) == 1:
            table = list(table_aliases.values())[0]
            return table, col
        # Ambiguous — can't resolve without table qualifier
        # Be conservative: check all tables
        for real_table in table_aliases.values():
            if real_table.startswith("__"):
                continue
            if not allowlist_check_column_exists(real_table, col):
                continue
            return real_table, col
        return None, col

    if len(fields) == 2:
        alias, col = fields
        if col == "*":
            return table_aliases.get(alias, alias), None
        real_table = table_aliases.get(alias, alias)
        return real_table, col

    return None, None


def allowlist_check_column_exists(table: str, column: str) -> bool:
    """Placeholder — used only for ambiguous resolution.

    In practice, we rely on the allowlist passed to sanitize_query.
    """
    return True


# ======================================================================
# SELECT target rewriting
# ======================================================================


def _rewrite_select_targets(
    stmt,
    allowlist: Allowlist,
    table_aliases: dict[str, str],
    columns_accessed: list[str],
    columns_redacted: list[str],
) -> bool:
    """Rewrite SELECT target list to replace non-allowlisted columns.

    Returns True if any rewriting occurred.
    """
    if stmt.targetList is None:
        return False

    was_rewritten = False
    new_targets = []

    for target in stmt.targetList:
        if not isinstance(target, pglast.ast.ResTarget):
            new_targets.append(target)
            continue

        val = target.val

        # Handle SELECT * (bare star)
        if isinstance(val, pglast.ast.ColumnRef) and _is_star(val):
            # Expand to explicit columns
            star_targets = _expand_star(
                val, allowlist, table_aliases, columns_accessed, columns_redacted
            )
            new_targets.extend(star_targets)
            was_rewritten = True
            continue

        # Handle regular column reference
        if isinstance(val, pglast.ast.ColumnRef):
            table, column = _resolve_column_ref(val, table_aliases)
            if table and column:
                if table.startswith("__"):
                    # Virtual table — pass through
                    columns_accessed.append(f"{table}.{column}")
                    new_targets.append(target)
                elif allowlist.is_column_visible(table, column):
                    columns_accessed.append(f"{table}.{column}")
                    new_targets.append(target)
                else:
                    # Replace with placeholder
                    columns_redacted.append(f"{table}.{column}")
                    placeholder = allowlist.get_placeholder(table, column)
                    new_targets.append(_make_placeholder_target(placeholder, target.name or column))
                    was_rewritten = True
            else:
                # Can't resolve — pass through (conservative)
                new_targets.append(target)
            continue

        # Handle expressions (functions, operators, CASE, etc.)
        # Check if any source column in the expression is non-allowlisted
        expr_columns = _extract_column_refs(val, table_aliases)
        has_hidden = False
        for tbl, col in expr_columns:
            if tbl and not tbl.startswith("__") and not allowlist.is_column_visible(tbl, col):
                has_hidden = True
                columns_redacted.append(f"{tbl}.{col}")
            else:
                columns_accessed.append(f"{tbl}.{col}" if tbl else col)

        if has_hidden:
            # Replace entire expression with placeholder
            alias = target.name or "redacted"
            new_targets.append(_make_placeholder_target("'[REDACTED]'", alias))
            was_rewritten = True
        else:
            new_targets.append(target)

    stmt.targetList = tuple(new_targets)
    return was_rewritten


def _is_star(col_ref) -> bool:
    """Check if a ColumnRef is * or alias.*"""
    if not col_ref.fields:
        return False
    last = col_ref.fields[-1]
    return isinstance(last, pglast.ast.A_Star)


def _expand_star(
    col_ref,
    allowlist: Allowlist,
    table_aliases: dict[str, str],
    columns_accessed: list[str],
    columns_redacted: list[str],
) -> list:
    """Expand a SELECT * or alias.* into explicit column targets."""
    # Determine which table(s) the star refers to
    if len(col_ref.fields) == 1:
        # Bare * — expand all tables
        tables_to_expand = list(table_aliases.items())
    else:
        # alias.* — expand just that table
        alias = col_ref.fields[0].sval if isinstance(col_ref.fields[0], pglast.ast.String) else None
        if alias and alias in table_aliases:
            tables_to_expand = [(alias, table_aliases[alias])]
        else:
            tables_to_expand = []

    targets = []
    for alias, real_table in tables_to_expand:
        if real_table.startswith("__"):
            continue

        visible_cols = allowlist.get_visible_columns(real_table)
        # We need to know ALL columns to do proper expansion.
        # For visible ones, emit the real column; for hidden ones, emit placeholder.
        # Since we don't have the full column list from the allowlist alone,
        # we emit only visible columns from the allowlist.
        # Hidden columns get a single redacted placeholder to signal their existence.
        for col_name in sorted(visible_cols):
            columns_accessed.append(f"{real_table}.{col_name}")
            targets.append(_make_column_target(alias, col_name))

        # Add a marker for redacted columns
        targets.append(_make_placeholder_target("'[REDACTED]'", f"_{alias}_redacted_columns"))

    return targets


def _extract_column_refs(node, table_aliases: dict[str, str]) -> list[tuple[str | None, str]]:
    """Extract all column references from an expression node."""
    refs = []
    _collect_column_refs(node, table_aliases, refs)
    return refs


def _collect_column_refs(node, table_aliases: dict[str, str], refs: list):
    """Recursively collect column references."""
    if node is None:
        return

    if isinstance(node, pglast.ast.ColumnRef):
        table, column = _resolve_column_ref(node, table_aliases)
        if column and column != "*":
            refs.append((table, column))
        return

    if isinstance(node, pglast.ast.Node):
        for attr_name in node.__slots__:  # type: ignore[attr-defined]
            attr = getattr(node, attr_name, None)
            if attr is None:
                continue
            if isinstance(attr, pglast.ast.Node):
                _collect_column_refs(attr, table_aliases, refs)
            elif isinstance(attr, tuple):
                for item in attr:
                    if isinstance(item, pglast.ast.Node):
                        _collect_column_refs(item, table_aliases, refs)


def _make_placeholder_target(placeholder: str, alias: str):
    """Create a ResTarget with a literal placeholder value."""
    # Parse a simple SELECT <placeholder> AS <alias> and extract the target
    safe_alias = alias.replace('"', "").replace("'", "").replace(";", "")[:63]
    try:
        mini = parse_sql(f'SELECT {placeholder} AS "{safe_alias}"')
        return mini[0].stmt.targetList[0]
    except Exception:
        # Fallback: bare string placeholder
        mini = parse_sql(f"SELECT '[REDACTED]' AS \"{safe_alias}\"")
        return mini[0].stmt.targetList[0]


def _make_column_target(alias: str, column: str):
    """Create a ResTarget for alias.column."""
    safe_alias = alias.replace('"', "")[:63]
    safe_col = column.replace('"', "")[:63]
    mini = parse_sql(f'SELECT "{safe_alias}"."{safe_col}"')
    return mini[0].stmt.targetList[0]
