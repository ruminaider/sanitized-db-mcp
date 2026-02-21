# Sanitized DB MCP Server

An MCP server that rewrites SQL queries before execution so PII/PHI columns never appear in results sent to LLM agents. It uses [pglast](https://github.com/lelit/pglast) (PostgreSQL's C parser) for AST-level SQL rewriting, ensuring that sensitive data is redacted at the syntax tree level rather than through fragile string matching.

## How It Works

The server exposes a single MCP tool (`query`) that accepts raw SQL and returns sanitized
results. Every query passes through an 11-step pipeline:

```
Agent sends SQL
      |
      v
1.  Parse (pglast) ----- syntax error? -> QuerySyntaxError
      |
      v
2.  Statement type ----- not SELECT? -> StatementTypeError
      |                   SELECT INTO? -> StatementTypeError
      |                   FOR UPDATE/SHARE? -> StatementTypeError
      v
3.  Table validation --- system catalog? -> SystemCatalogError
      |                   not in allowlist? -> RestrictedColumnError
      |                   TABLESAMPLE? -> unwrap, validate inner table
      v
4.  Function check ----- always-blocked? -> DisallowedFunctionError
      |                   not in allowlist? -> DisallowedFunctionError
      |                   FILTER (WHERE ...)? -> walk with WHERE rules
      |                   inline OVER clause? -> walk with WHERE rules
      v
5.  WHERE/JOIN check --- hidden column? -> RestrictedColumnError
      v
6.  Clause check ------- ORDER BY / GROUP BY / DISTINCT ON / WINDOW
      |                    hidden column? -> RestrictedColumnError
      v
7.  Subquery check ----- hidden column in subquery/CTE SELECT? -> RestrictedColumnError
      v
8.  Rewrite SELECT ----- hidden columns -> type-preserving placeholders
      |                   SELECT * -> visible columns + redaction marker
      v
9.  Serialize AST ------ rewritten SQL string
      v
10. Execute ------------ read-only, 5s timeout, SSL
      v
11. Audit log ---------- structured JSON (original, rewritten, outcome)
```

## Prerequisites

The server needs an **allowlist** -- a YAML file declaring which database columns are safe to expose.

### Allowlist YAML Format

```yaml
tables:
  accounts_profile:
    columns:
      id: { type: integer, placeholder: "0" }
      user_id: { type: integer, placeholder: "0" }
      is_active: { type: boolean, placeholder: "false" }
      created_at: { type: timestamp, placeholder: "'1900-01-01T00:00:00Z'" }
      # Columns NOT listed here are treated as hidden and will be redacted.
      # For example, email, phone_number, etc. are hidden by default.

  orders:
    columns:
      id: { type: integer, placeholder: "0" }
      user_id: { type: integer, placeholder: "0" }
      status: { type: varchar, placeholder: "'[REDACTED]'" }
      order_number: { type: varchar, placeholder: "'[REDACTED]'" }
      created_at: { type: timestamp, placeholder: "'1900-01-01T00:00:00Z'" }

allowed_functions:
  - COUNT
  - SUM
  - AVG
  - MIN
  - MAX
  - COALESCE
  - NULLIF
  - NOW
  - CURRENT_DATE
  - CURRENT_TIMESTAMP
  - DATE_TRUNC
  - EXTRACT
  - UPPER
  - LOWER
  - LENGTH
  - TRIM
  - ROUND
  - CEIL
  - FLOOR
  - ABS
  - CONCAT
  - CONCAT_WS
  - STRING_AGG
  - ARRAY_AGG
  - GENERATE_SERIES
  - CAST
```

Each table entry lists only the **visible** columns -- any column not listed is automatically hidden and will be redacted with its type-preserving placeholder. The `placeholder` value is substituted into the rewritten SQL so the result schema stays consistent (integers get `0`, strings get `'[REDACTED]'`, timestamps get a sentinel date, etc.).

Functions not in `allowed_functions` are blocked. Some functions are permanently blocked regardless of the allowlist (e.g., `row_to_json`, `json_agg`, `dblink`, `pg_sleep`).

## Quick Start

### Option A: pip install

```bash
cd sanitized-db-mcp
pip install -e ".[dev]"
```

Add to your `.mcp.json` (or the equivalent MCP configuration for your tooling):

```json
{
  "mcpServers": {
    "sanitized-db": {
      "type": "stdio",
      "command": "python3",
      "args": ["-m", "sanitized_db_mcp.server"],
      "env": {
        "ALLOWLIST_PATH": "path/to/allowlist.yaml",
        "DATABASE_URL": "postgresql://localhost:5432/myapp"
      }
    }
  }
}
```

### Option B: Docker

```bash
cd sanitized-db-mcp
docker build -t sanitized-db-mcp:local .
```

```json
{
  "mcpServers": {
    "sanitized-db": {
      "type": "stdio",
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "-e", "ALLOWLIST_PATH=/app/allowlist.yaml",
        "-e", "DATABASE_URL",
        "-v", "/path/to/allowlist.yaml:/app/allowlist.yaml:ro",
        "sanitized-db-mcp:local"
      ],
      "env": {
        "DATABASE_URL": "postgresql://localhost:5432/myapp"
      }
    }
  }
}
```

## Configuration

The server is configured via environment variables:

| Variable | Required | Description |
|---|---|---|
| `ALLOWLIST_PATH` | Yes | Path to `allowlist.yaml` |
| `DATABASE_URL` | Yes (if not using Render) | PostgreSQL connection string |
| `RENDER_POSTGRES_ID` | If using Render | Render Postgres instance ID |
| `RENDER_API_KEY` | If using Render | Render API bearer token |

The server prefers Render API credentials when both are set. For most deployments,
`DATABASE_URL` is sufficient.

## Running Tests

```bash
cd sanitized-db-mcp

# Full test suite (200 tests across 4 suites)
python -m pytest sanitized_db_mcp/tests/ -v

# Individual suites
python -m pytest sanitized_db_mcp/tests/test_sanitizer.py -v    # Core rewriting (37 tests)
python -m pytest sanitized_db_mcp/tests/test_bypass.py -v       # Bypass resistance (64 tests)
python -m pytest sanitized_db_mcp/tests/test_pentest.py -v      # Pen test (99 tests)
python -m pytest sanitized_db_mcp/tests/test_allowlist.py -v    # Allowlist loader
```

All 200 tests pass with 0 xfails. The pen test suite covers 21 attack categories:

| Category | Tests | Defense |
|---|---|---|
| ORDER BY / GROUP BY / DISTINCT ON | 13 | sortClause, groupClause, distinctClause walked with WHERE rules |
| Window function attacks | 6 | Named WINDOW and inline OVER walked with WHERE rules |
| Aggregate FILTER clause | 4 | agg_filter walked with WHERE rules |
| CTE attacks | 6 | CTE SELECT targets validated; unused CTEs with hidden columns rejected |
| LATERAL join attacks | 3 | Correlated subquery WHERE clauses validated |
| Schema/identifier tricks | 8 | Quoted identifiers, unicode escapes, pg_temp schema handled |
| Composite type / row attacks | 3 | Field selection rejected; ROW() with hidden columns redacted |
| ARRAY attacks | 3 | ARRAY subquery, ARRAY_AGG, ARRAY[] with hidden columns caught |
| JSONB operator attacks | 5 | ->, ->>, #>, @>, ? operators on hidden columns caught |
| Type cast attacks | 4 | Chained casts on hidden columns redacted; casts in WHERE rejected |
| FROM clause variants | 3 | TABLESAMPLE unwrapped, VALUES and generate_series handled |
| Locking clauses | 3 | FOR UPDATE, FOR SHARE rejected at sanitizer level |
| Subquery nesting | 5 | Triple-nested, correlated, NOT EXISTS, ANY all validated |
| Statement type / multi-statement | 5 | SELECT INTO rejected; null byte, comment, dollar quoting tested |
| Ambiguous column resolution | 3 | Unqualified columns conservatively resolved |
| Encoding edge cases | 4 | Cyrillic homoglyphs, unicode escapes, semicolons in aliases |
| Timing / side-channel | 4 | pg_sleep, amplification, cross-join, recursive CTE blocked |
| Error-based extraction | 4 | Generic error messages; no column/table names leaked |
| Connection security | 5 | SSL, timeout, read-only, autocommit, no connection strings in errors |
| Allowlist integrity | 4 | Case-insensitive lookup, unknown columns default to hidden |
| Audit logging | 4 | All outcomes covered, HIPAA fields present, finally-block guarantee |

## Key Files

| File | Purpose |
|---|---|
| `sanitized_db_mcp/server.py` | MCP server entry point, `query(sql)` tool |
| `sanitized_db_mcp/sanitizer.py` | AST-level SQL rewriting engine |
| `sanitized_db_mcp/allowlist.py` | In-memory allowlist representation |
| `sanitized_db_mcp/connection.py` | Database connection management (Render API + static URL) |
| `sanitized_db_mcp/errors.py` | Sanitized error classes (no schema leakage) |
| `sanitized_db_mcp/audit.py` | Structured query audit logging |

## Adding a Function to the Allowlist

If an agent needs a SQL function that is not on the allowlist:

1. Verify the function does not expose row-level data (functions like `row_to_json`, `json_agg`, `dblink` are permanently blocked in `ALWAYS_BLOCKED_FUNCTIONS`)
2. Add the function name to the `allowed_functions` list in your `allowlist.yaml`
3. Restart the MCP server to pick up the changes

## Adding a New Visible Column

To make a column visible to agents:

1. Add the column entry to the appropriate table in `allowlist.yaml` with its type and placeholder value
2. Restart the MCP server

Any column not listed in the allowlist is hidden by default -- the server defaults to redacting unknown columns rather than exposing them.

## Security Model

- **AST-level rewriting**: SQL is parsed into an abstract syntax tree using PostgreSQL's own C parser (via pglast), not string-matched. This prevents bypass via encoding tricks, comments, or whitespace.
- **Fail-closed**: Unknown columns are hidden. Unknown functions are blocked. Unknown tables are rejected.
- **No schema leakage**: Error messages returned to agents are generic -- they never reveal column names, table names, or type information.
- **Read-only enforcement**: Queries run in a read-only transaction with a 5-second timeout and autocommit enabled.
- **SSL by default**: Non-localhost connections require SSL.
- **Audit trail**: Every query (allowed, redacted, blocked, or errored) is logged as structured JSON with the original SQL, rewritten SQL, tables/columns accessed, and outcome.

## License

MIT
