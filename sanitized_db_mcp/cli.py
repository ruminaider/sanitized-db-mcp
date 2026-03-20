"""
CLI entry-point for the sanitized-db-mcp toolset.

Provides the ``generate-allowlist`` subcommand which introspects a
PostgreSQL database and produces an ``allowlist.yaml`` scaffold with
**no columns visible by default**.

Usage::

    sanitized-db-mcp generate-allowlist --database-url postgresql://... -o allowlist.yaml
    sanitized-db-mcp generate-allowlist --deny-pii  # reads DATABASE_URL from env
"""

from __future__ import annotations

import argparse
import os
import sys


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sanitized-db-mcp",
        description="Tools for the sanitized-db-mcp PII/PHI-safe query server.",
    )
    subparsers = parser.add_subparsers(dest="command")

    gen = subparsers.add_parser(
        "generate-allowlist",
        help="Introspect a PostgreSQL database and generate an allowlist.yaml scaffold.",
    )
    gen.add_argument(
        "--database-url",
        default=None,
        help=(
            "PostgreSQL connection string (e.g. postgresql://user:pass@host/db). "
            "Falls back to the DATABASE_URL environment variable."
        ),
    )
    gen.add_argument(
        "--deny-pii",
        action="store_true",
        default=False,
        help="Annotate likely PII/PHI columns with '# PII' comments.",
    )
    gen.add_argument(
        "--schema",
        nargs="+",
        default=["public"],
        help="Target schema(s) to introspect (default: public).",
    )
    gen.add_argument(
        "-o", "--output",
        default=None,
        help="Output file path. Defaults to stdout.",
    )
    gen.add_argument(
        "--include-functions",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Include the default safe-function list (default: True).",
    )

    return parser


def _cmd_generate_allowlist(args: argparse.Namespace) -> int:
    """Handle the ``generate-allowlist`` subcommand."""
    # Resolve database URL
    database_url = args.database_url or os.environ.get("DATABASE_URL")
    if not database_url:
        print(
            "Error: No database URL provided. "
            "Use --database-url or set the DATABASE_URL environment variable.",
            file=sys.stderr,
        )
        return 1

    # Ensure psycopg is available before attempting introspection
    try:
        import psycopg  # noqa: F401
    except ImportError:
        print(
            "Error: psycopg is required for database introspection. "
            "Install it with: pip install 'psycopg[binary]>=3.1'",
            file=sys.stderr,
        )
        return 1

    from .allowlist_generator import generate_allowlist_yaml, introspect_schema

    try:
        schema_info = introspect_schema(database_url, schemas=args.schema)
    except Exception as exc:
        print(f"Error connecting to database: {exc}", file=sys.stderr)
        return 1

    yaml_content = generate_allowlist_yaml(
        schema_info,
        deny_pii=args.deny_pii,
        include_functions=args.include_functions,
    )

    if args.output:
        with open(args.output, "w") as fh:
            fh.write(yaml_content)
        print(
            f"Allowlist written to {args.output} "
            f"({len(schema_info)} tables discovered)",
            file=sys.stderr,
        )
    else:
        sys.stdout.write(yaml_content)

    return 0


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(0)

    if args.command == "generate-allowlist":
        sys.exit(_cmd_generate_allowlist(args))
    else:
        parser.print_help()
        sys.exit(1)
