"""
Sanitized error responses for the MCP server.

All errors returned to agents are generic — they never include actual
column names, table names, constraint names, or type information that
could leak schema details about hidden columns.

Full unsanitized errors are logged server-side for debugging.
"""

import logging


logger = logging.getLogger(__name__)


class SanitizationError(Exception):
    """Base class for sanitization errors."""

    # The message shown to the agent (sanitized)
    agent_message: str = "Query could not be processed"

    def __init__(self, internal_message: str = "", agent_message: str | None = None):
        self._internal_message = internal_message
        if agent_message:
            self.agent_message = agent_message
        super().__init__(internal_message)

    def log(self):
        """Log the full internal error for debugging."""
        logger.warning("SanitizationError: %s", self._internal_message)


class QuerySyntaxError(SanitizationError):
    agent_message = "Query syntax error — check your SQL syntax"


class RestrictedColumnError(SanitizationError):
    agent_message = "Query references restricted columns or tables"


class DisallowedFunctionError(SanitizationError):
    agent_message = "Query uses a disallowed function or statement type"


class StatementTypeError(SanitizationError):
    agent_message = "Only SELECT statements are allowed"


class SystemCatalogError(SanitizationError):
    agent_message = "Access to system catalogs is not permitted"


class QueryExecutionError(SanitizationError):
    agent_message = "Query execution failed — database error"


class QueryTimeoutError(SanitizationError):
    agent_message = "Query timed out"


class ConfigurationError(SanitizationError):
    agent_message = "Server configuration error — contact an administrator"


def sanitize_pg_error(error: Exception) -> str:
    """Return a generic error message for a Postgres exception.

    Never leaks column names, constraint names, or detailed type info.
    """
    error_str = str(error).lower()

    if "timeout" in error_str or "cancel" in error_str:
        return QueryTimeoutError.agent_message

    if "permission denied" in error_str:
        return RestrictedColumnError.agent_message

    if "syntax error" in error_str:
        return QuerySyntaxError.agent_message

    # Default: generic execution error
    return QueryExecutionError.agent_message
