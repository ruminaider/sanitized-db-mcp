"""
Query audit logging for the sanitizing MCP server.

Logs every query with structured JSON for HIPAA compliance.
Future: send to centralized logging (CloudWatch, Datadog) for
6-year retention.
"""

from dataclasses import dataclass, field
import json
import logging
import time


logger = logging.getLogger("sanitized_db_audit")


@dataclass
class AuditEntry:
    """A single audited query."""

    timestamp: float = field(default_factory=time.time)
    original_sql: str = ""
    rewritten_sql: str | None = None
    outcome: str = "pending"  # "allowed", "redacted", "blocked", "error"
    rejection_reason: str | None = None
    tables_accessed: list[str] = field(default_factory=list)
    columns_accessed: list[str] = field(default_factory=list)
    columns_redacted: list[str] = field(default_factory=list)
    row_count: int | None = None
    execution_time_ms: float | None = None

    def to_json(self) -> str:
        return json.dumps(
            {
                "timestamp": self.timestamp,
                "original_sql": self.original_sql,
                "rewritten_sql": self.rewritten_sql,
                "outcome": self.outcome,
                "rejection_reason": self.rejection_reason,
                "tables_accessed": self.tables_accessed,
                "columns_accessed": self.columns_accessed,
                "columns_redacted": self.columns_redacted,
                "row_count": self.row_count,
                "execution_time_ms": self.execution_time_ms,
            },
            default=str,
        )


def log_query(entry: AuditEntry):
    """Write a structured audit log entry."""
    logger.info(entry.to_json())
