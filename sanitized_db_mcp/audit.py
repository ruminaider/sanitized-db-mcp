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
    # Client identity fields (HIPAA audit trail)
    client_ip: str | None = None
    request_id: str | None = None
    session_id: str | None = None
    user_agent: str | None = None
    transport: str | None = None

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
                "client_ip": self.client_ip,
                "request_id": self.request_id,
                "session_id": self.session_id,
                "user_agent": self.user_agent,
                "transport": self.transport,
            },
            default=str,
        )


def extract_client_ip(request) -> str | None:
    """Extract client IP, respecting reverse proxy headers."""
    if xff := request.headers.get("x-forwarded-for"):
        return xff.split(",")[0].strip()
    if xri := request.headers.get("x-real-ip"):
        return xri.strip()
    if request.client:
        return request.client.host
    return None


def log_query(entry: AuditEntry):
    """Write a structured audit log entry."""
    logger.info(entry.to_json())
