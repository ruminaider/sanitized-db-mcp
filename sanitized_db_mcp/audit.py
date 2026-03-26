"""
Query audit logging for the sanitizing MCP server.

Logs every query with structured JSON for HIPAA compliance.
Future: send to centralized logging (CloudWatch, Datadog) for
6-year retention.
"""

from dataclasses import asdict, dataclass, field
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
    # Required for HIPAA audit trail
    client_ip: str | None = None
    request_id: str | None = None
    session_id: str | None = None
    user_agent: str | None = None
    transport: str | None = None

    def to_json(self) -> str:
        return json.dumps(asdict(self), default=str)


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
