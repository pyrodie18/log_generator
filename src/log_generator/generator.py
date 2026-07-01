"""
Helpers for creating simple structured log messages.
"""

from datetime import datetime, timezone
from typing import Any, Optional


def generate_log_entry(level: str, message: str, timestamp: Optional[datetime] = None, **fields: Any) -> str:
    """
    Generate a structured single-line log entry.

    Args:
        level (str): Severity level to include in the generated log entry.
        message (str): Human-readable message to include in the generated log entry.
        timestamp (Optional[datetime]): Timestamp to use for the log entry. Uses the current UTC time when omitted.
        fields (Any): Additional key-value fields to append to the log entry.

    Returns:
        str: Formatted log entry containing a timestamp, level, message, and optional extra fields.
    """
    log_timestamp = timestamp or datetime.now(timezone.utc)
    normalized_level = level.strip().upper()
    normalized_message = message.strip()

    # ISO 8601 keeps generated logs easy to sort lexicographically and parse in downstream tools.
    parts = [
        f"timestamp={log_timestamp.isoformat()}",
        f"level={normalized_level}",
        f"message={normalized_message}",
    ]

    for key, value in fields.items():
        # Preserve caller-provided field order so generated lines are predictable in tests and snapshots.
        parts.append(f"{key}={value}")

    return " ".join(parts)
