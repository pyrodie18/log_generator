"""
Tests for log_generator.generator.
"""

from datetime import datetime, timezone

from log_generator import generate_log_entry


def test_generate_log_entry_includes_required_fields() -> None:
    """
    Verify the generated log entry includes the timestamp, level, and message.

    Returns:
        None: This test asserts the generated output directly.
    """
    timestamp = datetime(2026, 6, 27, 4, 30, tzinfo=timezone.utc)

    log_entry = generate_log_entry("info", " service started ", timestamp=timestamp)

    assert log_entry == "timestamp=2026-06-27T04:30:00+00:00 level=INFO message=service started"


def test_generate_log_entry_appends_extra_fields_in_order() -> None:
    """
    Verify extra fields are appended after the standard log fields in caller-provided order.

    Returns:
        None: This test asserts the generated output directly.
    """
    timestamp = datetime(2026, 6, 27, 4, 30, tzinfo=timezone.utc)

    log_entry = generate_log_entry("warning", "retrying request", timestamp=timestamp, attempts=2, service="api")

    assert log_entry == (
        "timestamp=2026-06-27T04:30:00+00:00 level=WARNING message=retrying request attempts=2 service=api"
    )
