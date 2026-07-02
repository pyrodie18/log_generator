"""
Tests for generic normalized JSON Lines output.
"""

import json
from pathlib import Path

import pytest

from log_generator.core.scenarios import (
    build_benign_internal_web_scenario,
    build_local_account_misuse_web_scenario,
)
from log_generator.output.jsonl import (
    GENERIC_NORMALIZED_EVENTS_PATH,
    safe_output_path,
    validate_path_component,
    write_generic_normalized_events,
)


def read_jsonl_records(path: Path) -> list[dict]:
    """
    Read JSON Lines records from a file.

    Args:
        path (Path): JSON Lines file to read.

    Returns:
        list[dict]: Parsed JSON object records.
    """
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_benign_generic_jsonl_writes_three_source_neutral_records(tmp_path: Path) -> None:
    """
    Verify benign scenario output writes exactly the expected generic normalized records.

    Args:
        tmp_path (Path): Pytest temporary output directory.

    Returns:
        None: This test asserts written records and paths directly.
    """
    scenario = build_benign_internal_web_scenario()

    events_path = write_generic_normalized_events(tmp_path, (scenario,))
    records = read_jsonl_records(events_path)

    assert events_path == tmp_path.joinpath(*GENERIC_NORMALIZED_EVENTS_PATH)
    assert len(records) == 3
    assert [record["event_id"] for record in records] == [
        "evt-benign-web-001",
        "evt-benign-web-002",
        "evt-benign-web-003",
    ]
    assert records[0]["timestamp"] == "2026-01-15T14:00:00+00:00"
    assert records[2]["event_type"] == "web_request"
    assert records[2]["status_code"] == 200
    assert records[2]["path"] == "/"


def test_misuse_generic_jsonl_writes_five_records_with_download_metadata(tmp_path: Path) -> None:
    """
    Verify misuse scenario output writes five records including download metadata.

    Args:
        tmp_path (Path): Pytest temporary output directory.

    Returns:
        None: This test asserts written records directly.
    """
    scenario = build_local_account_misuse_web_scenario()

    events_path = write_generic_normalized_events(tmp_path, (scenario,))
    records = read_jsonl_records(events_path)
    download_record = records[-1]

    assert len(records) == 5
    assert [record["event_id"] for record in records] == [
        "evt-misuse-web-001",
        "evt-misuse-web-002",
        "evt-misuse-web-003",
        "evt-misuse-web-004",
        "evt-misuse-web-005",
    ]
    assert download_record["event_type"] == "web_request"
    assert download_record["parent_event_id"] == "evt-misuse-web-003"
    assert download_record["metadata"] == {
        "download_classification": "download",
        "file_name": "archive.tar.gz",
    }
    assert events_path.read_text(encoding="utf-8").endswith("\n")


def test_generic_jsonl_records_omit_generator_owned_source_fields(tmp_path: Path) -> None:
    """
    Verify generic records do not include source-specific generator-owned fields.

    Args:
        tmp_path (Path): Pytest temporary output directory.

    Returns:
        None: This test asserts source-specific fields are absent.
    """
    scenario = build_local_account_misuse_web_scenario()

    records = read_jsonl_records(write_generic_normalized_events(tmp_path, (scenario,)))
    forbidden_fields = {
        "apache_bytes_sent",
        "auditd_serial",
        "firewall_rule_name",
        "uid",
        "zeek_uid",
    }

    for record in records:
        assert forbidden_fields.isdisjoint(record)


def test_generic_jsonl_writer_sorts_multiple_scenarios_by_timestamp(tmp_path: Path) -> None:
    """
    Verify multi-scenario output is sorted by event timestamp instead of scenario argument order.

    Args:
        tmp_path (Path): Pytest temporary output directory.

    Returns:
        None: This test asserts writer-level ordering directly.
    """
    benign_scenario = build_benign_internal_web_scenario()
    misuse_scenario = build_local_account_misuse_web_scenario()

    records = read_jsonl_records(write_generic_normalized_events(tmp_path, (benign_scenario, misuse_scenario)))

    assert [record["event_id"] for record in records[:5]] == [
        "evt-misuse-web-001",
        "evt-misuse-web-002",
        "evt-misuse-web-003",
        "evt-misuse-web-004",
        "evt-misuse-web-005",
    ]
    assert [record["event_id"] for record in records[5:]] == [
        "evt-benign-web-001",
        "evt-benign-web-002",
        "evt-benign-web-003",
    ]


def test_generic_jsonl_writer_does_not_create_source_specific_outputs(tmp_path: Path) -> None:
    """
    Verify the generic writer does not create Zeek, Apache, auditd, or firewall output directories.

    Args:
        tmp_path (Path): Pytest temporary output directory.

    Returns:
        None: This test asserts the created output tree directly.
    """
    scenario = build_local_account_misuse_web_scenario()

    write_generic_normalized_events(tmp_path, (scenario,))

    assert not (tmp_path / "logs" / "zeek-sensor-01").exists()
    assert not (tmp_path / "logs" / "linux-ws-01").exists()
    assert not (tmp_path / "logs" / "web-server-01").exists()
    assert not (tmp_path / "logs" / "boundary-fw-01").exists()


def test_safe_output_path_rejects_unsafe_components(tmp_path: Path) -> None:
    """
    Verify output path component validation rejects path traversal and nested components.

    Args:
        tmp_path (Path): Pytest temporary output directory.

    Returns:
        None: This test asserts path validation failures directly.
    """
    with pytest.raises(ValueError, match="unsafe output path component"):
        validate_path_component("..")

    with pytest.raises(ValueError, match="unsafe output path component"):
        validate_path_component("source-neutral-core/events.jsonl")

    with pytest.raises(ValueError, match="must not be empty"):
        validate_path_component("")

    assert safe_output_path(tmp_path, ("logs", "events.jsonl")) == tmp_path / "logs" / "events.jsonl"
