"""
Tests for output manifest and metadata writers.
"""

import json
from datetime import datetime, timezone
from pathlib import Path

from log_generator.core.scenarios import (
    build_benign_internal_web_scenario,
    build_local_account_misuse_web_scenario,
)
from log_generator.output.manifest import write_output_manifest


def read_json(path: Path) -> dict:
    """
    Read a JSON file.

    Args:
        path (Path): JSON file to read.

    Returns:
        dict: Parsed JSON object.
    """
    return json.loads(path.read_text(encoding="utf-8"))


def read_jsonl(path: Path) -> list[dict]:
    """
    Read a JSON Lines file.

    Args:
        path (Path): JSON Lines file to read.

    Returns:
        list[dict]: Parsed JSON records.
    """
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_benign_manifest_omits_ground_truth_and_matches_written_files(tmp_path: Path) -> None:
    """
    Verify benign output writes manifest metadata and omits ground truth.

    Args:
        tmp_path (Path): Pytest temporary output directory.

    Returns:
        None: This test asserts written manifest content directly.
    """
    scenario = build_benign_internal_web_scenario()
    generated_at = datetime(2026, 1, 15, 14, 0, 3, tzinfo=timezone.utc)

    manifest_path = write_output_manifest(tmp_path, (scenario,), "run-benign-001", generated_at=generated_at)
    manifest = read_json(manifest_path)
    scenario_manifest_path = tmp_path / "metadata" / "scenario-manifest.json"
    events_path = tmp_path / "logs" / "source-neutral-core" / "generic-normalized" / "events.jsonl"

    assert manifest_path == tmp_path / "manifest.json"
    assert events_path.exists()
    assert scenario_manifest_path.exists()
    assert not (tmp_path / "metadata" / "ground-truth.jsonl").exists()
    assert manifest["schema_version"] == "output-manifest/v0.1"
    assert manifest["generated_at"] == "2026-01-15T14:00:03+00:00"
    assert manifest["run"] == {
        "run_id": "run-benign-001",
        "seed": 1001,
        "output_root": str(tmp_path),
    }
    assert manifest["files"][0]["path"] == "logs/source-neutral-core/generic-normalized/events.jsonl"
    assert manifest["files"][0]["record_count"] == 3
    assert manifest["files"][0]["scenario_ids"] == ["scenario-benign-internal-web"]
    assert manifest["files"][0]["event_types"] == ["dns_lookup", "network_connection", "web_request"]
    assert manifest["metadata_files"] == [
        {
            "path": "metadata/scenario-manifest.json",
            "format": "json",
            "record_count": 1,
        }
    ]
    assert manifest["omitted_streams"] == []
    assert len(read_jsonl(events_path)) == manifest["files"][0]["record_count"]


def test_misuse_manifest_includes_ground_truth_record(tmp_path: Path) -> None:
    """
    Verify misuse output includes the documented suspicious download ground-truth record.

    Args:
        tmp_path (Path): Pytest temporary output directory.

    Returns:
        None: This test asserts written manifest and ground-truth content directly.
    """
    scenario = build_local_account_misuse_web_scenario()
    generated_at = datetime(2026, 1, 15, 3, 12, 29, tzinfo=timezone.utc)

    manifest_path = write_output_manifest(tmp_path, (scenario,), "run-misuse-001", generated_at=generated_at)
    manifest = read_json(manifest_path)
    ground_truth_path = tmp_path / "metadata" / "ground-truth.jsonl"
    ground_truth_records = read_jsonl(ground_truth_path)

    assert manifest["files"][0]["record_count"] == 5
    assert manifest["metadata_files"] == [
        {
            "path": "metadata/scenario-manifest.json",
            "format": "json",
            "record_count": 1,
        },
        {
            "path": "metadata/ground-truth.jsonl",
            "format": "jsonl",
            "record_count": 1,
        },
    ]
    assert ground_truth_records == [
        {
            "scenario_id": "scenario-local-account-misuse-web",
            "correlation_id": "corr-local-account-misuse-001",
            "label": "suspicious_internal_web_download",
            "primary_event_id": "evt-misuse-web-005",
            "supporting_event_ids": ["evt-misuse-web-001", "evt-misuse-web-004"],
            "description": "Suspicious local account use followed by admin page access and archive download.",
        }
    ]


def test_scenario_manifest_describes_expansion_without_event_duplication(tmp_path: Path) -> None:
    """
    Verify scenario metadata includes counts, time range, correlations, and answer-key labels.

    Args:
        tmp_path (Path): Pytest temporary output directory.

    Returns:
        None: This test asserts scenario manifest content directly.
    """
    scenario = build_local_account_misuse_web_scenario()

    write_output_manifest(
        tmp_path,
        (scenario,),
        "run-misuse-001",
        generated_at=datetime(2026, 1, 15, 3, 12, 29, tzinfo=timezone.utc),
    )
    scenario_manifest = read_json(tmp_path / "metadata" / "scenario-manifest.json")
    scenario_entry = scenario_manifest["scenarios"][0]

    assert scenario_manifest["schema_version"] == "scenario-manifest/v0.1"
    assert scenario_entry["scenario_id"] == "scenario-local-account-misuse-web"
    assert scenario_entry["authored_event_count"] == 3
    assert scenario_entry["expanded_event_count"] == 5
    assert scenario_entry["requested_output_families"] == ["generic-normalized"]
    assert scenario_entry["correlation_ids"] == ["corr-local-account-misuse-001"]
    assert scenario_entry["answer_key_labels"] == ["suspicious_internal_web_download"]
    assert "events" not in scenario_entry


def test_manifest_file_entries_match_files_written(tmp_path: Path) -> None:
    """
    Verify every manifest file entry points to an existing file.

    Args:
        tmp_path (Path): Pytest temporary output directory.

    Returns:
        None: This test asserts manifest path consistency directly.
    """
    scenario = build_local_account_misuse_web_scenario()
    manifest_path = write_output_manifest(
        tmp_path,
        (scenario,),
        "run-misuse-001",
        generated_at=datetime(2026, 1, 15, 3, 12, 29, tzinfo=timezone.utc),
    )
    manifest = read_json(manifest_path)
    file_paths = [entry["path"] for entry in manifest["files"] + manifest["metadata_files"]]

    assert sorted(file_paths) == [
        "logs/source-neutral-core/generic-normalized/events.jsonl",
        "metadata/ground-truth.jsonl",
        "metadata/scenario-manifest.json",
    ]

    for relative_path in file_paths:
        assert (tmp_path / relative_path).exists()
