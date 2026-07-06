"""
Tests for output manifest and metadata writers.
"""

import json
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

import pytest

from log_generator.core.scenarios import (
    build_benign_internal_web_scenario,
    build_local_account_misuse_web_scenario,
)
from log_generator.output.manifest import write_output_manifest
from log_generator.output import registry
from log_generator.output.registry import GENERIC_NORMALIZED_OUTPUT_FAMILY, OutputWriteResult, OutputWriter


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


def count_zeek_data_rows(path: Path) -> int:
    """
    Count non-header rows in a Zeek TSV file.

    Args:
        path (Path): Zeek TSV file to inspect.

    Returns:
        int: Number of rendered Zeek records, excluding header and close lines.
    """
    return sum(1 for line in path.read_text(encoding="utf-8").splitlines() if not line.startswith("#"))


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
    assert not (tmp_path / "logs" / "zeek-sensor-01").exists()
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


def test_successful_manifest_write_replaces_existing_output_directory(tmp_path: Path) -> None:
    """
    Verify successful generation replaces stale output directory contents.

    Args:
        tmp_path (Path): Pytest temporary output directory.

    Returns:
        None: This test asserts replacement behavior directly.
    """
    output_root = tmp_path / "output"
    stale_path = output_root / "stale.txt"
    output_root.mkdir()
    stale_path.write_text("old output", encoding="utf-8")

    manifest_path = write_output_manifest(
        output_root,
        (build_benign_internal_web_scenario(),),
        "run-replace-existing",
        generated_at=datetime(2026, 1, 15, 14, 0, 3, tzinfo=timezone.utc),
    )

    assert manifest_path == output_root / "manifest.json"
    assert manifest_path.exists()
    assert not stale_path.exists()
    assert read_json(manifest_path)["run"]["output_root"] == str(output_root)


def test_failed_manifest_write_leaves_existing_output_unchanged(tmp_path: Path, monkeypatch) -> None:
    """
    Verify writer failures do not replace an existing completed output tree.

    Args:
        tmp_path (Path): Pytest temporary output directory.
        monkeypatch (MonkeyPatch): Pytest monkeypatch fixture.

    Returns:
        None: This test asserts failed staged writes are cleaned up.
    """
    output_root = tmp_path / "output"
    manifest_path = output_root / "manifest.json"
    marker_path = output_root / "keep.txt"
    output_root.mkdir()
    manifest_path.write_text('{"old": true}\n', encoding="utf-8")
    marker_path.write_text("keep me", encoding="utf-8")

    def failing_write(output_root: Path, scenarios, generated_at: datetime) -> OutputWriteResult:
        """
        Write a staged partial file and then fail.

        Args:
            output_root (Path): Staging output directory.
            scenarios: Scenarios passed to the writer.
            generated_at (datetime): Generation timestamp.

        Returns:
            OutputWriteResult: This function always raises before returning.
        """
        partial_path = output_root / "partial.txt"
        partial_path.write_text("partial output", encoding="utf-8")
        raise RuntimeError("writer failed")

    monkeypatch.setitem(
        registry.OUTPUT_WRITERS,
        GENERIC_NORMALIZED_OUTPUT_FAMILY,
        OutputWriter(
            family_name=GENERIC_NORMALIZED_OUTPUT_FAMILY,
            validate=lambda scenarios: None,
            write=failing_write,
        ),
    )

    with pytest.raises(RuntimeError, match="writer failed"):
        write_output_manifest(
            output_root,
            (build_benign_internal_web_scenario(),),
            "run-failing-writer",
            generated_at=datetime(2026, 1, 15, 14, 0, 3, tzinfo=timezone.utc),
        )

    assert manifest_path.read_text(encoding="utf-8") == '{"old": true}\n'
    assert marker_path.read_text(encoding="utf-8") == "keep me"
    assert not (output_root / "partial.txt").exists()
    assert not list(tmp_path.glob(".output.tmp-*"))


def test_manifest_write_rejects_output_root_file(tmp_path: Path) -> None:
    """
    Verify an existing file at the output root fails before writing artifacts.

    Args:
        tmp_path (Path): Pytest temporary output directory.

    Returns:
        None: This test asserts invalid output root handling directly.
    """
    output_root = tmp_path / "output"
    output_root.write_text("not a directory", encoding="utf-8")

    with pytest.raises(ValueError, match="exists and is not a directory"):
        write_output_manifest(
            output_root,
            (build_benign_internal_web_scenario(),),
            "run-output-file",
            generated_at=datetime(2026, 1, 15, 14, 0, 3, tzinfo=timezone.utc),
        )

    assert output_root.read_text(encoding="utf-8") == "not a directory"
    assert not list(tmp_path.glob(".output.tmp-*"))


def test_manifest_includes_zeek_files_when_requested(tmp_path: Path) -> None:
    """
    Verify mixed generic and Zeek output writes all requested file entries.

    Args:
        tmp_path (Path): Pytest temporary output directory.

    Returns:
        None: This test asserts manifest file entries for Zeek output.
    """
    scenario = replace(
        build_benign_internal_web_scenario(),
        output_families=("generic-normalized", "zeek"),
    )
    manifest_path = write_output_manifest(
        tmp_path,
        (scenario,),
        "run-benign-zeek-001",
        generated_at=datetime(2026, 1, 15, 14, 0, 3, tzinfo=timezone.utc),
    )
    manifest = read_json(manifest_path)
    files_by_path = {entry["path"]: entry for entry in manifest["files"]}

    assert sorted(files_by_path) == [
        "logs/source-neutral-core/generic-normalized/events.jsonl",
        "logs/zeek-sensor-01/zeek/conn.log",
        "logs/zeek-sensor-01/zeek/dns.log",
        "logs/zeek-sensor-01/zeek/http.log",
    ]
    assert manifest["requested_output_families"] == ["generic-normalized", "zeek"]
    assert files_by_path["logs/zeek-sensor-01/zeek/conn.log"]["record_count"] == 2
    assert files_by_path["logs/zeek-sensor-01/zeek/conn.log"]["source_id"] == "zeek-sensor-01"
    assert files_by_path["logs/zeek-sensor-01/zeek/conn.log"]["source_kind"] == "sensor"
    assert files_by_path["logs/zeek-sensor-01/zeek/conn.log"]["log_family"] == "zeek"
    assert files_by_path["logs/zeek-sensor-01/zeek/conn.log"]["format"] == "zeek-tsv"
    assert files_by_path["logs/zeek-sensor-01/zeek/conn.log"]["timestamp_fields"] == ["ts"]
    assert files_by_path["logs/zeek-sensor-01/zeek/conn.log"]["scenario_ids"] == [
        "scenario-benign-internal-web"
    ]
    assert files_by_path["logs/zeek-sensor-01/zeek/dns.log"]["event_types"] == ["dns_lookup"]
    assert files_by_path["logs/zeek-sensor-01/zeek/http.log"]["event_types"] == ["web_request"]

    for file_path, file_entry in files_by_path.items():
        if file_entry["format"] == "zeek-tsv":
            assert file_entry["record_count"] == count_zeek_data_rows(tmp_path / file_path)

    assert manifest["omitted_streams"] == []


def test_zeek_only_manifest_skips_generic_output(tmp_path: Path) -> None:
    """
    Verify Zeek-only output writes no generic normalized events file.

    Args:
        tmp_path (Path): Pytest temporary output directory.

    Returns:
        None: This test asserts Zeek-only manifest behavior.
    """
    scenario = replace(build_benign_internal_web_scenario(), output_families=("zeek",))
    manifest_path = write_output_manifest(
        tmp_path,
        (scenario,),
        "run-benign-zeek-only-001",
        generated_at=datetime(2026, 1, 15, 14, 0, 3, tzinfo=timezone.utc),
    )
    manifest = read_json(manifest_path)

    assert [entry["path"] for entry in manifest["files"]] == [
        "logs/zeek-sensor-01/zeek/conn.log",
        "logs/zeek-sensor-01/zeek/dns.log",
        "logs/zeek-sensor-01/zeek/http.log",
    ]
    assert manifest["requested_output_families"] == ["zeek"]
    assert not (tmp_path / "logs" / "source-neutral-core" / "generic-normalized" / "events.jsonl").exists()


def test_manifest_rejects_unsupported_output_family_before_writing_files(tmp_path: Path) -> None:
    """
    Verify Python callers cannot produce partial output for unsupported families.

    Args:
        tmp_path (Path): Pytest temporary output directory.

    Returns:
        None: This test asserts generation fails before file creation.
    """
    scenario = replace(
        build_benign_internal_web_scenario(),
        output_families=("generic-normalized", "apache"),
    )

    with pytest.raises(ValueError, match="unsupported output family 'apache'"):
        write_output_manifest(
            tmp_path,
            (scenario,),
            "run-unsupported-family-001",
            generated_at=datetime(2026, 1, 15, 14, 0, 3, tzinfo=timezone.utc),
        )

    assert not (tmp_path / "manifest.json").exists()
    assert not (tmp_path / "logs").exists()
    assert not (tmp_path / "metadata").exists()


def test_manifest_rejects_unsupported_zeek_environment_before_writing_files(tmp_path: Path) -> None:
    """
    Verify Zeek writer capability checks run before generic output is written.

    Args:
        tmp_path (Path): Pytest temporary output directory.

    Returns:
        None: This test asserts generation fails before file creation.
    """
    scenario = replace(
        build_benign_internal_web_scenario(),
        environment_version="9.9",
        output_families=("generic-normalized", "zeek"),
    )

    with pytest.raises(ValueError, match="Zeek output currently supports linux-mini-lab version 0.1"):
        write_output_manifest(
            tmp_path,
            (scenario,),
            "run-unsupported-zeek-environment-001",
            generated_at=datetime(2026, 1, 15, 14, 0, 3, tzinfo=timezone.utc),
        )

    assert not (tmp_path / "manifest.json").exists()
    assert not (tmp_path / "logs").exists()
    assert not (tmp_path / "metadata").exists()


def test_manifest_includes_structured_zeek_omitted_streams(tmp_path: Path) -> None:
    """
    Verify requested Zeek streams with no records are described in the manifest.

    Args:
        tmp_path (Path): Pytest temporary output directory.

    Returns:
        None: This test asserts omitted-stream manifest entries directly.
    """
    misuse_scenario = build_local_account_misuse_web_scenario()
    scenario = replace(misuse_scenario, events=misuse_scenario.events[:1], output_families=("zeek",))
    manifest_path = write_output_manifest(
        tmp_path,
        (scenario,),
        "run-zeek-empty-001",
        generated_at=datetime(2026, 1, 15, 3, 12, 29, tzinfo=timezone.utc),
    )
    manifest = read_json(manifest_path)

    assert manifest["files"] == []
    assert manifest["requested_output_families"] == ["zeek"]
    assert manifest["omitted_streams"] == [
        {
            "source_id": "zeek-sensor-01",
            "source_kind": "sensor",
            "log_family": "zeek",
            "log_stream": "conn.log",
            "reason": "zero_records",
            "requested": True,
            "configured": True,
        },
        {
            "source_id": "zeek-sensor-01",
            "source_kind": "sensor",
            "log_family": "zeek",
            "log_stream": "dns.log",
            "reason": "zero_records",
            "requested": True,
            "configured": True,
        },
        {
            "source_id": "zeek-sensor-01",
            "source_kind": "sensor",
            "log_family": "zeek",
            "log_stream": "http.log",
            "reason": "zero_records",
            "requested": True,
            "configured": True,
        },
    ]
    assert not (tmp_path / "logs" / "zeek-sensor-01").exists()
