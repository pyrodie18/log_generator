"""
Output manifest model and writer helpers.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from log_generator.core.scenarios import Scenario
from log_generator.output.jsonl import safe_output_path
from log_generator.output.registry import (
    OutputOmittedStream,
    OutputWriteResult,
    OutputWrittenFile,
    plan_output_writer_runs,
    supported_output_families,
    validate_output_writer_runs,
)


MANIFEST_PATH = ("manifest.json",)
SCENARIO_MANIFEST_PATH = ("metadata", "scenario-manifest.json")
GROUND_TRUTH_PATH = ("metadata", "ground-truth.jsonl")
SUPPORTED_OUTPUT_FAMILIES = supported_output_families()


def write_output_manifest(
    output_root: Path,
    scenarios: tuple[Scenario, ...],
    run_id: str,
    generated_at: Optional[datetime] = None,
) -> Path:
    """
    Write the requested output set and top-level manifest.

    Args:
        output_root (Path): Root output directory where generated artifacts should be written.
        scenarios (tuple[Scenario, ...]): Scenarios included in the output set.
        run_id (str): Stable run identifier to include in the manifest.
        generated_at (Optional[datetime]): UTC generation time. Current UTC time is used when omitted.

    Returns:
        Path: Path to the written top-level manifest file.
    """
    generated_at = _normalize_generated_at(generated_at)
    writer_runs = plan_output_writer_runs(scenarios)
    validate_output_writer_runs(writer_runs)
    output_files = []
    omitted_streams = []

    for writer_run in writer_runs:
        result = writer_run.writer.write(output_root, writer_run.scenarios, generated_at)
        output_files.extend(result.files)
        omitted_streams.extend(result.omitted_streams)

    scenario_manifest_path = write_scenario_manifest(output_root, scenarios)
    ground_truth_path = write_ground_truth(output_root, scenarios)
    manifest_path = safe_output_path(output_root, MANIFEST_PATH)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)

    manifest = build_manifest(
        output_root=output_root,
        scenarios=scenarios,
        run_id=run_id,
        generated_at=generated_at,
        output_result=OutputWriteResult(files=tuple(output_files), omitted_streams=tuple(omitted_streams)),
        scenario_manifest_path=scenario_manifest_path,
        ground_truth_path=ground_truth_path,
    )
    _write_json_file(manifest_path, manifest)

    return manifest_path


def _validate_requested_output_families(scenarios: tuple[Scenario, ...]) -> None:
    """
    Validate requested output families before any output files are written.

    Args:
        scenarios (tuple[Scenario, ...]): Scenarios included in the output set.

    Returns:
        None: Raises ValueError when a requested writer is unsupported.
    """
    validate_output_writer_runs(plan_output_writer_runs(scenarios))


def write_scenario_manifest(output_root: Path, scenarios: tuple[Scenario, ...]) -> Path:
    """
    Write scenario-level metadata.

    Args:
        output_root (Path): Root output directory where generated artifacts should be written.
        scenarios (tuple[Scenario, ...]): Scenarios to describe.

    Returns:
        Path: Path to the written scenario manifest.
    """
    scenario_manifest_path = safe_output_path(output_root, SCENARIO_MANIFEST_PATH)
    scenario_manifest_path.parent.mkdir(parents=True, exist_ok=True)
    _write_json_file(
        scenario_manifest_path,
        {
            "schema_version": "scenario-manifest/v0.1",
            "scenarios": [_scenario_manifest_entry(scenario) for scenario in scenarios],
        },
    )

    return scenario_manifest_path


def write_ground_truth(output_root: Path, scenarios: tuple[Scenario, ...]) -> Optional[Path]:
    """
    Write ground-truth JSON Lines metadata when answer-key records exist.

    Args:
        output_root (Path): Root output directory where generated artifacts should be written.
        scenarios (tuple[Scenario, ...]): Scenarios whose answer-key records should be written.

    Returns:
        Optional[Path]: Path to the written ground-truth file, or None when no records exist.
    """
    answer_key_records = []

    for scenario in scenarios:
        # Flatten records across scenarios so the file remains a simple JSON Lines stream.
        answer_key_records.extend(record.to_dict() for record in scenario.answer_key)

    if not answer_key_records:
        return None

    ground_truth_path = safe_output_path(output_root, GROUND_TRUTH_PATH)
    ground_truth_path.parent.mkdir(parents=True, exist_ok=True)

    with ground_truth_path.open("w", encoding="utf-8") as output_file:
        for record in answer_key_records:
            output_file.write(json.dumps(record, sort_keys=True, separators=(",", ":")))
            output_file.write("\n")

    return ground_truth_path


def build_manifest(
    output_root: Path,
    scenarios: tuple[Scenario, ...],
    run_id: str,
    generated_at: datetime,
    output_result: OutputWriteResult,
    scenario_manifest_path: Path,
    ground_truth_path: Optional[Path],
) -> dict[str, object]:
    """
    Build the top-level output manifest payload.

    Args:
        output_root (Path): Root output directory.
        scenarios (tuple[Scenario, ...]): Scenarios included in the output set.
        run_id (str): Stable run identifier.
        generated_at (datetime): UTC generation timestamp.
        output_result (OutputWriteResult): Written log files and omitted streams returned by registered writers.
        scenario_manifest_path (Path): Written scenario manifest file.
        ground_truth_path (Optional[Path]): Written ground-truth file when present.

    Returns:
        dict[str, object]: JSON-compatible manifest payload.
    """
    metadata_files = [
        {
            "path": _relative_output_path(output_root, scenario_manifest_path),
            "format": "json",
            "record_count": len(scenarios),
        }
    ]

    if ground_truth_path is not None:
        # Count lines after writing so the manifest describes the exact file on disk.
        metadata_files.append(
            {
                "path": _relative_output_path(output_root, ground_truth_path),
                "format": "jsonl",
                "record_count": _line_count(ground_truth_path),
            }
        )

    return {
        "schema_version": "output-manifest/v0.1",
        "generated_at": _format_timestamp(generated_at),
        "generator": {
            "name": "log-generator",
            "version": "0.1",
        },
        "run": {
            "run_id": run_id,
            "seed": _run_seed(scenarios),
            "output_root": str(output_root),
        },
        "scenarios": [_manifest_scenario_entry(scenario) for scenario in scenarios],
        "requested_output_families": _requested_output_families(scenarios),
        "files": [_output_file_entry(output_root, output_file) for output_file in output_result.files],
        "metadata_files": metadata_files,
        "omitted_streams": [_omitted_stream_entry(stream) for stream in output_result.omitted_streams],
    }


def _output_file_entry(output_root: Path, output_file: OutputWrittenFile) -> dict[str, object]:
    """
    Build a manifest file entry for a writer output file.

    Args:
        output_root (Path): Root output directory.
        output_file (OutputWrittenFile): Writer output file metadata.

    Returns:
        dict[str, object]: JSON-compatible file entry.
    """
    return {
        "path": _relative_output_path(output_root, output_file.path),
        "source_id": output_file.source_id,
        "source_kind": output_file.source_kind,
        "log_family": output_file.log_family,
        "log_stream": output_file.log_stream,
        "format": output_file.format,
        "record_count": output_file.record_count,
        "timestamp_fields": list(output_file.timestamp_fields),
        "scenario_ids": list(output_file.scenario_ids),
        "event_types": list(output_file.event_types),
    }


def _omitted_stream_entry(omitted_stream: OutputOmittedStream) -> dict[str, object]:
    """
    Build a manifest entry for a requested stream omitted because it had no records.

    Args:
        omitted_stream (OutputOmittedStream): Omitted stream metadata returned by an output writer.

    Returns:
        dict[str, object]: JSON-compatible omitted-stream entry.
    """
    return {
        "source_id": omitted_stream.source_id,
        "source_kind": omitted_stream.source_kind,
        "log_family": omitted_stream.log_family,
        "log_stream": omitted_stream.log_stream,
        "reason": omitted_stream.reason,
        "requested": omitted_stream.requested,
        "configured": omitted_stream.configured,
    }


def _manifest_scenario_entry(scenario: Scenario) -> dict[str, object]:
    """
    Build a top-level manifest scenario entry.

    Args:
        scenario (Scenario): Scenario to describe.

    Returns:
        dict[str, object]: JSON-compatible scenario entry.
    """
    return {
        "scenario_id": scenario.id,
        "scenario_name": scenario.name,
        "environment_id": scenario.environment_id,
        "environment_version": scenario.environment_version,
        "seed": scenario.seed,
        "time_range": _time_range(scenario),
    }


def _scenario_manifest_entry(scenario: Scenario) -> dict[str, object]:
    """
    Build a scenario metadata entry.

    Args:
        scenario (Scenario): Scenario to describe.

    Returns:
        dict[str, object]: JSON-compatible scenario metadata entry.
    """
    authored_event_count = scenario.authored_event_count

    if authored_event_count is None:
        authored_event_count = len(scenario.events)

    return {
        "scenario_id": scenario.id,
        "scenario_name": scenario.name,
        "seed": scenario.seed,
        "environment_id": scenario.environment_id,
        "environment_version": scenario.environment_version,
        "authored_event_count": authored_event_count,
        "expanded_event_count": len(scenario.events),
        "requested_output_families": list(scenario.output_families),
        "time_range": _time_range(scenario),
        "correlation_ids": list(scenario.correlation_ids()),
        "answer_key_labels": [record.label for record in scenario.answer_key],
    }


def _time_range(scenario: Scenario) -> dict[str, Optional[str]]:
    """
    Build a scenario time range dictionary.

    Args:
        scenario (Scenario): Scenario to inspect.

    Returns:
        dict[str, Optional[str]]: Start and optional end timestamps.
    """
    end_time = None

    if scenario.end_time is not None:
        end_time = _format_timestamp(scenario.end_time)

    return {
        "start": _format_timestamp(scenario.start_time),
        "end": end_time,
    }


def _requested_output_families(scenarios: tuple[Scenario, ...]) -> list[str]:
    """
    Return requested output families across scenarios.

    Args:
        scenarios (tuple[Scenario, ...]): Scenarios to inspect.

    Returns:
        list[str]: Sorted unique output families.
    """
    output_families = set()

    for scenario in scenarios:
        output_families.update(scenario.output_families)

    return sorted(output_families)


def _run_seed(scenarios: tuple[Scenario, ...]) -> int:
    """
    Return a deterministic run seed for the manifest.

    Args:
        scenarios (tuple[Scenario, ...]): Scenarios included in the run.

    Returns:
        int: Scenario seed for single-scenario runs or a deterministic combined value.
    """
    if len(scenarios) == 1:
        return scenarios[0].seed

    return sum(scenario.seed for scenario in scenarios)


def _line_count(path: Path) -> int:
    """
    Count lines in a text file.

    Args:
        path (Path): File to inspect.

    Returns:
        int: Number of lines in the file.
    """
    with path.open("r", encoding="utf-8") as input_file:
        return sum(1 for _ in input_file)


def _relative_output_path(output_root: Path, path: Path) -> str:
    """
    Return a portable path relative to the output root.

    Args:
        output_root (Path): Root output directory.
        path (Path): Child path to render.

    Returns:
        str: POSIX-style relative path.
    """
    return path.relative_to(output_root).as_posix()


def _write_json_file(path: Path, payload: dict[str, object]) -> None:
    """
    Write a stable formatted JSON file.

    Args:
        path (Path): File path to write.
        payload (dict[str, object]): JSON-compatible payload.

    Returns:
        None: The file is written to disk.
    """
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _normalize_generated_at(generated_at: Optional[datetime]) -> datetime:
    """
    Normalize a generation timestamp to UTC.

    Args:
        generated_at (Optional[datetime]): Generation timestamp or None.

    Returns:
        datetime: Timezone-aware UTC timestamp.
    """
    if generated_at is None:
        return datetime.now(timezone.utc)

    if generated_at.tzinfo is None or generated_at.utcoffset() is None:
        raise ValueError("generated_at must be timezone-aware")

    return generated_at.astimezone(timezone.utc)


def _format_timestamp(timestamp: datetime) -> str:
    """
    Format a UTC timestamp in stable ISO 8601 form.

    Args:
        timestamp (datetime): Timezone-aware timestamp.

    Returns:
        str: ISO 8601 timestamp.
    """
    return timestamp.astimezone(timezone.utc).isoformat()


__all__ = [
    "GROUND_TRUTH_PATH",
    "MANIFEST_PATH",
    "SCENARIO_MANIFEST_PATH",
    "build_manifest",
    "write_ground_truth",
    "write_output_manifest",
    "write_scenario_manifest",
]
