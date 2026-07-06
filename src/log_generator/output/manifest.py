"""
Output manifest model and writer helpers.
"""

from contextlib import contextmanager
from dataclasses import dataclass
import json
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Optional
from uuid import uuid4

from log_generator.core.scenarios import Scenario
from log_generator.output.jsonl import safe_output_path
from log_generator.output.registry import (
    OutputOmittedStream,
    OutputWriteResult,
    OutputWrittenFile,
    OutputWriterRun,
    plan_output_writer_runs,
    supported_output_families,
    validate_output_writer_runs,
)


MANIFEST_PATH = ("manifest.json",)
SCENARIO_MANIFEST_PATH = ("metadata", "scenario-manifest.json")
GROUND_TRUTH_PATH = ("metadata", "ground-truth.jsonl")
SUPPORTED_OUTPUT_FAMILIES = supported_output_families()


@dataclass(frozen=True)
class GroundTruthWriteResult:
    """
    Describe a written ground-truth metadata file.
    """

    path: Path
    record_count: int


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
    output_root = Path(output_root)
    generated_at = _normalize_generated_at(generated_at)
    writer_runs = plan_output_writer_runs(scenarios)
    validate_output_writer_runs(writer_runs)

    _validate_replaceable_output_root(output_root)

    with _staged_output_root(output_root) as staging_root:
        output_result = _write_registered_outputs(staging_root, writer_runs, generated_at)
        scenario_manifest_path = write_scenario_manifest(staging_root, scenarios)
        ground_truth_result = write_ground_truth(staging_root, scenarios)
        manifest_path = safe_output_path(staging_root, MANIFEST_PATH)
        manifest_path.parent.mkdir(parents=True, exist_ok=True)

        manifest = build_manifest(
            output_root=output_root,
            scenarios=scenarios,
            run_id=run_id,
            generated_at=generated_at,
            output_result=output_result,
            scenario_manifest_path=scenario_manifest_path,
            ground_truth_result=ground_truth_result,
            artifact_root=staging_root,
        )
        _write_json_file(manifest_path, manifest)
        _replace_output_root(staging_root, output_root)

    return safe_output_path(output_root, MANIFEST_PATH)


def _write_registered_outputs(
    output_root: Path,
    writer_runs: tuple[OutputWriterRun, ...],
    generated_at: datetime,
) -> OutputWriteResult:
    """
    Write all planned output-family artifacts and combine their metadata.

    Args:
        output_root (Path): Root output directory where generated artifacts should be written.
        writer_runs (tuple[OutputWriterRun, ...]): Planned output writer runs.
        generated_at (datetime): UTC generation timestamp.

    Returns:
        OutputWriteResult: Combined writer output metadata.
    """
    output_files = []
    omitted_streams = []

    for writer_run in writer_runs:
        result = writer_run.writer.write(output_root, writer_run.scenarios, generated_at)
        output_files.extend(result.files)
        omitted_streams.extend(result.omitted_streams)

    return OutputWriteResult(files=tuple(output_files), omitted_streams=tuple(omitted_streams))


def _validate_replaceable_output_root(output_root: Path) -> None:
    """
    Validate that an output root can be atomically replaced.

    Args:
        output_root (Path): Requested final output directory.

    Returns:
        None: Raises ValueError when the path cannot be replaced.
    """
    if output_root.exists() and not output_root.is_dir():
        raise ValueError(f"output root '{output_root}' exists and is not a directory")


@contextmanager
def _staged_output_root(output_root: Path) -> Iterator[Path]:
    """
    Create and clean up a sibling staging directory for atomic output writes.

    Args:
        output_root (Path): Requested final output directory.

    Yields:
        Path: Temporary staging output directory.
    """
    output_root.parent.mkdir(parents=True, exist_ok=True)
    staging_root = Path(
        tempfile.mkdtemp(
            prefix=f".{output_root.name}.tmp-",
            dir=str(output_root.parent),
        )
    )

    try:
        yield staging_root
    finally:
        # After a successful commit this path has been renamed into output_root and no longer exists.
        if staging_root.exists():
            shutil.rmtree(staging_root, ignore_errors=True)


def _replace_output_root(staging_root: Path, output_root: Path) -> None:
    """
    Replace the final output root with a fully written staging directory.

    Args:
        staging_root (Path): Fully written staging output directory.
        output_root (Path): Requested final output directory.

    Returns:
        None: The staging directory is moved into place.
    """
    backup_root = None

    if output_root.exists():
        backup_root = output_root.parent / f".{output_root.name}.backup-{uuid4().hex}"
        output_root.rename(backup_root)

    try:
        staging_root.rename(output_root)
    except Exception:
        # Restore the previous completed output if committing the new tree fails after the backup move.
        if backup_root is not None and backup_root.exists() and not output_root.exists():
            backup_root.rename(output_root)
        raise

    if backup_root is not None and backup_root.exists():
        shutil.rmtree(backup_root, ignore_errors=True)


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


def write_ground_truth(output_root: Path, scenarios: tuple[Scenario, ...]) -> Optional[GroundTruthWriteResult]:
    """
    Write ground-truth JSON Lines metadata when answer-key records exist.

    Args:
        output_root (Path): Root output directory where generated artifacts should be written.
        scenarios (tuple[Scenario, ...]): Scenarios whose answer-key records should be written.

    Returns:
        Optional[GroundTruthWriteResult]: Written ground-truth metadata, or None when no records exist.
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

    return GroundTruthWriteResult(path=ground_truth_path, record_count=len(answer_key_records))


def build_manifest(
    output_root: Path,
    scenarios: tuple[Scenario, ...],
    run_id: str,
    generated_at: datetime,
    output_result: OutputWriteResult,
    scenario_manifest_path: Path,
    ground_truth_result: Optional[GroundTruthWriteResult],
    artifact_root: Optional[Path] = None,
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
        ground_truth_result (Optional[GroundTruthWriteResult]): Written ground-truth metadata when present.
        artifact_root (Optional[Path]): Root used to compute relative artifact paths.

    Returns:
        dict[str, object]: JSON-compatible manifest payload.
    """
    if artifact_root is None:
        artifact_root = output_root

    metadata_files = [
        {
            "path": _relative_output_path(artifact_root, scenario_manifest_path),
            "format": "json",
            "record_count": len(scenarios),
        }
    ]

    if ground_truth_result is not None:
        # Reuse the writer's record count so manifest construction does not reread the file it just wrote.
        metadata_files.append(
            {
                "path": _relative_output_path(artifact_root, ground_truth_result.path),
                "format": "jsonl",
                "record_count": ground_truth_result.record_count,
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
        "files": [_output_file_entry(artifact_root, output_file) for output_file in output_result.files],
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
    "GroundTruthWriteResult",
    "GROUND_TRUTH_PATH",
    "MANIFEST_PATH",
    "SCENARIO_MANIFEST_PATH",
    "build_manifest",
    "write_ground_truth",
    "write_output_manifest",
    "write_scenario_manifest",
]
