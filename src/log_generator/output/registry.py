"""
Registered output-family writers.
"""

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional

from log_generator.core.events import SourceNeutralEvent
from log_generator.core.scenarios import Scenario
from log_generator.output.jsonl import (
    GENERIC_NORMALIZED_EVENTS_PATH,
    SOURCE_SPECIFIC_OUTPUT_FAMILIES,
    iter_ordered_events,
    write_generic_normalized_events,
)
from log_generator.output.zeek import validate_zeek_scenarios, write_zeek_logs


GENERIC_NORMALIZED_OUTPUT_FAMILY = "generic-normalized"
ZEEK_OUTPUT_FAMILY = "zeek"
DEFAULT_OUTPUT_FAMILIES = (GENERIC_NORMALIZED_OUTPUT_FAMILY,)
OUTPUT_FAMILY_ORDER = (GENERIC_NORMALIZED_OUTPUT_FAMILY, ZEEK_OUTPUT_FAMILY)


@dataclass(frozen=True)
class OutputWriter:
    """
    Describe a registered output-family writer.
    """

    family_name: str
    validate: Callable[[tuple[Scenario, ...]], None]
    write: Callable[[Path, tuple[Scenario, ...], datetime], "OutputWriteResult"]


@dataclass(frozen=True)
class OutputWrittenFile:
    """
    Describe one log output file for the top-level manifest.
    """

    path: Path
    source_id: str
    source_kind: str
    log_family: str
    log_stream: str
    format: str
    record_count: int
    timestamp_fields: tuple[str, ...]
    scenario_ids: tuple[str, ...]
    event_types: tuple[str, ...]


@dataclass(frozen=True)
class OutputOmittedStream:
    """
    Describe one requested stream intentionally omitted by an output writer.
    """

    source_id: str
    source_kind: str
    log_family: str
    log_stream: str
    reason: str
    requested: bool
    configured: bool


@dataclass(frozen=True)
class OutputWriteResult:
    """
    Describe output files written and streams omitted by one writer run.
    """

    files: tuple[OutputWrittenFile, ...] = ()
    omitted_streams: tuple[OutputOmittedStream, ...] = ()


@dataclass(frozen=True)
class OutputWriterRun:
    """
    Pair a registered writer with the scenarios requesting it.
    """

    writer: OutputWriter
    scenarios: tuple[Scenario, ...]


def supported_output_families() -> frozenset[str]:
    """
    Return output families backed by registered writers.

    Returns:
        frozenset[str]: Supported output-family names.
    """
    return frozenset(OUTPUT_WRITERS)


def unsupported_source_specific_output_families() -> frozenset[str]:
    """
    Return known source-specific output families not supported by registered writers yet.

    Returns:
        frozenset[str]: Known source-specific family names without registered writers.
    """
    return SOURCE_SPECIFIC_OUTPUT_FAMILIES - supported_output_families()


def get_output_writer(family_name: str) -> Optional[OutputWriter]:
    """
    Look up a registered output writer by family name.

    Args:
        family_name (str): Output family name.

    Returns:
        Optional[OutputWriter]: Registered writer when supported.
    """
    return OUTPUT_WRITERS.get(family_name)


def plan_output_writer_runs(scenarios: tuple[Scenario, ...]) -> tuple[OutputWriterRun, ...]:
    """
    Plan deterministic writer runs for requested scenario output families.

    Args:
        scenarios (tuple[Scenario, ...]): Scenarios included in the output set.

    Returns:
        tuple[OutputWriterRun, ...]: Writer runs in deterministic output-family order.
    """
    for scenario in scenarios:
        for output_family in scenario.output_families:
            if get_output_writer(output_family) is None:
                raise ValueError(f"unsupported output family '{output_family}'")

    writer_runs = []

    for output_family in OUTPUT_FAMILY_ORDER:
        requested_scenarios = tuple(scenario for scenario in scenarios if output_family in scenario.output_families)

        if requested_scenarios:
            writer_runs.append(
                OutputWriterRun(
                    writer=OUTPUT_WRITERS[output_family],
                    scenarios=requested_scenarios,
                )
            )

    return tuple(writer_runs)


def validate_output_writer_runs(writer_runs: tuple[OutputWriterRun, ...]) -> None:
    """
    Validate all planned output writers before any output files are written.

    Args:
        writer_runs (tuple[OutputWriterRun, ...]): Planned writer runs.

    Returns:
        None: Raises ValueError when a writer cannot handle the requested scenarios.
    """
    for writer_run in writer_runs:
        writer_run.writer.validate(writer_run.scenarios)


def _validate_generic_normalized_scenarios(scenarios: tuple[Scenario, ...]) -> None:
    """
    Validate scenarios for generic normalized output.

    Args:
        scenarios (tuple[Scenario, ...]): Scenarios requesting generic normalized output.

    Returns:
        None: Generic normalized output currently accepts every valid scenario.
    """


def _write_generic_normalized_output(
    output_root: Path,
    scenarios: tuple[Scenario, ...],
    generated_at: datetime,
) -> OutputWriteResult:
    """
    Write generic normalized output through the registry adapter.

    Args:
        output_root (Path): Root output directory where artifacts should be written.
        scenarios (tuple[Scenario, ...]): Scenarios requesting generic normalized output.
        generated_at (datetime): Generation timestamp, unused by this writer.

    Returns:
        OutputWriteResult: Manifest-ready metadata for the written generic JSON Lines file.
    """
    events_path = write_generic_normalized_events(output_root, scenarios)
    events = iter_ordered_events(scenarios)

    return OutputWriteResult(
        files=(
            OutputWrittenFile(
                path=events_path,
                source_id="source-neutral-core",
                source_kind="logical",
                log_family=GENERIC_NORMALIZED_OUTPUT_FAMILY,
                log_stream=GENERIC_NORMALIZED_EVENTS_PATH[-1],
                format="jsonl",
                record_count=len(events),
                timestamp_fields=("timestamp",),
                scenario_ids=_scenario_ids(scenarios),
                event_types=_event_types(events),
            ),
        ),
    )


def _write_zeek_output(
    output_root: Path,
    scenarios: tuple[Scenario, ...],
    generated_at: datetime,
) -> OutputWriteResult:
    """
    Write Zeek output through the registry adapter.

    Args:
        output_root (Path): Root output directory where artifacts should be written.
        scenarios (tuple[Scenario, ...]): Scenarios requesting Zeek output.
        generated_at (datetime): Deterministic wall-clock time for Zeek headers.

    Returns:
        OutputWriteResult: Manifest-ready metadata for written and omitted Zeek streams.
    """
    zeek_result = write_zeek_logs(output_root, scenarios, generated_at=generated_at)

    return OutputWriteResult(
        files=tuple(
            OutputWrittenFile(
                path=zeek_file.path,
                source_id="zeek-sensor-01",
                source_kind="sensor",
                log_family=ZEEK_OUTPUT_FAMILY,
                log_stream=zeek_file.path.name,
                format="zeek-tsv",
                record_count=zeek_file.record_count,
                timestamp_fields=("ts",),
                scenario_ids=zeek_file.scenario_ids,
                event_types=zeek_file.event_types,
            )
            for zeek_file in zeek_result.files
        ),
        omitted_streams=tuple(
            OutputOmittedStream(
                source_id=omitted_stream.source_id,
                source_kind=omitted_stream.source_kind,
                log_family=omitted_stream.log_family,
                log_stream=omitted_stream.log_stream,
                reason=omitted_stream.reason,
                requested=omitted_stream.requested,
                configured=omitted_stream.configured,
            )
            for omitted_stream in zeek_result.omitted_streams
        ),
    )


def _scenario_ids(scenarios: tuple[Scenario, ...]) -> tuple[str, ...]:
    """
    Return scenario IDs in caller-provided order without duplicates.

    Args:
        scenarios (tuple[Scenario, ...]): Scenarios to inspect.

    Returns:
        tuple[str, ...]: Scenario identifiers.
    """
    scenario_ids = []

    for scenario in scenarios:
        if scenario.id not in scenario_ids:
            scenario_ids.append(scenario.id)

    return tuple(scenario_ids)


def _event_types(events: tuple[SourceNeutralEvent, ...]) -> tuple[str, ...]:
    """
    Return event types in first-seen order.

    Args:
        events (tuple[SourceNeutralEvent, ...]): Events to inspect.

    Returns:
        tuple[str, ...]: Event type names.
    """
    event_types = []

    for event in events:
        if event.event_type not in event_types:
            event_types.append(event.event_type)

    return tuple(event_types)


OUTPUT_WRITERS = {
    GENERIC_NORMALIZED_OUTPUT_FAMILY: OutputWriter(
        family_name=GENERIC_NORMALIZED_OUTPUT_FAMILY,
        validate=_validate_generic_normalized_scenarios,
        write=_write_generic_normalized_output,
    ),
    ZEEK_OUTPUT_FAMILY: OutputWriter(
        family_name=ZEEK_OUTPUT_FAMILY,
        validate=validate_zeek_scenarios,
        write=_write_zeek_output,
    ),
}
