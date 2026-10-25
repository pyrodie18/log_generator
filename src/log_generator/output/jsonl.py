"""
Generic normalized JSON Lines output helpers.
"""

import json
import os
from pathlib import Path

from log_generator.core.enrichment import enrich_scenarios
from log_generator.core.events import SourceNeutralEvent
from log_generator.core.scenarios import Scenario


GENERIC_NORMALIZED_EVENTS_PATH = (
    "logs",
    "source-neutral-core",
    "generic-normalized",
    "events.jsonl",
)
SOURCE_SPECIFIC_OUTPUT_FAMILIES = frozenset({"apache", "auditd", "firewall", "proxy", "zeek"})


def write_generic_normalized_events(output_root: Path, scenarios: tuple[Scenario, ...]) -> Path:
    """
    Write expanded source-neutral events to the generic normalized JSON Lines output file.

    Args:
        output_root (Path): Root output directory where generated artifacts should be written.
        scenarios (tuple[Scenario, ...]): Scenarios whose expanded events should be written.

    Returns:
        Path: Path to the written generic normalized JSON Lines file.
    """
    scenarios = enrich_scenarios(scenarios)
    events_path = safe_output_path(output_root, GENERIC_NORMALIZED_EVENTS_PATH)
    events_path.parent.mkdir(parents=True, exist_ok=True)

    with events_path.open("w", encoding="utf-8") as output_file:
        for event in iter_ordered_events(scenarios):
            output_file.write(serialize_event(event))
            output_file.write("\n")

    return events_path


def iter_ordered_events(scenarios: tuple[Scenario, ...]) -> tuple[SourceNeutralEvent, ...]:
    """
    Return source-neutral events in deterministic writer order across scenarios.

    Args:
        scenarios (tuple[Scenario, ...]): Scenarios whose events should be ordered.

    Returns:
        tuple[SourceNeutralEvent, ...]: Ordered expanded events.
    """
    events = []

    for scenario_index, scenario in enumerate(scenarios):
        for scenario_event in scenario.events:
            # Scenario index keeps cross-scenario ordering deterministic when timestamps and sequence tie.
            events.append(
                (scenario_event.event.timestamp, scenario_event.sequence_order, scenario_index, scenario_event)
            )

    return tuple(scenario_event.event for *_, scenario_event in sorted(events))


def serialize_event(event: SourceNeutralEvent) -> str:
    """
    Serialize one source-neutral event as a stable JSON Lines record.

    Args:
        event (SourceNeutralEvent): Event to serialize.

    Returns:
        str: Compact JSON object string.
    """
    return json.dumps(event.to_dict(), sort_keys=True, separators=(",", ":"))


def safe_output_path(output_root: Path, path_components: tuple[str, ...]) -> Path:
    """
    Build a path under the output root from safe relative path components.

    Args:
        output_root (Path): Root output directory.
        path_components (tuple[str, ...]): Relative path components to append.

    Returns:
        Path: Safe path below the output root.
    """
    for component in path_components:
        validate_path_component(component)

    return output_root.joinpath(*path_components)


def validate_path_component(component: str) -> None:
    """
    Validate a single safe output path component.

    Args:
        component (str): Path component to validate.

    Returns:
        None: Raises ValueError when the component is unsafe.
    """
    separators = {os.sep, "/", "\\"}

    if os.altsep is not None:
        separators.add(os.altsep)

    # Writers compose paths from known components only; rejecting separators prevents path traversal.
    if not component:
        raise ValueError("output path components must not be empty")

    if component in {".", ".."}:
        raise ValueError(f"unsafe output path component '{component}'")

    if Path(component).is_absolute() or any(separator in component for separator in separators):
        raise ValueError(f"unsafe output path component '{component}'")


__all__ = [
    "GENERIC_NORMALIZED_EVENTS_PATH",
    "SOURCE_SPECIFIC_OUTPUT_FAMILIES",
    "iter_ordered_events",
    "safe_output_path",
    "serialize_event",
    "validate_path_component",
    "write_generic_normalized_events",
]
