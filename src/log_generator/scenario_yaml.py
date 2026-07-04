"""
YAML scenario loading and structural validation.
"""

from dataclasses import dataclass
from datetime import date, datetime, timedelta
from pathlib import Path
import re
from typing import Any, Mapping, Optional, Union

from log_generator.core.environment import Environment, build_linux_mini_lab
from log_generator.core.events import LinuxLocalLoginEvent, VALID_STATUSES, normalize_utc_timestamp
from log_generator.core.scenarios import (
    AnswerKeyRecord,
    AuthoredEvent,
    AuthoredWebRequest,
    Scenario,
    ScenarioEvent,
    expand_authored_events,
)
from log_generator.output.jsonl import validate_path_component
from log_generator.output.manifest import write_output_manifest


SUPPORTED_SCHEMA_VERSION = "scenario/v0.1"
DEFAULT_OUTPUT_FAMILIES = ("generic-normalized",)
SUPPORTED_EVENT_TYPES = frozenset({"web_request", "linux_local_login"})
TOP_LEVEL_FIELDS = frozenset(
    {
        "schema_version",
        "id",
        "name",
        "description",
        "seed",
        "environment",
        "time_range",
        "output_families",
        "events",
        "attack_chain",
        "answer_key",
        "metadata",
        "noise_profiles",
    }
)
COMMON_EVENT_FIELDS = frozenset(
    {
        "id",
        "type",
        "at",
        "after",
        "delay",
        "actor",
        "source_host",
        "target_host",
        "service",
        "status",
        "correlation_id",
        "metadata",
        "attack",
    }
)
EVENT_TYPE_FIELDS = {
    "web_request": frozenset(
        {
            "method",
            "path",
            "status_code",
            "query_string",
            "headers",
        }
    ),
    "linux_local_login": frozenset(
        {
            "login_method",
            "source_ip",
        }
    ),
}
SAFE_IDENTIFIER_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
DURATION_RE = re.compile(r"^\+?(?P<amount>\d+)(?P<unit>ms|s|m|h)$")
ATTACK_TECHNIQUE_ID_RE = re.compile(r"^T\d+$")
ATTACK_CHAIN_FIELDS = frozenset(
    {
        "id",
        "name",
        "primary_event_id",
        "supporting_event_ids",
        "technique_id",
        "technique_name",
    }
)
ANSWER_KEY_FIELDS = frozenset(
    {
        "label",
        "primary_event_id",
        "supporting_event_ids",
        "description",
    }
)


@dataclass(frozen=True)
class ScenarioYamlValidationError:
    """
    Represent one YAML scenario validation error.
    """

    scenario_id: Optional[str]
    field_path: str
    invalid_value: Any
    reason: str

    def __str__(self) -> str:
        """
        Render the validation error for CLI and test output.

        Returns:
            str: Human-readable validation error.
        """
        prefix = self.scenario_id or "<unknown-scenario>"

        return f"{prefix} {self.field_path}: {self.invalid_value!r} is invalid because {self.reason}"


class ScenarioYamlError(ValueError):
    """
    Represent one or more YAML scenario validation errors.
    """

    def __init__(self, errors: list[ScenarioYamlValidationError]) -> None:
        """
        Initialize the exception from validation errors.

        Args:
            errors (list[ScenarioYamlValidationError]): Validation errors to expose.

        Returns:
            None: The exception is initialized.
        """
        self.errors = errors
        super().__init__("\n".join(str(error) for error in errors))


@dataclass(frozen=True)
class ParsedYamlEvent:
    """
    Represent one structurally valid authored YAML event with resolved timing.
    """

    event_id: str
    event_type: str
    timestamp: datetime
    source_index: int
    raw: dict[str, Any]
    after: Optional[str] = None
    delay: Optional[timedelta] = None


@dataclass(frozen=True)
class ParsedScenarioYaml:
    """
    Represent a structurally valid YAML scenario document.
    """

    schema_version: str
    scenario_id: str
    name: str
    seed: int
    environment_id: str
    environment_version: str
    start_time: datetime
    events: tuple[ParsedYamlEvent, ...]
    end_time: Optional[datetime] = None
    output_families: tuple[str, ...] = DEFAULT_OUTPUT_FAMILIES
    description: Optional[str] = None
    attack_chain: tuple[dict[str, Any], ...] = ()
    answer_key: tuple[dict[str, Any], ...] = ()
    metadata: Optional[dict[str, Any]] = None


EnvironmentRegistry = Mapping[str, Environment]


def load_scenario_yaml(
    path: Path,
    environment_registry: Optional[EnvironmentRegistry] = None,
) -> ParsedScenarioYaml:
    """
    Load and validate a single YAML scenario document from disk.

    Args:
        path (Path): YAML scenario file to read.
        environment_registry (Optional[EnvironmentRegistry]): Environment registry overrides.

    Returns:
        ParsedScenarioYaml: Parsed scenario with resolved top-level metadata and event timing.
    """
    return parse_scenario_yaml_text(
        path.read_text(encoding="utf-8"),
        environment_registry=environment_registry,
    )


def build_scenario_from_yaml(
    path: Path,
    environment_registry: Optional[EnvironmentRegistry] = None,
) -> Scenario:
    """
    Load a YAML scenario file and convert it into an expanded source-neutral scenario.

    Args:
        path (Path): YAML scenario file to read.
        environment_registry (Optional[EnvironmentRegistry]): Environment registry overrides.

    Returns:
        Scenario: Expanded source-neutral scenario.
    """
    return load_scenario_from_yaml(path, environment_registry=environment_registry)


def load_scenario_from_yaml(
    path: Path,
    environment_registry: Optional[EnvironmentRegistry] = None,
) -> Scenario:
    """
    Load a YAML scenario file and return an expanded source-neutral scenario.

    Args:
        path (Path): YAML scenario file to read.
        environment_registry (Optional[EnvironmentRegistry]): Environment registry overrides.

    Returns:
        Scenario: Expanded source-neutral scenario.
    """
    parsed = load_scenario_yaml(path, environment_registry=environment_registry)

    return build_scenario_from_parsed_yaml(parsed, environment_registry=environment_registry)


def generate_from_yaml(
    path: Path,
    output_root: Path,
    run_id: Optional[str] = None,
    generated_at: Optional[datetime] = None,
    environment_registry: Optional[EnvironmentRegistry] = None,
) -> Path:
    """
    Generate the generic output tree from a YAML scenario file.

    Args:
        path (Path): YAML scenario file to load.
        output_root (Path): Root output directory to write.
        run_id (Optional[str]): Run ID to include in the manifest. A deterministic default is used when omitted.
        generated_at (Optional[datetime]): UTC generation timestamp to include in the manifest.
        environment_registry (Optional[EnvironmentRegistry]): Environment registry overrides.

    Returns:
        Path: Path to the written manifest file.
    """
    scenario = load_scenario_from_yaml(path, environment_registry=environment_registry)

    if run_id is None:
        run_id = _default_run_id(scenario)

    return write_output_manifest(output_root, (scenario,), run_id=run_id, generated_at=generated_at)


def parse_scenario_yaml_text(
    text: str,
    environment_registry: Optional[EnvironmentRegistry] = None,
) -> ParsedScenarioYaml:
    """
    Parse and validate a single YAML scenario document from text.

    Args:
        text (str): YAML scenario document text.
        environment_registry (Optional[EnvironmentRegistry]): Environment registry overrides.

    Returns:
        ParsedScenarioYaml: Parsed scenario with resolved top-level metadata and event timing.
    """
    document = _load_yaml_document(text)

    return parse_scenario_yaml_document(document, environment_registry=environment_registry)


def build_scenario_from_yaml_text(
    text: str,
    environment_registry: Optional[EnvironmentRegistry] = None,
) -> Scenario:
    """
    Parse YAML scenario text and convert it into an expanded source-neutral scenario.

    Args:
        text (str): YAML scenario document text.
        environment_registry (Optional[EnvironmentRegistry]): Environment registry overrides.

    Returns:
        Scenario: Expanded source-neutral scenario.
    """
    parsed = parse_scenario_yaml_text(text, environment_registry=environment_registry)

    return build_scenario_from_parsed_yaml(parsed, environment_registry=environment_registry)


def parse_scenario_yaml_document(
    document: dict[str, Any],
    environment_registry: Optional[EnvironmentRegistry] = None,
) -> ParsedScenarioYaml:
    """
    Validate a parsed YAML mapping and return a structured scenario document.

    Args:
        document (dict[str, Any]): Parsed YAML mapping.
        environment_registry (Optional[EnvironmentRegistry]): Environment registry overrides.

    Returns:
        ParsedScenarioYaml: Parsed scenario with resolved top-level metadata and event timing.
    """
    errors: list[ScenarioYamlValidationError] = []
    scenario_id = _scenario_id_for_errors(document)

    _require_mapping(document, "<document>", scenario_id, errors)

    if errors:
        raise ScenarioYamlError(errors)

    _validate_top_level_fields(document, scenario_id, errors)

    schema_version = _required_string(document, "schema_version", scenario_id, errors)
    if schema_version is not None and schema_version != SUPPORTED_SCHEMA_VERSION:
        errors.append(_error(scenario_id, "schema_version", schema_version, "supported value is 'scenario/v0.1'"))

    parsed_scenario_id = _required_string(document, "id", scenario_id, errors)
    if parsed_scenario_id is not None:
        _validate_safe_identifier(parsed_scenario_id, "id", scenario_id, errors)
        scenario_id = parsed_scenario_id

    name = _required_string(document, "name", scenario_id, errors)
    seed = _required_integer(document, "seed", scenario_id, errors)
    environment_id, environment_version = _parse_environment(
        document.get("environment"),
        scenario_id,
        errors,
        environment_registry=environment_registry,
    )
    start_time, end_time = _parse_time_range(document.get("time_range"), scenario_id, errors)
    output_families = _parse_output_families(document.get("output_families"), scenario_id, errors)
    events = _parse_events(document.get("events"), scenario_id, start_time, end_time, errors)
    description = _optional_string(document, "description", scenario_id, errors)
    metadata = _optional_mapping(document, "metadata", scenario_id, errors)
    attack_chain = _optional_mapping_sequence(document, "attack_chain", scenario_id, errors)
    answer_key = _optional_mapping_sequence(document, "answer_key", scenario_id, errors)

    if errors:
        raise ScenarioYamlError(errors)

    parsed = ParsedScenarioYaml(
        schema_version=schema_version,
        scenario_id=scenario_id,
        name=name,
        seed=seed,
        environment_id=environment_id,
        environment_version=environment_version,
        start_time=start_time,
        end_time=end_time,
        output_families=output_families,
        events=events,
        description=description,
        attack_chain=attack_chain,
        answer_key=answer_key,
        metadata=metadata,
    )

    environment_errors = _validate_parsed_scenario_environment(
        parsed,
        environment_registry=environment_registry,
    )

    if environment_errors:
        raise ScenarioYamlError(environment_errors)

    return parsed


def build_scenario_from_parsed_yaml(
    parsed: ParsedScenarioYaml,
    environment_registry: Optional[EnvironmentRegistry] = None,
) -> Scenario:
    """
    Convert a parsed YAML scenario into the existing source-neutral Scenario model.

    Args:
        parsed (ParsedScenarioYaml): Structurally valid parsed YAML scenario.
        environment_registry (Optional[EnvironmentRegistry]): Environment registry overrides.

    Returns:
        Scenario: Expanded source-neutral scenario.
    """
    environment = _lookup_environment(parsed.environment_id, environment_registry=environment_registry)

    if environment is None:
        raise ScenarioYamlError(
            [_error(parsed.scenario_id, "environment.id", parsed.environment_id, "unknown environment")]
        )

    authored_events = _build_authored_events(parsed)
    expanded_events = expand_authored_events(
        scenario_id=parsed.scenario_id,
        seed=parsed.seed,
        environment=environment,
        authored_events=authored_events,
    )
    metadata_errors = _validate_metadata_references(parsed, expanded_events)

    if metadata_errors:
        raise ScenarioYamlError(metadata_errors)

    return Scenario(
        id=parsed.scenario_id,
        name=parsed.name,
        seed=parsed.seed,
        environment_id=parsed.environment_id,
        environment_version=parsed.environment_version,
        start_time=parsed.start_time,
        end_time=parsed.end_time,
        output_families=parsed.output_families,
        events=expanded_events,
        answer_key=_build_answer_key_records(parsed, expanded_events),
        authored_event_count=len(parsed.events),
    )


def _build_authored_events(parsed: ParsedScenarioYaml) -> tuple[AuthoredEvent, ...]:
    """
    Build Phase 1 authored event primitives from parsed YAML events.

    Args:
        parsed (ParsedScenarioYaml): Parsed YAML scenario to convert.

    Returns:
        tuple[AuthoredEvent, ...]: Authored event primitives accepted by scenario expansion.
    """
    errors: list[ScenarioYamlValidationError] = []
    authored_events: list[AuthoredEvent] = []
    correlation_ids_by_event_id: dict[str, str] = {}
    event_types_by_id = {event.event_id: event.event_type for event in parsed.events}
    all_authored_event_ids = {event.event_id for event in parsed.events}

    for parsed_event in parsed.events:
        correlation_id = _event_correlation_id(parsed, parsed_event, correlation_ids_by_event_id)
        parent_event_id = parsed_event.after

        if parsed_event.event_type == "web_request":
            authored_event = _build_authored_web_request(
                parsed=parsed,
                parsed_event=parsed_event,
                correlation_id=correlation_id,
                parent_event_id=parent_event_id,
                event_types_by_id=event_types_by_id,
                all_authored_event_ids=all_authored_event_ids,
                errors=errors,
            )
        elif parsed_event.event_type == "linux_local_login":
            authored_event = _build_linux_local_login_event(
                parsed=parsed,
                parsed_event=parsed_event,
                correlation_id=correlation_id,
                parent_event_id=parent_event_id,
                errors=errors,
            )
        else:
            errors.append(
                _error(
                    parsed.scenario_id,
                    _event_field_path(parsed_event, "type"),
                    parsed_event.event_type,
                    "unsupported event type",
                )
            )
            continue

        if authored_event is not None:
            authored_events.append(authored_event)
            correlation_ids_by_event_id[parsed_event.event_id] = correlation_id

    if errors:
        raise ScenarioYamlError(errors)

    return tuple(authored_events)


def _validate_metadata_references(
    parsed: ParsedScenarioYaml,
    expanded_events: tuple[ScenarioEvent, ...],
) -> list[ScenarioYamlValidationError]:
    """
    Validate attack-chain and answer-key references against expanded event IDs.

    Args:
        parsed (ParsedScenarioYaml): Parsed YAML scenario that owns metadata.
        expanded_events (tuple[ScenarioEvent, ...]): Expanded source-neutral scenario events.

    Returns:
        list[ScenarioYamlValidationError]: Metadata validation errors.
    """
    errors: list[ScenarioYamlValidationError] = []
    expanded_event_ids = {scenario_event.event.event_id for scenario_event in expanded_events}

    for index, attack_step in enumerate(parsed.attack_chain):
        _validate_attack_chain_step(parsed.scenario_id, index, attack_step, expanded_event_ids, errors)

    for index, answer_key_record in enumerate(parsed.answer_key):
        _validate_answer_key_record(parsed.scenario_id, index, answer_key_record, expanded_event_ids, errors)

    return errors


def _build_answer_key_records(
    parsed: ParsedScenarioYaml,
    expanded_events: tuple[ScenarioEvent, ...],
) -> tuple[AnswerKeyRecord, ...]:
    """
    Build answer-key records from validated YAML metadata.

    Args:
        parsed (ParsedScenarioYaml): Parsed YAML scenario that owns answer-key metadata.
        expanded_events (tuple[ScenarioEvent, ...]): Expanded source-neutral scenario events.

    Returns:
        tuple[AnswerKeyRecord, ...]: Answer-key records ready for metadata output.
    """
    events_by_id = {scenario_event.event.event_id: scenario_event.event for scenario_event in expanded_events}
    answer_key_records = []

    for record in parsed.answer_key:
        primary_event_id = record["primary_event_id"]
        primary_event = events_by_id[primary_event_id]

        answer_key_records.append(
            AnswerKeyRecord(
                scenario_id=parsed.scenario_id,
                correlation_id=primary_event.correlation_id,
                label=record["label"],
                primary_event_id=primary_event_id,
                supporting_event_ids=tuple(record.get("supporting_event_ids", ())),
                description=record["description"],
            )
        )

    return tuple(answer_key_records)


def _validate_attack_chain_step(
    scenario_id: str,
    index: int,
    attack_step: dict[str, Any],
    expanded_event_ids: set[str],
    errors: list[ScenarioYamlValidationError],
) -> None:
    """
    Validate one attack-chain step.

    Args:
        scenario_id (str): Scenario ID for validation errors.
        index (int): Attack-chain item index.
        attack_step (dict[str, Any]): Raw attack-chain step mapping.
        expanded_event_ids (set[str]): Valid event IDs after expansion.
        errors (list[ScenarioYamlValidationError]): Validation errors to update.

    Returns:
        None: The errors list is updated in place.
    """
    prefix = f"attack_chain[{index}]"

    _validate_unknown_fields(attack_step, ATTACK_CHAIN_FIELDS, prefix, scenario_id, errors)
    _required_metadata_string(attack_step, "id", prefix, scenario_id, errors)
    _required_metadata_string(attack_step, "name", prefix, scenario_id, errors)
    primary_event_id = _required_metadata_string(attack_step, "primary_event_id", prefix, scenario_id, errors)
    supporting_event_ids = _optional_string_list(
        attack_step, "supporting_event_ids", prefix, scenario_id, errors
    )
    _validate_optional_metadata_technique_id(attack_step, "technique_id", prefix, scenario_id, errors)

    if primary_event_id is not None:
        _validate_metadata_event_reference(
            primary_event_id, f"{prefix}.primary_event_id", scenario_id, expanded_event_ids, errors
        )

    for supporting_index, supporting_event_id in enumerate(supporting_event_ids):
        _validate_metadata_event_reference(
            supporting_event_id,
            f"{prefix}.supporting_event_ids[{supporting_index}]",
            scenario_id,
            expanded_event_ids,
            errors,
        )


def _validate_answer_key_record(
    scenario_id: str,
    index: int,
    answer_key_record: dict[str, Any],
    expanded_event_ids: set[str],
    errors: list[ScenarioYamlValidationError],
) -> None:
    """
    Validate one answer-key record.

    Args:
        scenario_id (str): Scenario ID for validation errors.
        index (int): Answer-key item index.
        answer_key_record (dict[str, Any]): Raw answer-key mapping.
        expanded_event_ids (set[str]): Valid event IDs after expansion.
        errors (list[ScenarioYamlValidationError]): Validation errors to update.

    Returns:
        None: The errors list is updated in place.
    """
    prefix = f"answer_key[{index}]"

    _validate_unknown_fields(answer_key_record, ANSWER_KEY_FIELDS, prefix, scenario_id, errors)
    _required_metadata_string(answer_key_record, "label", prefix, scenario_id, errors)
    primary_event_id = _required_metadata_string(
        answer_key_record, "primary_event_id", prefix, scenario_id, errors
    )
    supporting_event_ids = _optional_string_list(
        answer_key_record, "supporting_event_ids", prefix, scenario_id, errors
    )
    _required_metadata_string(answer_key_record, "description", prefix, scenario_id, errors)

    if primary_event_id is not None:
        _validate_metadata_event_reference(
            primary_event_id, f"{prefix}.primary_event_id", scenario_id, expanded_event_ids, errors
        )

    for supporting_index, supporting_event_id in enumerate(supporting_event_ids):
        _validate_metadata_event_reference(
            supporting_event_id,
            f"{prefix}.supporting_event_ids[{supporting_index}]",
            scenario_id,
            expanded_event_ids,
            errors,
        )


def _validate_metadata_event_reference(
    event_id: str,
    field_path: str,
    scenario_id: str,
    expanded_event_ids: set[str],
    errors: list[ScenarioYamlValidationError],
) -> None:
    """
    Validate that a metadata event reference resolves after scenario expansion.

    Args:
        event_id (str): Event ID to validate.
        field_path (str): Field path for validation errors.
        scenario_id (str): Scenario ID for validation errors.
        expanded_event_ids (set[str]): Valid event IDs after expansion.
        errors (list[ScenarioYamlValidationError]): Validation errors to update.

    Returns:
        None: The errors list is updated in place.
    """
    if event_id not in expanded_event_ids:
        errors.append(_error(scenario_id, field_path, event_id, "event reference does not resolve"))


def _required_metadata_string(
    values: dict[str, Any],
    field_name: str,
    prefix: str,
    scenario_id: str,
    errors: list[ScenarioYamlValidationError],
) -> Optional[str]:
    """
    Read a required string field from metadata.

    Args:
        values (dict[str, Any]): Metadata mapping to read.
        field_name (str): Field name to require.
        prefix (str): Field path prefix.
        scenario_id (str): Scenario ID for validation errors.
        errors (list[ScenarioYamlValidationError]): Validation errors to update.

    Returns:
        Optional[str]: Field value when valid.
    """
    value = values.get(field_name)
    field_path = f"{prefix}.{field_name}"

    if value is None:
        errors.append(_error(scenario_id, field_path, None, "field is required"))
        return None

    if not isinstance(value, str):
        errors.append(_error(scenario_id, field_path, value, "expected string"))
        return None

    if not value:
        errors.append(_error(scenario_id, field_path, value, "must not be empty"))
        return None

    return value


def _optional_string_list(
    values: dict[str, Any],
    field_name: str,
    prefix: str,
    scenario_id: str,
    errors: list[ScenarioYamlValidationError],
) -> tuple[str, ...]:
    """
    Read an optional list of strings from metadata.

    Args:
        values (dict[str, Any]): Metadata mapping to read.
        field_name (str): Field name to read.
        prefix (str): Field path prefix.
        scenario_id (str): Scenario ID for validation errors.
        errors (list[ScenarioYamlValidationError]): Validation errors to update.

    Returns:
        tuple[str, ...]: String values when present and valid.
    """
    if field_name not in values or values[field_name] is None:
        return ()

    value = values[field_name]
    field_path = f"{prefix}.{field_name}"

    if not isinstance(value, list):
        errors.append(_error(scenario_id, field_path, value, "expected list of strings"))
        return ()

    output = []

    for index, item in enumerate(value):
        if not isinstance(item, str):
            errors.append(_error(scenario_id, f"{field_path}[{index}]", item, "expected string"))
            continue

        output.append(item)

    return tuple(output)


def _validate_optional_metadata_technique_id(
    values: dict[str, Any],
    field_name: str,
    prefix: str,
    scenario_id: str,
    errors: list[ScenarioYamlValidationError],
) -> None:
    """
    Validate an optional metadata-level ATT&CK technique ID.

    Args:
        values (dict[str, Any]): Metadata mapping to inspect.
        field_name (str): Technique ID field name.
        prefix (str): Field path prefix.
        scenario_id (str): Scenario ID for validation errors.
        errors (list[ScenarioYamlValidationError]): Validation errors to update.

    Returns:
        None: The errors list is updated in place.
    """
    if field_name not in values or values[field_name] is None:
        return

    value = values[field_name]
    field_path = f"{prefix}.{field_name}"

    if not isinstance(value, str):
        errors.append(_error(scenario_id, field_path, value, "expected string"))
        return

    if ATTACK_TECHNIQUE_ID_RE.match(value) is None:
        errors.append(_error(scenario_id, field_path, value, "expected ATT&CK technique ID like 'T1105'"))


def _build_authored_web_request(
    parsed: ParsedScenarioYaml,
    parsed_event: ParsedYamlEvent,
    correlation_id: str,
    parent_event_id: Optional[str],
    event_types_by_id: dict[str, str],
    all_authored_event_ids: set[str],
    errors: list[ScenarioYamlValidationError],
) -> Optional[AuthoredWebRequest]:
    """
    Convert one parsed YAML web request into an AuthoredWebRequest.

    Args:
        parsed (ParsedScenarioYaml): Parsed YAML scenario that owns the event.
        parsed_event (ParsedYamlEvent): Parsed YAML web request event.
        correlation_id (str): Correlation ID resolved for the event.
        parent_event_id (Optional[str]): Parent event ID inferred from `after`.
        event_types_by_id (dict[str, str]): Authored event types by event ID.
        all_authored_event_ids (set[str]): Authored event IDs used to avoid helper ID collisions.
        errors (list[ScenarioYamlValidationError]): Validation errors to update.

    Returns:
        Optional[AuthoredWebRequest]: Authored web request when required fields are valid.
    """
    raw_event = parsed_event.raw
    actor_user_id = _required_event_string(parsed, parsed_event, "actor", errors)
    source_host_id = _required_event_string(parsed, parsed_event, "source_host", errors)
    service_id = _required_event_string(parsed, parsed_event, "service", errors)
    method = _required_event_string(parsed, parsed_event, "method", errors)
    path = _required_event_string(parsed, parsed_event, "path", errors)
    status = _event_status(raw_event)
    status_code = _optional_event_integer(parsed, parsed_event, "status_code", errors)

    if not all((actor_user_id, source_host_id, service_id, method, path)):
        return None

    dns_helper_offset = timedelta(seconds=2)
    connection_helper_offset = timedelta(seconds=1)

    # Login-driven web activity reserves a little extra time for generated DNS and connection helpers.
    if parent_event_id is not None and event_types_by_id.get(parent_event_id) == "linux_local_login":
        dns_helper_offset = timedelta(seconds=3)
        connection_helper_offset = timedelta(seconds=2)

    return AuthoredWebRequest(
        event_id=parsed_event.event_id,
        timestamp=parsed_event.timestamp,
        actor_user_id=actor_user_id,
        source_host_id=source_host_id,
        service_id=service_id,
        method=method,
        path=path,
        correlation_id=correlation_id,
        status=status,
        parent_event_id=parent_event_id,
        status_code=status_code,
        attack=_optional_dict(raw_event.get("attack")),
        metadata=_optional_dict(raw_event.get("metadata")),
        helper_event_ids=_canonical_helper_event_ids(parsed_event.event_id, all_authored_event_ids),
        dns_helper_offset=dns_helper_offset,
        connection_helper_offset=connection_helper_offset,
    )


def _build_linux_local_login_event(
    parsed: ParsedScenarioYaml,
    parsed_event: ParsedYamlEvent,
    correlation_id: str,
    parent_event_id: Optional[str],
    errors: list[ScenarioYamlValidationError],
) -> Optional[LinuxLocalLoginEvent]:
    """
    Convert one parsed YAML Linux local login into a source-neutral login event.

    Args:
        parsed (ParsedScenarioYaml): Parsed YAML scenario that owns the event.
        parsed_event (ParsedYamlEvent): Parsed YAML login event.
        correlation_id (str): Correlation ID resolved for the event.
        parent_event_id (Optional[str]): Parent event ID inferred from `after`.
        errors (list[ScenarioYamlValidationError]): Validation errors to update.

    Returns:
        Optional[LinuxLocalLoginEvent]: Login event when required fields are valid.
    """
    raw_event = parsed_event.raw
    actor_user_id = _required_event_string(parsed, parsed_event, "actor", errors)
    target_host_id = _required_event_string(parsed, parsed_event, "target_host", errors)
    login_method = _required_event_string(parsed, parsed_event, "login_method", errors)
    source_host_id = _optional_event_string(parsed, parsed_event, "source_host", errors)
    source_ip = _optional_event_string(parsed, parsed_event, "source_ip", errors)

    if not all((actor_user_id, target_host_id, login_method)):
        return None

    return LinuxLocalLoginEvent(
        event_id=parsed_event.event_id,
        scenario_id=parsed.scenario_id,
        timestamp=parsed_event.timestamp,
        status=_event_status(raw_event),
        correlation_id=correlation_id,
        parent_event_id=parent_event_id,
        actor_user_id=actor_user_id,
        target_host_id=target_host_id,
        login_method=login_method,
        source_host_id=source_host_id,
        source_ip=source_ip,
        metadata=_optional_dict(raw_event.get("metadata")),
        attack=_optional_dict(raw_event.get("attack")),
    )


def _event_correlation_id(
    parsed: ParsedScenarioYaml,
    parsed_event: ParsedYamlEvent,
    correlation_ids_by_event_id: dict[str, str],
) -> str:
    """
    Resolve or derive a deterministic correlation ID for an authored event.

    Args:
        parsed (ParsedScenarioYaml): Parsed YAML scenario that owns the event.
        parsed_event (ParsedYamlEvent): Parsed YAML event.
        correlation_ids_by_event_id (dict[str, str]): Correlation IDs for earlier events.

    Returns:
        str: Explicit, inherited, or generated correlation ID.
    """
    raw_correlation_id = parsed_event.raw.get("correlation_id")

    if isinstance(raw_correlation_id, str) and raw_correlation_id:
        return raw_correlation_id

    if parsed_event.after in correlation_ids_by_event_id:
        return correlation_ids_by_event_id[parsed_event.after]

    return f"corr-{parsed.scenario_id}-{parsed_event.source_index + 1:03d}"


def _canonical_helper_event_ids(event_id: str, all_authored_event_ids: set[str]) -> Optional[dict[str, str]]:
    """
    Derive canonical helper IDs when an authored event leaves numbered gaps for helpers.

    Args:
        event_id (str): Authored web request event ID.
        all_authored_event_ids (set[str]): Authored event IDs used to avoid helper ID collisions.

    Returns:
        Optional[dict[str, str]]: Helper ID overrides when the canonical pattern is safe.
    """
    match = re.match(r"^(?P<prefix>.+-)(?P<number>\d{3})$", event_id)

    if match is None:
        return None

    number = int(match.group("number"))

    if number < 3:
        return None

    prefix = match.group("prefix")
    dns_helper_id = f"{prefix}{number - 2:03d}"
    connection_helper_id = f"{prefix}{number - 1:03d}"

    # Do not invent helper IDs that would collide with events the author explicitly wrote.
    if dns_helper_id in all_authored_event_ids or connection_helper_id in all_authored_event_ids:
        return None

    return {
        "dns_lookup": dns_helper_id,
        "network_connection": connection_helper_id,
    }


def _event_status(raw_event: dict[str, Any]) -> str:
    """
    Return an event status with the source-neutral default applied.

    Args:
        raw_event (dict[str, Any]): Raw event mapping.

    Returns:
        str: Event status.
    """
    return raw_event.get("status", "success")


def _required_event_string(
    parsed: ParsedScenarioYaml,
    parsed_event: ParsedYamlEvent,
    field_name: str,
    errors: list[ScenarioYamlValidationError],
) -> Optional[str]:
    """
    Read a required string from a parsed YAML event.

    Args:
        parsed (ParsedScenarioYaml): Parsed YAML scenario that owns the event.
        parsed_event (ParsedYamlEvent): Parsed YAML event.
        field_name (str): Required field name.
        errors (list[ScenarioYamlValidationError]): Validation errors to update.

    Returns:
        Optional[str]: Field value when valid.
    """
    value = parsed_event.raw.get(field_name)
    field_path = _event_field_path(parsed_event, field_name)

    if value is None:
        errors.append(_error(parsed.scenario_id, field_path, None, "field is required"))
        return None

    if not isinstance(value, str):
        errors.append(_error(parsed.scenario_id, field_path, value, "expected string"))
        return None

    if not value:
        errors.append(_error(parsed.scenario_id, field_path, value, "must not be empty"))
        return None

    return value


def _optional_event_string(
    parsed: ParsedScenarioYaml,
    parsed_event: ParsedYamlEvent,
    field_name: str,
    errors: list[ScenarioYamlValidationError],
) -> Optional[str]:
    """
    Read an optional string from a parsed YAML event.

    Args:
        parsed (ParsedScenarioYaml): Parsed YAML scenario that owns the event.
        parsed_event (ParsedYamlEvent): Parsed YAML event.
        field_name (str): Optional field name.
        errors (list[ScenarioYamlValidationError]): Validation errors to update.

    Returns:
        Optional[str]: Field value when present and valid.
    """
    if field_name not in parsed_event.raw or parsed_event.raw[field_name] is None:
        return None

    value = parsed_event.raw[field_name]

    if not isinstance(value, str):
        errors.append(_error(parsed.scenario_id, _event_field_path(parsed_event, field_name), value, "expected string"))
        return None

    return value


def _optional_event_integer(
    parsed: ParsedScenarioYaml,
    parsed_event: ParsedYamlEvent,
    field_name: str,
    errors: list[ScenarioYamlValidationError],
) -> Optional[int]:
    """
    Read an optional integer from a parsed YAML event.

    Args:
        parsed (ParsedScenarioYaml): Parsed YAML scenario that owns the event.
        parsed_event (ParsedYamlEvent): Parsed YAML event.
        field_name (str): Optional field name.
        errors (list[ScenarioYamlValidationError]): Validation errors to update.

    Returns:
        Optional[int]: Field value when present and valid.
    """
    if field_name not in parsed_event.raw or parsed_event.raw[field_name] is None:
        return None

    value = parsed_event.raw[field_name]

    if not isinstance(value, int) or isinstance(value, bool):
        errors.append(
            _error(parsed.scenario_id, _event_field_path(parsed_event, field_name), value, "expected integer")
        )
        return None

    return value


def _optional_dict(value: Any) -> Optional[dict[str, Any]]:
    """
    Return a shallow dictionary copy for optional mapping values.

    Args:
        value (Any): Candidate mapping value.

    Returns:
        Optional[dict[str, Any]]: Dictionary copy, or None when absent or empty.
    """
    if not value:
        return None

    if isinstance(value, dict):
        return dict(value)

    return None


def _event_field_path(parsed_event: ParsedYamlEvent, field_name: str) -> str:
    """
    Build a field path for a parsed YAML event field.

    Args:
        parsed_event (ParsedYamlEvent): Parsed YAML event.
        field_name (str): Field name.

    Returns:
        str: Event field path.
    """
    return f"events[{parsed_event.source_index}].{field_name}"


def _validate_parsed_scenario_environment(
    parsed: ParsedScenarioYaml,
    environment_registry: Optional[EnvironmentRegistry] = None,
) -> list[ScenarioYamlValidationError]:
    """
    Validate parsed YAML events against the referenced environment.

    Args:
        parsed (ParsedScenarioYaml): Parsed YAML scenario to validate.
        environment_registry (Optional[EnvironmentRegistry]): Environment registry overrides.

    Returns:
        list[ScenarioYamlValidationError]: Environment-aware validation errors.
    """
    environment = _lookup_environment(parsed.environment_id, environment_registry=environment_registry)

    if environment is None:
        return [_error(parsed.scenario_id, "environment.id", parsed.environment_id, "unknown environment")]

    errors: list[ScenarioYamlValidationError] = []
    event_types_by_id = {event.event_id: event.event_type for event in parsed.events}

    for parsed_event in parsed.events:
        _validate_attack_metadata(parsed.scenario_id, parsed_event, errors)

        if parsed_event.event_type == "web_request":
            _validate_yaml_web_request(parsed, parsed_event, environment, event_types_by_id, errors)
        elif parsed_event.event_type == "linux_local_login":
            _validate_yaml_linux_local_login(parsed.scenario_id, parsed_event, environment, errors)

    return errors


def _validate_yaml_web_request(
    parsed: ParsedScenarioYaml,
    parsed_event: ParsedYamlEvent,
    environment: Environment,
    event_types_by_id: dict[str, str],
    errors: list[ScenarioYamlValidationError],
) -> None:
    """
    Validate one parsed YAML web request against the environment.

    Args:
        parsed (ParsedScenarioYaml): Parsed YAML scenario that owns the event.
        parsed_event (ParsedYamlEvent): Parsed YAML web request event.
        environment (Environment): Environment used for reference lookups.
        event_types_by_id (dict[str, str]): Authored event types by event ID.
        errors (list[ScenarioYamlValidationError]): Validation errors to update.

    Returns:
        None: The errors list is updated in place.
    """
    raw_event = parsed_event.raw
    actor_user_id = _string_event_value(raw_event, "actor")
    source_host_id = _string_event_value(raw_event, "source_host")
    service_id = _string_event_value(raw_event, "service")
    method = _string_event_value(raw_event, "method")
    path = _string_event_value(raw_event, "path")
    service = None

    _require_environment_user(parsed.scenario_id, parsed_event, "actor", actor_user_id, environment, errors)
    _require_environment_host(parsed.scenario_id, parsed_event, "source_host", source_host_id, environment, errors)

    if service_id is not None:
        service = environment.get_service(service_id)

        if service is None:
            errors.append(
                _error(parsed.scenario_id, _event_field_path(parsed_event, "service"), service_id, "unknown service")
            )
        elif service.application_protocol != "http":
            errors.append(
                _error(
                    parsed.scenario_id,
                    _event_field_path(parsed_event, "service"),
                    service_id,
                    "web_request events must target an HTTP service",
                )
            )
        elif environment.get_host(service.target_host_id) is None:
            errors.append(
                _error(
                    parsed.scenario_id,
                    _event_field_path(parsed_event, "service"),
                    service_id,
                    f"service target host '{service.target_host_id}' is not defined in the environment",
                )
            )

    if path is not None and not path.startswith("/"):
        errors.append(
            _error(parsed.scenario_id, _event_field_path(parsed_event, "path"), path, "path must start with '/'")
        )

    if raw_event.get("status_code") is not None:
        _validate_status_code(parsed.scenario_id, parsed_event, raw_event["status_code"], errors)

    if service is not None and service.application_protocol == "http" and method is not None and path is not None:
        route = environment.get_http_route(service.id, method, path)

        if route is None and raw_event.get("status_code") is None:
            errors.append(
                _error(
                    parsed.scenario_id,
                    _event_field_path(parsed_event, "path"),
                    path,
                    f"route '{method} {path}' is not defined for service '{service.id}'",
                )
            )

    _validate_generated_helper_timestamps(parsed, parsed_event, event_types_by_id, errors)


def _validate_yaml_linux_local_login(
    scenario_id: str,
    parsed_event: ParsedYamlEvent,
    environment: Environment,
    errors: list[ScenarioYamlValidationError],
) -> None:
    """
    Validate one parsed YAML Linux local login against the environment.

    Args:
        scenario_id (str): Scenario ID for validation errors.
        parsed_event (ParsedYamlEvent): Parsed YAML login event.
        environment (Environment): Environment used for reference lookups.
        errors (list[ScenarioYamlValidationError]): Validation errors to update.

    Returns:
        None: The errors list is updated in place.
    """
    raw_event = parsed_event.raw
    actor_user_id = _string_event_value(raw_event, "actor")
    target_host_id = _string_event_value(raw_event, "target_host")
    source_host_id = _string_event_value(raw_event, "source_host")
    user = _require_environment_user(scenario_id, parsed_event, "actor", actor_user_id, environment, errors)
    target_host = _require_environment_host(
        scenario_id, parsed_event, "target_host", target_host_id, environment, errors
    )

    if source_host_id is not None:
        _require_environment_host(scenario_id, parsed_event, "source_host", source_host_id, environment, errors)

    if user is not None and target_host is not None and raw_event.get("status", "success") == "success":
        if target_host.id not in user.login_hosts:
            errors.append(
                _error(
                    scenario_id,
                    _event_field_path(parsed_event, "target_host"),
                    target_host_id,
                    f"user '{user.id}' cannot log in to '{target_host.id}'",
                )
            )


def _validate_generated_helper_timestamps(
    parsed: ParsedScenarioYaml,
    parsed_event: ParsedYamlEvent,
    event_types_by_id: dict[str, str],
    errors: list[ScenarioYamlValidationError],
) -> None:
    """
    Validate generated DNS and connection helper timestamps for a web request.

    Args:
        parsed (ParsedScenarioYaml): Parsed YAML scenario that owns the event.
        parsed_event (ParsedYamlEvent): Parsed YAML web request event.
        event_types_by_id (dict[str, str]): Authored event types by event ID.
        errors (list[ScenarioYamlValidationError]): Validation errors to update.

    Returns:
        None: The errors list is updated in place.
    """
    dns_helper_offset = timedelta(seconds=2)
    connection_helper_offset = timedelta(seconds=1)

    if parsed_event.after is not None and event_types_by_id.get(parsed_event.after) == "linux_local_login":
        dns_helper_offset = timedelta(seconds=3)
        connection_helper_offset = timedelta(seconds=2)

    helper_times = (
        ("generated dns_lookup helper", parsed_event.timestamp - dns_helper_offset),
        ("generated network_connection helper", parsed_event.timestamp - connection_helper_offset),
    )

    for helper_name, helper_timestamp in helper_times:
        if helper_timestamp > parsed_event.timestamp:
            errors.append(
                _error(
                    parsed.scenario_id,
                    _event_field_path(parsed_event, "at"),
                    helper_timestamp.isoformat(),
                    f"{helper_name} must not sort after its authored web_request",
                )
            )

        if helper_timestamp < parsed.start_time:
            errors.append(
                _error(
                    parsed.scenario_id,
                    _event_field_path(parsed_event, "at"),
                    helper_timestamp.isoformat(),
                    f"{helper_name} must stay inside time_range",
                )
            )

        if parsed.end_time is not None and helper_timestamp > parsed.end_time:
            errors.append(
                _error(
                    parsed.scenario_id,
                    _event_field_path(parsed_event, "at"),
                    helper_timestamp.isoformat(),
                    f"{helper_name} must stay inside time_range",
                )
            )


def _validate_attack_metadata(
    scenario_id: str,
    parsed_event: ParsedYamlEvent,
    errors: list[ScenarioYamlValidationError],
) -> None:
    """
    Validate optional ATT&CK-style metadata.

    Args:
        scenario_id (str): Scenario ID for validation errors.
        parsed_event (ParsedYamlEvent): Parsed YAML event.
        errors (list[ScenarioYamlValidationError]): Validation errors to update.

    Returns:
        None: The errors list is updated in place.
    """
    attack = parsed_event.raw.get("attack")

    if attack is None:
        return

    if not isinstance(attack, dict):
        errors.append(_error(scenario_id, _event_field_path(parsed_event, "attack"), attack, "expected mapping"))
        return

    technique_id = attack.get("technique_id")

    if technique_id is not None:
        if not isinstance(technique_id, str):
            errors.append(
                _error(
                    scenario_id,
                    f"{_event_field_path(parsed_event, 'attack')}.technique_id",
                    technique_id,
                    "expected string",
                )
            )
        elif ATTACK_TECHNIQUE_ID_RE.match(technique_id) is None:
            errors.append(
                _error(
                    scenario_id,
                    f"{_event_field_path(parsed_event, 'attack')}.technique_id",
                    technique_id,
                    "expected ATT&CK technique ID like 'T1105'",
                )
            )


def _validate_status_code(
    scenario_id: str,
    parsed_event: ParsedYamlEvent,
    value: Any,
    errors: list[ScenarioYamlValidationError],
) -> None:
    """
    Validate an optional HTTP status code.

    Args:
        scenario_id (str): Scenario ID for validation errors.
        parsed_event (ParsedYamlEvent): Parsed YAML event.
        value (Any): Status code value.
        errors (list[ScenarioYamlValidationError]): Validation errors to update.

    Returns:
        None: The errors list is updated in place.
    """
    if not isinstance(value, int) or isinstance(value, bool):
        return

    if value < 100 or value > 599:
        errors.append(
            _error(
                scenario_id,
                _event_field_path(parsed_event, "status_code"),
                value,
                "status_code must be between 100 and 599",
            )
        )


def _require_environment_user(
    scenario_id: str,
    parsed_event: ParsedYamlEvent,
    field_name: str,
    user_id: Optional[str],
    environment: Environment,
    errors: list[ScenarioYamlValidationError],
):
    """
    Resolve a user reference and append a validation error when missing.

    Args:
        scenario_id (str): Scenario ID for validation errors.
        parsed_event (ParsedYamlEvent): Parsed YAML event.
        field_name (str): YAML field name containing the user reference.
        user_id (Optional[str]): User reference value.
        environment (Environment): Environment used for reference lookup.
        errors (list[ScenarioYamlValidationError]): Validation errors to update.

    Returns:
        Optional[User]: Environment user when resolved.
    """
    if user_id is None:
        return None

    user = environment.get_user(user_id)

    if user is None:
        errors.append(_error(scenario_id, _event_field_path(parsed_event, field_name), user_id, "unknown user"))

    return user


def _require_environment_host(
    scenario_id: str,
    parsed_event: ParsedYamlEvent,
    field_name: str,
    host_id: Optional[str],
    environment: Environment,
    errors: list[ScenarioYamlValidationError],
):
    """
    Resolve a host reference and append a validation error when missing.

    Args:
        scenario_id (str): Scenario ID for validation errors.
        parsed_event (ParsedYamlEvent): Parsed YAML event.
        field_name (str): YAML field name containing the host reference.
        host_id (Optional[str]): Host reference value.
        environment (Environment): Environment used for reference lookup.
        errors (list[ScenarioYamlValidationError]): Validation errors to update.

    Returns:
        Optional[Host]: Environment host when resolved.
    """
    if host_id is None:
        return None

    host = environment.get_host(host_id)

    if host is None:
        errors.append(_error(scenario_id, _event_field_path(parsed_event, field_name), host_id, "unknown host"))

    return host


def _string_event_value(raw_event: dict[str, Any], field_name: str) -> Optional[str]:
    """
    Return an event field only when it is already a string.

    Args:
        raw_event (dict[str, Any]): Raw event mapping.
        field_name (str): Field to read.

    Returns:
        Optional[str]: String value when present.
    """
    value = raw_event.get(field_name)

    if isinstance(value, str):
        return value

    return None


def _load_yaml_document(text: str) -> dict[str, Any]:
    """
    Safely load exactly one YAML document from text.

    Args:
        text (str): YAML scenario document text.

    Returns:
        dict[str, Any]: Parsed YAML document mapping.
    """
    if not text.strip():
        raise ScenarioYamlError([_error(None, "<document>", None, "scenario YAML document must not be empty")])

    try:
        import yaml
    except ImportError as exc:
        raise ScenarioYamlError([_error(None, "<document>", None, "PyYAML is required to parse YAML")]) from exc

    try:
        documents = list(yaml.safe_load_all(text))
    except yaml.YAMLError as exc:
        raise ScenarioYamlError([_error(None, "<document>", text, f"YAML parser error: {exc}")]) from exc

    if len(documents) != 1:
        raise ScenarioYamlError(
            [_error(None, "<document>", len(documents), "multi-document YAML is not supported yet")]
        )

    document = documents[0]

    if document is None:
        raise ScenarioYamlError([_error(None, "<document>", None, "scenario YAML document must not be empty")])

    if not isinstance(document, dict):
        raise ScenarioYamlError([_error(None, "<document>", document, "scenario YAML document must be a mapping")])

    return document


def _parse_environment(
    value: Any,
    scenario_id: Optional[str],
    errors: list[ScenarioYamlValidationError],
    environment_registry: Optional[EnvironmentRegistry] = None,
) -> tuple[Optional[str], Optional[str]]:
    """
    Parse and validate the top-level environment reference.

    Args:
        value (Any): Raw environment field value.
        scenario_id (Optional[str]): Scenario ID for validation errors.
        errors (list[ScenarioYamlValidationError]): Validation errors to update.
        environment_registry (Optional[EnvironmentRegistry]): Environment registry overrides.

    Returns:
        tuple[Optional[str], Optional[str]]: Environment ID and version when valid enough to continue.
    """
    if value is None:
        errors.append(_error(scenario_id, "environment", None, "field is required"))
        return None, None

    if isinstance(value, str):
        environment_id = value
        environment = _lookup_environment(environment_id, environment_registry=environment_registry)

        if environment is None:
            errors.append(_error(scenario_id, "environment", value, "unknown environment"))
            return environment_id, None

        return environment.id, environment.version

    if not isinstance(value, dict):
        errors.append(_error(scenario_id, "environment", value, "expected string or mapping"))
        return None, None

    allowed_fields = {"id", "version"}
    _validate_unknown_fields(value, allowed_fields, "environment", scenario_id, errors)
    environment_id = _required_string(value, "id", scenario_id, errors, prefix="environment")
    environment_version = _optional_string(value, "version", scenario_id, errors, prefix="environment")

    if environment_id is None:
        return None, environment_version

    environment = _lookup_environment(environment_id, environment_registry=environment_registry)

    if environment is None:
        errors.append(_error(scenario_id, "environment.id", environment_id, "unknown environment"))
        return environment_id, environment_version

    if environment_version is not None and environment_version != environment.version:
        errors.append(
            _error(
                scenario_id,
                "environment.version",
                environment_version,
                f"supported version for '{environment.id}' is '{environment.version}'",
            )
        )

    return environment.id, environment_version or environment.version


def _parse_time_range(
    value: Any,
    scenario_id: Optional[str],
    errors: list[ScenarioYamlValidationError],
) -> tuple[Optional[datetime], Optional[datetime]]:
    """
    Parse and validate the top-level time range.

    Args:
        value (Any): Raw time_range field value.
        scenario_id (Optional[str]): Scenario ID for validation errors.
        errors (list[ScenarioYamlValidationError]): Validation errors to update.

    Returns:
        tuple[Optional[datetime], Optional[datetime]]: Start and optional end timestamps.
    """
    if value is None:
        errors.append(_error(scenario_id, "time_range", None, "field is required"))
        return None, None

    if not isinstance(value, dict):
        errors.append(_error(scenario_id, "time_range", value, "expected mapping"))
        return None, None

    _validate_unknown_fields(value, {"start", "end"}, "time_range", scenario_id, errors)

    start_time = _parse_datetime_field(value.get("start"), "time_range.start", scenario_id, errors, required=True)
    end_time = _parse_datetime_field(value.get("end"), "time_range.end", scenario_id, errors, required=False)

    if start_time is not None and end_time is not None and end_time < start_time:
        errors.append(_error(scenario_id, "time_range.end", value.get("end"), "end must not be before start"))

    return start_time, end_time


def _parse_output_families(
    value: Any,
    scenario_id: Optional[str],
    errors: list[ScenarioYamlValidationError],
) -> tuple[str, ...]:
    """
    Parse and validate requested output families.

    Args:
        value (Any): Raw output_families field value.
        scenario_id (Optional[str]): Scenario ID for validation errors.
        errors (list[ScenarioYamlValidationError]): Validation errors to update.

    Returns:
        tuple[str, ...]: Requested output families.
    """
    if value is None:
        return DEFAULT_OUTPUT_FAMILIES

    if not isinstance(value, list):
        errors.append(_error(scenario_id, "output_families", value, "expected list of strings"))
        return DEFAULT_OUTPUT_FAMILIES

    if not value:
        errors.append(_error(scenario_id, "output_families", value, "must include at least one output family"))
        return DEFAULT_OUTPUT_FAMILIES

    output_families = []

    for index, output_family in enumerate(value):
        field_path = f"output_families[{index}]"

        if not isinstance(output_family, str):
            errors.append(_error(scenario_id, field_path, output_family, "expected string"))
            continue

        _validate_safe_identifier(output_family, field_path, scenario_id, errors)
        output_families.append(output_family)

    return tuple(output_families)


def _parse_events(
    value: Any,
    scenario_id: Optional[str],
    start_time: Optional[datetime],
    end_time: Optional[datetime],
    errors: list[ScenarioYamlValidationError],
) -> tuple[ParsedYamlEvent, ...]:
    """
    Parse authored events and resolve their timestamps.

    Args:
        value (Any): Raw events field value.
        scenario_id (Optional[str]): Scenario ID for validation errors.
        start_time (Optional[datetime]): Scenario start time used for offsets.
        end_time (Optional[datetime]): Optional scenario end time for bounds checks.
        errors (list[ScenarioYamlValidationError]): Validation errors to update.

    Returns:
        tuple[ParsedYamlEvent, ...]: Parsed events with resolved timing.
    """
    if value is None:
        errors.append(_error(scenario_id, "events", None, "field is required"))
        return ()

    if not isinstance(value, list):
        errors.append(_error(scenario_id, "events", value, "expected list of event mappings"))
        return ()

    if not value:
        errors.append(_error(scenario_id, "events", value, "must include at least one event"))
        return ()

    parsed_events = []
    authored_timestamps: dict[str, datetime] = {}
    seen_event_ids = set()

    for index, event_document in enumerate(value):
        field_path = f"events[{index}]"

        if not isinstance(event_document, dict):
            errors.append(_error(scenario_id, field_path, event_document, "expected mapping"))
            continue

        event_type = _required_string(event_document, "type", scenario_id, errors, prefix=field_path)
        event_id = _required_string(event_document, "id", scenario_id, errors, prefix=field_path)

        if event_id is not None:
            _validate_safe_identifier(event_id, f"{field_path}.id", scenario_id, errors)

            if event_id in seen_event_ids:
                errors.append(_error(scenario_id, f"{field_path}.id", event_id, "duplicate event ID"))

            seen_event_ids.add(event_id)

        if event_type is not None:
            _validate_event_type_fields(event_document, event_type, field_path, scenario_id, errors)

            if event_type not in SUPPORTED_EVENT_TYPES:
                errors.append(_error(scenario_id, f"{field_path}.type", event_type, "unsupported event type"))

        _validate_common_event_fields(event_document, field_path, scenario_id, errors)
        timestamp, after, delay = _parse_event_timing(
            event_document,
            field_path,
            scenario_id,
            start_time,
            authored_timestamps,
            errors,
        )

        if timestamp is not None and end_time is not None and timestamp > end_time:
            errors.append(
                _error(scenario_id, f"{field_path}.at", timestamp.isoformat(), "event is after time_range.end")
            )

        if event_id is not None and timestamp is not None:
            authored_timestamps[event_id] = timestamp

        if event_id is not None and event_type is not None and timestamp is not None:
            parsed_events.append(
                ParsedYamlEvent(
                    event_id=event_id,
                    event_type=event_type,
                    timestamp=timestamp,
                    source_index=index,
                    raw=dict(event_document),
                    after=after,
                    delay=delay,
                )
            )

    return tuple(parsed_events)


def _parse_event_timing(
    event_document: dict[str, Any],
    field_path: str,
    scenario_id: Optional[str],
    start_time: Optional[datetime],
    authored_timestamps: dict[str, datetime],
    errors: list[ScenarioYamlValidationError],
) -> tuple[Optional[datetime], Optional[str], Optional[timedelta]]:
    """
    Resolve an authored event timestamp from absolute, relative, or dependency-based fields.

    Args:
        event_document (dict[str, Any]): Raw event mapping.
        field_path (str): Event field path prefix.
        scenario_id (Optional[str]): Scenario ID for validation errors.
        start_time (Optional[datetime]): Scenario start time used for offsets.
        authored_timestamps (dict[str, datetime]): Earlier event timestamps by event ID.
        errors (list[ScenarioYamlValidationError]): Validation errors to update.

    Returns:
        tuple[Optional[datetime], Optional[str], Optional[timedelta]]: Timestamp, after reference, and delay.
    """
    at_value = event_document.get("at")
    after = event_document.get("after")
    delay_value = event_document.get("delay")

    if at_value is None and after is None:
        errors.append(_error(scenario_id, field_path, None, "expected either 'at' or 'after'"))
        return None, None, None

    if delay_value is not None and after is None:
        errors.append(_error(scenario_id, f"{field_path}.delay", delay_value, "delay may appear only with after"))

    if after is not None and not isinstance(after, str):
        errors.append(_error(scenario_id, f"{field_path}.after", after, "expected event ID string"))
        after = None

    if after is not None and after not in authored_timestamps:
        errors.append(_error(scenario_id, f"{field_path}.after", after, "event is not defined before this event"))

    delay = None

    if delay_value is not None:
        delay = _parse_duration(delay_value, f"{field_path}.delay", scenario_id, errors, allow_leading_plus=False)

    if at_value is not None:
        return _parse_event_at(at_value, f"{field_path}.at", scenario_id, start_time, errors), after, delay

    if after not in authored_timestamps:
        return None, after, delay

    if delay is None:
        delay = timedelta(0)

    return authored_timestamps[after] + delay, after, delay


def _parse_event_at(
    value: Any,
    field_path: str,
    scenario_id: Optional[str],
    start_time: Optional[datetime],
    errors: list[ScenarioYamlValidationError],
) -> Optional[datetime]:
    """
    Parse one event `at` value.

    Args:
        value (Any): Raw event at value.
        field_path (str): Field path for errors.
        scenario_id (Optional[str]): Scenario ID for validation errors.
        start_time (Optional[datetime]): Scenario start time used for relative offsets.
        errors (list[ScenarioYamlValidationError]): Validation errors to update.

    Returns:
        Optional[datetime]: Resolved timestamp when valid.
    """
    if isinstance(value, str) and value.startswith("+"):
        if start_time is None:
            errors.append(_error(scenario_id, field_path, value, "relative offsets require time_range.start"))
            return None

        duration = _parse_duration(value, field_path, scenario_id, errors, allow_leading_plus=True)

        if duration is None:
            return None

        return start_time + duration

    return _parse_datetime_field(value, field_path, scenario_id, errors, required=True)


def _parse_duration(
    value: Any,
    field_path: str,
    scenario_id: Optional[str],
    errors: list[ScenarioYamlValidationError],
    allow_leading_plus: bool,
) -> Optional[timedelta]:
    """
    Parse a simple duration with one unit.

    Args:
        value (Any): Raw duration value.
        field_path (str): Field path for errors.
        scenario_id (Optional[str]): Scenario ID for validation errors.
        errors (list[ScenarioYamlValidationError]): Validation errors to update.
        allow_leading_plus (bool): Whether a leading plus sign is valid for this field.

    Returns:
        Optional[timedelta]: Parsed duration when valid.
    """
    if not isinstance(value, str):
        errors.append(_error(scenario_id, field_path, value, "expected duration string"))
        return None

    if value.startswith("+") and not allow_leading_plus:
        errors.append(_error(scenario_id, field_path, value, "delay durations must not use a leading plus sign"))
        return None

    match = DURATION_RE.match(value)

    if match is None:
        errors.append(_error(scenario_id, field_path, value, "expected a simple duration such as '+2s' or '500ms'"))
        return None

    amount = int(match.group("amount"))
    unit = match.group("unit")

    if unit == "ms":
        return timedelta(milliseconds=amount)

    if unit == "s":
        return timedelta(seconds=amount)

    if unit == "m":
        return timedelta(minutes=amount)

    return timedelta(hours=amount)


def _parse_datetime_field(
    value: Any,
    field_path: str,
    scenario_id: Optional[str],
    errors: list[ScenarioYamlValidationError],
    required: bool,
) -> Optional[datetime]:
    """
    Parse a timezone-aware datetime field.

    Args:
        value (Any): Raw datetime field value.
        field_path (str): Field path for errors.
        scenario_id (Optional[str]): Scenario ID for validation errors.
        errors (list[ScenarioYamlValidationError]): Validation errors to update.
        required (bool): Whether a missing value should be reported as an error.

    Returns:
        Optional[datetime]: UTC-normalized datetime when valid.
    """
    if value is None:
        if required:
            errors.append(_error(scenario_id, field_path, None, "field is required"))

        return None

    if isinstance(value, datetime):
        return _normalize_datetime(value, field_path, scenario_id, errors)

    if isinstance(value, date):
        errors.append(_error(scenario_id, field_path, value.isoformat(), "expected datetime, not date"))
        return None

    if not isinstance(value, str):
        errors.append(_error(scenario_id, field_path, value, "expected timezone-aware ISO 8601 datetime string"))
        return None

    try:
        parsed_value = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        errors.append(_error(scenario_id, field_path, value, "expected timezone-aware ISO 8601 datetime string"))
        return None

    return _normalize_datetime(parsed_value, field_path, scenario_id, errors)


def _normalize_datetime(
    value: datetime,
    field_path: str,
    scenario_id: Optional[str],
    errors: list[ScenarioYamlValidationError],
) -> Optional[datetime]:
    """
    Normalize a datetime and report naive values as validation errors.

    Args:
        value (datetime): Datetime value to normalize.
        field_path (str): Field path for errors.
        scenario_id (Optional[str]): Scenario ID for validation errors.
        errors (list[ScenarioYamlValidationError]): Validation errors to update.

    Returns:
        Optional[datetime]: UTC-normalized datetime when valid.
    """
    try:
        return normalize_utc_timestamp(value)
    except ValueError:
        errors.append(_error(scenario_id, field_path, value.isoformat(), "timestamp must include a timezone"))
        return None


def _validate_top_level_fields(
    document: dict[str, Any],
    scenario_id: Optional[str],
    errors: list[ScenarioYamlValidationError],
) -> None:
    """
    Validate unknown top-level fields.

    Args:
        document (dict[str, Any]): Parsed YAML document.
        scenario_id (Optional[str]): Scenario ID for validation errors.
        errors (list[ScenarioYamlValidationError]): Validation errors to update.

    Returns:
        None: The errors list is updated in place.
    """
    _validate_unknown_fields(document, TOP_LEVEL_FIELDS, "", scenario_id, errors)

    if "noise_profiles" in document:
        errors.append(
            _error(scenario_id, "noise_profiles", document["noise_profiles"], "noise_profiles is not supported yet")
        )


def _validate_event_type_fields(
    event_document: dict[str, Any],
    event_type: str,
    field_path: str,
    scenario_id: Optional[str],
    errors: list[ScenarioYamlValidationError],
) -> None:
    """
    Validate unknown fields for an event type.

    Args:
        event_document (dict[str, Any]): Raw event mapping.
        event_type (str): Authored event type.
        field_path (str): Event field path prefix.
        scenario_id (Optional[str]): Scenario ID for validation errors.
        errors (list[ScenarioYamlValidationError]): Validation errors to update.

    Returns:
        None: The errors list is updated in place.
    """
    if event_type not in SUPPORTED_EVENT_TYPES:
        return

    allowed_fields = COMMON_EVENT_FIELDS | EVENT_TYPE_FIELDS[event_type]
    _validate_unknown_fields(event_document, allowed_fields, field_path, scenario_id, errors)


def _validate_common_event_fields(
    event_document: dict[str, Any],
    field_path: str,
    scenario_id: Optional[str],
    errors: list[ScenarioYamlValidationError],
) -> None:
    """
    Validate common event field values that do not require environment lookups.

    Args:
        event_document (dict[str, Any]): Raw event mapping.
        field_path (str): Event field path prefix.
        scenario_id (Optional[str]): Scenario ID for validation errors.
        errors (list[ScenarioYamlValidationError]): Validation errors to update.

    Returns:
        None: The errors list is updated in place.
    """
    status = event_document.get("status")
    correlation_id = event_document.get("correlation_id")

    if status is not None and status not in VALID_STATUSES:
        errors.append(_error(scenario_id, f"{field_path}.status", status, "unsupported status value"))

    if correlation_id is not None:
        if not isinstance(correlation_id, str):
            errors.append(_error(scenario_id, f"{field_path}.correlation_id", correlation_id, "expected string"))
        else:
            _validate_safe_identifier(correlation_id, f"{field_path}.correlation_id", scenario_id, errors)


def _validate_unknown_fields(
    values: dict[str, Any],
    allowed_fields: Union[frozenset[str], set[str]],
    prefix: str,
    scenario_id: Optional[str],
    errors: list[ScenarioYamlValidationError],
) -> None:
    """
    Report unknown fields in a mapping.

    Args:
        values (dict[str, Any]): Mapping to inspect.
        allowed_fields (frozenset[str] | set[str]): Allowed field names.
        prefix (str): Field path prefix.
        scenario_id (Optional[str]): Scenario ID for validation errors.
        errors (list[ScenarioYamlValidationError]): Validation errors to update.

    Returns:
        None: The errors list is updated in place.
    """
    for field_name in values:
        if field_name in allowed_fields:
            continue

        field_path = f"{prefix}.{field_name}" if prefix else field_name
        errors.append(_error(scenario_id, field_path, values[field_name], "unknown field"))


def _required_string(
    values: dict[str, Any],
    field_name: str,
    scenario_id: Optional[str],
    errors: list[ScenarioYamlValidationError],
    prefix: str = "",
) -> Optional[str]:
    """
    Read a required string field.

    Args:
        values (dict[str, Any]): Mapping to read.
        field_name (str): Field name to require.
        scenario_id (Optional[str]): Scenario ID for validation errors.
        errors (list[ScenarioYamlValidationError]): Validation errors to update.
        prefix (str): Optional field path prefix.

    Returns:
        Optional[str]: Field value when valid.
    """
    field_path = _join_path(prefix, field_name)
    value = values.get(field_name)

    if value is None:
        errors.append(_error(scenario_id, field_path, None, "field is required"))
        return None

    if not isinstance(value, str):
        errors.append(_error(scenario_id, field_path, value, "expected string"))
        return None

    if not value:
        errors.append(_error(scenario_id, field_path, value, "must not be empty"))
        return None

    return value


def _optional_string(
    values: dict[str, Any],
    field_name: str,
    scenario_id: Optional[str],
    errors: list[ScenarioYamlValidationError],
    prefix: str = "",
) -> Optional[str]:
    """
    Read an optional string field.

    Args:
        values (dict[str, Any]): Mapping to read.
        field_name (str): Field name to read.
        scenario_id (Optional[str]): Scenario ID for validation errors.
        errors (list[ScenarioYamlValidationError]): Validation errors to update.
        prefix (str): Optional field path prefix.

    Returns:
        Optional[str]: Field value when present and valid.
    """
    if field_name not in values:
        return None

    field_path = _join_path(prefix, field_name)
    value = values[field_name]

    if value is None:
        return None

    if not isinstance(value, str):
        errors.append(_error(scenario_id, field_path, value, "expected string"))
        return None

    return value


def _required_integer(
    values: dict[str, Any],
    field_name: str,
    scenario_id: Optional[str],
    errors: list[ScenarioYamlValidationError],
) -> Optional[int]:
    """
    Read a required integer field.

    Args:
        values (dict[str, Any]): Mapping to read.
        field_name (str): Field name to require.
        scenario_id (Optional[str]): Scenario ID for validation errors.
        errors (list[ScenarioYamlValidationError]): Validation errors to update.

    Returns:
        Optional[int]: Field value when valid.
    """
    value = values.get(field_name)

    if value is None:
        errors.append(_error(scenario_id, field_name, None, "field is required"))
        return None

    if not isinstance(value, int) or isinstance(value, bool):
        errors.append(_error(scenario_id, field_name, value, "expected integer"))
        return None

    return value


def _optional_mapping(
    values: dict[str, Any],
    field_name: str,
    scenario_id: Optional[str],
    errors: list[ScenarioYamlValidationError],
) -> Optional[dict[str, Any]]:
    """
    Read an optional mapping field.

    Args:
        values (dict[str, Any]): Mapping to read.
        field_name (str): Field name to read.
        scenario_id (Optional[str]): Scenario ID for validation errors.
        errors (list[ScenarioYamlValidationError]): Validation errors to update.

    Returns:
        Optional[dict[str, Any]]: Mapping copy when present and valid.
    """
    if field_name not in values or values[field_name] is None:
        return None

    value = values[field_name]

    if not isinstance(value, dict):
        errors.append(_error(scenario_id, field_name, value, "expected mapping"))
        return None

    return dict(value)


def _optional_mapping_sequence(
    values: dict[str, Any],
    field_name: str,
    scenario_id: Optional[str],
    errors: list[ScenarioYamlValidationError],
) -> tuple[dict[str, Any], ...]:
    """
    Read an optional list of mapping fields.

    Args:
        values (dict[str, Any]): Mapping to read.
        field_name (str): Field name to read.
        scenario_id (Optional[str]): Scenario ID for validation errors.
        errors (list[ScenarioYamlValidationError]): Validation errors to update.

    Returns:
        tuple[dict[str, Any], ...]: Mapping copies when present and valid.
    """
    if field_name not in values or values[field_name] is None:
        return ()

    value = values[field_name]

    if not isinstance(value, list):
        errors.append(_error(scenario_id, field_name, value, "expected list of mappings"))
        return ()

    output = []

    for index, item in enumerate(value):
        if not isinstance(item, dict):
            errors.append(_error(scenario_id, f"{field_name}[{index}]", item, "expected mapping"))
            continue

        output.append(dict(item))

    return tuple(output)


def _validate_safe_identifier(
    value: str,
    field_path: str,
    scenario_id: Optional[str],
    errors: list[ScenarioYamlValidationError],
) -> None:
    """
    Validate an author-facing identifier for filesystem-safe use.

    Args:
        value (str): Identifier to validate.
        field_path (str): Field path for errors.
        scenario_id (Optional[str]): Scenario ID for validation errors.
        errors (list[ScenarioYamlValidationError]): Validation errors to update.

    Returns:
        None: The errors list is updated in place.
    """
    try:
        validate_path_component(value)
    except ValueError as exc:
        errors.append(_error(scenario_id, field_path, value, str(exc)))
        return

    if SAFE_IDENTIFIER_RE.match(value) is None:
        errors.append(
            _error(
                scenario_id,
                field_path,
                value,
                "expected lowercase ASCII letters, digits, hyphens, underscores, or dots",
            )
        )


def _require_mapping(
    value: Any,
    field_path: str,
    scenario_id: Optional[str],
    errors: list[ScenarioYamlValidationError],
) -> None:
    """
    Validate that a value is a mapping.

    Args:
        value (Any): Value to inspect.
        field_path (str): Field path for errors.
        scenario_id (Optional[str]): Scenario ID for validation errors.
        errors (list[ScenarioYamlValidationError]): Validation errors to update.

    Returns:
        None: The errors list is updated in place.
    """
    if not isinstance(value, dict):
        errors.append(_error(scenario_id, field_path, value, "expected mapping"))


def _lookup_environment(
    environment_id: str,
    environment_registry: Optional[EnvironmentRegistry] = None,
) -> Optional[Environment]:
    """
    Look up an environment from caller registry or supported built-ins.

    Args:
        environment_id (str): Environment identifier to resolve.
        environment_registry (Optional[EnvironmentRegistry]): Environment registry overrides.

    Returns:
        Optional[Environment]: Matching environment when supported.
    """
    if environment_registry is not None and environment_id in environment_registry:
        return environment_registry[environment_id]

    if environment_id == "linux-mini-lab":
        return build_linux_mini_lab()

    return None


def _default_run_id(scenario: Scenario) -> str:
    """
    Build a deterministic default run ID for a YAML-generated scenario.

    Args:
        scenario (Scenario): Scenario being generated.

    Returns:
        str: Stable run ID.
    """
    return f"run-{scenario.id}"


def _scenario_id_for_errors(document: Any) -> Optional[str]:
    """
    Return the scenario ID from a partially parsed document when available.

    Args:
        document (Any): Parsed YAML document.

    Returns:
        Optional[str]: Scenario ID when present as a string.
    """
    if isinstance(document, dict) and isinstance(document.get("id"), str):
        return document["id"]

    return None


def _join_path(prefix: str, field_name: str) -> str:
    """
    Join a field path prefix and field name.

    Args:
        prefix (str): Optional field path prefix.
        field_name (str): Field name.

    Returns:
        str: Combined field path.
    """
    if prefix:
        return f"{prefix}.{field_name}"

    return field_name


def _error(
    scenario_id: Optional[str],
    field_path: str,
    invalid_value: Any,
    reason: str,
) -> ScenarioYamlValidationError:
    """
    Build one YAML validation error.

    Args:
        scenario_id (Optional[str]): Scenario ID when known.
        field_path (str): Field path containing the error.
        invalid_value (Any): Invalid value.
        reason (str): Actionable reason.

    Returns:
        ScenarioYamlValidationError: Validation error object.
    """
    return ScenarioYamlValidationError(
        scenario_id=scenario_id,
        field_path=field_path,
        invalid_value=invalid_value,
        reason=reason,
    )


__all__ = [
    "DEFAULT_OUTPUT_FAMILIES",
    "ParsedScenarioYaml",
    "ParsedYamlEvent",
    "SUPPORTED_SCHEMA_VERSION",
    "ScenarioYamlError",
    "ScenarioYamlValidationError",
    "build_scenario_from_parsed_yaml",
    "build_scenario_from_yaml",
    "build_scenario_from_yaml_text",
    "generate_from_yaml",
    "load_scenario_yaml",
    "load_scenario_from_yaml",
    "parse_scenario_yaml_document",
    "parse_scenario_yaml_text",
]
