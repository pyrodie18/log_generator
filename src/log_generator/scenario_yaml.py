"""
YAML scenario loading and structural validation.
"""

from dataclasses import dataclass
from datetime import date, datetime, timedelta
from pathlib import Path
import re
from typing import Any, Optional, Union

from log_generator.core.environment import Environment, build_linux_mini_lab
from log_generator.core.events import VALID_STATUSES, normalize_utc_timestamp
from log_generator.output.jsonl import validate_path_component


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


def load_scenario_yaml(path: Path) -> ParsedScenarioYaml:
    """
    Load and validate a single YAML scenario document from disk.

    Args:
        path (Path): YAML scenario file to read.

    Returns:
        ParsedScenarioYaml: Parsed scenario with resolved top-level metadata and event timing.
    """
    return parse_scenario_yaml_text(path.read_text(encoding="utf-8"))


def parse_scenario_yaml_text(text: str) -> ParsedScenarioYaml:
    """
    Parse and validate a single YAML scenario document from text.

    Args:
        text (str): YAML scenario document text.

    Returns:
        ParsedScenarioYaml: Parsed scenario with resolved top-level metadata and event timing.
    """
    document = _load_yaml_document(text)

    return parse_scenario_yaml_document(document)


def parse_scenario_yaml_document(document: dict[str, Any]) -> ParsedScenarioYaml:
    """
    Validate a parsed YAML mapping and return a structured scenario document.

    Args:
        document (dict[str, Any]): Parsed YAML mapping.

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
    environment_id, environment_version = _parse_environment(document.get("environment"), scenario_id, errors)
    start_time, end_time = _parse_time_range(document.get("time_range"), scenario_id, errors)
    output_families = _parse_output_families(document.get("output_families"), scenario_id, errors)
    events = _parse_events(document.get("events"), scenario_id, start_time, end_time, errors)
    description = _optional_string(document, "description", scenario_id, errors)
    metadata = _optional_mapping(document, "metadata", scenario_id, errors)
    attack_chain = _optional_mapping_sequence(document, "attack_chain", scenario_id, errors)
    answer_key = _optional_mapping_sequence(document, "answer_key", scenario_id, errors)

    if errors:
        raise ScenarioYamlError(errors)

    return ParsedScenarioYaml(
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
) -> tuple[Optional[str], Optional[str]]:
    """
    Parse and validate the top-level environment reference.

    Args:
        value (Any): Raw environment field value.
        scenario_id (Optional[str]): Scenario ID for validation errors.
        errors (list[ScenarioYamlValidationError]): Validation errors to update.

    Returns:
        tuple[Optional[str], Optional[str]]: Environment ID and version when valid enough to continue.
    """
    if value is None:
        errors.append(_error(scenario_id, "environment", None, "field is required"))
        return None, None

    if isinstance(value, str):
        environment_id = value
        environment = _lookup_environment(environment_id)

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

    environment = _lookup_environment(environment_id)

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


def _lookup_environment(environment_id: str) -> Optional[Environment]:
    """
    Look up a supported built-in environment.

    Args:
        environment_id (str): Environment identifier to resolve.

    Returns:
        Optional[Environment]: Matching environment when supported.
    """
    if environment_id == "linux-mini-lab":
        return build_linux_mini_lab()

    return None


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
    "load_scenario_yaml",
    "parse_scenario_yaml_document",
    "parse_scenario_yaml_text",
]
