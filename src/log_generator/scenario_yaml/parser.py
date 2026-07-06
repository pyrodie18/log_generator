"""
YAML scenario document loading and structural parsing.
"""

from datetime import date, datetime, timedelta
from typing import Any, Optional

from log_generator.core.events import VALID_STATUSES, normalize_utc_timestamp
from log_generator.core.value_checks import is_ip_address
from log_generator.scenario_yaml.common import (
    _error,
    _lookup_environment,
    _optional_mapping,
    _optional_mapping_sequence,
    _optional_string,
    _require_mapping,
    _required_integer,
    _required_string,
    _scenario_id_for_errors,
    _validate_safe_identifier,
    _validate_unknown_fields,
)
from log_generator.scenario_yaml.constants import (
    DEFAULT_OUTPUT_FAMILIES,
    DURATION_RE,
    SUPPORTED_OUTPUT_FAMILIES,
    SUPPORTED_SCHEMA_VERSION,
    TOP_LEVEL_FIELDS,
    UNSUPPORTED_SOURCE_SPECIFIC_OUTPUT_FAMILIES,
)
from log_generator.scenario_yaml.event_types import get_event_type
from log_generator.scenario_yaml.errors import ScenarioYamlError, ScenarioYamlValidationError
from log_generator.scenario_yaml.models import EnvironmentRegistry, ParsedScenarioYaml, ParsedYamlEvent
from log_generator.scenario_yaml.validators import _validate_parsed_scenario_environment


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

    # Confirm the root shape before reading fields so later validation can assume mapping access is safe.
    _require_mapping(document, "<document>", scenario_id, errors)

    if errors:
        raise ScenarioYamlError(errors)

    # Collect all structural top-level errors first so authors get a complete report in one run.
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
        # Stop before environment-aware validation when required structural fields are missing.
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
        # Environment checks need a complete parsed scenario because they resolve cross-field references.
        raise ScenarioYamlError(environment_errors)

    return parsed


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

    # Multi-document files make manifest identity ambiguous, so the loader accepts exactly one document.
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

        # String shorthand uses the environment's current version so fixtures can stay compact.
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
    seen_output_families = set()

    for index, output_family in enumerate(value):
        field_path = f"output_families[{index}]"

        if not isinstance(output_family, str):
            errors.append(_error(scenario_id, field_path, output_family, "expected string"))
            continue

        # Output family names become path components, so validate filesystem safety before support checks.
        _validate_safe_identifier(output_family, field_path, scenario_id, errors)

        if output_family in UNSUPPORTED_SOURCE_SPECIFIC_OUTPUT_FAMILIES:
            errors.append(
                _error(
                    scenario_id,
                    field_path,
                    output_family,
                    "source-specific output family is not supported yet",
                )
            )
            continue

        if output_family not in SUPPORTED_OUTPUT_FAMILIES:
            errors.append(_error(scenario_id, field_path, output_family, "unsupported output family"))
            continue

        if output_family in seen_output_families:
            errors.append(_error(scenario_id, field_path, output_family, "duplicate output family"))
            continue

        seen_output_families.add(output_family)
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
            authored_event_type = get_event_type(event_type)

            if authored_event_type is None:
                errors.append(_error(scenario_id, f"{field_path}.type", event_type, "unsupported event type"))
            else:
                for field_name in authored_event_type.optional_ip_fields:
                    _validate_optional_ip_address_field(event_document, field_name, field_path, scenario_id, errors)

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
            # Relative `after` timing is intentionally limited to earlier authored events.
            authored_timestamps[event_id] = timestamp

        if event_id is not None and event_type is not None and timestamp is not None:
            # Keep a copy of the raw event so later type-specific builders can read optional fields.
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
        # A delay has no anchor without `after`, so keep validating but do not use it by itself.
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
        # Absolute `at` wins for the timestamp while `after` can still express parentage/correlation.
        return _parse_event_at(at_value, f"{field_path}.at", scenario_id, start_time, errors), after, delay

    if after not in authored_timestamps:
        return None, after, delay

    if delay is None:
        # `after` with no delay means the child shares the parent's timestamp.
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
    authored_event_type = get_event_type(event_type)

    if authored_event_type is None:
        return

    _validate_unknown_fields(event_document, authored_event_type.allowed_fields(), field_path, scenario_id, errors)


def _validate_optional_ip_address_field(
    event_document: dict[str, Any],
    field_name: str,
    field_path: str,
    scenario_id: Optional[str],
    errors: list[ScenarioYamlValidationError],
) -> None:
    """
    Validate an optional IP address field in an authored event mapping.

    Args:
        event_document (dict[str, Any]): Raw event mapping.
        field_name (str): Optional IP address field name.
        field_path (str): Event field path prefix.
        scenario_id (Optional[str]): Scenario ID for validation errors.
        errors (list[ScenarioYamlValidationError]): Validation errors to update.

    Returns:
        None: The errors list is updated in place.
    """
    if field_name not in event_document or event_document[field_name] is None:
        return

    value = event_document[field_name]

    if not is_ip_address(value):
        errors.append(_error(scenario_id, f"{field_path}.{field_name}", value, "must be a valid IP address"))


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
