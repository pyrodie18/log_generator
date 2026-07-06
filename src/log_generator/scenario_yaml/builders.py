"""
Build source-neutral scenario models from parsed YAML scenarios.
"""

import re
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Callable, Optional

from log_generator.core.events import LinuxLocalLoginEvent
from log_generator.core.scenarios import (
    AnswerKeyRecord,
    AuthoredEvent,
    AuthoredWebRequest,
    Scenario,
    ScenarioEvent,
    expand_authored_events,
)
from log_generator.core.value_checks import is_integer, is_ip_address
from log_generator.scenario_yaml.common import (
    _error,
    _event_field_path,
    _lookup_environment,
    _optional_dict,
    _optional_string_mapping,
)
from log_generator.scenario_yaml.contexts import (
    _optional_dns_context,
    _optional_http_context,
    _optional_network_context,
)
from log_generator.scenario_yaml.event_types import (
    LINUX_LOCAL_LOGIN_EVENT_TYPE,
    WEB_REQUEST_EVENT_TYPE,
    uses_web_login_helper_offsets,
)
from log_generator.scenario_yaml.errors import ScenarioYamlError, ScenarioYamlValidationError
from log_generator.scenario_yaml.models import EnvironmentRegistry, ParsedScenarioYaml, ParsedYamlEvent
from log_generator.scenario_yaml.validators import _validate_metadata_references


@dataclass(frozen=True)
class AuthoredEventBuildContext:
    """
    Carry shared inputs for building one parsed YAML event.
    """

    parsed: ParsedScenarioYaml
    parsed_event: ParsedYamlEvent
    correlation_id: str
    parent_event_id: Optional[str]
    event_types_by_id: dict[str, str]
    all_authored_event_ids: set[str]
    errors: list[ScenarioYamlValidationError]


AuthoredEventBuilder = Callable[[AuthoredEventBuildContext], Optional[AuthoredEvent]]


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

    # YAML web requests are authored at a higher level; expansion adds DNS and connection helpers as needed.
    authored_events = _build_authored_events(parsed)
    expanded_events = expand_authored_events(
        scenario_id=parsed.scenario_id,
        seed=parsed.seed,
        environment=environment,
        authored_events=authored_events,
    )
    # Metadata references are validated after expansion because helper events may become valid targets.
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
        # Correlation IDs can be explicit, inherited from a parent, or deterministically generated.
        correlation_id = _event_correlation_id(parsed, parsed_event, correlation_ids_by_event_id)
        authored_event = _build_authored_event(
            AuthoredEventBuildContext(
                parsed=parsed,
                parsed_event=parsed_event,
                correlation_id=correlation_id,
                parent_event_id=parsed_event.after,
                event_types_by_id=event_types_by_id,
                all_authored_event_ids=all_authored_event_ids,
                errors=errors,
            )
        )

        if authored_event is not None:
            authored_events.append(authored_event)
            # Store after successful conversion so children inherit only usable parent correlation IDs.
            correlation_ids_by_event_id[parsed_event.event_id] = correlation_id

    if errors:
        raise ScenarioYamlError(errors)

    return tuple(authored_events)


def _build_authored_event(context: AuthoredEventBuildContext) -> Optional[AuthoredEvent]:
    """
    Dispatch one parsed YAML event to its registered authored-event builder.

    Args:
        context (AuthoredEventBuildContext): Shared event-building inputs.

    Returns:
        Optional[AuthoredEvent]: Built authored event when valid.
    """
    builder = AUTHORED_EVENT_BUILDERS.get(context.parsed_event.event_type)

    if builder is None:
        context.errors.append(
            _error(
                context.parsed.scenario_id,
                _event_field_path(context.parsed_event, "type"),
                context.parsed_event.event_type,
                "unsupported event type",
            )
        )
        return None

    return builder(context)


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


def _build_authored_web_request(context: AuthoredEventBuildContext) -> Optional[AuthoredWebRequest]:
    """
    Convert one parsed YAML web request into an AuthoredWebRequest.

    Args:
        context (AuthoredEventBuildContext): Shared event-building inputs.

    Returns:
        Optional[AuthoredWebRequest]: Authored web request when required fields are valid.
    """
    parsed = context.parsed
    parsed_event = context.parsed_event
    errors = context.errors
    raw_event = parsed_event.raw
    actor_user_id = _required_event_string(parsed, parsed_event, "actor", errors)
    source_host_id = _required_event_string(parsed, parsed_event, "source_host", errors)
    service_id = _required_event_string(parsed, parsed_event, "service", errors)
    method = _required_event_string(parsed, parsed_event, "method", errors)
    path = _required_event_string(parsed, parsed_event, "path", errors)
    status = _event_status(raw_event)
    status_code = _optional_event_integer(parsed, parsed_event, "status_code", errors)
    request_headers = _optional_string_mapping(parsed, parsed_event, "headers", errors)
    network = _optional_network_context(parsed, parsed_event, errors)
    dns = _optional_dns_context(parsed, parsed_event, errors)
    http = _optional_http_context(parsed, parsed_event, errors)

    # Return no event when required fields are invalid; accumulated errors describe the missing pieces.
    if not all((actor_user_id, source_host_id, service_id, method, path)):
        return None

    dns_helper_offset = timedelta(seconds=2)
    connection_helper_offset = timedelta(seconds=1)

    # Login-driven web activity reserves a little extra time for generated DNS and connection helpers.
    parent_event_type = context.event_types_by_id.get(context.parent_event_id)

    if uses_web_login_helper_offsets(parent_event_type):
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
        correlation_id=context.correlation_id,
        status=status,
        parent_event_id=context.parent_event_id,
        status_code=status_code,
        attack=_optional_dict(raw_event.get("attack")),
        metadata=_optional_dict(raw_event.get("metadata")),
        request_headers=request_headers,
        network=network,
        dns=dns,
        http=http,
        helper_event_ids=_canonical_helper_event_ids(parsed_event.event_id, context.all_authored_event_ids),
        dns_helper_offset=dns_helper_offset,
        connection_helper_offset=connection_helper_offset,
    )


def _build_linux_local_login_event(context: AuthoredEventBuildContext) -> Optional[LinuxLocalLoginEvent]:
    """
    Convert one parsed YAML Linux local login into a source-neutral login event.

    Args:
        context (AuthoredEventBuildContext): Shared event-building inputs.

    Returns:
        Optional[LinuxLocalLoginEvent]: Login event when required fields are valid.
    """
    parsed = context.parsed
    parsed_event = context.parsed_event
    errors = context.errors
    raw_event = parsed_event.raw
    actor_user_id = _required_event_string(parsed, parsed_event, "actor", errors)
    target_host_id = _required_event_string(parsed, parsed_event, "target_host", errors)
    login_method = _required_event_string(parsed, parsed_event, "login_method", errors)
    source_host_id = _optional_event_string(parsed, parsed_event, "source_host", errors)
    source_ip = _optional_event_string(parsed, parsed_event, "source_ip", errors)
    source_ip_is_valid = source_ip is None or is_ip_address(source_ip)

    if not source_ip_is_valid:
        errors.append(
            _error(
                parsed.scenario_id,
                _event_field_path(parsed_event, "source_ip"),
                source_ip,
                "must be a valid IP address",
            )
        )

    # Required reference checks and optional IP validation are reported separately for clearer author feedback.
    if not all((actor_user_id, target_host_id, login_method)):
        return None

    if not source_ip_is_valid:
        return None

    return LinuxLocalLoginEvent(
        event_id=parsed_event.event_id,
        scenario_id=parsed.scenario_id,
        timestamp=parsed_event.timestamp,
        status=_event_status(raw_event),
        correlation_id=context.correlation_id,
        parent_event_id=context.parent_event_id,
        actor_user_id=actor_user_id,
        target_host_id=target_host_id,
        login_method=login_method,
        source_host_id=source_host_id,
        source_ip=source_ip,
        metadata=_optional_dict(raw_event.get("metadata")),
        attack=_optional_dict(raw_event.get("attack")),
    )


AUTHORED_EVENT_BUILDERS: dict[str, AuthoredEventBuilder] = {
    WEB_REQUEST_EVENT_TYPE: _build_authored_web_request,
    LINUX_LOCAL_LOGIN_EVENT_TYPE: _build_linux_local_login_event,
}


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

    if not is_integer(value):
        errors.append(
            _error(parsed.scenario_id, _event_field_path(parsed_event, field_name), value, "expected integer")
        )
        return None

    return value
