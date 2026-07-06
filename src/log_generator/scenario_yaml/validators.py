"""
Validation helpers for parsed YAML scenarios.
"""

from datetime import timedelta
from typing import Any, Optional

from log_generator.core.environment import Environment
from log_generator.core.scenarios import ScenarioEvent
from log_generator.core.value_checks import is_http_status_code, is_integer
from log_generator.scenario_yaml.common import (
    _error,
    _event_field_path,
    _lookup_environment,
    _optional_string_mapping,
    _validate_unknown_fields,
)
from log_generator.scenario_yaml.constants import ANSWER_KEY_FIELDS, ATTACK_CHAIN_FIELDS, ATTACK_TECHNIQUE_ID_RE
from log_generator.scenario_yaml.contexts import (
    _optional_dns_context,
    _optional_http_context,
    _optional_network_context,
)
from log_generator.scenario_yaml.errors import ScenarioYamlValidationError
from log_generator.scenario_yaml.models import EnvironmentRegistry, ParsedScenarioYaml, ParsedYamlEvent


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
        # Attack metadata is type-independent, then each event type gets environment-specific checks.
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
        # The service must be an HTTP service with a real target host before route validation is meaningful.
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

    _optional_network_context(parsed, parsed_event, errors)
    _optional_dns_context(parsed, parsed_event, errors)
    _optional_http_context(parsed, parsed_event, errors)
    _optional_string_mapping(parsed, parsed_event, "headers", errors)

    if service is not None and service.application_protocol == "http" and method is not None and path is not None:
        # Unknown routes are allowed only when the author supplies an explicit status_code override.
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

    # These helper times mirror expansion so YAML can reject requests that would emit out-of-range helpers.
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
    if not is_integer(value):
        return

    if not is_http_status_code(value):
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
