"""
Shared helpers for YAML scenario modules.
"""

from typing import Any, Optional, Union

from log_generator.core.environment import Environment, build_linux_mini_lab
from log_generator.core.value_checks import is_integer
from log_generator.output.jsonl import validate_path_component
from log_generator.scenario_yaml.constants import SAFE_IDENTIFIER_RE
from log_generator.scenario_yaml.errors import ScenarioYamlValidationError
from log_generator.scenario_yaml.models import EnvironmentRegistry, ParsedScenarioYaml, ParsedYamlEvent


def _optional_string_mapping(
    parsed: ParsedScenarioYaml,
    parsed_event: ParsedYamlEvent,
    field_name: str,
    errors: list[ScenarioYamlValidationError],
) -> Optional[dict[str, str]]:
    """
    Read an optional mapping of strings from a parsed YAML event.

    Args:
        parsed (ParsedScenarioYaml): Parsed YAML scenario that owns the event.
        parsed_event (ParsedYamlEvent): Parsed YAML event.
        field_name (str): Optional field name.
        errors (list[ScenarioYamlValidationError]): Validation errors to update.

    Returns:
        Optional[dict[str, str]]: String mapping when present and valid.
    """
    if field_name not in parsed_event.raw or parsed_event.raw[field_name] is None:
        return None

    value = parsed_event.raw[field_name]
    field_path = _event_field_path(parsed_event, field_name)

    if not isinstance(value, dict):
        errors.append(_error(parsed.scenario_id, field_path, value, "expected mapping"))
        return None

    output = {}

    for key, item in value.items():
        if not isinstance(key, str):
            errors.append(_error(parsed.scenario_id, f"{field_path}.{key}", key, "expected string key"))
            continue

        if not isinstance(item, str):
            errors.append(_error(parsed.scenario_id, f"{field_path}.{key}", item, "expected string"))
            continue

        output[key] = item

    return output or None


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

    if not is_integer(value):
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
