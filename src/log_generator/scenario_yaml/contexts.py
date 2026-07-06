"""
Nested event context parsing helpers for YAML scenarios.
"""

from typing import Any, Optional

from log_generator.core.events import DnsContext, HttpContext, NetworkContext
from log_generator.core.value_checks import (
    is_integer,
    is_non_negative_integer,
    is_non_negative_number,
    is_number,
    is_port_number,
)
from log_generator.scenario_yaml.common import _error, _event_field_path, _validate_unknown_fields
from log_generator.scenario_yaml.errors import ScenarioYamlValidationError
from log_generator.scenario_yaml.models import ParsedScenarioYaml, ParsedYamlEvent


def _optional_network_context(
    parsed: ParsedScenarioYaml,
    parsed_event: ParsedYamlEvent,
    errors: list[ScenarioYamlValidationError],
) -> Optional[NetworkContext]:
    """
    Read optional source-neutral network detail overrides from a YAML event.

    Args:
        parsed (ParsedScenarioYaml): Parsed YAML scenario that owns the event.
        parsed_event (ParsedYamlEvent): Parsed YAML event.
        errors (list[ScenarioYamlValidationError]): Validation errors to update.

    Returns:
        Optional[NetworkContext]: Parsed network context when present and valid.
    """
    value = parsed_event.raw.get("network")

    if value is None:
        return None

    field_path = _event_field_path(parsed_event, "network")
    error_count = len(errors)

    if not isinstance(value, dict):
        errors.append(_error(parsed.scenario_id, field_path, value, "expected mapping"))
        return None

    _validate_unknown_fields(
        value,
        {"source_port", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts"},
        field_path,
        parsed.scenario_id,
        errors,
    )

    source_port = _optional_context_integer(parsed, value, "source_port", field_path, errors)
    orig_bytes = _optional_context_integer(parsed, value, "orig_bytes", field_path, errors)
    resp_bytes = _optional_context_integer(parsed, value, "resp_bytes", field_path, errors)
    orig_pkts = _optional_context_integer(parsed, value, "orig_pkts", field_path, errors)
    resp_pkts = _optional_context_integer(parsed, value, "resp_pkts", field_path, errors)

    _validate_context_port(parsed, "source_port", source_port, field_path, errors)
    _validate_context_non_negative(parsed, "orig_bytes", orig_bytes, field_path, errors)
    _validate_context_non_negative(parsed, "resp_bytes", resp_bytes, field_path, errors)
    _validate_context_non_negative(parsed, "orig_pkts", orig_pkts, field_path, errors)
    _validate_context_non_negative(parsed, "resp_pkts", resp_pkts, field_path, errors)

    if len(errors) > error_count:
        # Avoid constructing a NetworkContext that would raise before all YAML errors are reported.
        return None

    return NetworkContext(
        source_port=source_port,
        orig_bytes=orig_bytes,
        resp_bytes=resp_bytes,
        orig_pkts=orig_pkts,
        resp_pkts=resp_pkts,
    )


def _optional_dns_context(
    parsed: ParsedScenarioYaml,
    parsed_event: ParsedYamlEvent,
    errors: list[ScenarioYamlValidationError],
) -> Optional[DnsContext]:
    """
    Read optional source-neutral DNS detail overrides from a YAML event.

    Args:
        parsed (ParsedScenarioYaml): Parsed YAML scenario that owns the event.
        parsed_event (ParsedYamlEvent): Parsed YAML event.
        errors (list[ScenarioYamlValidationError]): Validation errors to update.

    Returns:
        Optional[DnsContext]: Parsed DNS context when present and valid.
    """
    value = parsed_event.raw.get("dns")

    if value is None:
        return None

    field_path = _event_field_path(parsed_event, "dns")
    error_count = len(errors)

    if not isinstance(value, dict):
        errors.append(_error(parsed.scenario_id, field_path, value, "expected mapping"))
        return None

    _validate_unknown_fields(value, {"trans_id", "rtt", "ttls", "flags"}, field_path, parsed.scenario_id, errors)
    trans_id = _optional_context_integer(parsed, value, "trans_id", field_path, errors)
    rtt = _optional_context_number(parsed, value, "rtt", field_path, errors)
    ttls = _optional_context_number_list(parsed, value, "ttls", field_path, errors)
    flags = _optional_dns_flags(parsed, value, field_path, errors)

    _validate_context_port(parsed, "trans_id", trans_id, field_path, errors)
    _validate_context_non_negative_number(parsed, "rtt", rtt, field_path, errors)

    if ttls is not None:
        for index, ttl in enumerate(ttls):
            _validate_context_non_negative_number(parsed, f"ttls[{index}]", ttl, field_path, errors)

    if len(errors) > error_count:
        # Keep parsing tolerant: validation errors are accumulated instead of failing in the dataclass.
        return None

    return DnsContext(trans_id=trans_id, rtt=rtt, ttls=ttls, flags=flags)


def _optional_http_context(
    parsed: ParsedScenarioYaml,
    parsed_event: ParsedYamlEvent,
    errors: list[ScenarioYamlValidationError],
) -> Optional[HttpContext]:
    """
    Read optional source-neutral HTTP detail overrides from a YAML event.

    Args:
        parsed (ParsedScenarioYaml): Parsed YAML scenario that owns the event.
        parsed_event (ParsedYamlEvent): Parsed YAML event.
        errors (list[ScenarioYamlValidationError]): Validation errors to update.

    Returns:
        Optional[HttpContext]: Parsed HTTP context when present and valid.
    """
    value = parsed_event.raw.get("http")

    if value is None:
        return None

    field_path = _event_field_path(parsed_event, "http")
    error_count = len(errors)

    if not isinstance(value, dict):
        errors.append(_error(parsed.scenario_id, field_path, value, "expected mapping"))
        return None

    _validate_unknown_fields(
        value,
        {"user_agent", "version", "response_body_len", "response_content_type"},
        field_path,
        parsed.scenario_id,
        errors,
    )
    user_agent = _optional_context_string(parsed, value, "user_agent", field_path, errors)
    version = _optional_context_string(parsed, value, "version", field_path, errors)
    response_body_len = _optional_context_integer(parsed, value, "response_body_len", field_path, errors)
    response_content_type = _optional_context_string(parsed, value, "response_content_type", field_path, errors)

    _validate_context_non_negative(parsed, "response_body_len", response_body_len, field_path, errors)

    if len(errors) > error_count:
        # Do not create partial HTTP context when any nested field was malformed.
        return None

    return HttpContext(
        user_agent=user_agent,
        version=version,
        response_body_len=response_body_len,
        response_content_type=response_content_type,
    )


def _optional_context_integer(
    parsed: ParsedScenarioYaml,
    values: dict[str, Any],
    field_name: str,
    prefix: str,
    errors: list[ScenarioYamlValidationError],
) -> Optional[int]:
    """
    Read an optional integer from a nested context mapping.

    Args:
        parsed (ParsedScenarioYaml): Parsed YAML scenario that owns the event.
        values (dict[str, Any]): Context mapping to read.
        field_name (str): Optional field name.
        prefix (str): Field path prefix.
        errors (list[ScenarioYamlValidationError]): Validation errors to update.

    Returns:
        Optional[int]: Integer value when present and valid.
    """
    if field_name not in values or values[field_name] is None:
        return None

    value = values[field_name]

    if not is_integer(value):
        errors.append(_error(parsed.scenario_id, f"{prefix}.{field_name}", value, "expected integer"))
        return None

    return value


def _optional_context_number(
    parsed: ParsedScenarioYaml,
    values: dict[str, Any],
    field_name: str,
    prefix: str,
    errors: list[ScenarioYamlValidationError],
) -> Optional[float]:
    """
    Read an optional number from a nested context mapping.

    Args:
        parsed (ParsedScenarioYaml): Parsed YAML scenario that owns the event.
        values (dict[str, Any]): Context mapping to read.
        field_name (str): Optional field name.
        prefix (str): Field path prefix.
        errors (list[ScenarioYamlValidationError]): Validation errors to update.

    Returns:
        Optional[float]: Numeric value when present and valid.
    """
    if field_name not in values or values[field_name] is None:
        return None

    value = values[field_name]

    if not is_number(value):
        errors.append(_error(parsed.scenario_id, f"{prefix}.{field_name}", value, "expected number"))
        return None

    return float(value)


def _optional_context_number_list(
    parsed: ParsedScenarioYaml,
    values: dict[str, Any],
    field_name: str,
    prefix: str,
    errors: list[ScenarioYamlValidationError],
) -> Optional[list[float]]:
    """
    Read an optional list of numbers from a nested context mapping.

    Args:
        parsed (ParsedScenarioYaml): Parsed YAML scenario that owns the event.
        values (dict[str, Any]): Context mapping to read.
        field_name (str): Optional field name.
        prefix (str): Field path prefix.
        errors (list[ScenarioYamlValidationError]): Validation errors to update.

    Returns:
        Optional[list[float]]: Numeric list when present and valid.
    """
    if field_name not in values or values[field_name] is None:
        return None

    value = values[field_name]

    if not isinstance(value, list):
        errors.append(_error(parsed.scenario_id, f"{prefix}.{field_name}", value, "expected list of numbers"))
        return None

    output = []

    for index, item in enumerate(value):
        if not is_number(item):
            errors.append(_error(parsed.scenario_id, f"{prefix}.{field_name}[{index}]", item, "expected number"))
            continue

        output.append(float(item))

    return output


def _optional_context_string(
    parsed: ParsedScenarioYaml,
    values: dict[str, Any],
    field_name: str,
    prefix: str,
    errors: list[ScenarioYamlValidationError],
) -> Optional[str]:
    """
    Read an optional string from a nested context mapping.

    Args:
        parsed (ParsedScenarioYaml): Parsed YAML scenario that owns the event.
        values (dict[str, Any]): Context mapping to read.
        field_name (str): Optional field name.
        prefix (str): Field path prefix.
        errors (list[ScenarioYamlValidationError]): Validation errors to update.

    Returns:
        Optional[str]: String value when present and valid.
    """
    if field_name not in values or values[field_name] is None:
        return None

    value = values[field_name]

    if not isinstance(value, str):
        errors.append(_error(parsed.scenario_id, f"{prefix}.{field_name}", value, "expected string"))
        return None

    return value


def _optional_dns_flags(
    parsed: ParsedScenarioYaml,
    values: dict[str, Any],
    prefix: str,
    errors: list[ScenarioYamlValidationError],
) -> Optional[dict[str, bool]]:
    """
    Read optional DNS response flags from a nested context mapping.

    Args:
        parsed (ParsedScenarioYaml): Parsed YAML scenario that owns the event.
        values (dict[str, Any]): Context mapping to read.
        prefix (str): Field path prefix.
        errors (list[ScenarioYamlValidationError]): Validation errors to update.

    Returns:
        Optional[dict[str, bool]]: DNS flag overrides when present and valid.
    """
    if "flags" not in values or values["flags"] is None:
        return None

    flags = values["flags"]
    field_path = f"{prefix}.flags"

    if not isinstance(flags, dict):
        errors.append(_error(parsed.scenario_id, field_path, flags, "expected mapping"))
        return None

    _validate_unknown_fields(flags, {"AA", "TC", "RD", "RA"}, field_path, parsed.scenario_id, errors)
    output = {}

    for name, value in flags.items():
        if name not in {"AA", "TC", "RD", "RA"}:
            continue

        if not isinstance(value, bool):
            errors.append(_error(parsed.scenario_id, f"{field_path}.{name}", value, "expected boolean"))
            continue

        output[name] = value

    return output or None


def _validate_context_port(
    parsed: ParsedScenarioYaml,
    field_name: str,
    value: Optional[int],
    prefix: str,
    errors: list[ScenarioYamlValidationError],
) -> None:
    """
    Validate that an optional context integer fits the port/count16 range.

    Args:
        parsed (ParsedScenarioYaml): Parsed YAML scenario that owns the event.
        field_name (str): Context field name.
        value (Optional[int]): Optional value to validate.
        prefix (str): Field path prefix.
        errors (list[ScenarioYamlValidationError]): Validation errors to update.

    Returns:
        None: The errors list is updated in place.
    """
    if not is_port_number(value, allow_none=True):
        errors.append(_error(parsed.scenario_id, f"{prefix}.{field_name}", value, "must be between 0 and 65535"))


def _validate_context_non_negative(
    parsed: ParsedScenarioYaml,
    field_name: str,
    value: Optional[int],
    prefix: str,
    errors: list[ScenarioYamlValidationError],
) -> None:
    """
    Validate that an optional context integer is non-negative.

    Args:
        parsed (ParsedScenarioYaml): Parsed YAML scenario that owns the event.
        field_name (str): Context field name.
        value (Optional[int]): Optional value to validate.
        prefix (str): Field path prefix.
        errors (list[ScenarioYamlValidationError]): Validation errors to update.

    Returns:
        None: The errors list is updated in place.
    """
    if not is_non_negative_integer(value, allow_none=True):
        errors.append(_error(parsed.scenario_id, f"{prefix}.{field_name}", value, "must be non-negative"))


def _validate_context_non_negative_number(
    parsed: ParsedScenarioYaml,
    field_name: str,
    value: Optional[float],
    prefix: str,
    errors: list[ScenarioYamlValidationError],
) -> None:
    """
    Validate that an optional context number is non-negative.

    Args:
        parsed (ParsedScenarioYaml): Parsed YAML scenario that owns the event.
        field_name (str): Context field name.
        value (Optional[float]): Optional value to validate.
        prefix (str): Field path prefix.
        errors (list[ScenarioYamlValidationError]): Validation errors to update.

    Returns:
        None: The errors list is updated in place.
    """
    if not is_non_negative_number(value, allow_none=True):
        errors.append(_error(parsed.scenario_id, f"{prefix}.{field_name}", value, "must be non-negative"))
