"""
Validation helpers for environments, scenarios, and source-neutral events.
"""

from typing import Any, Optional

from log_generator.core.environment import Environment, Host, Service, User
from log_generator.core.events import (
    DnsLookupEvent,
    LinuxLocalLoginEvent,
    NetworkConnectionEvent,
    SourceNeutralEvent,
    WebRequestEvent,
)
from log_generator.core.scenarios import Scenario
from log_generator.core.value_checks import is_http_status_code
from log_generator.core.validation_errors import ValidationIssue, ValidationIssueError


class ValidationError(ValidationIssue):
    """
    Represent one actionable semantic validation error.
    """

    def __str__(self) -> str:
        """
        Render the validation error for logs and exceptions.

        Returns:
            str: Human-readable validation error.
        """
        return (
            f"{self.scenario_id}: {self.field_path}={self.invalid_value!r} is invalid because "
            f"{self.reason}"
        )


class ScenarioValidationError(ValidationIssueError[ValidationError]):
    """
    Represent one or more semantic validation errors for a scenario.
    """


def validate_scenario(scenario: Scenario, environment: Environment) -> list[ValidationError]:
    """
    Validate a scenario against an environment.

    Args:
        scenario (Scenario): Scenario to validate.
        environment (Environment): Environment that scenario references must resolve through.

    Returns:
        list[ValidationError]: Semantic validation errors, or an empty list when valid.
    """
    errors = []

    if scenario.environment_id != environment.id:
        errors.append(
            _error(
                scenario.id,
                "environment_id",
                scenario.environment_id,
                f"scenario must target environment '{environment.id}'",
            )
        )

    if scenario.environment_version != environment.version:
        errors.append(
            _error(
                scenario.id,
                "environment_version",
                scenario.environment_version,
                f"scenario must target environment version '{environment.version}'",
            )
        )

    # Event validation is separate so callers can validate prebuilt event tuples without a Scenario object.
    errors.extend(validate_events(scenario.id, scenario.ordered_events(), environment))

    return errors


def validate_events(
    scenario_id: str,
    events: tuple[SourceNeutralEvent, ...],
    environment: Environment,
) -> list[ValidationError]:
    """
    Validate an ordered source-neutral event sequence against an environment.

    Args:
        scenario_id (str): Scenario identifier to include in validation errors.
        events (tuple[SourceNeutralEvent, ...]): Ordered events to validate.
        environment (Environment): Environment that event references must resolve through.

    Returns:
        list[ValidationError]: Semantic validation errors, or an empty list when valid.
    """
    errors = []
    earlier_event_ids = set()

    for event in events:
        parent_event_id = getattr(event, "parent_event_id", None)

        if parent_event_id is not None and parent_event_id not in earlier_event_ids:
            # Parent relationships are causal references, so they must point to an event already seen.
            errors.append(
                _error(
                    scenario_id,
                    _field_path(event, "parent_event_id"),
                    parent_event_id,
                    "parent_event_id must resolve to an earlier event in the same scenario",
                )
            )

        earlier_event_ids.add(event.event_id)
        errors.extend(_validate_event(scenario_id, event, environment))

    return errors


def require_valid_scenario(scenario: Scenario, environment: Environment) -> None:
    """
    Raise when a scenario has semantic validation errors.

    Args:
        scenario (Scenario): Scenario to validate.
        environment (Environment): Environment that scenario references must resolve through.

    Returns:
        None: Raises ScenarioValidationError when validation fails.
    """
    errors = validate_scenario(scenario, environment)

    if errors:
        raise ScenarioValidationError(errors)


def _validate_event(
    scenario_id: str,
    event: SourceNeutralEvent,
    environment: Environment,
) -> list[ValidationError]:
    """
    Dispatch event-type-specific semantic validation.

    Args:
        scenario_id (str): Scenario identifier to include in validation errors.
        event (SourceNeutralEvent): Event to validate.
        environment (Environment): Environment that event references must resolve through.

    Returns:
        list[ValidationError]: Semantic validation errors for the event.
    """
    errors = []
    actor_user_id = getattr(event, "actor_user_id", None)

    if actor_user_id is not None and not isinstance(event, LinuxLocalLoginEvent):
        # Login events validate actor permissions in their own branch because they need target host context too.
        _require_user(scenario_id, event, "actor_user_id", actor_user_id, environment, errors)

    # Dispatch after common actor checks so every event type can report its own environment constraints.
    if isinstance(event, DnsLookupEvent):
        errors.extend(_validate_dns_lookup(scenario_id, event, environment))
    elif isinstance(event, NetworkConnectionEvent):
        errors.extend(_validate_network_connection(scenario_id, event, environment))
    elif isinstance(event, WebRequestEvent):
        errors.extend(_validate_web_request(scenario_id, event, environment))
    elif isinstance(event, LinuxLocalLoginEvent):
        errors.extend(_validate_linux_local_login(scenario_id, event, environment))

    return errors


def _validate_dns_lookup(
    scenario_id: str,
    event: DnsLookupEvent,
    environment: Environment,
) -> list[ValidationError]:
    """
    Validate DNS lookup semantics against the environment.

    Args:
        scenario_id (str): Scenario identifier to include in validation errors.
        event (DnsLookupEvent): DNS lookup event to validate.
        environment (Environment): Environment that event references must resolve through.

    Returns:
        list[ValidationError]: Semantic validation errors for the DNS event.
    """
    errors = []
    destination_host = None
    service = None

    _require_host(scenario_id, event, "source_host_id", event.source_host_id, environment, errors)

    if event.destination_host_id is not None:
        destination_host = _require_host(
            scenario_id,
            event,
            "destination_host_id",
            event.destination_host_id,
            environment,
            errors,
        )

    if event.service_id is not None:
        service = _require_service(scenario_id, event, "service_id", event.service_id, environment, errors)

    if service is not None:
        # DNS events should point at a DNS service and, when a host is supplied, that service's host.
        if service.application_protocol != "dns":
            errors.append(
                _error(
                    scenario_id,
                    _field_path(event, "service_id"),
                    event.service_id,
                    "DNS lookup events must target a DNS service",
                )
            )

        _validate_service_host_conflict(scenario_id, event, service, destination_host, errors)

    if _is_internal_a_lookup(event, environment):
        # Internal successful A lookups should match the environment's authoritative DNS records.
        dns_record = environment.get_dns_record(event.query_name, event.query_type)

        if dns_record is None:
            errors.append(
                _error(
                    scenario_id,
                    _field_path(event, "query_name"),
                    event.query_name,
                    "internal A lookups must resolve through an environment DNS record",
                )
            )
        elif event.status == "success":
            _validate_successful_dns_answer(scenario_id, event, dns_record.value, errors)

    if event.status == "failure" and event.resolved_addresses:
        errors.append(
            _error(
                scenario_id,
                _field_path(event, "resolved_addresses"),
                event.resolved_addresses,
                "failed DNS lookups must not include successful answer addresses",
            )
        )

    return errors


def _validate_network_connection(
    scenario_id: str,
    event: NetworkConnectionEvent,
    environment: Environment,
) -> list[ValidationError]:
    """
    Validate network connection semantics against the environment.

    Args:
        scenario_id (str): Scenario identifier to include in validation errors.
        event (NetworkConnectionEvent): Network connection event to validate.
        environment (Environment): Environment that event references must resolve through.

    Returns:
        list[ValidationError]: Semantic validation errors for the connection event.
    """
    errors = []
    source_host = _require_host(scenario_id, event, "source_host_id", event.source_host_id, environment, errors)
    destination_host = None
    service = None

    if source_host is not None and event.source_ip != source_host.primary_ip:
        errors.append(
            _error(
                scenario_id,
                _field_path(event, "source_ip"),
                event.source_ip,
                f"source_ip must match source host '{source_host.id}' primary IP '{source_host.primary_ip}'",
            )
        )

    if event.destination_host_id is not None:
        destination_host = _require_host(
            scenario_id,
            event,
            "destination_host_id",
            event.destination_host_id,
            environment,
            errors,
        )

    if destination_host is not None and event.destination_ip != destination_host.primary_ip:
        # When a destination host is named, the emitted IP must stay in sync with that host.
        errors.append(
            _error(
                scenario_id,
                _field_path(event, "destination_ip"),
                event.destination_ip,
                (
                    f"destination_ip must match destination host '{destination_host.id}' primary IP "
                    f"'{destination_host.primary_ip}'"
                ),
            )
        )

    if event.service_id is not None:
        service = _require_service(scenario_id, event, "service_id", event.service_id, environment, errors)

    if service is not None:
        # Service checks compare the connection tuple against the environment's declared listener.
        _validate_network_service_conflicts(scenario_id, event, service, destination_host, environment, errors)

    return errors


def _validate_web_request(
    scenario_id: str,
    event: WebRequestEvent,
    environment: Environment,
) -> list[ValidationError]:
    """
    Validate web request semantics against the environment.

    Args:
        scenario_id (str): Scenario identifier to include in validation errors.
        event (WebRequestEvent): Web request event to validate.
        environment (Environment): Environment that event references must resolve through.

    Returns:
        list[ValidationError]: Semantic validation errors for the web request event.
    """
    errors = []
    service = _require_service(scenario_id, event, "service_id", event.service_id, environment, errors)
    destination_host = None

    _require_host(scenario_id, event, "source_host_id", event.source_host_id, environment, errors)

    if event.destination_host_id is not None:
        destination_host = _require_host(
            scenario_id,
            event,
            "destination_host_id",
            event.destination_host_id,
            environment,
            errors,
        )

    if service is None:
        # Without a service there is no reliable route or destination-host context to validate.
        return errors

    if service.application_protocol != "http":
        errors.append(
            _error(
                scenario_id,
                _field_path(event, "service_id"),
                event.service_id,
                "web_request events must target an HTTP service",
            )
        )
    else:
        # Source-neutral web events represent known routes in the modeled HTTP service.
        route = environment.get_http_route(service.id, event.method, event.path)

        if route is None:
            errors.append(
                _error(
                    scenario_id,
                    _field_path(event, "path"),
                    event.path,
                    f"route '{event.method} {event.path}' must exist on service '{service.id}'",
                )
            )
        elif not is_http_status_code(event.status_code):
            errors.append(
                _error(
                    scenario_id,
                    _field_path(event, "status_code"),
                    event.status_code,
                    "status_code must be between 100 and 599",
                )
            )

    _validate_service_host_conflict(scenario_id, event, service, destination_host, errors)

    return errors


def _validate_linux_local_login(
    scenario_id: str,
    event: LinuxLocalLoginEvent,
    environment: Environment,
) -> list[ValidationError]:
    """
    Validate Linux local login semantics against the environment.

    Args:
        scenario_id (str): Scenario identifier to include in validation errors.
        event (LinuxLocalLoginEvent): Linux local login event to validate.
        environment (Environment): Environment that event references must resolve through.

    Returns:
        list[ValidationError]: Semantic validation errors for the login event.
    """
    errors = []
    user = _require_user(scenario_id, event, "actor_user_id", event.actor_user_id, environment, errors)
    target_host = _require_host(scenario_id, event, "target_host_id", event.target_host_id, environment, errors)
    source_host = None

    if event.source_host_id is not None:
        source_host = _require_host(scenario_id, event, "source_host_id", event.source_host_id, environment, errors)

    if source_host is not None and event.source_ip is not None and event.source_ip != source_host.primary_ip:
        # Remote login source details are optional, but supplied host/IP pairs must agree.
        errors.append(
            _error(
                scenario_id,
                _field_path(event, "source_ip"),
                event.source_ip,
                f"source_ip must match source host '{source_host.id}' primary IP '{source_host.primary_ip}'",
            )
        )

    if event.status == "success" and user is not None and target_host is not None:
        # Failed attempts can target unusual hosts; successful local logins must be allowed for that user.
        if target_host.id not in user.login_hosts:
            errors.append(
                _error(
                    scenario_id,
                    _field_path(event, "target_host_id"),
                    event.target_host_id,
                    f"successful local login requires target host to be in user '{user.id}' login_hosts",
                )
            )

    return errors


def _validate_network_service_conflicts(
    scenario_id: str,
    event: NetworkConnectionEvent,
    service: Service,
    destination_host: Optional[Host],
    environment: Environment,
    errors: list[ValidationError],
) -> None:
    """
    Validate that a network connection agrees with its referenced service.

    Args:
        scenario_id (str): Scenario identifier to include in validation errors.
        event (NetworkConnectionEvent): Network connection event to validate.
        service (Service): Referenced environment service.
        destination_host (Optional[Host]): Referenced destination host when already resolved.
        environment (Environment): Environment that event references must resolve through.
        errors (list[ValidationError]): Error list to update.

    Returns:
        None: Errors are appended to the provided list.
    """
    service_host = environment.get_host(service.target_host_id)

    if destination_host is not None:
        # Prefer explicit destination-host validation when the event supplied a host reference.
        _validate_service_host_conflict(scenario_id, event, service, destination_host, errors)
    elif service_host is not None and event.destination_ip != service_host.primary_ip:
        # Hostless events can still be checked against the service's target host IP.
        errors.append(
            _error(
                scenario_id,
                _field_path(event, "destination_ip"),
                event.destination_ip,
                f"destination_ip must match service '{service.id}' host IP '{service_host.primary_ip}'",
            )
        )

    if event.destination_port != service.port:
        errors.append(
            _error(
                scenario_id,
                _field_path(event, "destination_port"),
                event.destination_port,
                f"destination_port must match service '{service.id}' port '{service.port}'",
            )
        )

    if event.network_protocol != service.transport_protocol:
        errors.append(
            _error(
                scenario_id,
                _field_path(event, "network_protocol"),
                event.network_protocol,
                f"network_protocol must match service '{service.id}' transport protocol '{service.transport_protocol}'",
            )
        )

    if event.application_protocol is not None and event.application_protocol != service.application_protocol:
        errors.append(
            _error(
                scenario_id,
                _field_path(event, "application_protocol"),
                event.application_protocol,
                (
                    f"application_protocol must match service '{service.id}' application protocol "
                    f"'{service.application_protocol}'"
                ),
            )
        )


def _validate_service_host_conflict(
    scenario_id: str,
    event: SourceNeutralEvent,
    service: Service,
    destination_host: Optional[Host],
    errors: list[ValidationError],
) -> None:
    """
    Validate that a destination host agrees with its referenced service.

    Args:
        scenario_id (str): Scenario identifier to include in validation errors.
        event (SourceNeutralEvent): Event being validated.
        service (Service): Referenced environment service.
        destination_host (Optional[Host]): Referenced destination host when already resolved.
        errors (list[ValidationError]): Error list to update.

    Returns:
        None: Errors are appended to the provided list.
    """
    if destination_host is not None and destination_host.id != service.target_host_id:
        errors.append(
            _error(
                scenario_id,
                _field_path(event, "destination_host_id"),
                destination_host.id,
                f"destination_host_id must match service '{service.id}' target host '{service.target_host_id}'",
            )
        )


def _validate_successful_dns_answer(
    scenario_id: str,
    event: DnsLookupEvent,
    expected_address: str,
    errors: list[ValidationError],
) -> None:
    """
    Validate successful internal DNS answers.

    Args:
        scenario_id (str): Scenario identifier to include in validation errors.
        event (DnsLookupEvent): DNS lookup event to validate.
        expected_address (str): Expected answer from the environment DNS record.
        errors (list[ValidationError]): Error list to update.

    Returns:
        None: Errors are appended to the provided list.
    """
    if not event.resolved_addresses:
        # A successful internal lookup without addresses is semantically different from NXDOMAIN.
        errors.append(
            _error(
                scenario_id,
                _field_path(event, "resolved_addresses"),
                event.resolved_addresses,
                "successful internal A lookups must include at least one resolved address",
            )
        )
        return

    if expected_address not in event.resolved_addresses:
        errors.append(
            _error(
                scenario_id,
                _field_path(event, "resolved_addresses"),
                event.resolved_addresses,
                f"successful internal A lookup must include environment answer '{expected_address}'",
            )
        )


def _is_internal_a_lookup(event: DnsLookupEvent, environment: Environment) -> bool:
    """
    Return whether a DNS lookup targets an internal A record.

    Args:
        event (DnsLookupEvent): DNS lookup event to inspect.
        environment (Environment): Environment that defines the internal domain.

    Returns:
        bool: True when the lookup targets the environment domain as an A record.
    """
    return event.query_type == "A" and event.query_name.endswith(f".{environment.domain}")


def _require_user(
    scenario_id: str,
    event: SourceNeutralEvent,
    field_name: str,
    value: str,
    environment: Environment,
    errors: list[ValidationError],
) -> Optional[User]:
    """
    Resolve a user reference and append an error when it is unknown.

    Args:
        scenario_id (str): Scenario identifier to include in validation errors.
        event (SourceNeutralEvent): Event being validated.
        field_name (str): Field name that contains the user reference.
        value (str): User reference value.
        environment (Environment): Environment that should contain the user.
        errors (list[ValidationError]): Error list to update.

    Returns:
        Optional[User]: Resolved user when found; otherwise None.
    """
    user = environment.get_user(value)

    if user is None:
        errors.append(
            _error(
                scenario_id,
                _field_path(event, field_name),
                value,
                "user must exist in the environment",
            )
        )

    return user


def _require_host(
    scenario_id: str,
    event: SourceNeutralEvent,
    field_name: str,
    value: str,
    environment: Environment,
    errors: list[ValidationError],
) -> Optional[Host]:
    """
    Resolve a host reference and append an error when it is unknown.

    Args:
        scenario_id (str): Scenario identifier to include in validation errors.
        event (SourceNeutralEvent): Event being validated.
        field_name (str): Field name that contains the host reference.
        value (str): Host reference value.
        environment (Environment): Environment that should contain the host.
        errors (list[ValidationError]): Error list to update.

    Returns:
        Optional[Host]: Resolved host when found; otherwise None.
    """
    host = environment.get_host(value)

    if host is None:
        errors.append(
            _error(
                scenario_id,
                _field_path(event, field_name),
                value,
                "host must exist in the environment",
            )
        )

    return host


def _require_service(
    scenario_id: str,
    event: SourceNeutralEvent,
    field_name: str,
    value: str,
    environment: Environment,
    errors: list[ValidationError],
) -> Optional[Service]:
    """
    Resolve a service reference and append an error when it is unknown.

    Args:
        scenario_id (str): Scenario identifier to include in validation errors.
        event (SourceNeutralEvent): Event being validated.
        field_name (str): Field name that contains the service reference.
        value (str): Service reference value.
        environment (Environment): Environment that should contain the service.
        errors (list[ValidationError]): Error list to update.

    Returns:
        Optional[Service]: Resolved service when found; otherwise None.
    """
    service = environment.get_service(value)

    if service is None:
        errors.append(
            _error(
                scenario_id,
                _field_path(event, field_name),
                value,
                "service must exist in the environment",
            )
        )

    return service


def _field_path(event: SourceNeutralEvent, field_name: str) -> str:
    """
    Build a stable field path for an event validation error.

    Args:
        event (SourceNeutralEvent): Event containing the invalid field.
        field_name (str): Invalid field name.

    Returns:
        str: Stable event field path.
    """
    return f"events.{event.event_id}.{field_name}"


def _error(scenario_id: str, field_path: str, invalid_value: Any, reason: str) -> ValidationError:
    """
    Build a validation error.

    Args:
        scenario_id (str): Scenario identifier where the error occurred.
        field_path (str): Path to the invalid field.
        invalid_value (Any): Invalid value.
        reason (str): Actionable reason that explains the failure.

    Returns:
        ValidationError: Structured validation error.
    """
    return ValidationError(
        scenario_id=scenario_id,
        field_path=field_path,
        invalid_value=invalid_value,
        reason=reason,
    )


__all__ = [
    "ScenarioValidationError",
    "ValidationError",
    "require_valid_scenario",
    "validate_events",
    "validate_scenario",
]
