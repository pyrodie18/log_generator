"""
Tests for semantic validation of source-neutral scenarios and events.
"""

import pytest

from log_generator.core.environment import build_linux_mini_lab
from log_generator.core.events import DnsLookupEvent, LinuxLocalLoginEvent, WebRequestEvent
from log_generator.core.scenarios import (
    Scenario,
    ScenarioEvent,
    build_benign_internal_web_scenario,
    build_local_account_misuse_web_scenario,
    parse_utc_datetime,
)
from log_generator.core.validation import (
    ScenarioValidationError,
    require_valid_scenario,
    validate_events,
    validate_scenario,
)


def test_canonical_scenarios_validate_successfully() -> None:
    """
    Verify both canonical scenarios pass semantic validation.

    Returns:
        None: This test asserts validation results directly.
    """
    environment = build_linux_mini_lab()

    assert validate_scenario(build_benign_internal_web_scenario(), environment) == []
    assert validate_scenario(build_local_account_misuse_web_scenario(), environment) == []


def test_require_valid_scenario_raises_structured_exception() -> None:
    """
    Verify callers can opt into exception-based validation.

    Returns:
        None: This test asserts the exception payload directly.
    """
    environment = build_linux_mini_lab()
    event = LinuxLocalLoginEvent(
        event_id="evt-invalid-login",
        scenario_id="scenario-invalid",
        timestamp=parse_utc_datetime("2026-01-15T14:00:00Z"),
        status="success",
        correlation_id="corr-invalid",
        actor_user_id="user-alice",
        target_host_id="linux-ws-02",
        login_method="local_console",
    )

    with pytest.raises(ScenarioValidationError) as exc_info:
        require_valid_scenario(
            Scenario(
                id="scenario-invalid",
                name="Invalid Scenario",
                seed=1,
                environment_id="linux-mini-lab",
                environment_version="0.1",
                start_time=parse_utc_datetime("2026-01-15T14:00:00Z"),
                events=(ScenarioEvent(sequence_order=1, event=event),),
            ),
            environment,
        )

    assert len(exc_info.value.errors) == 1
    assert "scenario-invalid: events.evt-invalid-login.target_host_id" in str(exc_info.value)


def test_unknown_user_validation_error_includes_actionable_context() -> None:
    """
    Verify unknown users produce structured validation errors.

    Returns:
        None: This test asserts validation error fields directly.
    """
    event = LinuxLocalLoginEvent(
        event_id="evt-unknown-user",
        scenario_id="scenario-invalid",
        timestamp=parse_utc_datetime("2026-01-15T14:00:00Z"),
        status="success",
        correlation_id="corr-invalid",
        actor_user_id="user-missing",
        target_host_id="linux-ws-01",
        login_method="local_console",
    )

    error = validate_events("scenario-invalid", (event,), build_linux_mini_lab())[0]

    assert error.scenario_id == "scenario-invalid"
    assert error.field_path == "events.evt-unknown-user.actor_user_id"
    assert error.invalid_value == "user-missing"
    assert error.reason == "user must exist in the environment"


def test_unknown_host_validation_error_includes_actionable_context() -> None:
    """
    Verify unknown hosts produce structured validation errors.

    Returns:
        None: This test asserts validation error fields directly.
    """
    event = DnsLookupEvent(
        event_id="evt-unknown-host",
        scenario_id="scenario-invalid",
        timestamp=parse_utc_datetime("2026-01-15T14:00:00Z"),
        status="success",
        correlation_id="corr-invalid",
        source_host_id="missing-host",
        query_name="web-server-01.internal",
        query_type="A",
        resolved_addresses=["10.10.20.21"],
    )

    error = validate_events("scenario-invalid", (event,), build_linux_mini_lab())[0]

    assert error.field_path == "events.evt-unknown-host.source_host_id"
    assert error.invalid_value == "missing-host"
    assert "host must exist" in error.reason


def test_invalid_login_host_is_rejected() -> None:
    """
    Verify successful local logins must target one of the user's valid login hosts.

    Returns:
        None: This test asserts validation error fields directly.
    """
    event = LinuxLocalLoginEvent(
        event_id="evt-invalid-login-host",
        scenario_id="scenario-invalid",
        timestamp=parse_utc_datetime("2026-01-15T14:00:00Z"),
        status="success",
        correlation_id="corr-invalid",
        actor_user_id="user-alice",
        target_host_id="linux-ws-02",
        login_method="local_console",
    )

    error = validate_events("scenario-invalid", (event,), build_linux_mini_lab())[0]

    assert error.field_path == "events.evt-invalid-login-host.target_host_id"
    assert error.invalid_value == "linux-ws-02"
    assert "login_hosts" in error.reason


def test_unknown_service_is_rejected() -> None:
    """
    Verify service references must resolve through the environment.

    Returns:
        None: This test asserts validation error fields directly.
    """
    event = WebRequestEvent(
        event_id="evt-unknown-service",
        scenario_id="scenario-invalid",
        timestamp=parse_utc_datetime("2026-01-15T14:00:00Z"),
        status="success",
        correlation_id="corr-invalid",
        actor_user_id="user-alice",
        source_host_id="linux-ws-01",
        service_id="svc-missing",
        method="GET",
        path="/",
        status_code=200,
    )

    error = validate_events("scenario-invalid", (event,), build_linux_mini_lab())[0]

    assert error.field_path == "events.evt-unknown-service.service_id"
    assert error.invalid_value == "svc-missing"
    assert "service must exist" in error.reason


def test_bad_route_is_rejected() -> None:
    """
    Verify web request paths must resolve to known HTTP routes.

    Returns:
        None: This test asserts validation error fields directly.
    """
    event = WebRequestEvent(
        event_id="evt-bad-route",
        scenario_id="scenario-invalid",
        timestamp=parse_utc_datetime("2026-01-15T14:00:00Z"),
        status="success",
        correlation_id="corr-invalid",
        actor_user_id="user-alice",
        source_host_id="linux-ws-01",
        destination_host_id="web-server-01",
        service_id="svc-web-http",
        method="GET",
        path="/admin/missing-file",
        status_code=404,
    )

    error = validate_events("scenario-invalid", (event,), build_linux_mini_lab())[0]

    assert error.field_path == "events.evt-bad-route.path"
    assert error.invalid_value == "/admin/missing-file"
    assert "must exist on service" in error.reason


def test_web_status_code_can_override_route_default() -> None:
    """
    Verify explicit web response status codes can differ from route defaults.

    Returns:
        None: This test asserts authored source-neutral override behavior directly.
    """
    event = WebRequestEvent(
        event_id="evt-status-override",
        scenario_id="scenario-valid",
        timestamp=parse_utc_datetime("2026-01-15T14:00:00Z"),
        status="success",
        correlation_id="corr-valid",
        actor_user_id="user-alice",
        source_host_id="linux-ws-01",
        destination_host_id="web-server-01",
        service_id="svc-web-http",
        method="GET",
        path="/",
        status_code=503,
    )

    assert validate_events("scenario-valid", (event,), build_linux_mini_lab()) == []


def test_web_status_code_range_is_validated_semantically() -> None:
    """
    Verify direct source-neutral web request events reject invalid HTTP status codes.

    Returns:
        None: This test asserts semantic status-code validation directly.
    """
    event = WebRequestEvent(
        event_id="evt-invalid-status",
        scenario_id="scenario-invalid",
        timestamp=parse_utc_datetime("2026-01-15T14:00:00Z"),
        status="success",
        correlation_id="corr-invalid",
        actor_user_id="user-alice",
        source_host_id="linux-ws-01",
        destination_host_id="web-server-01",
        service_id="svc-web-http",
        method="GET",
        path="/",
        status_code=99,
    )

    error = validate_events("scenario-invalid", (event,), build_linux_mini_lab())[0]

    assert error.field_path == "events.evt-invalid-status.status_code"
    assert error.invalid_value == 99
    assert "between 100 and 599" in error.reason


def test_unresolved_parent_event_is_rejected() -> None:
    """
    Verify parent references must point to earlier events in the same validation sequence.

    Returns:
        None: This test asserts validation error fields directly.
    """
    event = DnsLookupEvent(
        event_id="evt-child",
        scenario_id="scenario-invalid",
        timestamp=parse_utc_datetime("2026-01-15T14:00:00Z"),
        status="success",
        correlation_id="corr-invalid",
        parent_event_id="evt-missing-parent",
        source_host_id="linux-ws-01",
        query_name="web-server-01.internal",
        query_type="A",
        resolved_addresses=["10.10.20.21"],
    )

    error = validate_events("scenario-invalid", (event,), build_linux_mini_lab())[0]

    assert error.field_path == "events.evt-child.parent_event_id"
    assert error.invalid_value == "evt-missing-parent"
    assert "earlier event" in error.reason


def test_successful_internal_dns_lookup_requires_answer() -> None:
    """
    Verify successful internal A lookups include the environment DNS answer.

    Returns:
        None: This test asserts validation error fields directly.
    """
    event = DnsLookupEvent(
        event_id="evt-dns-missing-answer",
        scenario_id="scenario-invalid",
        timestamp=parse_utc_datetime("2026-01-15T14:00:00Z"),
        status="success",
        correlation_id="corr-invalid",
        source_host_id="linux-ws-01",
        query_name="web-server-01.internal",
        query_type="A",
        resolved_addresses=[],
    )

    error = validate_events("scenario-invalid", (event,), build_linux_mini_lab())[0]

    assert error.field_path == "events.evt-dns-missing-answer.resolved_addresses"
    assert "must include at least one resolved address" in error.reason
