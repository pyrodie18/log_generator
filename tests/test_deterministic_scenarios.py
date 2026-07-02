"""
Tests for deterministic scenario primitives and canonical fixtures.
"""

from datetime import datetime, timezone

import pytest

from log_generator.core.events import DnsLookupEvent
from log_generator.core.environment import build_linux_mini_lab
from log_generator.core.scenarios import (
    AuthoredWebRequest,
    Scenario,
    ScenarioEvent,
    build_benign_internal_web_scenario,
    build_local_account_misuse_web_scenario,
    classify_web_request_path,
    derive_event_id,
    expand_authored_events,
    parse_utc_datetime,
)


def assert_parent_events_are_earlier(scenario: Scenario) -> None:
    """
    Assert every parent event reference points to an earlier event in scenario order.

    Args:
        scenario (Scenario): Scenario to inspect.

    Returns:
        None: This helper asserts parent ordering directly.
    """
    earlier_event_ids = set()

    for event in scenario.ordered_events():
        parent_event_id = getattr(event, "parent_event_id", None)

        if parent_event_id is not None:
            assert parent_event_id in earlier_event_ids

        earlier_event_ids.add(event.event_id)


def test_benign_canonical_scenario_has_stable_identity_and_ordering() -> None:
    """
    Verify the benign canonical fixture matches the documented deterministic sequence.

    Returns:
        None: This test asserts scenario metadata and event ordering directly.
    """
    scenario = build_benign_internal_web_scenario()
    rebuilt_scenario = build_benign_internal_web_scenario()

    assert scenario.id == "scenario-benign-internal-web"
    assert scenario.name == "Benign Internal Web Browsing"
    assert scenario.seed == 1001
    assert scenario.environment_id == "linux-mini-lab"
    assert scenario.environment_version == "0.1"
    assert scenario.start_time == datetime(2026, 1, 15, 14, 0, tzinfo=timezone.utc)
    assert scenario.end_time == datetime(2026, 1, 15, 14, 0, 2, tzinfo=timezone.utc)
    assert scenario.event_ids() == (
        "evt-benign-web-001",
        "evt-benign-web-002",
        "evt-benign-web-003",
    )
    assert scenario.event_ids() == rebuilt_scenario.event_ids()
    assert tuple(event.timestamp.isoformat() for event in scenario.ordered_events()) == (
        "2026-01-15T14:00:00+00:00",
        "2026-01-15T14:00:01+00:00",
        "2026-01-15T14:00:02+00:00",
    )
    assert scenario.correlation_ids() == ("corr-benign-internal-web-001",)
    assert_parent_events_are_earlier(scenario)


def test_misuse_canonical_scenario_has_stable_identity_and_ordering() -> None:
    """
    Verify the misuse canonical fixture matches the documented deterministic sequence.

    Returns:
        None: This test asserts scenario metadata and event ordering directly.
    """
    scenario = build_local_account_misuse_web_scenario()
    rebuilt_scenario = build_local_account_misuse_web_scenario()
    ordered_events = scenario.ordered_events()

    assert scenario.id == "scenario-local-account-misuse-web"
    assert scenario.name == "Local Account Misuse and Suspicious Web Access"
    assert scenario.seed == 2002
    assert scenario.environment_id == "linux-mini-lab"
    assert scenario.environment_version == "0.1"
    assert scenario.start_time == datetime(2026, 1, 15, 3, 12, tzinfo=timezone.utc)
    assert scenario.end_time == datetime(2026, 1, 15, 3, 12, 28, tzinfo=timezone.utc)
    assert scenario.event_ids() == (
        "evt-misuse-web-001",
        "evt-misuse-web-002",
        "evt-misuse-web-003",
        "evt-misuse-web-004",
        "evt-misuse-web-005",
    )
    assert scenario.event_ids() == rebuilt_scenario.event_ids()
    assert tuple(event.timestamp.isoformat() for event in ordered_events) == (
        "2026-01-15T03:12:00+00:00",
        "2026-01-15T03:12:15+00:00",
        "2026-01-15T03:12:16+00:00",
        "2026-01-15T03:12:18+00:00",
        "2026-01-15T03:12:28+00:00",
    )
    assert scenario.correlation_ids() == ("corr-local-account-misuse-001",)
    assert ordered_events[4].parent_event_id == "evt-misuse-web-003"
    assert_parent_events_are_earlier(scenario)


def test_web_expansion_generates_helpers_and_route_status_code() -> None:
    """
    Verify authored web requests expand into DNS, connection, and request events.

    Returns:
        None: This test asserts expanded helper behavior directly.
    """
    environment = build_linux_mini_lab()
    authored_events = (
        AuthoredWebRequest(
            event_id="evt-web-request",
            timestamp=parse_utc_datetime("2026-01-15T14:00:02Z"),
            actor_user_id="user-alice",
            source_host_id="linux-ws-01",
            service_id="svc-web-http",
            method="GET",
            path="/",
            correlation_id="corr-web-expansion",
        ),
    )

    events = expand_authored_events("scenario-web-expansion", 1001, environment, authored_events)
    expanded_events = tuple(scenario_event.event for scenario_event in events)

    assert tuple(event.event_type for event in expanded_events) == (
        "dns_lookup",
        "network_connection",
        "web_request",
    )
    assert tuple(event.timestamp.isoformat() for event in expanded_events) == (
        "2026-01-15T14:00:00+00:00",
        "2026-01-15T14:00:01+00:00",
        "2026-01-15T14:00:02+00:00",
    )
    assert expanded_events[0].event_id == derive_event_id("scenario-web-expansion", "dns_lookup", 1, 1001)
    assert expanded_events[1].parent_event_id == expanded_events[0].event_id
    assert expanded_events[2].parent_event_id == expanded_events[1].event_id
    assert expanded_events[2].status_code == 200


def test_misuse_web_expansion_reuses_connection_and_classifies_download() -> None:
    """
    Verify the misuse scenario reuses the HTTP connection and marks the archive as a download.

    Returns:
        None: This test asserts canonical web expansion behavior directly.
    """
    scenario = build_local_account_misuse_web_scenario()
    ordered_events = scenario.ordered_events()

    assert len(ordered_events) == 5
    assert ordered_events[3].event_type == "web_request"
    assert ordered_events[4].event_type == "web_request"
    assert ordered_events[3].parent_event_id == "evt-misuse-web-003"
    assert ordered_events[4].parent_event_id == "evt-misuse-web-003"
    assert ordered_events[4].metadata == {
        "download_classification": "download",
        "file_name": "archive.tar.gz",
    }


def test_web_path_download_classification_keeps_pages_unclassified() -> None:
    """
    Verify download classification only labels non-HTML file paths.

    Returns:
        None: This test asserts path classification directly.
    """
    assert classify_web_request_path("/") is None
    assert classify_web_request_path("/admin") is None
    assert classify_web_request_path("/about.html") is None
    assert classify_web_request_path("/admin/archive.tar.gz") == {
        "download_classification": "download",
        "file_name": "archive.tar.gz",
    }


def test_scenario_orders_same_timestamp_events_by_sequence_order() -> None:
    """
    Verify timestamp ties are resolved by authored or expanded sequence order.

    Returns:
        None: This test asserts deterministic ordering directly.
    """
    timestamp = parse_utc_datetime("2026-01-15T14:00:00Z")
    second_event = DnsLookupEvent(
        event_id="evt-order-002",
        scenario_id="scenario-order-test",
        timestamp=timestamp,
        status="success",
        correlation_id="corr-order-test",
        source_host_id="linux-ws-01",
        query_name="linux-ws-01.internal",
        query_type="A",
    )
    first_event = DnsLookupEvent(
        event_id="evt-order-001",
        scenario_id="scenario-order-test",
        timestamp=timestamp,
        status="success",
        correlation_id="corr-order-test",
        source_host_id="linux-ws-01",
        query_name="web-server-01.internal",
        query_type="A",
    )

    scenario = Scenario(
        id="scenario-order-test",
        name="Ordering Test",
        seed=99,
        environment_id="linux-mini-lab",
        environment_version="0.1",
        start_time=timestamp,
        events=(
            ScenarioEvent(sequence_order=2, event=second_event),
            ScenarioEvent(sequence_order=1, event=first_event),
        ),
    )

    assert scenario.event_ids() == ("evt-order-001", "evt-order-002")


def test_scenario_rejects_parent_that_is_not_earlier() -> None:
    """
    Verify scenario validation rejects unresolved or later parent event references.

    Returns:
        None: This test asserts parent validation directly.
    """
    timestamp = parse_utc_datetime("2026-01-15T14:00:00Z")
    child_event = DnsLookupEvent(
        event_id="evt-child",
        scenario_id="scenario-bad-parent",
        timestamp=timestamp,
        status="success",
        correlation_id="corr-bad-parent",
        parent_event_id="evt-parent",
        source_host_id="linux-ws-01",
        query_name="web-server-01.internal",
        query_type="A",
    )
    parent_event = DnsLookupEvent(
        event_id="evt-parent",
        scenario_id="scenario-bad-parent",
        timestamp=timestamp,
        status="success",
        correlation_id="corr-bad-parent",
        source_host_id="linux-ws-01",
        query_name="linux-ws-01.internal",
        query_type="A",
    )

    with pytest.raises(ValueError, match="must resolve to an earlier event"):
        Scenario(
            id="scenario-bad-parent",
            name="Bad Parent Test",
            seed=99,
            environment_id="linux-mini-lab",
            environment_version="0.1",
            start_time=timestamp,
            events=(
                ScenarioEvent(sequence_order=1, event=child_event),
                ScenarioEvent(sequence_order=2, event=parent_event),
            ),
        )


def test_derived_event_ids_are_stable_for_helper_events() -> None:
    """
    Verify helper event ID derivation is deterministic for identical scenario inputs.

    Returns:
        None: This test asserts derived event IDs directly.
    """
    first_event_id = derive_event_id("scenario-example", "dns_lookup", 1, 1001)
    second_event_id = derive_event_id("scenario-example", "dns_lookup", 1, 1001)
    different_event_id = derive_event_id("scenario-example", "network_connection", 2, 1001)

    assert first_event_id == second_event_id
    assert first_event_id == "evt-dns-lookup-001-1136ed55"
    assert different_event_id != first_event_id
