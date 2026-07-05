"""
Tests for source-neutral event models.
"""

from datetime import datetime, timezone

import pytest

from log_generator.core.events import (
    DnsLookupEvent,
    DnsContext,
    HttpContext,
    LinuxLocalLoginEvent,
    NetworkContext,
    NetworkConnectionEvent,
    WebRequestEvent,
)


def test_dns_lookup_event_serializes_required_and_optional_fields() -> None:
    """
    Verify DNS lookup events serialize the common envelope and DNS fields.

    Returns:
        None: This test asserts serialized event fields directly.
    """
    event = DnsLookupEvent(
        event_id="evt-benign-web-001",
        scenario_id="scenario-benign-internal-web",
        timestamp=datetime(2026, 1, 15, 14, 0, 3, tzinfo=timezone.utc),
        status="success",
        correlation_id="corr-benign-web",
        source_host_id="linux-ws-01",
        query_name="web-server-01.internal",
        query_type="A",
        destination_host_id="lab-dns-01",
        service_id="svc-dns",
        resolved_addresses=["10.10.20.21"],
        rcode="NOERROR",
    )

    assert event.to_dict() == {
        "event_id": "evt-benign-web-001",
        "scenario_id": "scenario-benign-internal-web",
        "event_type": "dns_lookup",
        "timestamp": "2026-01-15T14:00:03+00:00",
        "status": "success",
        "correlation_id": "corr-benign-web",
        "source_host_id": "linux-ws-01",
        "destination_host_id": "lab-dns-01",
        "service_id": "svc-dns",
        "query_name": "web-server-01.internal",
        "query_type": "A",
        "resolved_addresses": ["10.10.20.21"],
        "rcode": "NOERROR",
    }


def test_network_connection_event_serializes_required_fields_without_placeholders() -> None:
    """
    Verify network connection events omit unspecified optional and source-specific fields.

    Returns:
        None: This test asserts serialized event fields directly.
    """
    event = NetworkConnectionEvent(
        event_id="evt-benign-web-002",
        scenario_id="scenario-benign-internal-web",
        timestamp=datetime(2026, 1, 15, 14, 0, 4, tzinfo=timezone.utc),
        status="success",
        correlation_id="corr-benign-web",
        source_host_id="linux-ws-01",
        source_ip="10.10.10.11",
        destination_ip="10.10.20.21",
        destination_port=80,
        network_protocol="tcp",
        parent_event_id="evt-benign-web-001",
        destination_host_id="web-server-01",
        service_id="svc-web-http",
        application_protocol="http",
    )
    serialized_event = event.to_dict()

    assert serialized_event["event_type"] == "network_connection"
    assert serialized_event["source_ip"] == "10.10.10.11"
    assert serialized_event["destination_ip"] == "10.10.20.21"
    assert serialized_event["destination_port"] == 80
    assert serialized_event["network_protocol"] == "tcp"
    assert serialized_event["application_protocol"] == "http"
    assert serialized_event["parent_event_id"] == "evt-benign-web-001"
    assert "uid" not in serialized_event
    assert "firewall_rule_name" not in serialized_event
    assert "metadata" not in serialized_event
    assert "attack" not in serialized_event


def test_shared_detail_contexts_serialize_under_source_neutral_namespaces() -> None:
    """
    Verify authored shared details serialize without introducing source-specific fields.

    Returns:
        None: This test asserts serialized context namespaces directly.
    """
    connection_event = NetworkConnectionEvent(
        event_id="evt-web-002",
        scenario_id="scenario-shared-details",
        timestamp=datetime(2026, 1, 15, 14, 0, 4, tzinfo=timezone.utc),
        status="success",
        correlation_id="corr-shared-details",
        source_host_id="linux-ws-01",
        source_ip="10.10.10.11",
        destination_ip="10.10.20.21",
        destination_port=80,
        network_protocol="tcp",
        network=NetworkContext(source_port=55000, orig_bytes=120, resp_bytes=2048),
    )
    dns_event = DnsLookupEvent(
        event_id="evt-web-001",
        scenario_id="scenario-shared-details",
        timestamp=datetime(2026, 1, 15, 14, 0, 3, tzinfo=timezone.utc),
        status="success",
        correlation_id="corr-shared-details",
        source_host_id="linux-ws-01",
        query_name="web-server-01.internal",
        query_type="A",
        dns=DnsContext(trans_id=4242, rtt=0.125, ttls=[60.0], flags={"RD": False, "RA": True}),
    )
    web_event = WebRequestEvent(
        event_id="evt-web-003",
        scenario_id="scenario-shared-details",
        timestamp=datetime(2026, 1, 15, 14, 0, 5, tzinfo=timezone.utc),
        status="success",
        correlation_id="corr-shared-details",
        source_host_id="linux-ws-01",
        service_id="svc-web-http",
        method="GET",
        path="/",
        status_code=200,
        http=HttpContext(user_agent="curl/8.5.0", version="1.0", response_body_len=512),
    )

    assert connection_event.to_dict()["network"] == {
        "source_port": 55000,
        "orig_bytes": 120,
        "resp_bytes": 2048,
    }
    assert dns_event.to_dict()["dns"] == {
        "trans_id": 4242,
        "rtt": 0.125,
        "ttls": [60.0],
        "flags": {"RD": False, "RA": True},
    }
    assert web_event.to_dict()["http"] == {
        "user_agent": "curl/8.5.0",
        "version": "1.0",
        "response_body_len": 512,
    }
    assert "uid" not in connection_event.to_dict()


def test_web_request_event_requires_status_code_and_serializes_metadata() -> None:
    """
    Verify web request events include expanded status codes and optional source-neutral metadata.

    Returns:
        None: This test asserts serialized event fields directly.
    """
    event = WebRequestEvent(
        event_id="evt-misuse-web-005",
        scenario_id="scenario-local-account-misuse-web",
        timestamp=datetime(2026, 1, 15, 14, 5, 20, tzinfo=timezone.utc),
        status="success",
        correlation_id="corr-misuse-web",
        source_host_id="linux-ws-01",
        service_id="svc-web-http",
        method="GET",
        path="/admin/archive.tar.gz",
        status_code=200,
        parent_event_id="evt-misuse-web-003",
        actor_user_id="user-alice",
        destination_host_id="web-server-01",
        metadata={"download_classification": "download", "file_name": "archive.tar.gz"},
        attack={"technique_id": "T1005", "tactic": "collection"},
    )
    serialized_event = event.to_dict()

    assert serialized_event["event_type"] == "web_request"
    assert serialized_event["method"] == "GET"
    assert serialized_event["path"] == "/admin/archive.tar.gz"
    assert serialized_event["status_code"] == 200
    assert serialized_event["metadata"] == {
        "download_classification": "download",
        "file_name": "archive.tar.gz",
    }
    assert serialized_event["attack"] == {"technique_id": "T1005", "tactic": "collection"}
    assert "apache_bytes_sent" not in serialized_event


def test_linux_local_login_event_serializes_required_fields() -> None:
    """
    Verify Linux local login events serialize login-specific fields.

    Returns:
        None: This test asserts serialized event fields directly.
    """
    event = LinuxLocalLoginEvent(
        event_id="evt-misuse-web-001",
        scenario_id="scenario-local-account-misuse-web",
        timestamp=datetime(2026, 1, 15, 14, 5, 0, tzinfo=timezone.utc),
        status="success",
        correlation_id="corr-misuse-web",
        actor_user_id="user-alice",
        target_host_id="linux-ws-01",
        login_method="local_console",
        metadata={"activity_classification": "suspicious"},
    )

    assert event.to_dict() == {
        "event_id": "evt-misuse-web-001",
        "scenario_id": "scenario-local-account-misuse-web",
        "event_type": "linux_local_login",
        "timestamp": "2026-01-15T14:05:00+00:00",
        "status": "success",
        "correlation_id": "corr-misuse-web",
        "actor_user_id": "user-alice",
        "metadata": {"activity_classification": "suspicious"},
        "target_host_id": "linux-ws-01",
        "login_method": "local_console",
    }


def test_event_timestamp_must_be_timezone_aware() -> None:
    """
    Verify naive datetimes are rejected before serialization.

    Returns:
        None: This test asserts timestamp validation directly.
    """
    with pytest.raises(ValueError, match="event timestamp must be timezone-aware"):
        DnsLookupEvent(
            event_id="evt-invalid",
            scenario_id="scenario-invalid",
            timestamp=datetime(2026, 1, 15, 14, 0, 3),
            status="success",
            correlation_id="corr-invalid",
            source_host_id="linux-ws-01",
            query_name="web-server-01.internal",
            query_type="A",
        )


def test_event_status_must_be_supported() -> None:
    """
    Verify unsupported status values are rejected.

    Returns:
        None: This test asserts status validation directly.
    """
    with pytest.raises(ValueError, match="unsupported event status 'partial'"):
        WebRequestEvent(
            event_id="evt-invalid",
            scenario_id="scenario-invalid",
            timestamp=datetime(2026, 1, 15, 14, 0, 5, tzinfo=timezone.utc),
            status="partial",
            correlation_id="corr-invalid",
            source_host_id="linux-ws-01",
            service_id="svc-web-http",
            method="GET",
            path="/",
            status_code=200,
        )


def test_network_connection_requires_valid_ip_addresses_and_port() -> None:
    """
    Verify network connection event fields reject invalid address and port values.

    Returns:
        None: This test asserts validation failures directly.
    """
    with pytest.raises(ValueError, match="source_ip must be a valid IP address"):
        NetworkConnectionEvent(
            event_id="evt-invalid-network",
            scenario_id="scenario-invalid",
            timestamp=datetime(2026, 1, 15, 14, 0, 4, tzinfo=timezone.utc),
            status="success",
            correlation_id="corr-invalid",
            source_host_id="linux-ws-01",
            source_ip="not an address",
            destination_ip="10.10.20.21",
            destination_port=80,
            network_protocol="tcp",
        )

    with pytest.raises(ValueError, match="destination_port must be between 0 and 65535"):
        NetworkConnectionEvent(
            event_id="evt-invalid-network",
            scenario_id="scenario-invalid",
            timestamp=datetime(2026, 1, 15, 14, 0, 4, tzinfo=timezone.utc),
            status="success",
            correlation_id="corr-invalid",
            source_host_id="linux-ws-01",
            source_ip="10.10.10.11",
            destination_ip="10.10.20.21",
            destination_port=70000,
            network_protocol="tcp",
        )


def test_dns_lookup_requires_valid_resolved_addresses() -> None:
    """
    Verify DNS lookup answer addresses must be syntactically valid IP addresses.

    Returns:
        None: This test asserts validation failures directly.
    """
    with pytest.raises(ValueError, match=r"resolved_addresses\[0\] must be a valid IP address"):
        DnsLookupEvent(
            event_id="evt-invalid-dns",
            scenario_id="scenario-invalid",
            timestamp=datetime(2026, 1, 15, 14, 0, 3, tzinfo=timezone.utc),
            status="success",
            correlation_id="corr-invalid",
            source_host_id="linux-ws-01",
            query_name="web-server-01.internal",
            query_type="A",
            resolved_addresses=["not an address"],
        )
