"""
Tests for the built-in linux-mini-lab environment fixture.
"""

import pytest

from log_generator.core.environment import (
    Environment,
    Host,
    NetworkZone,
    Service,
    User,
    build_linux_mini_lab,
)


def test_linux_mini_lab_identity_and_zones() -> None:
    """
    Verify the built-in environment exposes the expected identity and zones.

    Returns:
        None: This test asserts environment identity and zone fields directly.
    """
    environment = build_linux_mini_lab()

    assert environment.id == "linux-mini-lab"
    assert environment.version == "0.1"
    assert environment.timezone == "UTC"
    assert environment.get_zone("workstation-vlan").cidr == "10.10.10.0/24"
    assert environment.get_zone("server-vlan").cidr == "10.10.20.0/24"
    assert environment.get_zone("monitoring-vlan").cidr == "10.10.30.0/24"
    assert environment.get_zone("internet").zone_type == "external"


def test_host_lookup_resolves_canonical_identifiers() -> None:
    """
    Verify hosts resolve by ID, hostname, FQDN, and IP address.

    Returns:
        None: This test asserts host lookup behavior directly.
    """
    environment = build_linux_mini_lab()

    assert environment.get_host("linux-ws-01").primary_ip == "10.10.10.11"
    assert environment.get_host("linux-ws-01.internal").id == "linux-ws-01"
    assert environment.get_host("10.10.20.21").id == "web-server-01"
    assert environment.get_host("zeek-sensor-01").zone_id == "monitoring-vlan"

    lab_dns = environment.require_host("lab-dns-01")

    assert lab_dns.primary_ip == "10.10.20.53"
    assert lab_dns.logging_profiles == ()


def test_user_lookup_and_login_hosts_match_template() -> None:
    """
    Verify users resolve by ID and username with expected login hosts.

    Returns:
        None: This test asserts user lookup behavior directly.
    """
    environment = build_linux_mini_lab()

    assert environment.get_user("user-alice").username == "alice"
    assert environment.get_user("alice").login_hosts == ("linux-ws-01",)
    assert environment.get_user("bob").normal_login_hosts == ("linux-ws-01",)
    assert environment.get_user("carol").login_hosts == ("linux-ws-02",)
    assert environment.get_user("www-data").account_type == "service-account"


def test_service_lookup_and_http_routes_match_template() -> None:
    """
    Verify services and HTTP route defaults match the environment template.

    Returns:
        None: This test asserts service and route lookup behavior directly.
    """
    environment = build_linux_mini_lab()
    web_service = environment.require_service("svc-web-http")

    assert web_service.target_host_id == "web-server-01"
    assert web_service.port == 80
    assert web_service.transport_protocol == "tcp"
    assert web_service.application_protocol == "http"
    assert environment.get_service("web-server-01.internal").id == "svc-web-http"
    assert environment.get_http_route("svc-web-http", "GET", "/").default_status == 200
    assert environment.get_http_route("svc-web-http", "GET", "/admin").default_status == 200
    assert environment.get_http_route("svc-web-http", "GET", "/login").default_status == 403
    archive_route = environment.get_http_route("svc-web-http", "GET", "/admin/archive.tar.gz")

    assert archive_route.default_status == 200
    assert archive_route.purpose == "Suspicious archive download"


def test_dns_records_resolve_canonical_names() -> None:
    """
    Verify DNS records resolve the canonical lab names.

    Returns:
        None: This test asserts DNS lookup behavior directly.
    """
    environment = build_linux_mini_lab()

    assert environment.resolve_dns("linux-ws-01.internal") == "10.10.10.11"
    assert environment.resolve_dns("linux-ws-02.internal") == "10.10.10.12"
    assert environment.resolve_dns("web-server-01.internal") == "10.10.20.21"
    assert environment.resolve_dns("zeek-sensor-01.internal") == "10.10.30.31"
    assert environment.resolve_dns("lab-dns-01.internal") == "10.10.20.53"
    assert environment.resolve_dns("missing.internal") is None


def test_logging_profiles_and_network_device_references_match_template() -> None:
    """
    Verify logging profiles, firewall rules, and sensor visibility are represented.

    Returns:
        None: This test asserts environment telemetry references directly.
    """
    environment = build_linux_mini_lab()
    zeek_profile = environment.get_logging_profile("profile-zeek-only")
    apache_profile = environment.get_logging_profile("profile-apache-auditd")
    firewall = environment.get_network_device("boundary-fw-01")

    assert zeek_profile.families[0].streams == ("conn.log", "dns.log", "http.log")
    assert apache_profile.families[0].streams == ("access.log", "error.log")
    assert firewall.interfaces[0].ip == "10.10.10.1"
    assert environment.get_network_device("10.10.20.1").id == "boundary-fw-01"
    assert environment.get_firewall_rule("allow-workstations-dns").destination_ports == ("53",)
    assert environment.get_firewall_rule("allow-workstations-internal-web").protocols == ("tcp",)
    assert any(
        visibility.visible
        and visibility.sensor_id == "zeek-sensor-01"
        and visibility.source_zone_id == "workstation-vlan"
        and visibility.destination_zone_id == "server-vlan"
        for visibility in environment.sensor_visibility
    )


def test_required_lookup_helpers_raise_clear_errors() -> None:
    """
    Verify required lookup helpers raise clear errors for missing references.

    Returns:
        None: This test asserts missing-reference errors directly.
    """
    environment = build_linux_mini_lab()

    with pytest.raises(ValueError, match="unknown host 'missing-host'"):
        environment.require_host("missing-host")

    with pytest.raises(ValueError, match="unknown user 'missing-user'"):
        environment.require_user("missing-user")

    with pytest.raises(ValueError, match="unknown service 'missing-service'"):
        environment.require_service("missing-service")


def test_environment_lookup_index_preserves_first_match_and_equality() -> None:
    """
    Verify lookup indexes preserve scan-order semantics and do not affect equality.

    Returns:
        None: This test asserts indexed lookup behavior directly.
    """
    first_host = Host(
        id="host-first",
        hostname="shared",
        fqdn="shared.internal",
        zone_id="zone-a",
        primary_ip="10.0.0.1",
        os="linux",
        roles=(),
        logging_profiles=(),
    )
    second_host = Host(
        id="host-second",
        hostname="shared",
        fqdn="other.internal",
        zone_id="zone-a",
        primary_ip="10.0.0.2",
        os="linux",
        roles=(),
        logging_profiles=(),
    )
    environment = Environment(
        id="test-env",
        version="1",
        display_name="Test Environment",
        domain="internal",
        timezone="UTC",
        environment_type="test",
        zones=(
            NetworkZone(
                id="zone-a",
                display_name="Zone A",
                cidr=None,
                zone_type="internal",
                purpose="Testing",
                hosts=(first_host, second_host),
            ),
        ),
        users=(
            User(
                id="user-first",
                username="shared-user",
                display_name="First User",
                account_type="human",
                login_hosts=(),
                normal_login_hosts=(),
            ),
            User(
                id="user-second",
                username="shared-user",
                display_name="Second User",
                account_type="human",
                login_hosts=(),
                normal_login_hosts=(),
            ),
        ),
        groups=(),
        services=(
            Service(
                id="svc-first",
                name="Shared Service",
                target_host_id="host-first",
                port=80,
                transport_protocol="tcp",
                application_protocol="http",
                names=("shared-service.internal",),
                visibility=(),
            ),
            Service(
                id="svc-second",
                name="Shared Service",
                target_host_id="host-second",
                port=8080,
                transport_protocol="tcp",
                application_protocol="http",
                names=("other-service.internal",),
                visibility=(),
            ),
        ),
        dns_records=(),
        logging_profiles=(),
        network_devices=(),
        sensor_visibility=(),
    )
    equivalent_environment = Environment(
        id=environment.id,
        version=environment.version,
        display_name=environment.display_name,
        domain=environment.domain,
        timezone=environment.timezone,
        environment_type=environment.environment_type,
        zones=environment.zones,
        users=environment.users,
        groups=environment.groups,
        services=environment.services,
        dns_records=environment.dns_records,
        logging_profiles=environment.logging_profiles,
        network_devices=environment.network_devices,
        sensor_visibility=environment.sensor_visibility,
    )

    assert environment.get_host("shared").id == "host-first"
    assert environment.get_user("shared-user").id == "user-first"
    assert environment.get_service("Shared Service").id == "svc-first"
    assert environment == equivalent_environment
