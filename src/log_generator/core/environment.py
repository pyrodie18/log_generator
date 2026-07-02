"""
Environment model definitions for source-neutral generation.
"""

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class NetworkZone:
    """
    Represent a network zone in a modeled environment.
    """

    id: str
    display_name: str
    cidr: Optional[str]
    zone_type: str
    purpose: str
    hosts: tuple["Host", ...]


@dataclass(frozen=True)
class Host:
    """
    Represent a host that can participate in source-neutral activity.
    """

    id: str
    hostname: str
    fqdn: str
    zone_id: str
    primary_ip: str
    os: str
    roles: tuple[str, ...]
    logging_profiles: tuple[str, ...]


@dataclass(frozen=True)
class User:
    """
    Represent a user or service account in the modeled environment.
    """

    id: str
    username: str
    display_name: str
    account_type: str
    login_hosts: tuple[str, ...]
    normal_login_hosts: tuple[str, ...]


@dataclass(frozen=True)
class Group:
    """
    Represent a simple user group.
    """

    id: str
    name: str
    members: tuple[str, ...]
    purpose: str


@dataclass(frozen=True)
class HttpRoute:
    """
    Represent a route served by an HTTP service.
    """

    method: str
    path: str
    default_status: int
    purpose: str


@dataclass(frozen=True)
class Service:
    """
    Represent a service hosted by an environment host.
    """

    id: str
    name: str
    target_host_id: str
    port: int
    transport_protocol: str
    application_protocol: str
    names: tuple[str, ...]
    visibility: tuple[str, ...]
    routes: tuple[HttpRoute, ...] = ()


@dataclass(frozen=True)
class DnsRecord:
    """
    Represent a DNS record known by the environment.
    """

    name: str
    record_type: str
    value: str


@dataclass(frozen=True)
class LoggingFamily:
    """
    Represent one logging family and its streams.
    """

    name: str
    streams: tuple[str, ...]


@dataclass(frozen=True)
class LoggingProfile:
    """
    Represent telemetry streams attached to hosts or network devices.
    """

    id: str
    families: tuple[LoggingFamily, ...]


@dataclass(frozen=True)
class NetworkInterface:
    """
    Represent an interface on a modeled network device.
    """

    zone_id: str
    ip: str


@dataclass(frozen=True)
class FirewallRule:
    """
    Represent a network-device policy rule.
    """

    id: str
    source_zones: tuple[str, ...]
    destination_zones: tuple[str, ...]
    protocols: tuple[str, ...]
    destination_ports: tuple[str, ...]
    action: str
    logging: bool
    nat: Optional[dict[str, str]] = None


@dataclass(frozen=True)
class NetworkDevice:
    """
    Represent a routed or filtering network device.
    """

    id: str
    device_type: str
    interfaces: tuple[NetworkInterface, ...]
    logging_profiles: tuple[str, ...]
    policies: tuple[FirewallRule, ...]


@dataclass(frozen=True)
class SensorVisibility:
    """
    Represent whether a passive sensor can observe traffic between two zones.
    """

    sensor_id: str
    source_zone_id: str
    destination_zone_id: str
    visible: bool
    notes: str


@dataclass(frozen=True)
class Environment:
    """
    Represent a complete source-neutral environment template.
    """

    id: str
    version: str
    display_name: str
    domain: str
    timezone: str
    environment_type: str
    zones: tuple[NetworkZone, ...]
    users: tuple[User, ...]
    groups: tuple[Group, ...]
    services: tuple[Service, ...]
    dns_records: tuple[DnsRecord, ...]
    logging_profiles: tuple[LoggingProfile, ...]
    network_devices: tuple[NetworkDevice, ...]
    sensor_visibility: tuple[SensorVisibility, ...]

    def all_hosts(self) -> tuple[Host, ...]:
        """
        Return all hosts from every zone.

        Returns:
            tuple[Host, ...]: Hosts defined in the environment.
        """
        hosts = []

        for zone in self.zones:
            # Hosts are nested under zones in the template, but most validation wants a flat host view.
            hosts.extend(zone.hosts)

        return tuple(hosts)

    def get_zone(self, identifier: str) -> Optional[NetworkZone]:
        """
        Look up a zone by ID.

        Args:
            identifier (str): Zone ID to resolve.

        Returns:
            Optional[NetworkZone]: Matching zone when found; otherwise None.
        """
        normalized_identifier = identifier.lower()

        for zone in self.zones:
            if zone.id == normalized_identifier:
                return zone

        return None

    def get_host(self, identifier: str) -> Optional[Host]:
        """
        Look up a host by ID, hostname, FQDN, or primary IP address.

        Args:
            identifier (str): Host identifier to resolve.

        Returns:
            Optional[Host]: Matching host when found; otherwise None.
        """
        normalized_identifier = identifier.lower()

        for host in self.all_hosts():
            if normalized_identifier in {host.id, host.hostname, host.fqdn, host.primary_ip}:
                return host

        return None

    def require_host(self, identifier: str) -> Host:
        """
        Look up a host and raise ValueError when it is missing.

        Args:
            identifier (str): Host identifier to resolve.

        Returns:
            Host: Matching host.
        """
        host = self.get_host(identifier)

        if host is None:
            raise ValueError(f"unknown host '{identifier}'")

        return host

    def get_user(self, identifier: str) -> Optional[User]:
        """
        Look up a user by user ID or username.

        Args:
            identifier (str): User identifier to resolve.

        Returns:
            Optional[User]: Matching user when found; otherwise None.
        """
        normalized_identifier = identifier.lower()

        for user in self.users:
            if normalized_identifier in {user.id, user.username}:
                return user

        return None

    def require_user(self, identifier: str) -> User:
        """
        Look up a user and raise ValueError when it is missing.

        Args:
            identifier (str): User identifier to resolve.

        Returns:
            User: Matching user.
        """
        user = self.get_user(identifier)

        if user is None:
            raise ValueError(f"unknown user '{identifier}'")

        return user

    def get_service(self, identifier: str) -> Optional[Service]:
        """
        Look up a service by ID, display name, or configured service name.

        Args:
            identifier (str): Service identifier to resolve.

        Returns:
            Optional[Service]: Matching service when found; otherwise None.
        """
        normalized_identifier = identifier.lower()

        for service in self.services:
            service_names = {service.id, service.name.lower(), *service.names}
            if normalized_identifier in service_names:
                return service

        return None

    def require_service(self, identifier: str) -> Service:
        """
        Look up a service and raise ValueError when it is missing.

        Args:
            identifier (str): Service identifier to resolve.

        Returns:
            Service: Matching service.
        """
        service = self.get_service(identifier)

        if service is None:
            raise ValueError(f"unknown service '{identifier}'")

        return service

    def get_network_device(self, identifier: str) -> Optional[NetworkDevice]:
        """
        Look up a network device by ID or interface IP address.

        Args:
            identifier (str): Network device identifier to resolve.

        Returns:
            Optional[NetworkDevice]: Matching network device when found; otherwise None.
        """
        normalized_identifier = identifier.lower()

        for device in self.network_devices:
            interface_ips = {interface.ip for interface in device.interfaces}
            if normalized_identifier == device.id or normalized_identifier in interface_ips:
                return device

        return None

    def get_firewall_rule(self, identifier: str) -> Optional[FirewallRule]:
        """
        Look up a firewall rule by rule ID.

        Args:
            identifier (str): Firewall rule ID to resolve.

        Returns:
            Optional[FirewallRule]: Matching firewall rule when found; otherwise None.
        """
        normalized_identifier = identifier.lower()

        for device in self.network_devices:
            for rule in device.policies:
                if rule.id == normalized_identifier:
                    return rule

        return None

    def get_logging_profile(self, identifier: str) -> Optional[LoggingProfile]:
        """
        Look up a logging profile by profile ID.

        Args:
            identifier (str): Logging profile ID to resolve.

        Returns:
            Optional[LoggingProfile]: Matching logging profile when found; otherwise None.
        """
        normalized_identifier = identifier.lower()

        for profile in self.logging_profiles:
            if profile.id == normalized_identifier:
                return profile

        return None

    def get_dns_record(self, name: str, record_type: str = "A") -> Optional[DnsRecord]:
        """
        Look up a DNS record by name and record type.

        Args:
            name (str): DNS name to resolve.
            record_type (str): DNS record type to match.

        Returns:
            Optional[DnsRecord]: Matching DNS record when found; otherwise None.
        """
        normalized_name = name.lower()
        normalized_record_type = record_type.upper()

        for record in self.dns_records:
            if record.name == normalized_name and record.record_type == normalized_record_type:
                return record

        return None

    def resolve_dns(self, name: str, record_type: str = "A") -> Optional[str]:
        """
        Resolve a DNS record to its value.

        Args:
            name (str): DNS name to resolve.
            record_type (str): DNS record type to match.

        Returns:
            Optional[str]: DNS record value when found; otherwise None.
        """
        record = self.get_dns_record(name, record_type=record_type)

        if record is None:
            return None

        return record.value

    def get_http_route(self, service_id: str, method: str, path: str) -> Optional[HttpRoute]:
        """
        Look up an HTTP route by service ID, method, and path.

        Args:
            service_id (str): Service ID that owns the route.
            method (str): HTTP method to match.
            path (str): HTTP path to match.

        Returns:
            Optional[HttpRoute]: Matching route when found; otherwise None.
        """
        service = self.get_service(service_id)

        if service is None:
            return None

        normalized_method = method.upper()

        for route in service.routes:
            if route.method == normalized_method and route.path == path:
                return route

        return None


def build_linux_mini_lab() -> Environment:
    """
    Build the built-in linux-mini-lab environment fixture.

    Returns:
        Environment: Complete linux-mini-lab environment definition.
    """
    linux_ws_01 = Host(
        id="linux-ws-01",
        hostname="linux-ws-01",
        fqdn="linux-ws-01.internal",
        zone_id="workstation-vlan",
        primary_ip="10.10.10.11",
        os="ubuntu-linux",
        roles=("workstation",),
        logging_profiles=("profile-auditd-only",),
    )
    linux_ws_02 = Host(
        id="linux-ws-02",
        hostname="linux-ws-02",
        fqdn="linux-ws-02.internal",
        zone_id="workstation-vlan",
        primary_ip="10.10.10.12",
        os="ubuntu-linux",
        roles=("workstation",),
        logging_profiles=("profile-auditd-only",),
    )
    web_server_01 = Host(
        id="web-server-01",
        hostname="web-server-01",
        fqdn="web-server-01.internal",
        zone_id="server-vlan",
        primary_ip="10.10.20.21",
        os="ubuntu-linux",
        roles=("web-server",),
        logging_profiles=("profile-apache-auditd",),
    )
    lab_dns_01 = Host(
        id="lab-dns-01",
        hostname="lab-dns-01",
        fqdn="lab-dns-01.internal",
        zone_id="server-vlan",
        primary_ip="10.10.20.53",
        os="ubuntu-linux",
        roles=("dns-resolver",),
        logging_profiles=(),
    )
    zeek_sensor_01 = Host(
        id="zeek-sensor-01",
        hostname="zeek-sensor-01",
        fqdn="zeek-sensor-01.internal",
        zone_id="monitoring-vlan",
        primary_ip="10.10.30.31",
        os="zeek-sensor",
        roles=("network-sensor",),
        logging_profiles=("profile-zeek-only",),
    )

    zones = (
        NetworkZone(
            id="workstation-vlan",
            display_name="Workstation VLAN",
            cidr="10.10.10.0/24",
            zone_type="internal",
            purpose="Linux user workstations.",
            hosts=(linux_ws_01, linux_ws_02),
        ),
        NetworkZone(
            id="server-vlan",
            display_name="Server VLAN",
            cidr="10.10.20.0/24",
            zone_type="internal",
            purpose="Internal application and infrastructure services.",
            hosts=(web_server_01, lab_dns_01),
        ),
        NetworkZone(
            id="monitoring-vlan",
            display_name="Monitoring VLAN",
            cidr="10.10.30.0/24",
            zone_type="internal",
            purpose="Sensor management and monitoring interfaces.",
            hosts=(zeek_sensor_01,),
        ),
        NetworkZone(
            id="internet",
            display_name="Internet",
            cidr=None,
            zone_type="external",
            purpose="External resources outside the lab boundary.",
            hosts=(),
        ),
    )

    routes = (
        HttpRoute(method="GET", path="/", default_status=200, purpose="Homepage"),
        HttpRoute(method="GET", path="/about", default_status=200, purpose="Static informational page"),
        HttpRoute(method="GET", path="/admin", default_status=200, purpose="Administrative page"),
        HttpRoute(method="GET", path="/login", default_status=403, purpose="Denied login portal access attempt"),
        HttpRoute(
            method="GET",
            path="/admin/archive.tar.gz",
            default_status=200,
            purpose="Suspicious archive download",
        ),
        HttpRoute(method="GET", path="/missing", default_status=404, purpose="Missing page"),
    )

    network_devices = (
        NetworkDevice(
            id="boundary-fw-01",
            device_type="firewall",
            interfaces=(
                NetworkInterface(zone_id="workstation-vlan", ip="10.10.10.1"),
                NetworkInterface(zone_id="server-vlan", ip="10.10.20.1"),
                NetworkInterface(zone_id="internet", ip="203.0.113.10"),
            ),
            logging_profiles=("profile-firewall-traffic",),
            policies=(
                FirewallRule(
                    id="allow-workstations-dns",
                    source_zones=("workstation-vlan",),
                    destination_zones=("server-vlan",),
                    protocols=("udp",),
                    destination_ports=("53",),
                    action="allow",
                    logging=True,
                ),
                FirewallRule(
                    id="allow-workstations-internal-web",
                    source_zones=("workstation-vlan",),
                    destination_zones=("server-vlan",),
                    protocols=("tcp",),
                    destination_ports=("80",),
                    action="allow",
                    logging=True,
                ),
                FirewallRule(
                    id="allow-workstations-external-web",
                    source_zones=("workstation-vlan",),
                    destination_zones=("internet",),
                    protocols=("tcp",),
                    destination_ports=("80", "443"),
                    action="allow",
                    logging=True,
                    nat={"type": "source_nat", "translated_source_ip": "203.0.113.10"},
                ),
                FirewallRule(
                    id="deny-workstations-other",
                    source_zones=("workstation-vlan",),
                    destination_zones=("any",),
                    protocols=("any",),
                    destination_ports=("any",),
                    action="deny",
                    logging=True,
                ),
            ),
        ),
    )

    return Environment(
        id="linux-mini-lab",
        version="0.1",
        display_name="Linux Mini Lab",
        domain="internal",
        timezone="UTC",
        environment_type="small-internal-lab",
        zones=zones,
        users=(
            User(
                id="user-alice",
                username="alice",
                display_name="Alice Adams",
                account_type="local-user",
                login_hosts=("linux-ws-01",),
                normal_login_hosts=("linux-ws-01",),
            ),
            User(
                id="user-bob",
                username="bob",
                display_name="Bob Brown",
                account_type="local-user",
                login_hosts=("linux-ws-01",),
                normal_login_hosts=("linux-ws-01",),
            ),
            User(
                id="user-carol",
                username="carol",
                display_name="Carol Clark",
                account_type="local-user",
                login_hosts=("linux-ws-02",),
                normal_login_hosts=("linux-ws-02",),
            ),
            User(
                id="user-www-data",
                username="www-data",
                display_name="Apache Runtime User",
                account_type="service-account",
                login_hosts=("web-server-01",),
                normal_login_hosts=(),
            ),
        ),
        groups=(
            Group(
                id="group-workstation-users",
                name="workstation-users",
                members=("user-alice", "user-bob", "user-carol"),
                purpose="Normal interactive workstation users.",
            ),
            Group(
                id="group-web-runtime",
                name="web-runtime",
                members=("user-www-data",),
                purpose="Runtime identity for the Apache service.",
            ),
        ),
        services=(
            Service(
                id="svc-web-http",
                name="Internal Apache HTTP",
                target_host_id="web-server-01",
                port=80,
                transport_protocol="tcp",
                application_protocol="http",
                names=("web-server-01.internal",),
                visibility=("zeek", "apache"),
                routes=routes,
            ),
            Service(
                id="svc-web-ssh",
                name="Web Server SSH",
                target_host_id="web-server-01",
                port=22,
                transport_protocol="tcp",
                application_protocol="ssh",
                names=("web-server-01.internal",),
                visibility=("zeek", "auditd"),
            ),
            Service(
                id="svc-dns",
                name="Internal DNS Resolver",
                target_host_id="lab-dns-01",
                port=53,
                transport_protocol="udp",
                application_protocol="dns",
                names=("lab-dns-01.internal",),
                visibility=("zeek",),
            ),
        ),
        dns_records=(
            DnsRecord(name="linux-ws-01.internal", record_type="A", value="10.10.10.11"),
            DnsRecord(name="linux-ws-02.internal", record_type="A", value="10.10.10.12"),
            DnsRecord(name="web-server-01.internal", record_type="A", value="10.10.20.21"),
            DnsRecord(name="zeek-sensor-01.internal", record_type="A", value="10.10.30.31"),
            DnsRecord(name="lab-dns-01.internal", record_type="A", value="10.10.20.53"),
        ),
        logging_profiles=(
            LoggingProfile(
                id="profile-zeek-only",
                families=(LoggingFamily(name="zeek", streams=("conn.log", "dns.log", "http.log")),),
            ),
            LoggingProfile(
                id="profile-auditd-only",
                families=(LoggingFamily(name="auditd", streams=("audit.log",)),),
            ),
            LoggingProfile(
                id="profile-apache-auditd",
                families=(
                    LoggingFamily(name="apache", streams=("access.log", "error.log")),
                    LoggingFamily(name="auditd", streams=("audit.log",)),
                ),
            ),
            LoggingProfile(
                id="profile-firewall-traffic",
                families=(LoggingFamily(name="firewall", streams=("traffic.log",)),),
            ),
        ),
        network_devices=network_devices,
        sensor_visibility=(
            SensorVisibility(
                sensor_id="zeek-sensor-01",
                source_zone_id="workstation-vlan",
                destination_zone_id="server-vlan",
                visible=True,
                notes="Required for DNS and web scenarios.",
            ),
            SensorVisibility(
                sensor_id="zeek-sensor-01",
                source_zone_id="server-vlan",
                destination_zone_id="workstation-vlan",
                visible=True,
                notes="Required for response-side connection metadata.",
            ),
            SensorVisibility(
                sensor_id="zeek-sensor-01",
                source_zone_id="workstation-vlan",
                destination_zone_id="workstation-vlan",
                visible=True,
                notes="Useful for future lateral or peer traffic scenarios.",
            ),
            SensorVisibility(
                sensor_id="zeek-sensor-01",
                source_zone_id="server-vlan",
                destination_zone_id="server-vlan",
                visible=True,
                notes="No MVP scenario currently depends on this path.",
            ),
            SensorVisibility(
                sensor_id="zeek-sensor-01",
                source_zone_id="workstation-vlan",
                destination_zone_id="internet",
                visible=False,
                notes="Boundary firewall telemetry covers external traffic in this template.",
            ),
            SensorVisibility(
                sensor_id="zeek-sensor-01",
                source_zone_id="monitoring-vlan",
                destination_zone_id="any",
                visible=False,
                notes="Sensor management traffic is out of scope for MVP scenarios.",
            ),
        ),
    )


__all__ = [
    "DnsRecord",
    "Environment",
    "FirewallRule",
    "Group",
    "Host",
    "HttpRoute",
    "LoggingFamily",
    "LoggingProfile",
    "NetworkDevice",
    "NetworkInterface",
    "NetworkZone",
    "SensorVisibility",
    "Service",
    "User",
    "build_linux_mini_lab",
]
