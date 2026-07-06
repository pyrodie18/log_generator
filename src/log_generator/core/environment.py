"""
Environment model definitions for source-neutral generation.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Optional


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
class EnvironmentIndex:
    """
    Store precomputed lookup indexes for an environment.
    """

    hosts: tuple[Host, ...]
    zones_by_id: dict[str, NetworkZone]
    hosts_by_identifier: dict[str, Host]
    users_by_identifier: dict[str, User]
    services_by_identifier: dict[str, Service]
    network_devices_by_identifier: dict[str, NetworkDevice]
    firewall_rules_by_id: dict[str, FirewallRule]
    logging_profiles_by_id: dict[str, LoggingProfile]
    dns_records_by_key: dict[tuple[str, str], DnsRecord]
    http_routes_by_key: dict[tuple[str, str, str], HttpRoute]


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
    _lookup_index: Optional[EnvironmentIndex] = field(default=None, init=False, repr=False, compare=False)

    def _index(self) -> EnvironmentIndex:
        """
        Return the lazily built lookup index for this environment.

        Returns:
            EnvironmentIndex: Cached lookup index.
        """
        if self._lookup_index is None:
            # The dataclass is frozen for public model immutability; the private cache avoids repeated scans.
            object.__setattr__(self, "_lookup_index", build_environment_index(self))

        return self._lookup_index

    def all_hosts(self) -> tuple[Host, ...]:
        """
        Return all hosts from every zone.

        Returns:
            tuple[Host, ...]: Hosts defined in the environment.
        """
        return self._index().hosts

    def get_zone(self, identifier: str) -> Optional[NetworkZone]:
        """
        Look up a zone by ID.

        Args:
            identifier (str): Zone ID to resolve.

        Returns:
            Optional[NetworkZone]: Matching zone when found; otherwise None.
        """
        return self._index().zones_by_id.get(identifier.lower())

    def get_host(self, identifier: str) -> Optional[Host]:
        """
        Look up a host by ID, hostname, FQDN, or primary IP address.

        Args:
            identifier (str): Host identifier to resolve.

        Returns:
            Optional[Host]: Matching host when found; otherwise None.
        """
        return self._index().hosts_by_identifier.get(identifier.lower())

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
        return self._index().users_by_identifier.get(identifier.lower())

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
        return self._index().services_by_identifier.get(identifier.lower())

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
        return self._index().network_devices_by_identifier.get(identifier.lower())

    def get_firewall_rule(self, identifier: str) -> Optional[FirewallRule]:
        """
        Look up a firewall rule by rule ID.

        Args:
            identifier (str): Firewall rule ID to resolve.

        Returns:
            Optional[FirewallRule]: Matching firewall rule when found; otherwise None.
        """
        return self._index().firewall_rules_by_id.get(identifier.lower())

    def get_logging_profile(self, identifier: str) -> Optional[LoggingProfile]:
        """
        Look up a logging profile by profile ID.

        Args:
            identifier (str): Logging profile ID to resolve.

        Returns:
            Optional[LoggingProfile]: Matching logging profile when found; otherwise None.
        """
        return self._index().logging_profiles_by_id.get(identifier.lower())

    def get_dns_record(self, name: str, record_type: str = "A") -> Optional[DnsRecord]:
        """
        Look up a DNS record by name and record type.

        Args:
            name (str): DNS name to resolve.
            record_type (str): DNS record type to match.

        Returns:
            Optional[DnsRecord]: Matching DNS record when found; otherwise None.
        """
        return self._index().dns_records_by_key.get((name.lower(), record_type.upper()))

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

        return self._index().http_routes_by_key.get((service.id, method.upper(), path))


def build_environment_index(environment: Environment) -> EnvironmentIndex:
    """
    Build first-match lookup indexes for an environment.

    Args:
        environment (Environment): Environment to index.

    Returns:
        EnvironmentIndex: Precomputed environment lookup index.
    """
    hosts = []
    zones_by_id = {}
    hosts_by_identifier = {}
    users_by_identifier = {}
    services_by_identifier = {}
    network_devices_by_identifier = {}
    firewall_rules_by_id = {}
    logging_profiles_by_id = {}
    dns_records_by_key = {}
    http_routes_by_key = {}

    for zone in environment.zones:
        zones_by_id.setdefault(zone.id.lower(), zone)
        hosts.extend(zone.hosts)

    for host in hosts:
        for identifier in (host.id, host.hostname, host.fqdn, host.primary_ip):
            hosts_by_identifier.setdefault(identifier.lower(), host)

    for user in environment.users:
        for identifier in (user.id, user.username):
            users_by_identifier.setdefault(identifier.lower(), user)

    for service in environment.services:
        for identifier in (service.id, service.name, *service.names):
            services_by_identifier.setdefault(identifier.lower(), service)

        for route in service.routes:
            http_routes_by_key.setdefault((service.id, route.method.upper(), route.path), route)

    for device in environment.network_devices:
        network_devices_by_identifier.setdefault(device.id.lower(), device)

        for interface in device.interfaces:
            network_devices_by_identifier.setdefault(interface.ip.lower(), device)

        for rule in device.policies:
            firewall_rules_by_id.setdefault(rule.id.lower(), rule)

    for profile in environment.logging_profiles:
        logging_profiles_by_id.setdefault(profile.id.lower(), profile)

    for record in environment.dns_records:
        dns_records_by_key.setdefault((record.name.lower(), record.record_type.upper()), record)

    return EnvironmentIndex(
        hosts=tuple(hosts),
        zones_by_id=zones_by_id,
        hosts_by_identifier=hosts_by_identifier,
        users_by_identifier=users_by_identifier,
        services_by_identifier=services_by_identifier,
        network_devices_by_identifier=network_devices_by_identifier,
        firewall_rules_by_id=firewall_rules_by_id,
        logging_profiles_by_id=logging_profiles_by_id,
        dns_records_by_key=dns_records_by_key,
        http_routes_by_key=http_routes_by_key,
    )


def load_environment_yaml(path: Path) -> Environment:
    """
    Load an environment definition from a YAML file.

    Args:
        path (Path): Environment YAML file to read.

    Returns:
        Environment: Parsed source-neutral environment definition.
    """
    return parse_environment_yaml_text(path.read_text(encoding="utf-8"))


def parse_environment_yaml_text(text: str) -> Environment:
    """
    Parse an environment definition from YAML text.

    Args:
        text (str): YAML text containing one environment document.

    Returns:
        Environment: Parsed source-neutral environment definition.
    """
    try:
        import yaml
    except ImportError as exc:
        raise ValueError("PyYAML is required to parse environment YAML") from exc

    try:
        documents = list(yaml.safe_load_all(text))
    except yaml.YAMLError as exc:
        raise ValueError(f"invalid environment YAML: {exc}") from exc

    if len(documents) != 1:
        raise ValueError("environment YAML must contain exactly one document")

    document = documents[0]

    if not isinstance(document, dict):
        raise ValueError("environment YAML document must be a mapping")

    return parse_environment_yaml_document(document)


def parse_environment_yaml_document(document: Mapping[str, Any]) -> Environment:
    """
    Convert a parsed environment YAML mapping into an Environment.

    Args:
        document (Mapping[str, Any]): Parsed YAML environment mapping.

    Returns:
        Environment: Source-neutral environment definition.
    """
    schema_version = _required_string(document, "schema_version", "environment")

    if schema_version != "environment/v0.1":
        raise ValueError("environment.schema_version must be 'environment/v0.1'")

    return Environment(
        id=_required_string(document, "id", "environment"),
        version=_required_string(document, "version", "environment"),
        display_name=_required_string(document, "display_name", "environment"),
        domain=_required_string(document, "domain", "environment"),
        timezone=_required_string(document, "timezone", "environment"),
        environment_type=_required_string(document, "environment_type", "environment"),
        zones=tuple(_build_zone(item, index) for index, item in enumerate(_mapping_list(document, "zones"))),
        users=tuple(_build_user(item, index) for index, item in enumerate(_mapping_list(document, "users"))),
        groups=tuple(_build_group(item, index) for index, item in enumerate(_mapping_list(document, "groups"))),
        services=tuple(_build_service(item, index) for index, item in enumerate(_mapping_list(document, "services"))),
        dns_records=tuple(
            _build_dns_record(item, index) for index, item in enumerate(_mapping_list(document, "dns_records"))
        ),
        logging_profiles=tuple(
            _build_logging_profile(item, index)
            for index, item in enumerate(_mapping_list(document, "logging_profiles"))
        ),
        network_devices=tuple(
            _build_network_device(item, index)
            for index, item in enumerate(_mapping_list(document, "network_devices"))
        ),
        sensor_visibility=tuple(
            _build_sensor_visibility(item, index)
            for index, item in enumerate(_mapping_list(document, "sensor_visibility"))
        ),
    )


def _build_zone(values: Mapping[str, Any], index: int) -> NetworkZone:
    """
    Build one network zone from a YAML mapping.

    Args:
        values (Mapping[str, Any]): Zone mapping.
        index (int): Zone index for error paths.

    Returns:
        NetworkZone: Parsed network zone.
    """
    prefix = f"environment.zones[{index}]"
    hosts = tuple(
        _build_host(item, host_index, prefix)
        for host_index, item in enumerate(_mapping_list(values, "hosts"))
    )

    return NetworkZone(
        id=_required_string(values, "id", prefix),
        display_name=_required_string(values, "display_name", prefix),
        cidr=_optional_string(values, "cidr", prefix),
        zone_type=_required_string(values, "zone_type", prefix),
        purpose=_required_string(values, "purpose", prefix),
        hosts=hosts,
    )


def _build_host(values: Mapping[str, Any], index: int, parent_path: str) -> Host:
    """
    Build one host from a YAML mapping.

    Args:
        values (Mapping[str, Any]): Host mapping.
        index (int): Host index for error paths.
        parent_path (str): Parent zone field path.

    Returns:
        Host: Parsed host.
    """
    prefix = f"{parent_path}.hosts[{index}]"

    return Host(
        id=_required_string(values, "id", prefix),
        hostname=_required_string(values, "hostname", prefix),
        fqdn=_required_string(values, "fqdn", prefix),
        zone_id=_required_string(values, "zone_id", prefix),
        primary_ip=_required_string(values, "primary_ip", prefix),
        os=_required_string(values, "os", prefix),
        roles=_string_tuple(values, "roles", prefix),
        logging_profiles=_string_tuple(values, "logging_profiles", prefix),
    )


def _build_user(values: Mapping[str, Any], index: int) -> User:
    """
    Build one user from a YAML mapping.

    Args:
        values (Mapping[str, Any]): User mapping.
        index (int): User index for error paths.

    Returns:
        User: Parsed user.
    """
    prefix = f"environment.users[{index}]"

    return User(
        id=_required_string(values, "id", prefix),
        username=_required_string(values, "username", prefix),
        display_name=_required_string(values, "display_name", prefix),
        account_type=_required_string(values, "account_type", prefix),
        login_hosts=_string_tuple(values, "login_hosts", prefix),
        normal_login_hosts=_string_tuple(values, "normal_login_hosts", prefix),
    )


def _build_group(values: Mapping[str, Any], index: int) -> Group:
    """
    Build one group from a YAML mapping.

    Args:
        values (Mapping[str, Any]): Group mapping.
        index (int): Group index for error paths.

    Returns:
        Group: Parsed group.
    """
    prefix = f"environment.groups[{index}]"

    return Group(
        id=_required_string(values, "id", prefix),
        name=_required_string(values, "name", prefix),
        members=_string_tuple(values, "members", prefix),
        purpose=_required_string(values, "purpose", prefix),
    )


def _build_service(values: Mapping[str, Any], index: int) -> Service:
    """
    Build one service from a YAML mapping.

    Args:
        values (Mapping[str, Any]): Service mapping.
        index (int): Service index for error paths.

    Returns:
        Service: Parsed service.
    """
    prefix = f"environment.services[{index}]"

    return Service(
        id=_required_string(values, "id", prefix),
        name=_required_string(values, "name", prefix),
        target_host_id=_required_string(values, "target_host_id", prefix),
        port=_required_integer(values, "port", prefix),
        transport_protocol=_required_string(values, "transport_protocol", prefix),
        application_protocol=_required_string(values, "application_protocol", prefix),
        names=_string_tuple(values, "names", prefix),
        visibility=_string_tuple(values, "visibility", prefix),
        routes=tuple(
            _build_http_route(item, route_index, prefix)
            for route_index, item in enumerate(_mapping_list(values, "routes"))
        ),
    )


def _build_http_route(values: Mapping[str, Any], index: int, parent_path: str) -> HttpRoute:
    """
    Build one HTTP route from a YAML mapping.

    Args:
        values (Mapping[str, Any]): Route mapping.
        index (int): Route index for error paths.
        parent_path (str): Parent service field path.

    Returns:
        HttpRoute: Parsed HTTP route.
    """
    prefix = f"{parent_path}.routes[{index}]"

    return HttpRoute(
        method=_required_string(values, "method", prefix),
        path=_required_string(values, "path", prefix),
        default_status=_required_integer(values, "default_status", prefix),
        purpose=_required_string(values, "purpose", prefix),
    )


def _build_dns_record(values: Mapping[str, Any], index: int) -> DnsRecord:
    """
    Build one DNS record from a YAML mapping.

    Args:
        values (Mapping[str, Any]): DNS record mapping.
        index (int): DNS record index for error paths.

    Returns:
        DnsRecord: Parsed DNS record.
    """
    prefix = f"environment.dns_records[{index}]"

    return DnsRecord(
        name=_required_string(values, "name", prefix),
        record_type=_required_string(values, "record_type", prefix),
        value=_required_string(values, "value", prefix),
    )


def _build_logging_profile(values: Mapping[str, Any], index: int) -> LoggingProfile:
    """
    Build one logging profile from a YAML mapping.

    Args:
        values (Mapping[str, Any]): Logging profile mapping.
        index (int): Logging profile index for error paths.

    Returns:
        LoggingProfile: Parsed logging profile.
    """
    prefix = f"environment.logging_profiles[{index}]"

    return LoggingProfile(
        id=_required_string(values, "id", prefix),
        families=tuple(
            _build_logging_family(item, family_index, prefix)
            for family_index, item in enumerate(_mapping_list(values, "families"))
        ),
    )


def _build_logging_family(values: Mapping[str, Any], index: int, parent_path: str) -> LoggingFamily:
    """
    Build one logging family from a YAML mapping.

    Args:
        values (Mapping[str, Any]): Logging family mapping.
        index (int): Logging family index for error paths.
        parent_path (str): Parent logging profile field path.

    Returns:
        LoggingFamily: Parsed logging family.
    """
    prefix = f"{parent_path}.families[{index}]"

    return LoggingFamily(
        name=_required_string(values, "name", prefix),
        streams=_string_tuple(values, "streams", prefix),
    )


def _build_network_device(values: Mapping[str, Any], index: int) -> NetworkDevice:
    """
    Build one network device from a YAML mapping.

    Args:
        values (Mapping[str, Any]): Network device mapping.
        index (int): Network device index for error paths.

    Returns:
        NetworkDevice: Parsed network device.
    """
    prefix = f"environment.network_devices[{index}]"

    return NetworkDevice(
        id=_required_string(values, "id", prefix),
        device_type=_required_string(values, "device_type", prefix),
        interfaces=tuple(
            _build_network_interface(item, interface_index, prefix)
            for interface_index, item in enumerate(_mapping_list(values, "interfaces"))
        ),
        logging_profiles=_string_tuple(values, "logging_profiles", prefix),
        policies=tuple(
            _build_firewall_rule(item, policy_index, prefix)
            for policy_index, item in enumerate(_mapping_list(values, "policies"))
        ),
    )


def _build_network_interface(values: Mapping[str, Any], index: int, parent_path: str) -> NetworkInterface:
    """
    Build one network interface from a YAML mapping.

    Args:
        values (Mapping[str, Any]): Network interface mapping.
        index (int): Interface index for error paths.
        parent_path (str): Parent network device field path.

    Returns:
        NetworkInterface: Parsed network interface.
    """
    prefix = f"{parent_path}.interfaces[{index}]"

    return NetworkInterface(
        zone_id=_required_string(values, "zone_id", prefix),
        ip=_required_string(values, "ip", prefix),
    )


def _build_firewall_rule(values: Mapping[str, Any], index: int, parent_path: str) -> FirewallRule:
    """
    Build one firewall rule from a YAML mapping.

    Args:
        values (Mapping[str, Any]): Firewall rule mapping.
        index (int): Rule index for error paths.
        parent_path (str): Parent network device field path.

    Returns:
        FirewallRule: Parsed firewall rule.
    """
    prefix = f"{parent_path}.policies[{index}]"

    return FirewallRule(
        id=_required_string(values, "id", prefix),
        source_zones=_string_tuple(values, "source_zones", prefix),
        destination_zones=_string_tuple(values, "destination_zones", prefix),
        protocols=_string_tuple(values, "protocols", prefix),
        destination_ports=_string_tuple(values, "destination_ports", prefix),
        action=_required_string(values, "action", prefix),
        logging=_required_boolean(values, "logging", prefix),
        nat=_optional_mapping(values, "nat", prefix),
    )


def _build_sensor_visibility(values: Mapping[str, Any], index: int) -> SensorVisibility:
    """
    Build one sensor visibility rule from a YAML mapping.

    Args:
        values (Mapping[str, Any]): Sensor visibility mapping.
        index (int): Sensor visibility index for error paths.

    Returns:
        SensorVisibility: Parsed sensor visibility rule.
    """
    prefix = f"environment.sensor_visibility[{index}]"

    return SensorVisibility(
        sensor_id=_required_string(values, "sensor_id", prefix),
        source_zone_id=_required_string(values, "source_zone_id", prefix),
        destination_zone_id=_required_string(values, "destination_zone_id", prefix),
        visible=_required_boolean(values, "visible", prefix),
        notes=_required_string(values, "notes", prefix),
    )


def _required_string(values: Mapping[str, Any], field_name: str, prefix: str) -> str:
    """
    Read a required string from a YAML mapping.

    Args:
        values (Mapping[str, Any]): Mapping to read.
        field_name (str): Field name to require.
        prefix (str): Field path prefix for errors.

    Returns:
        str: Required string value.
    """
    value = _required_value(values, field_name, prefix)

    if not isinstance(value, str):
        raise ValueError(f"{prefix}.{field_name} must be a string")

    return value


def _optional_string(values: Mapping[str, Any], field_name: str, prefix: str) -> Optional[str]:
    """
    Read an optional string from a YAML mapping.

    Args:
        values (Mapping[str, Any]): Mapping to read.
        field_name (str): Field name to read.
        prefix (str): Field path prefix for errors.

    Returns:
        Optional[str]: String value when present; otherwise None.
    """
    value = values.get(field_name)

    if value is None:
        return None

    if not isinstance(value, str):
        raise ValueError(f"{prefix}.{field_name} must be a string")

    return value


def _required_integer(values: Mapping[str, Any], field_name: str, prefix: str) -> int:
    """
    Read a required integer from a YAML mapping.

    Args:
        values (Mapping[str, Any]): Mapping to read.
        field_name (str): Field name to require.
        prefix (str): Field path prefix for errors.

    Returns:
        int: Required integer value.
    """
    value = _required_value(values, field_name, prefix)

    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{prefix}.{field_name} must be an integer")

    return value


def _required_boolean(values: Mapping[str, Any], field_name: str, prefix: str) -> bool:
    """
    Read a required boolean from a YAML mapping.

    Args:
        values (Mapping[str, Any]): Mapping to read.
        field_name (str): Field name to require.
        prefix (str): Field path prefix for errors.

    Returns:
        bool: Required boolean value.
    """
    value = _required_value(values, field_name, prefix)

    if not isinstance(value, bool):
        raise ValueError(f"{prefix}.{field_name} must be a boolean")

    return value


def _string_tuple(values: Mapping[str, Any], field_name: str, prefix: str) -> tuple[str, ...]:
    """
    Read a required list of strings from a YAML mapping.

    Args:
        values (Mapping[str, Any]): Mapping to read.
        field_name (str): Field name to require.
        prefix (str): Field path prefix for errors.

    Returns:
        tuple[str, ...]: String values as an immutable tuple.
    """
    value = _required_value(values, field_name, prefix)

    if not isinstance(value, list):
        raise ValueError(f"{prefix}.{field_name} must be a list")

    for index, item in enumerate(value):
        if not isinstance(item, str):
            raise ValueError(f"{prefix}.{field_name}[{index}] must be a string")

    return tuple(value)


def _mapping_list(values: Mapping[str, Any], field_name: str) -> tuple[Mapping[str, Any], ...]:
    """
    Read a required list of mappings from a YAML mapping.

    Args:
        values (Mapping[str, Any]): Mapping to read.
        field_name (str): Field name to require.

    Returns:
        tuple[Mapping[str, Any], ...]: Mapping values as an immutable tuple.
    """
    value = _required_value(values, field_name, "environment")

    if not isinstance(value, list):
        raise ValueError(f"environment.{field_name} must be a list")

    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise ValueError(f"environment.{field_name}[{index}] must be a mapping")

    return tuple(value)


def _optional_mapping(values: Mapping[str, Any], field_name: str, prefix: str) -> Optional[dict[str, str]]:
    """
    Read an optional mapping with string keys and values.

    Args:
        values (Mapping[str, Any]): Mapping to read.
        field_name (str): Field name to read.
        prefix (str): Field path prefix for errors.

    Returns:
        Optional[dict[str, str]]: Mapping copy when present; otherwise None.
    """
    value = values.get(field_name)

    if value is None:
        return None

    if not isinstance(value, dict):
        raise ValueError(f"{prefix}.{field_name} must be a mapping")

    output = {}

    for key, item in value.items():
        if not isinstance(key, str) or not isinstance(item, str):
            raise ValueError(f"{prefix}.{field_name} must contain only string keys and values")

        output[key] = item

    return output


def _required_value(values: Mapping[str, Any], field_name: str, prefix: str) -> Any:
    """
    Read a required value from a YAML mapping.

    Args:
        values (Mapping[str, Any]): Mapping to read.
        field_name (str): Field name to require.
        prefix (str): Field path prefix for errors.

    Returns:
        Any: Required field value.
    """
    if field_name not in values:
        raise ValueError(f"{prefix}.{field_name} is required")

    return values[field_name]


def _builtin_environment_path(environment_id: str) -> Path:
    """
    Return the repository YAML path for a built-in environment.

    Args:
        environment_id (str): Built-in environment identifier.

    Returns:
        Path: YAML file path for the built-in environment.
    """
    repository_root = Path(__file__).resolve().parents[3]

    return repository_root / "environments" / f"{environment_id}.yaml"


def build_linux_mini_lab() -> Environment:
    """
    Load the built-in linux-mini-lab environment definition.

    Returns:
        Environment: Complete linux-mini-lab environment definition.
    """
    return load_environment_yaml(_builtin_environment_path("linux-mini-lab"))


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
    "load_environment_yaml",
    "parse_environment_yaml_document",
    "parse_environment_yaml_text",
]
