"""
Scenario model and expansion definitions.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta
from hashlib import sha1
from typing import Any, Optional, Union

from log_generator.core.environment import Environment, Host, Service, build_linux_mini_lab
from log_generator.core.events import (
    DnsLookupEvent,
    LinuxLocalLoginEvent,
    NetworkConnectionEvent,
    SourceNeutralEvent,
    WebRequestEvent,
    normalize_utc_timestamp,
)


AuthoredEvent = Union[SourceNeutralEvent, "AuthoredWebRequest"]


def derive_event_id(scenario_id: str, event_type: str, sequence_order: int, seed: int) -> str:
    """
    Derive a stable event ID from deterministic scenario inputs.

    Args:
        scenario_id (str): Scenario identifier that owns the event.
        event_type (str): Source-neutral event type.
        sequence_order (int): Authored or expanded sequence order.
        seed (int): Scenario seed.

    Returns:
        str: Stable event ID suitable for generated helper events.
    """
    event_type_slug = event_type.replace("_", "-")
    digest_input = f"{scenario_id}:{event_type}:{sequence_order}:{seed}".encode("utf-8")
    digest = sha1(digest_input).hexdigest()[:8]

    return f"evt-{event_type_slug}-{sequence_order:03d}-{digest}"


def parse_utc_datetime(value: str) -> datetime:
    """
    Parse an ISO 8601 datetime string into a timezone-aware UTC datetime.

    Args:
        value (str): ISO 8601 datetime string, optionally using UTC Z suffix.

    Returns:
        datetime: Parsed UTC datetime.
    """
    normalized_value = value.replace("Z", "+00:00")

    return normalize_utc_timestamp(datetime.fromisoformat(normalized_value))


def classify_web_request_path(path: str) -> Optional[dict[str, str]]:
    """
    Classify a web request path when it represents a file download.

    Args:
        path (str): HTTP request path without scheme or host.

    Returns:
        Optional[dict[str, str]]: Download metadata when the path is a download; otherwise None.
    """
    path_without_query = path.split("?", 1)[0]

    if path_without_query.endswith("/"):
        return None

    file_name = path_without_query.rsplit("/", 1)[-1]

    # Routes without a file extension are pages in the source-neutral taxonomy.
    if "." not in file_name:
        return None

    if file_name.lower().endswith((".html", ".htm")):
        return None

    return {"download_classification": "download", "file_name": file_name}


@dataclass(frozen=True)
class AuthoredWebRequest:
    """
    Represent a high-level authored web request before helper expansion.
    """

    event_id: str
    timestamp: datetime
    actor_user_id: str
    source_host_id: str
    service_id: str
    method: str
    path: str
    correlation_id: str
    status: str = "success"
    parent_event_id: Optional[str] = None
    status_code: Optional[int] = None
    url: Optional[str] = None
    attack: Optional[dict[str, str]] = None
    metadata: Optional[dict[str, Any]] = None
    helper_event_ids: Optional[dict[str, str]] = None
    dns_helper_offset: timedelta = timedelta(seconds=2)
    connection_helper_offset: timedelta = timedelta(seconds=1)

    def __post_init__(self) -> None:
        """
        Normalize the authored web request timestamp.

        Returns:
            None: The frozen instance is updated through dataclass internals during initialization.
        """
        object.__setattr__(self, "timestamp", normalize_utc_timestamp(self.timestamp))


@dataclass(frozen=True)
class ScenarioEvent:
    """
    Pair a source-neutral event with its deterministic sequence order.
    """

    sequence_order: int
    event: SourceNeutralEvent

    def sort_key(self) -> tuple[datetime, int]:
        """
        Return the deterministic ordering key for this scenario event.

        Returns:
            tuple[datetime, int]: Timestamp followed by authored or expanded sequence order.
        """
        return self.event.timestamp, self.sequence_order


@dataclass(frozen=True)
class Scenario:
    """
    Represent a deterministic source-neutral scenario.
    """

    id: str
    name: str
    seed: int
    environment_id: str
    environment_version: str
    start_time: datetime
    events: tuple[ScenarioEvent, ...]
    end_time: Optional[datetime] = None
    output_families: tuple[str, ...] = ("generic-normalized",)

    def __post_init__(self) -> None:
        """
        Normalize scenario times and validate deterministic event relationships.

        Returns:
            None: The frozen instance is updated through dataclass internals during initialization.
        """
        object.__setattr__(self, "start_time", normalize_utc_timestamp(self.start_time))

        if self.end_time is not None:
            object.__setattr__(self, "end_time", normalize_utc_timestamp(self.end_time))

        self._validate_events()

    def ordered_events(self) -> tuple[SourceNeutralEvent, ...]:
        """
        Return expanded source-neutral events in deterministic output order.

        Returns:
            tuple[SourceNeutralEvent, ...]: Events sorted by timestamp and sequence order.
        """
        return tuple(scenario_event.event for scenario_event in sorted(self.events, key=ScenarioEvent.sort_key))

    def event_ids(self) -> tuple[str, ...]:
        """
        Return event IDs in deterministic output order.

        Returns:
            tuple[str, ...]: Ordered event identifiers.
        """
        return tuple(event.event_id for event in self.ordered_events())

    def correlation_ids(self) -> tuple[str, ...]:
        """
        Return unique correlation IDs in deterministic first-seen order.

        Returns:
            tuple[str, ...]: Unique correlation identifiers.
        """
        correlation_ids = []

        for event in self.ordered_events():
            if event.correlation_id not in correlation_ids:
                correlation_ids.append(event.correlation_id)

        return tuple(correlation_ids)

    def _validate_events(self) -> None:
        """
        Validate event identity, sequence, scenario ownership, and parent ordering.

        Returns:
            None: Raises ValueError when scenario event relationships are invalid.
        """
        seen_event_ids = set()
        seen_sequence_orders = set()

        for scenario_event in self.events:
            if scenario_event.sequence_order in seen_sequence_orders:
                raise ValueError(f"duplicate sequence order '{scenario_event.sequence_order}' in scenario '{self.id}'")

            seen_sequence_orders.add(scenario_event.sequence_order)

            if scenario_event.event.scenario_id != self.id:
                raise ValueError(
                    f"event '{scenario_event.event.event_id}' belongs to scenario "
                    f"'{scenario_event.event.scenario_id}', not '{self.id}'"
                )

            if scenario_event.event.event_id in seen_event_ids:
                raise ValueError(f"duplicate event ID '{scenario_event.event.event_id}' in scenario '{self.id}'")

            seen_event_ids.add(scenario_event.event.event_id)

        earlier_event_ids = set()

        for event in self.ordered_events():
            parent_event_id = getattr(event, "parent_event_id", None)

            if parent_event_id is not None and parent_event_id not in earlier_event_ids:
                raise ValueError(
                    f"parent event '{parent_event_id}' for event '{event.event_id}' must resolve to an earlier event"
                )

            earlier_event_ids.add(event.event_id)


def expand_authored_events(
    scenario_id: str,
    seed: int,
    environment: Environment,
    authored_events: tuple[AuthoredEvent, ...],
) -> tuple[ScenarioEvent, ...]:
    """
    Expand authored source-neutral activity into deterministic scenario events.

    Args:
        scenario_id (str): Scenario identifier that owns the events.
        seed (int): Scenario seed used for generated helper event IDs.
        environment (Environment): Environment used to resolve services, hosts, and route defaults.
        authored_events (tuple[AuthoredEvent, ...]): Authored events to expand.

    Returns:
        tuple[ScenarioEvent, ...]: Expanded events with deterministic sequence order.
    """
    expanded_events: list[ScenarioEvent] = []

    for authored_event in authored_events:
        if isinstance(authored_event, AuthoredWebRequest):
            _expand_web_request(
                scenario_id=scenario_id,
                seed=seed,
                environment=environment,
                authored_event=authored_event,
                expanded_events=expanded_events,
            )
            continue

        expanded_events.append(
            ScenarioEvent(sequence_order=_next_sequence_order(expanded_events), event=authored_event)
        )

    return tuple(expanded_events)


def _expand_web_request(
    scenario_id: str,
    seed: int,
    environment: Environment,
    authored_event: AuthoredWebRequest,
    expanded_events: list[ScenarioEvent],
) -> None:
    """
    Expand one authored web request into DNS, connection, and web request events when needed.

    Args:
        scenario_id (str): Scenario identifier that owns the events.
        seed (int): Scenario seed used for generated helper event IDs.
        environment (Environment): Environment used to resolve service details.
        authored_event (AuthoredWebRequest): Authored web request to expand.
        expanded_events (list[ScenarioEvent]): Previously expanded events, updated in place.

    Returns:
        None: Expanded events are appended to the provided list.
    """
    service = environment.require_service(authored_event.service_id)
    destination_host = environment.require_host(service.target_host_id)
    route = environment.get_http_route(service.id, authored_event.method, authored_event.path)
    status_code = authored_event.status_code

    if status_code is None:
        if route is None:
            raise ValueError(
                f"web request '{authored_event.event_id}' needs status_code because route "
                f"'{authored_event.method} {authored_event.path}' is unknown"
            )

        status_code = route.default_status

    existing_connection = _find_compatible_connection(expanded_events, authored_event, service, destination_host)

    if existing_connection is None:
        dns_event = _find_compatible_dns_lookup(expanded_events, authored_event, service, destination_host)

        if dns_event is None:
            dns_event = _build_dns_helper_event(
                scenario_id=scenario_id,
                seed=seed,
                environment=environment,
                authored_event=authored_event,
                service=service,
                destination_ip=destination_host.primary_ip,
                expanded_events=expanded_events,
            )
            expanded_events.append(ScenarioEvent(sequence_order=_next_sequence_order(expanded_events), event=dns_event))

        connection_event = _build_connection_helper_event(
            scenario_id=scenario_id,
            seed=seed,
            environment=environment,
            authored_event=authored_event,
            service=service,
            destination_host_id=destination_host.id,
            destination_ip=destination_host.primary_ip,
            parent_event_id=dns_event.event_id,
            expanded_events=expanded_events,
        )
        expanded_events.append(
            ScenarioEvent(sequence_order=_next_sequence_order(expanded_events), event=connection_event)
        )
        existing_connection = connection_event

    web_request_event = _build_expanded_web_request(
        scenario_id=scenario_id,
        authored_event=authored_event,
        service=service,
        destination_host_id=destination_host.id,
        status_code=status_code,
        parent_event_id=existing_connection.event_id,
    )
    expanded_events.append(
        ScenarioEvent(sequence_order=_next_sequence_order(expanded_events), event=web_request_event)
    )


def _build_dns_helper_event(
    scenario_id: str,
    seed: int,
    environment: Environment,
    authored_event: AuthoredWebRequest,
    service: Service,
    destination_ip: str,
    expanded_events: list[ScenarioEvent],
) -> DnsLookupEvent:
    """
    Build a deterministic DNS helper event for an authored web request.

    Args:
        scenario_id (str): Scenario identifier that owns the helper.
        seed (int): Scenario seed used when the helper ID is not explicitly supplied.
        environment (Environment): Environment used to find the default DNS resolver.
        authored_event (AuthoredWebRequest): Authored web request that needs DNS.
        service (Service): Target web service.
        destination_ip (str): Destination IP resolved from the target service.
        expanded_events (list[ScenarioEvent]): Previously expanded events.

    Returns:
        DnsLookupEvent: Generated DNS helper event.
    """
    dns_service = _get_default_dns_service(environment)
    dns_host = environment.require_host(dns_service.target_host_id)
    sequence_order = _next_sequence_order(expanded_events)
    event_id = _get_helper_event_id(authored_event, "dns_lookup", scenario_id, seed, sequence_order)

    # DNS helper timing is relative to the authored request so generated events remain reproducible.
    return DnsLookupEvent(
        event_id=event_id,
        scenario_id=scenario_id,
        timestamp=authored_event.timestamp - authored_event.dns_helper_offset,
        status="success",
        correlation_id=authored_event.correlation_id,
        parent_event_id=authored_event.parent_event_id,
        actor_user_id=authored_event.actor_user_id,
        source_host_id=authored_event.source_host_id,
        destination_host_id=dns_host.id,
        service_id=dns_service.id,
        query_name=service.names[0],
        query_type="A",
        resolved_addresses=[destination_ip],
    )


def _build_connection_helper_event(
    scenario_id: str,
    seed: int,
    environment: Environment,
    authored_event: AuthoredWebRequest,
    service: Service,
    destination_host_id: str,
    destination_ip: str,
    parent_event_id: str,
    expanded_events: list[ScenarioEvent],
) -> NetworkConnectionEvent:
    """
    Build a deterministic network connection helper event for an authored web request.

    Args:
        scenario_id (str): Scenario identifier that owns the helper.
        seed (int): Scenario seed used when the helper ID is not explicitly supplied.
        environment (Environment): Environment used to resolve the source host.
        authored_event (AuthoredWebRequest): Authored web request that needs a connection.
        service (Service): Target web service.
        destination_host_id (str): Destination host resolved from the target service.
        destination_ip (str): Destination IP resolved from the target service.
        parent_event_id (str): DNS event that enabled this connection.
        expanded_events (list[ScenarioEvent]): Previously expanded events.

    Returns:
        NetworkConnectionEvent: Generated connection helper event.
    """
    source_host = environment.require_host(authored_event.source_host_id)
    sequence_order = _next_sequence_order(expanded_events)
    event_id = _get_helper_event_id(authored_event, "network_connection", scenario_id, seed, sequence_order)

    return NetworkConnectionEvent(
        event_id=event_id,
        scenario_id=scenario_id,
        timestamp=authored_event.timestamp - authored_event.connection_helper_offset,
        status="success",
        correlation_id=authored_event.correlation_id,
        parent_event_id=parent_event_id,
        actor_user_id=authored_event.actor_user_id,
        source_host_id=source_host.id,
        source_ip=source_host.primary_ip,
        destination_host_id=destination_host_id,
        destination_ip=destination_ip,
        service_id=service.id,
        destination_port=service.port,
        network_protocol=service.transport_protocol,
        application_protocol=service.application_protocol,
    )


def _build_expanded_web_request(
    scenario_id: str,
    authored_event: AuthoredWebRequest,
    service: Service,
    destination_host_id: str,
    status_code: int,
    parent_event_id: str,
) -> WebRequestEvent:
    """
    Build an expanded web request event from authored web activity.

    Args:
        scenario_id (str): Scenario identifier that owns the event.
        authored_event (AuthoredWebRequest): Authored web request to expand.
        service (Service): Target web service.
        destination_host_id (str): Destination host resolved from the target service.
        status_code (int): Expanded HTTP status code.
        parent_event_id (str): Network connection event used for this request.

    Returns:
        WebRequestEvent: Expanded web request event.
    """
    metadata = dict(authored_event.metadata or {})
    download_metadata = classify_web_request_path(authored_event.path)

    if download_metadata is not None:
        metadata.update(download_metadata)

    url = authored_event.url

    if url is None:
        url = f"http://{service.names[0]}{authored_event.path}"

    return WebRequestEvent(
        event_id=authored_event.event_id,
        scenario_id=scenario_id,
        timestamp=authored_event.timestamp,
        status=authored_event.status,
        correlation_id=authored_event.correlation_id,
        parent_event_id=parent_event_id,
        actor_user_id=authored_event.actor_user_id,
        source_host_id=authored_event.source_host_id,
        destination_host_id=destination_host_id,
        service_id=authored_event.service_id,
        method=authored_event.method,
        url=url,
        path=authored_event.path,
        status_code=status_code,
        attack=authored_event.attack,
        metadata=metadata or None,
    )


def _find_compatible_dns_lookup(
    expanded_events: list[ScenarioEvent],
    authored_event: AuthoredWebRequest,
    service: Service,
    destination_host: Host,
) -> Optional[DnsLookupEvent]:
    """
    Find a successful DNS lookup compatible with an authored web request.

    Args:
        expanded_events (list[ScenarioEvent]): Events already expanded.
        authored_event (AuthoredWebRequest): Authored web request being expanded.
        service (Service): Target service for the request.
        destination_host (Host): Destination host for the request.

    Returns:
        Optional[DnsLookupEvent]: Compatible DNS event when one exists; otherwise None.
    """
    for scenario_event in reversed(expanded_events):
        event = scenario_event.event

        if not isinstance(event, DnsLookupEvent):
            continue

        if event.status != "success" or event.correlation_id != authored_event.correlation_id:
            continue

        if event.source_host_id != authored_event.source_host_id or event.query_type != "A":
            continue

        if event.query_name not in service.names:
            continue

        if event.resolved_addresses is not None and destination_host.primary_ip in event.resolved_addresses:
            return event

    return None


def _find_compatible_connection(
    expanded_events: list[ScenarioEvent],
    authored_event: AuthoredWebRequest,
    service: Service,
    destination_host: Host,
) -> Optional[NetworkConnectionEvent]:
    """
    Find a successful connection compatible with an authored web request.

    Args:
        expanded_events (list[ScenarioEvent]): Events already expanded.
        authored_event (AuthoredWebRequest): Authored web request being expanded.
        service (Service): Target service for the request.
        destination_host (Host): Destination host for the request.

    Returns:
        Optional[NetworkConnectionEvent]: Compatible connection when one exists; otherwise None.
    """
    for scenario_event in reversed(expanded_events):
        event = scenario_event.event

        if not isinstance(event, NetworkConnectionEvent):
            continue

        if event.status != "success" or event.correlation_id != authored_event.correlation_id:
            continue

        if event.source_host_id != authored_event.source_host_id or event.service_id != service.id:
            continue

        if event.destination_host_id != destination_host.id or event.destination_ip != destination_host.primary_ip:
            continue

        if event.destination_port == service.port and event.network_protocol == service.transport_protocol:
            return event

    return None


def _get_default_dns_service(environment: Environment) -> Service:
    """
    Return the default DNS service used for generated helper lookups.

    Args:
        environment (Environment): Environment to inspect.

    Returns:
        Service: DNS resolver service.
    """
    return environment.require_service("svc-dns")


def _get_helper_event_id(
    authored_event: AuthoredWebRequest,
    event_type: str,
    scenario_id: str,
    seed: int,
    sequence_order: int,
) -> str:
    """
    Return an explicit or derived helper event ID.

    Args:
        authored_event (AuthoredWebRequest): Authored event that owns helper settings.
        event_type (str): Helper event type.
        scenario_id (str): Scenario identifier used for deterministic ID derivation.
        seed (int): Scenario seed used for deterministic ID derivation.
        sequence_order (int): Sequence order used for deterministic ID derivation.

    Returns:
        str: Helper event ID.
    """
    if authored_event.helper_event_ids is not None and event_type in authored_event.helper_event_ids:
        return authored_event.helper_event_ids[event_type]

    return derive_event_id(scenario_id, event_type, sequence_order, seed)


def _next_sequence_order(expanded_events: list[ScenarioEvent]) -> int:
    """
    Return the next deterministic sequence order.

    Args:
        expanded_events (list[ScenarioEvent]): Events already expanded.

    Returns:
        int: Next sequence order.
    """
    return len(expanded_events) + 1


def build_benign_internal_web_scenario() -> Scenario:
    """
    Build the canonical benign internal web scenario fixture.

    Returns:
        Scenario: Deterministic expanded benign web scenario.
    """
    scenario_id = "scenario-benign-internal-web"
    correlation_id = "corr-benign-internal-web-001"
    seed = 1001
    environment = build_linux_mini_lab()
    start_time = parse_utc_datetime("2026-01-15T14:00:00Z")

    authored_events = (
        AuthoredWebRequest(
            event_id="evt-benign-web-003",
            timestamp=parse_utc_datetime("2026-01-15T14:00:02Z"),
            actor_user_id="user-alice",
            source_host_id="linux-ws-01",
            service_id="svc-web-http",
            method="GET",
            path="/",
            correlation_id=correlation_id,
            helper_event_ids={
                "dns_lookup": "evt-benign-web-001",
                "network_connection": "evt-benign-web-002",
            },
        ),
    )
    events = expand_authored_events(scenario_id, seed, environment, authored_events)

    return Scenario(
        id=scenario_id,
        name="Benign Internal Web Browsing",
        seed=seed,
        environment_id=environment.id,
        environment_version=environment.version,
        start_time=start_time,
        end_time=parse_utc_datetime("2026-01-15T14:00:02Z"),
        events=events,
    )


def build_local_account_misuse_web_scenario() -> Scenario:
    """
    Build the canonical local account misuse web scenario fixture.

    Returns:
        Scenario: Deterministic expanded misuse web scenario.
    """
    scenario_id = "scenario-local-account-misuse-web"
    correlation_id = "corr-local-account-misuse-001"
    seed = 2002
    environment = build_linux_mini_lab()
    start_time = parse_utc_datetime("2026-01-15T03:12:00Z")

    authored_events = (
        LinuxLocalLoginEvent(
            event_id="evt-misuse-web-001",
            scenario_id=scenario_id,
            timestamp=parse_utc_datetime("2026-01-15T03:12:00Z"),
            status="success",
            correlation_id=correlation_id,
            actor_user_id="user-alice",
            target_host_id="linux-ws-01",
            login_method="local_console",
            metadata={"activity_classification": "suspicious"},
        ),
        AuthoredWebRequest(
            event_id="evt-misuse-web-004",
            timestamp=parse_utc_datetime("2026-01-15T03:12:18Z"),
            actor_user_id="user-alice",
            source_host_id="linux-ws-01",
            service_id="svc-web-http",
            method="GET",
            path="/admin",
            correlation_id=correlation_id,
            parent_event_id="evt-misuse-web-001",
            attack={"technique_id": "T1087", "technique_name": "Account Discovery"},
            helper_event_ids={
                "dns_lookup": "evt-misuse-web-002",
                "network_connection": "evt-misuse-web-003",
            },
            dns_helper_offset=timedelta(seconds=3),
            connection_helper_offset=timedelta(seconds=2),
        ),
        AuthoredWebRequest(
            event_id="evt-misuse-web-005",
            timestamp=parse_utc_datetime("2026-01-15T03:12:28Z"),
            actor_user_id="user-alice",
            source_host_id="linux-ws-01",
            service_id="svc-web-http",
            method="GET",
            path="/admin/archive.tar.gz",
            correlation_id=correlation_id,
            attack={"technique_id": "T1105", "technique_name": "Ingress Tool Transfer"},
        ),
    )
    events = expand_authored_events(scenario_id, seed, environment, authored_events)

    return Scenario(
        id=scenario_id,
        name="Local Account Misuse and Suspicious Web Access",
        seed=seed,
        environment_id=environment.id,
        environment_version=environment.version,
        start_time=start_time,
        end_time=parse_utc_datetime("2026-01-15T03:12:28Z"),
        events=events,
    )


__all__ = [
    "AuthoredWebRequest",
    "Scenario",
    "ScenarioEvent",
    "build_benign_internal_web_scenario",
    "build_local_account_misuse_web_scenario",
    "classify_web_request_path",
    "derive_event_id",
    "expand_authored_events",
    "parse_utc_datetime",
]
