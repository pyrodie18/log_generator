"""
Scenario model and expansion definitions.
"""

from dataclasses import dataclass
from datetime import datetime
from hashlib import sha1
from typing import Optional

from log_generator.core.events import (
    DnsLookupEvent,
    LinuxLocalLoginEvent,
    NetworkConnectionEvent,
    SourceNeutralEvent,
    WebRequestEvent,
    normalize_utc_timestamp,
)


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


def build_benign_internal_web_scenario() -> Scenario:
    """
    Build the canonical benign internal web scenario fixture.

    Returns:
        Scenario: Deterministic expanded benign web scenario.
    """
    scenario_id = "scenario-benign-internal-web"
    correlation_id = "corr-benign-internal-web-001"
    start_time = parse_utc_datetime("2026-01-15T14:00:00Z")

    events = (
        ScenarioEvent(
            sequence_order=1,
            event=DnsLookupEvent(
                event_id="evt-benign-web-001",
                scenario_id=scenario_id,
                timestamp=parse_utc_datetime("2026-01-15T14:00:00Z"),
                status="success",
                correlation_id=correlation_id,
                actor_user_id="user-alice",
                source_host_id="linux-ws-01",
                destination_host_id="lab-dns-01",
                service_id="svc-dns",
                query_name="web-server-01.internal",
                query_type="A",
                resolved_addresses=["10.10.20.21"],
            ),
        ),
        ScenarioEvent(
            sequence_order=2,
            event=NetworkConnectionEvent(
                event_id="evt-benign-web-002",
                scenario_id=scenario_id,
                timestamp=parse_utc_datetime("2026-01-15T14:00:01Z"),
                status="success",
                correlation_id=correlation_id,
                parent_event_id="evt-benign-web-001",
                actor_user_id="user-alice",
                source_host_id="linux-ws-01",
                source_ip="10.10.10.11",
                destination_host_id="web-server-01",
                destination_ip="10.10.20.21",
                service_id="svc-web-http",
                destination_port=80,
                network_protocol="tcp",
                application_protocol="http",
            ),
        ),
        ScenarioEvent(
            sequence_order=3,
            event=WebRequestEvent(
                event_id="evt-benign-web-003",
                scenario_id=scenario_id,
                timestamp=parse_utc_datetime("2026-01-15T14:00:02Z"),
                status="success",
                correlation_id=correlation_id,
                parent_event_id="evt-benign-web-002",
                actor_user_id="user-alice",
                source_host_id="linux-ws-01",
                destination_host_id="web-server-01",
                service_id="svc-web-http",
                method="GET",
                url="http://web-server-01.internal/",
                path="/",
                status_code=200,
            ),
        ),
    )

    return Scenario(
        id=scenario_id,
        name="Benign Internal Web Browsing",
        seed=1001,
        environment_id="linux-mini-lab",
        environment_version="0.1",
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
    start_time = parse_utc_datetime("2026-01-15T03:12:00Z")

    events = (
        ScenarioEvent(
            sequence_order=1,
            event=LinuxLocalLoginEvent(
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
        ),
        ScenarioEvent(
            sequence_order=2,
            event=DnsLookupEvent(
                event_id="evt-misuse-web-002",
                scenario_id=scenario_id,
                timestamp=parse_utc_datetime("2026-01-15T03:12:15Z"),
                status="success",
                correlation_id=correlation_id,
                parent_event_id="evt-misuse-web-001",
                actor_user_id="user-alice",
                source_host_id="linux-ws-01",
                destination_host_id="lab-dns-01",
                service_id="svc-dns",
                query_name="web-server-01.internal",
                query_type="A",
                resolved_addresses=["10.10.20.21"],
            ),
        ),
        ScenarioEvent(
            sequence_order=3,
            event=NetworkConnectionEvent(
                event_id="evt-misuse-web-003",
                scenario_id=scenario_id,
                timestamp=parse_utc_datetime("2026-01-15T03:12:16Z"),
                status="success",
                correlation_id=correlation_id,
                parent_event_id="evt-misuse-web-002",
                actor_user_id="user-alice",
                source_host_id="linux-ws-01",
                source_ip="10.10.10.11",
                destination_host_id="web-server-01",
                destination_ip="10.10.20.21",
                service_id="svc-web-http",
                destination_port=80,
                network_protocol="tcp",
                application_protocol="http",
            ),
        ),
        ScenarioEvent(
            sequence_order=4,
            event=WebRequestEvent(
                event_id="evt-misuse-web-004",
                scenario_id=scenario_id,
                timestamp=parse_utc_datetime("2026-01-15T03:12:18Z"),
                status="success",
                correlation_id=correlation_id,
                parent_event_id="evt-misuse-web-003",
                actor_user_id="user-alice",
                source_host_id="linux-ws-01",
                destination_host_id="web-server-01",
                service_id="svc-web-http",
                method="GET",
                url="http://web-server-01.internal/admin",
                path="/admin",
                status_code=200,
                attack={"technique_id": "T1087", "technique_name": "Account Discovery"},
            ),
        ),
        ScenarioEvent(
            sequence_order=5,
            event=WebRequestEvent(
                event_id="evt-misuse-web-005",
                scenario_id=scenario_id,
                timestamp=parse_utc_datetime("2026-01-15T03:12:28Z"),
                status="success",
                correlation_id=correlation_id,
                parent_event_id="evt-misuse-web-003",
                actor_user_id="user-alice",
                source_host_id="linux-ws-01",
                destination_host_id="web-server-01",
                service_id="svc-web-http",
                method="GET",
                url="http://web-server-01.internal/admin/archive.tar.gz",
                path="/admin/archive.tar.gz",
                status_code=200,
                attack={"technique_id": "T1105", "technique_name": "Ingress Tool Transfer"},
                metadata={"download_classification": "download", "file_name": "archive.tar.gz"},
            ),
        ),
    )

    return Scenario(
        id=scenario_id,
        name="Local Account Misuse and Suspicious Web Access",
        seed=2002,
        environment_id="linux-mini-lab",
        environment_version="0.1",
        start_time=start_time,
        end_time=parse_utc_datetime("2026-01-15T03:12:28Z"),
        events=events,
    )


__all__ = [
    "Scenario",
    "ScenarioEvent",
    "build_benign_internal_web_scenario",
    "build_local_account_misuse_web_scenario",
    "derive_event_id",
    "parse_utc_datetime",
]
