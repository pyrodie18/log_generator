"""
Source-neutral event model definitions.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, ClassVar, Optional


VALID_STATUSES = frozenset({"success", "failure", "denied", "unknown"})


def normalize_utc_timestamp(timestamp: datetime) -> datetime:
    """
    Normalize an aware datetime to UTC.

    Args:
        timestamp (datetime): Datetime value to normalize.

    Returns:
        datetime: Timezone-aware UTC datetime.
    """
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise ValueError("event timestamp must be timezone-aware")

    return timestamp.astimezone(timezone.utc)


def _add_optional_field(output: dict[str, Any], field_name: str, value: Any) -> None:
    """
    Add an optional value to a serialized event when it has meaningful content.

    Args:
        output (dict[str, Any]): Serialized event dictionary being built.
        field_name (str): Output field name to add.
        value (Any): Candidate value for the field.

    Returns:
        None: The dictionary is updated in place.
    """
    if value is None:
        return

    # Empty optional maps should be omitted so events do not emit placeholder context fields.
    if isinstance(value, dict) and not value:
        return

    # Copy mutable containers to keep callers from accidentally mutating serialized output later.
    if isinstance(value, dict):
        output[field_name] = dict(value)
        return

    if isinstance(value, list):
        output[field_name] = list(value)
        return

    output[field_name] = value


@dataclass(frozen=True)
class SourceNeutralEvent:
    """
    Represent the common envelope shared by all source-neutral events.
    """

    event_id: str
    scenario_id: str
    timestamp: datetime
    status: str
    correlation_id: str

    event_type: ClassVar[str] = "source_neutral_event"
    optional_envelope_fields: ClassVar[tuple[str, ...]] = (
        "parent_event_id",
        "actor_user_id",
        "source_host_id",
        "destination_host_id",
        "service_id",
        "metadata",
        "attack",
    )

    def __post_init__(self) -> None:
        """
        Validate and normalize the common event envelope.

        Returns:
            None: The frozen instance is updated through dataclass internals during initialization.
        """
        if self.status not in VALID_STATUSES:
            raise ValueError(f"unsupported event status '{self.status}'")

        object.__setattr__(self, "timestamp", normalize_utc_timestamp(self.timestamp))

    def event_fields(self) -> dict[str, Any]:
        """
        Return event-type-specific fields for serialization.

        Returns:
            dict[str, Any]: Event-specific fields for the concrete event type.
        """
        return {}

    def to_dict(self) -> dict[str, Any]:
        """
        Serialize the event to a JSON Lines compatible dictionary.

        Returns:
            dict[str, Any]: Source-neutral event dictionary with omitted empty optional fields.
        """
        output = {
            "event_id": self.event_id,
            "scenario_id": self.scenario_id,
            "event_type": self.event_type,
            "timestamp": self.timestamp.isoformat(),
            "status": self.status,
            "correlation_id": self.correlation_id,
        }

        for field_name in self.optional_envelope_fields:
            _add_optional_field(output, field_name, getattr(self, field_name, None))

        for field_name, value in self.event_fields().items():
            _add_optional_field(output, field_name, value)

        return output


@dataclass(frozen=True)
class DnsLookupEvent(SourceNeutralEvent):
    """
    Represent a host DNS lookup against a resolver.
    """

    source_host_id: str
    query_name: str
    query_type: str
    parent_event_id: Optional[str] = None
    actor_user_id: Optional[str] = None
    destination_host_id: Optional[str] = None
    service_id: Optional[str] = None
    resolved_addresses: Optional[list[str]] = None
    rcode: Optional[str] = None
    metadata: Optional[dict[str, Any]] = None
    attack: Optional[dict[str, Any]] = None

    event_type: ClassVar[str] = "dns_lookup"

    def event_fields(self) -> dict[str, Any]:
        """
        Return DNS lookup fields for serialization.

        Returns:
            dict[str, Any]: DNS lookup fields.
        """
        return {
            "query_name": self.query_name,
            "query_type": self.query_type,
            "resolved_addresses": self.resolved_addresses,
            "rcode": self.rcode,
        }


@dataclass(frozen=True)
class NetworkConnectionEvent(SourceNeutralEvent):
    """
    Represent a transport-level connection or flow between hosts.
    """

    source_host_id: str
    source_ip: str
    destination_ip: str
    destination_port: int
    network_protocol: str
    parent_event_id: Optional[str] = None
    actor_user_id: Optional[str] = None
    destination_host_id: Optional[str] = None
    service_id: Optional[str] = None
    application_protocol: Optional[str] = None
    metadata: Optional[dict[str, Any]] = None
    attack: Optional[dict[str, Any]] = None

    event_type: ClassVar[str] = "network_connection"

    def event_fields(self) -> dict[str, Any]:
        """
        Return network connection fields for serialization.

        Returns:
            dict[str, Any]: Network connection fields.
        """
        return {
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "destination_port": self.destination_port,
            "network_protocol": self.network_protocol,
            "application_protocol": self.application_protocol,
        }


@dataclass(frozen=True)
class WebRequestEvent(SourceNeutralEvent):
    """
    Represent an expanded HTTP request to a modeled web service.
    """

    source_host_id: str
    service_id: str
    method: str
    path: str
    status_code: int
    parent_event_id: Optional[str] = None
    actor_user_id: Optional[str] = None
    destination_host_id: Optional[str] = None
    url: Optional[str] = None
    query_string: Optional[str] = None
    request_headers: Optional[dict[str, str]] = None
    response_content_type: Optional[str] = None
    metadata: Optional[dict[str, Any]] = None
    attack: Optional[dict[str, Any]] = None

    event_type: ClassVar[str] = "web_request"

    def event_fields(self) -> dict[str, Any]:
        """
        Return web request fields for serialization.

        Returns:
            dict[str, Any]: Web request fields.
        """
        return {
            "method": self.method,
            "path": self.path,
            "status_code": self.status_code,
            "url": self.url,
            "query_string": self.query_string,
            "request_headers": self.request_headers,
            "response_content_type": self.response_content_type,
        }


@dataclass(frozen=True)
class LinuxLocalLoginEvent(SourceNeutralEvent):
    """
    Represent a local Linux login attempt on a host.
    """

    actor_user_id: str
    target_host_id: str
    login_method: str
    parent_event_id: Optional[str] = None
    source_host_id: Optional[str] = None
    source_ip: Optional[str] = None
    metadata: Optional[dict[str, Any]] = None
    attack: Optional[dict[str, Any]] = None

    event_type: ClassVar[str] = "linux_local_login"

    def event_fields(self) -> dict[str, Any]:
        """
        Return Linux local login fields for serialization.

        Returns:
            dict[str, Any]: Linux local login fields.
        """
        return {
            "target_host_id": self.target_host_id,
            "login_method": self.login_method,
            "source_ip": self.source_ip,
        }


__all__ = [
    "DnsLookupEvent",
    "LinuxLocalLoginEvent",
    "NetworkConnectionEvent",
    "SourceNeutralEvent",
    "VALID_STATUSES",
    "WebRequestEvent",
    "normalize_utc_timestamp",
]
