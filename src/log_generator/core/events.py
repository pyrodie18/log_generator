"""
Source-neutral event model definitions.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, ClassVar, Optional

from log_generator.core.value_checks import (
    require_ip_address,
    require_non_negative_integer,
    require_non_negative_number,
    require_port_number,
)


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

    if hasattr(value, "to_dict"):
        serialized_value = value.to_dict()

        if serialized_value:
            output[field_name] = serialized_value

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
class NetworkContext:
    """
    Carry source-neutral flow details shared by network-oriented output families.
    """

    source_port: Optional[int] = None
    orig_bytes: Optional[int] = None
    resp_bytes: Optional[int] = None
    orig_pkts: Optional[int] = None
    resp_pkts: Optional[int] = None

    def __post_init__(self) -> None:
        """
        Validate authored flow details.

        Returns:
            None: Raises ValueError when a field cannot represent a plausible flow value.
        """
        require_port_number("network.source_port", self.source_port, allow_none=True)
        require_non_negative_integer("network.orig_bytes", self.orig_bytes, allow_none=True)
        require_non_negative_integer("network.resp_bytes", self.resp_bytes, allow_none=True)
        require_non_negative_integer("network.orig_pkts", self.orig_pkts, allow_none=True)
        require_non_negative_integer("network.resp_pkts", self.resp_pkts, allow_none=True)

    def to_dict(self) -> dict[str, int]:
        """
        Serialize populated flow details.

        Returns:
            dict[str, int]: Populated source-neutral flow detail fields.
        """
        output = {}

        for field_name in ("source_port", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts"):
            value = getattr(self, field_name)

            if value is not None:
                output[field_name] = value

        return output


@dataclass(frozen=True)
class DnsContext:
    """
    Carry source-neutral DNS transaction details shared by DNS-capable outputs.
    """

    trans_id: Optional[int] = None
    rtt: Optional[float] = None
    ttls: Optional[list[float]] = None
    flags: Optional[dict[str, bool]] = None

    def __post_init__(self) -> None:
        """
        Validate authored DNS details.

        Returns:
            None: Raises ValueError when a field cannot represent plausible DNS context.
        """
        require_port_number("dns.trans_id", self.trans_id, allow_none=True)
        require_non_negative_number("dns.rtt", self.rtt, allow_none=True)

        if self.ttls is not None:
            for index, ttl in enumerate(self.ttls):
                require_non_negative_number(f"dns.ttls[{index}]", ttl, allow_none=True)

        if self.flags is not None:
            for name, value in self.flags.items():
                if name not in {"AA", "TC", "RD", "RA"}:
                    raise ValueError("dns.flags supports only AA, TC, RD, and RA")

                if not isinstance(value, bool):
                    raise ValueError(f"dns.flags.{name} must be a boolean")

    def to_dict(self) -> dict[str, Any]:
        """
        Serialize populated DNS details.

        Returns:
            dict[str, Any]: Populated source-neutral DNS detail fields.
        """
        output: dict[str, Any] = {}

        if self.trans_id is not None:
            output["trans_id"] = self.trans_id

        if self.rtt is not None:
            output["rtt"] = self.rtt

        if self.ttls is not None:
            output["ttls"] = list(self.ttls)

        if self.flags is not None:
            output["flags"] = dict(self.flags)

        return output


@dataclass(frozen=True)
class HttpContext:
    """
    Carry source-neutral HTTP transaction details shared by HTTP-capable outputs.
    """

    user_agent: Optional[str] = None
    version: Optional[str] = None
    response_body_len: Optional[int] = None
    response_content_type: Optional[str] = None

    def __post_init__(self) -> None:
        """
        Validate authored HTTP details.

        Returns:
            None: Raises ValueError when a field cannot represent plausible HTTP context.
        """
        require_non_negative_integer("http.response_body_len", self.response_body_len, allow_none=True)

        for field_name in ("user_agent", "version", "response_content_type"):
            value = getattr(self, field_name)

            if value is not None and not isinstance(value, str):
                raise ValueError(f"http.{field_name} must be a string")

    def to_dict(self) -> dict[str, Any]:
        """
        Serialize populated HTTP details.

        Returns:
            dict[str, Any]: Populated source-neutral HTTP detail fields.
        """
        output: dict[str, Any] = {}

        for field_name in ("user_agent", "version", "response_body_len", "response_content_type"):
            value = getattr(self, field_name)

            if value is not None:
                output[field_name] = value

        return output


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
    network: Optional[NetworkContext] = None
    dns: Optional[DnsContext] = None
    metadata: Optional[dict[str, Any]] = None
    attack: Optional[dict[str, Any]] = None

    event_type: ClassVar[str] = "dns_lookup"

    def __post_init__(self) -> None:
        """
        Validate and normalize DNS lookup event fields.

        Returns:
            None: The frozen instance is updated through dataclass internals during initialization.
        """
        super().__post_init__()

        if self.resolved_addresses is not None:
            for index, resolved_address in enumerate(self.resolved_addresses):
                require_ip_address(f"resolved_addresses[{index}]", resolved_address)

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
            "network": self.network,
            "dns": self.dns,
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
    network: Optional[NetworkContext] = None
    metadata: Optional[dict[str, Any]] = None
    attack: Optional[dict[str, Any]] = None

    event_type: ClassVar[str] = "network_connection"

    def __post_init__(self) -> None:
        """
        Validate and normalize network connection event fields.

        Returns:
            None: The frozen instance is updated through dataclass internals during initialization.
        """
        super().__post_init__()
        require_ip_address("source_ip", self.source_ip)
        require_ip_address("destination_ip", self.destination_ip)
        require_port_number("destination_port", self.destination_port)

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
            "network": self.network,
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
    http: Optional[HttpContext] = None
    metadata: Optional[dict[str, Any]] = None
    attack: Optional[dict[str, Any]] = None
    network: Optional[NetworkContext] = None

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
            "http": self.http,
            "network": self.network,
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

    def __post_init__(self) -> None:
        """
        Validate and normalize Linux local login event fields.

        Returns:
            None: The frozen instance is updated through dataclass internals during initialization.
        """
        super().__post_init__()
        require_ip_address("source_ip", self.source_ip, allow_none=True)

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
