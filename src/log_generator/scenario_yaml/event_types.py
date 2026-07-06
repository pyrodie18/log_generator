"""
Authored YAML event-type registry.
"""

from dataclasses import dataclass
from typing import Optional


WEB_REQUEST_EVENT_TYPE = "web_request"
LINUX_LOCAL_LOGIN_EVENT_TYPE = "linux_local_login"
COMMON_EVENT_FIELDS = frozenset(
    {
        "id",
        "type",
        "at",
        "after",
        "delay",
        "actor",
        "source_host",
        "target_host",
        "service",
        "status",
        "correlation_id",
        "metadata",
        "attack",
    }
)


@dataclass(frozen=True)
class AuthoredEventType:
    """
    Describe one YAML-authored event type and its shared parser behavior.
    """

    name: str
    specific_fields: frozenset[str]
    optional_ip_fields: tuple[str, ...] = ()
    web_helper_offset_anchor: bool = False

    def allowed_fields(self) -> frozenset[str]:
        """
        Return all fields allowed for this authored event type.

        Returns:
            frozenset[str]: Common event fields plus event-type-specific fields.
        """
        return COMMON_EVENT_FIELDS | self.specific_fields


AUTHORED_EVENT_TYPES = {
    WEB_REQUEST_EVENT_TYPE: AuthoredEventType(
        name=WEB_REQUEST_EVENT_TYPE,
        specific_fields=frozenset(
            {
                "method",
                "path",
                "status_code",
                "query_string",
                "headers",
                "network",
                "dns",
                "http",
            }
        ),
    ),
    LINUX_LOCAL_LOGIN_EVENT_TYPE: AuthoredEventType(
        name=LINUX_LOCAL_LOGIN_EVENT_TYPE,
        specific_fields=frozenset(
            {
                "login_method",
                "source_ip",
            }
        ),
        optional_ip_fields=("source_ip",),
        web_helper_offset_anchor=True,
    ),
}
SUPPORTED_EVENT_TYPES = frozenset(AUTHORED_EVENT_TYPES)


def get_event_type(event_type: str) -> Optional[AuthoredEventType]:
    """
    Return registered metadata for an authored YAML event type.

    Args:
        event_type (str): Authored event type name.

    Returns:
        Optional[AuthoredEventType]: Event type metadata when registered.
    """
    return AUTHORED_EVENT_TYPES.get(event_type)


def uses_web_login_helper_offsets(event_type: Optional[str]) -> bool:
    """
    Return whether an event type anchors login-driven web helper timing.

    Args:
        event_type (Optional[str]): Event type name to inspect.

    Returns:
        bool: True when child web requests should reserve extra helper time.
    """
    if event_type is None:
        return False

    authored_event_type = get_event_type(event_type)

    if authored_event_type is None:
        return False

    return authored_event_type.web_helper_offset_anchor
