"""
Deterministic source-neutral detail enrichment for expanded scenarios.
"""

from dataclasses import replace
from hashlib import sha1
from typing import Optional

from log_generator.core.events import (
    DnsContext,
    DnsLookupEvent,
    HttpContext,
    NetworkConnectionEvent,
    NetworkContext,
    WebRequestEvent,
)
from log_generator.core.scenarios import Scenario, ScenarioEvent


HTTP_REQUEST_HEADER_BYTES = 120
HTTP_DOWNLOAD_RESPONSE_BYTES = 32768
DEFAULT_HTTP_USER_AGENT = "Mozilla/5.0 log-generator/0.1"
DEFAULT_HTTP_VERSION = "1.1"
DEFAULT_DNS_FLAGS = {"AA": False, "TC": False, "RD": True, "RA": True}


def enrich_scenarios(scenarios: tuple[Scenario, ...]) -> tuple[Scenario, ...]:
    """
    Fill omitted source-neutral network, DNS, and HTTP details before output writers run.

    Authored values take precedence. All defaults derive from scenario and event data so repeated
    enrichment and generation produce the same scenario facts.

    Args:
        scenarios (tuple[Scenario, ...]): Scenarios to enrich.

    Returns:
        tuple[Scenario, ...]: Scenarios with populated shared detail contexts.
    """
    return tuple(_enrich_scenario(scenario) for scenario in scenarios)


def _enrich_scenario(scenario: Scenario) -> Scenario:
    ordered_events = tuple(sorted(scenario.events, key=ScenarioEvent.sort_key))
    events_by_id = {
        scenario_event.event.event_id: scenario_event.event for scenario_event in ordered_events
    }
    enriched_web_requests = {
        event_id: _enrich_http_event(event)
        for event_id, event in events_by_id.items()
        if isinstance(event, WebRequestEvent)
    }
    enriched_connections: dict[str, NetworkConnectionEvent] = {}
    enriched_dns_events: dict[str, DnsLookupEvent] = {
        event_id: _enrich_dns_event(scenario, event)
        for event_id, event in events_by_id.items()
        if isinstance(event, DnsLookupEvent)
    }
    web_requests_by_connection: dict[str, list[WebRequestEvent]] = {}

    for scenario_event in ordered_events:
        event = scenario_event.event

        if isinstance(event, WebRequestEvent) and isinstance(
            events_by_id.get(event.parent_event_id), NetworkConnectionEvent
        ):
            web_requests_by_connection.setdefault(event.parent_event_id, []).append(
                enriched_web_requests[event.event_id]
            )

    for event_id, event in events_by_id.items():
        if isinstance(event, NetworkConnectionEvent):
            requests = web_requests_by_connection.get(event_id, [])
            enriched_connections[event_id] = _enrich_connection_event(scenario, event, requests)

    for connection_id, connection in enriched_connections.items():
        requests = web_requests_by_connection.get(connection_id, [])
        enriched_web_requests.update(
            {request.event_id: replace(request, network=connection.network) for request in requests}
        )

    enriched_events = []

    for scenario_event in scenario.events:
        event = scenario_event.event

        if isinstance(event, DnsLookupEvent):
            event = enriched_dns_events[event.event_id]
        elif isinstance(event, NetworkConnectionEvent):
            event = enriched_connections[event.event_id]
        elif isinstance(event, WebRequestEvent):
            event = enriched_web_requests[event.event_id]

            if not isinstance(events_by_id.get(event.parent_event_id), NetworkConnectionEvent):
                event = replace(
                    event,
                    network=_network_context_with_defaults(
                        scenario,
                        flow_key=f"http:{event.event_id}",
                        authored_contexts=(event.network,),
                        orig_bytes=_http_request_size(event),
                        resp_bytes=_http_response_size(event),
                    ),
                )

        enriched_events.append(replace(scenario_event, event=event))

    return replace(scenario, events=tuple(enriched_events))


def _enrich_dns_event(scenario: Scenario, event: DnsLookupEvent) -> DnsLookupEvent:
    answers = event.resolved_addresses or []
    dns = event.dns or DnsContext()
    flags = dict(DEFAULT_DNS_FLAGS)

    if dns.flags is not None:
        flags.update(dns.flags)

    dns = replace(
        dns,
        trans_id=(
            dns.trans_id
            if dns.trans_id is not None
            else _stable_count(event.scenario_id, event.event_id, modulo=65536)
        ),
        rtt=dns.rtt if dns.rtt is not None else 0.025,
        ttls=list(dns.ttls) if dns.ttls is not None else [300.0 for _ in answers],
        flags=flags,
    )
    network = _network_context_with_defaults(
        scenario,
        flow_key=f"dns:{event.event_id}",
        authored_contexts=(event.network,),
        orig_bytes=78,
        resp_bytes=120 + 16 * len(answers),
        orig_pkts=1,
        resp_pkts=1,
    )

    return replace(event, network=network, dns=dns)


def _enrich_connection_event(
    scenario: Scenario,
    event: NetworkConnectionEvent,
    web_requests: list[WebRequestEvent],
) -> NetworkConnectionEvent:
    authored_contexts = (event.network, *(request.network for request in web_requests))
    orig_bytes = sum(_http_request_size(request) for request in web_requests) if web_requests else 60
    resp_bytes = (
        sum(_http_response_size(request) for request in web_requests)
        if web_requests
        else 60
    )
    network = _network_context_with_defaults(
        scenario,
        flow_key=f"conn:{event.event_id}",
        authored_contexts=authored_contexts,
        orig_bytes=orig_bytes,
        resp_bytes=resp_bytes,
    )

    return replace(event, network=network)


def _enrich_http_event(event: WebRequestEvent) -> WebRequestEvent:
    authored = event.http or HttpContext()
    file_name = _response_file_name(event)
    response_content_type = authored.response_content_type or event.response_content_type

    if not response_content_type and file_name is not None:
        response_content_type = (
            "application/gzip"
            if file_name.lower().endswith((".tar.gz", ".tgz"))
            else "application/octet-stream"
        )

    user_agent = authored.user_agent

    if user_agent is None:
        user_agent = _header_value(event, "user-agent") or DEFAULT_HTTP_USER_AGENT

    http = replace(
        authored,
        user_agent=user_agent,
        version=authored.version if authored.version is not None else DEFAULT_HTTP_VERSION,
        response_body_len=(
            authored.response_body_len
            if authored.response_body_len is not None
            else _http_response_size(event)
        ),
        response_content_type=response_content_type,
    )

    return replace(event, http=http)


def _network_context_with_defaults(
    scenario: Scenario,
    flow_key: str,
    authored_contexts: tuple[Optional[NetworkContext], ...],
    orig_bytes: int,
    resp_bytes: int,
    orig_pkts: Optional[int] = None,
    resp_pkts: Optional[int] = None,
) -> NetworkContext:
    authored_values: dict[str, Optional[int]] = {}

    for field_name in ("source_port", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts"):
        values = [
            getattr(context, field_name)
            for context in authored_contexts
            if context is not None and getattr(context, field_name) is not None
        ]

        if len(set(values)) > 1:
            raise ValueError(f"conflicting authored network.{field_name} values for flow '{flow_key}'")

        authored_values[field_name] = values[0] if values else None

    enriched_orig_bytes = authored_values["orig_bytes"]

    if enriched_orig_bytes is None:
        enriched_orig_bytes = orig_bytes

    enriched_resp_bytes = authored_values["resp_bytes"]

    if enriched_resp_bytes is None:
        enriched_resp_bytes = resp_bytes

    enriched_orig_pkts = authored_values["orig_pkts"]

    if enriched_orig_pkts is None:
        enriched_orig_pkts = orig_pkts

    if enriched_orig_pkts is None:
        enriched_orig_pkts = _packet_count(enriched_orig_bytes)

    enriched_resp_pkts = authored_values["resp_pkts"]

    if enriched_resp_pkts is None:
        enriched_resp_pkts = resp_pkts

    if enriched_resp_pkts is None:
        enriched_resp_pkts = _packet_count(enriched_resp_bytes)

    return NetworkContext(
        source_port=(
            authored_values["source_port"]
            if authored_values["source_port"] is not None
            else 49152 + _stable_count(scenario.id, f"{scenario.seed}:{flow_key}", modulo=16384)
        ),
        orig_bytes=enriched_orig_bytes,
        resp_bytes=enriched_resp_bytes,
        orig_pkts=enriched_orig_pkts,
        resp_pkts=enriched_resp_pkts,
    )


def _http_request_size(event: WebRequestEvent) -> int:
    header_size = HTTP_REQUEST_HEADER_BYTES

    if event.request_headers:
        header_size += sum(len(name) + len(value) + 4 for name, value in event.request_headers.items())

    uri = event.path

    if event.query_string:
        uri = f"{uri}?{event.query_string}"

    return header_size + len(event.method) + len(uri)


def _http_response_size(event: WebRequestEvent) -> int:
    if event.http is not None and event.http.response_body_len is not None:
        return event.http.response_body_len

    metadata = event.metadata or {}

    if "response_body_len" in metadata:
        return int(metadata["response_body_len"])

    if metadata.get("download_classification") == "download":
        return HTTP_DOWNLOAD_RESPONSE_BYTES

    if event.status_code == 403:
        return 512

    if event.status_code == 404:
        return 384

    return 2048


def _response_file_name(event: WebRequestEvent) -> Optional[str]:
    file_name = (event.metadata or {}).get("file_name")
    return file_name if isinstance(file_name, str) and file_name else None


def _header_value(event: WebRequestEvent, header_name: str) -> Optional[str]:
    if event.request_headers is None:
        return None

    normalized_name = header_name.lower()

    for name, value in event.request_headers.items():
        if name.lower() == normalized_name:
            return value

    return None


def _packet_count(payload_bytes: int) -> int:
    return max(1, (payload_bytes + 1199) // 1200)


def _stable_count(scenario_id: str, key: str, modulo: int) -> int:
    digest = sha1(f"{scenario_id}:{key}".encode("utf-8")).hexdigest()
    return int(digest[:8], 16) % modulo


__all__ = ["enrich_scenarios"]
