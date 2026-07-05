"""
Zeek native TSV schema and rendering helpers.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha1
from math import ceil
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional

from log_generator.core.environment import Environment, Service, build_linux_mini_lab
from log_generator.core.events import DnsLookupEvent, NetworkConnectionEvent, SourceNeutralEvent, WebRequestEvent
from log_generator.core.events import normalize_utc_timestamp
from log_generator.core.scenarios import Scenario, ScenarioEvent
from log_generator.core.value_checks import is_integer, is_non_negative_integer, is_port_number
from log_generator.output.jsonl import safe_output_path


ZEEK_FIELD_SEPARATOR = "\t"
ZEEK_SEPARATOR_DIRECTIVE = r"\x09"
ZEEK_SET_SEPARATOR = ","
ZEEK_EMPTY_FIELD = "(empty)"
ZEEK_UNSET_FIELD = "-"
ZEEK_SENSOR_ID = "zeek-sensor-01"
ZEEK_OUTPUT_PATH = ("logs", ZEEK_SENSOR_ID, "zeek")
ZEEK_STREAM_FILE_NAMES = {
    "conn": "conn.log",
    "dns": "dns.log",
    "http": "http.log",
}


@dataclass(frozen=True)
class ZeekField:
    """
    Describe one Zeek log field and its native Zeek TSV type.
    """

    name: str
    zeek_type: str


@dataclass(frozen=True)
class ZeekStreamSchema:
    """
    Describe one Zeek stream schema.
    """

    path: str
    fields: tuple[ZeekField, ...]


@dataclass(frozen=True)
class ZeekFlowContext:
    """
    Describe shared connection facts used by Zeek records for a single flow.
    """

    uid: str
    source_ip: str
    source_port: int
    destination_ip: str
    destination_port: int
    network_protocol: str
    application_protocol: str
    source_host_id: str
    destination_host_id: str
    timestamp: datetime
    orig_bytes: Optional[int] = None
    resp_bytes: Optional[int] = None
    orig_pkts: Optional[int] = None
    resp_pkts: Optional[int] = None


@dataclass(frozen=True)
class ZeekWrittenFile:
    """
    Describe one Zeek log file written to disk.
    """

    path: Path
    stream_name: str
    record_count: int
    scenario_ids: tuple[str, ...]
    event_types: tuple[str, ...]


@dataclass(frozen=True)
class ZeekOmittedStream:
    """
    Describe one requested Zeek stream skipped because it had no records.
    """

    source_id: str
    log_family: str
    log_stream: str
    reason: str


@dataclass(frozen=True)
class ZeekWriteResult:
    """
    Describe Zeek files written and streams intentionally omitted.
    """

    files: tuple[ZeekWrittenFile, ...]
    omitted_streams: tuple[ZeekOmittedStream, ...]


ZEEK_STREAM_SCHEMAS = {
    "conn": ZeekStreamSchema(
        path="conn",
        fields=(
            ZeekField("ts", "time"),
            ZeekField("uid", "string"),
            ZeekField("id.orig_h", "addr"),
            ZeekField("id.orig_p", "port"),
            ZeekField("id.resp_h", "addr"),
            ZeekField("id.resp_p", "port"),
            ZeekField("proto", "enum"),
            ZeekField("service", "string"),
            ZeekField("duration", "interval"),
            ZeekField("orig_bytes", "count"),
            ZeekField("resp_bytes", "count"),
            ZeekField("conn_state", "string"),
            ZeekField("local_orig", "bool"),
            ZeekField("local_resp", "bool"),
            ZeekField("missed_bytes", "count"),
            ZeekField("history", "string"),
            ZeekField("orig_pkts", "count"),
            ZeekField("orig_ip_bytes", "count"),
            ZeekField("resp_pkts", "count"),
            ZeekField("resp_ip_bytes", "count"),
            ZeekField("tunnel_parents", "set[string]"),
            ZeekField("ip_proto", "count"),
        ),
    ),
    "dns": ZeekStreamSchema(
        path="dns",
        fields=(
            ZeekField("ts", "time"),
            ZeekField("uid", "string"),
            ZeekField("id.orig_h", "addr"),
            ZeekField("id.orig_p", "port"),
            ZeekField("id.resp_h", "addr"),
            ZeekField("id.resp_p", "port"),
            ZeekField("proto", "enum"),
            ZeekField("trans_id", "count"),
            ZeekField("rtt", "interval"),
            ZeekField("query", "string"),
            ZeekField("qclass", "count"),
            ZeekField("qclass_name", "string"),
            ZeekField("qtype", "count"),
            ZeekField("qtype_name", "string"),
            ZeekField("rcode", "count"),
            ZeekField("rcode_name", "string"),
            ZeekField("AA", "bool"),
            ZeekField("TC", "bool"),
            ZeekField("RD", "bool"),
            ZeekField("RA", "bool"),
            ZeekField("Z", "count"),
            ZeekField("answers", "vector[string]"),
            ZeekField("TTLs", "vector[interval]"),
            ZeekField("rejected", "bool"),
        ),
    ),
    "http": ZeekStreamSchema(
        path="http",
        fields=(
            ZeekField("ts", "time"),
            ZeekField("uid", "string"),
            ZeekField("id.orig_h", "addr"),
            ZeekField("id.orig_p", "port"),
            ZeekField("id.resp_h", "addr"),
            ZeekField("id.resp_p", "port"),
            ZeekField("trans_depth", "count"),
            ZeekField("method", "string"),
            ZeekField("host", "string"),
            ZeekField("uri", "string"),
            ZeekField("referrer", "string"),
            ZeekField("version", "string"),
            ZeekField("user_agent", "string"),
            ZeekField("request_body_len", "count"),
            ZeekField("response_body_len", "count"),
            ZeekField("status_code", "count"),
            ZeekField("status_msg", "string"),
            ZeekField("tags", "set[string]"),
            ZeekField("resp_fuids", "vector[string]"),
            ZeekField("resp_filenames", "vector[string]"),
            ZeekField("resp_mime_types", "vector[string]"),
        ),
    ),
}


def schema_for_stream(stream_name: str) -> ZeekStreamSchema:
    """
    Return the schema for a supported Zeek stream.

    Args:
        stream_name (str): Zeek stream path such as ``conn``, ``dns``, or ``http``.

    Returns:
        ZeekStreamSchema: Schema for the requested stream.
    """
    try:
        return ZEEK_STREAM_SCHEMAS[stream_name]
    except KeyError as exc:
        raise ValueError(f"unsupported Zeek stream '{stream_name}'") from exc


def zeek_schema_field_names(schema: ZeekStreamSchema) -> tuple[str, ...]:
    """
    Return the field names for a Zeek stream schema.

    Args:
        schema (ZeekStreamSchema): Zeek stream schema to inspect.

    Returns:
        tuple[str, ...]: Field names in native log order.
    """
    return tuple(field.name for field in schema.fields)


def zeek_schema_field_types(schema: ZeekStreamSchema) -> tuple[str, ...]:
    """
    Return the field types for a Zeek stream schema.

    Args:
        schema (ZeekStreamSchema): Zeek stream schema to inspect.

    Returns:
        tuple[str, ...]: Field types in native log order.
    """
    return tuple(field.zeek_type for field in schema.fields)


def render_zeek_log(
    stream_name: str,
    records: Iterable[Mapping[str, Any]],
    opened_at: datetime,
    closed_at: Optional[datetime] = None,
) -> str:
    """
    Render a complete native-style Zeek TSV log.

    Args:
        stream_name (str): Zeek stream path such as ``conn``, ``dns``, or ``http``.
        records (Iterable[Mapping[str, Any]]): Records keyed by Zeek field name.
        opened_at (datetime): Deterministic wall-clock time for the ``#open`` row.
        closed_at (Optional[datetime]): Deterministic wall-clock time for the ``#close`` row.

    Returns:
        str: Native-style Zeek TSV text ending with a newline.
    """
    if closed_at is None:
        closed_at = opened_at

    lines = list(build_zeek_header_lines(stream_name, opened_at))

    for record in records:
        lines.append(render_zeek_record(stream_name, record))

    lines.append(render_zeek_close(closed_at))

    return "\n".join(lines) + "\n"


def write_zeek_logs(
    output_root: Path,
    scenarios: tuple[Scenario, ...],
    generated_at: Optional[datetime] = None,
) -> ZeekWriteResult:
    """
    Write requested Zeek TSV logs for scenarios that include the Zeek output family.

    Args:
        output_root (Path): Root output directory where generated artifacts should be written.
        scenarios (tuple[Scenario, ...]): Scenarios whose Zeek output should be generated.
        generated_at (Optional[datetime]): Deterministic wall-clock time for Zeek headers.

    Returns:
        ZeekWriteResult: Written Zeek file metadata and any intentionally omitted streams.
    """
    zeek_scenarios = tuple(scenario for scenario in scenarios if "zeek" in scenario.output_families)

    if not zeek_scenarios:
        return ZeekWriteResult(files=(), omitted_streams=())

    if generated_at is None:
        generated_at = datetime.now(timezone.utc)

    generated_at = normalize_utc_timestamp(generated_at)
    records_by_stream, event_types_by_stream = build_zeek_records(zeek_scenarios)
    written_files = []
    omitted_streams = []

    for stream_name in ("conn", "dns", "http"):
        records = records_by_stream[stream_name]
        file_name = ZEEK_STREAM_FILE_NAMES[stream_name]

        if not records:
            omitted_streams.append(
                ZeekOmittedStream(
                    source_id=ZEEK_SENSOR_ID,
                    log_family="zeek",
                    log_stream=file_name,
                    reason="no matching visible records",
                )
            )
            continue

        log_path = safe_output_path(output_root, (*ZEEK_OUTPUT_PATH, file_name))
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(render_zeek_log(stream_name, records, generated_at), encoding="utf-8")
        written_files.append(
            ZeekWrittenFile(
                path=log_path,
                stream_name=stream_name,
                record_count=len(records),
                scenario_ids=_scenario_ids_for_records(records),
                event_types=tuple(event_types_by_stream[stream_name]),
            )
        )

    return ZeekWriteResult(files=tuple(written_files), omitted_streams=tuple(omitted_streams))


def build_zeek_records(
    scenarios: tuple[Scenario, ...],
) -> tuple[dict[str, list[dict[str, Any]]], dict[str, list[str]]]:
    """
    Build Zeek records for requested scenarios without writing files.

    Args:
        scenarios (tuple[Scenario, ...]): Zeek-enabled scenarios to convert.

    Returns:
        tuple[dict[str, list[dict[str, Any]]], dict[str, list[str]]]: Records and source event types by stream.
    """
    records_by_stream: dict[str, list[dict[str, Any]]] = {"conn": [], "dns": [], "http": []}
    event_types_by_stream: dict[str, list[str]] = {"conn": [], "dns": [], "http": []}

    for scenario in scenarios:
        environment = _environment_for_scenario(scenario)
        ordered_scenario_events = tuple(sorted(scenario.events, key=ScenarioEvent.sort_key))
        events_by_id = {
            scenario_event.event.event_id: scenario_event.event for scenario_event in ordered_scenario_events
        }
        flow_contexts = _build_flow_contexts(scenario, environment, ordered_scenario_events)
        web_requests_by_flow_key = _web_requests_by_http_flow_key(ordered_scenario_events, events_by_id)
        http_depths: dict[str, int] = {}
        emitted_conn_uids: set[str] = set()

        for scenario_event in ordered_scenario_events:
            event = scenario_event.event

            if isinstance(event, DnsLookupEvent):
                flow_context = flow_contexts.get(_dns_flow_key(event))

                if flow_context is None or not _flow_is_visible(environment, flow_context):
                    continue

                if flow_context.uid not in emitted_conn_uids:
                    _append_record(
                        records_by_stream,
                        event_types_by_stream,
                        "conn",
                        _dns_conn_record(event, flow_context, scenario_event.sequence_order),
                    )
                    emitted_conn_uids.add(flow_context.uid)

                _append_record(
                    records_by_stream,
                    event_types_by_stream,
                    "dns",
                    _dns_record(event, flow_context, scenario_event.sequence_order),
                )
                continue

            if isinstance(event, NetworkConnectionEvent):
                flow_context = flow_contexts.get(_connection_flow_key(event))

                if flow_context is None or not _flow_is_visible(environment, flow_context):
                    continue

                if flow_context.uid in emitted_conn_uids:
                    continue

                web_requests = _web_requests_for_connection(events_by_id.values(), event.event_id)
                _append_record(
                    records_by_stream,
                    event_types_by_stream,
                    "conn",
                    _connection_record(event, flow_context, web_requests, scenario_event.sequence_order),
                )
                emitted_conn_uids.add(flow_context.uid)
                continue

            if isinstance(event, WebRequestEvent):
                flow_key = _http_flow_key(event, events_by_id)
                flow_context = flow_contexts.get(flow_key)

                if flow_context is None or not _flow_is_visible(environment, flow_context):
                    continue

                needs_sibling_conn = not _web_request_uses_connection_event(event, events_by_id)

                if needs_sibling_conn and flow_context.uid not in emitted_conn_uids:
                    _append_record(
                        records_by_stream,
                        event_types_by_stream,
                        "conn",
                        _http_sibling_conn_record(
                            event,
                            flow_context,
                            web_requests_by_flow_key.get(flow_key, (event,)),
                            scenario_event.sequence_order,
                        ),
                    )
                    emitted_conn_uids.add(flow_context.uid)

                depth_key = flow_context.uid
                http_depths[depth_key] = http_depths.get(depth_key, 0) + 1
                _append_record(
                    records_by_stream,
                    event_types_by_stream,
                    "http",
                    _http_record(
                        event,
                        flow_context,
                        environment,
                        http_depths[depth_key],
                        scenario_event.sequence_order,
                    ),
                )

    for stream_name, records in records_by_stream.items():
        records_by_stream[stream_name] = sorted(records, key=_zeek_record_sort_key)

    return records_by_stream, event_types_by_stream


def _append_record(
    records_by_stream: dict[str, list[dict[str, Any]]],
    event_types_by_stream: dict[str, list[str]],
    stream_name: str,
    record: dict[str, Any],
) -> None:
    """
    Append a record and track first-seen source event types for the stream.

    Args:
        records_by_stream (dict[str, list[dict[str, Any]]]): Records collected by stream.
        event_types_by_stream (dict[str, list[str]]): Source event types collected by stream.
        stream_name (str): Zeek stream receiving the record.
        record (dict[str, Any]): Record to append.

    Returns:
        None: The provided dictionaries are updated in place.
    """
    records_by_stream[stream_name].append(record)
    event_type = str(record["_event_type"])

    if event_type not in event_types_by_stream[stream_name]:
        event_types_by_stream[stream_name].append(event_type)


def _build_flow_contexts(
    scenario: Scenario,
    environment: Environment,
    ordered_scenario_events: tuple[ScenarioEvent, ...],
) -> dict[str, ZeekFlowContext]:
    """
    Build deterministic shared flow context for DNS, connection, and HTTP records.

    Args:
        scenario (Scenario): Scenario owning the events.
        environment (Environment): Environment used to resolve host and service facts.
        ordered_scenario_events (tuple[ScenarioEvent, ...]): Scenario events in deterministic order.

    Returns:
        dict[str, ZeekFlowContext]: Flow contexts keyed by record-family-specific flow keys.
    """
    contexts = {}
    connection_contexts_by_event_id = {}

    for scenario_event in ordered_scenario_events:
        event = scenario_event.event

        if isinstance(event, DnsLookupEvent):
            context = _build_dns_flow_context(scenario, environment, event)
            contexts[_dns_flow_key(event)] = context
            continue

        if isinstance(event, NetworkConnectionEvent):
            context = _build_connection_flow_context(scenario, event)
            contexts[_connection_flow_key(event)] = context
            connection_contexts_by_event_id[event.event_id] = context

    for scenario_event in ordered_scenario_events:
        event = scenario_event.event

        if not isinstance(event, WebRequestEvent):
            continue

        if event.parent_event_id in connection_contexts_by_event_id:
            contexts[_http_connection_flow_key(event.parent_event_id)] = connection_contexts_by_event_id[
                event.parent_event_id
            ]
            continue

        context = _build_http_flow_context(scenario, environment, event)

        if context is not None:
            contexts[_http_standalone_flow_key(event)] = context

    return contexts


def _build_dns_flow_context(scenario: Scenario, environment: Environment, event: DnsLookupEvent) -> ZeekFlowContext:
    """
    Build shared flow context for a DNS lookup and its sibling Zeek connection record.

    Args:
        scenario (Scenario): Scenario owning the event.
        environment (Environment): Environment used to resolve hosts and services.
        event (DnsLookupEvent): DNS event to describe.

    Returns:
        ZeekFlowContext: Shared DNS flow context.
    """
    source_host = environment.require_host(event.source_host_id)
    service = _service_for_event(environment, event, default_service_id="svc-dns")
    destination_host = environment.require_host(service.target_host_id)
    network = event.network

    return ZeekFlowContext(
        uid=_stable_zeek_uid(scenario, f"dns:{event.event_id}"),
        source_ip=source_host.primary_ip,
        source_port=_context_source_port(network, scenario, f"dns:{event.event_id}"),
        destination_ip=destination_host.primary_ip,
        destination_port=service.port,
        network_protocol=service.transport_protocol,
        application_protocol=service.application_protocol,
        source_host_id=source_host.id,
        destination_host_id=destination_host.id,
        timestamp=event.timestamp,
        orig_bytes=_context_count(network, "orig_bytes"),
        resp_bytes=_context_count(network, "resp_bytes"),
        orig_pkts=_context_count(network, "orig_pkts"),
        resp_pkts=_context_count(network, "resp_pkts"),
    )


def _build_connection_flow_context(scenario: Scenario, event: NetworkConnectionEvent) -> ZeekFlowContext:
    """
    Build shared flow context for a transport connection event.

    Args:
        scenario (Scenario): Scenario owning the event.
        event (NetworkConnectionEvent): Connection event to describe.

    Returns:
        ZeekFlowContext: Shared connection flow context.
    """
    network = event.network

    return ZeekFlowContext(
        uid=_stable_zeek_uid(scenario, f"conn:{event.event_id}"),
        source_ip=event.source_ip,
        source_port=_context_source_port(network, scenario, f"conn:{event.event_id}"),
        destination_ip=event.destination_ip,
        destination_port=event.destination_port,
        network_protocol=event.network_protocol,
        application_protocol=event.application_protocol or "-",
        source_host_id=event.source_host_id,
        destination_host_id=event.destination_host_id or "",
        timestamp=event.timestamp,
        orig_bytes=_context_count(network, "orig_bytes"),
        resp_bytes=_context_count(network, "resp_bytes"),
        orig_pkts=_context_count(network, "orig_pkts"),
        resp_pkts=_context_count(network, "resp_pkts"),
    )


def _build_http_flow_context(
    scenario: Scenario,
    environment: Environment,
    event: WebRequestEvent,
) -> Optional[ZeekFlowContext]:
    """
    Build shared flow context for a standalone HTTP event without a connection parent.

    Args:
        scenario (Scenario): Scenario owning the event.
        environment (Environment): Environment used to resolve service and host facts.
        event (WebRequestEvent): HTTP event to describe.

    Returns:
        Optional[ZeekFlowContext]: Shared HTTP flow context, or None when references cannot resolve.
    """
    source_host = environment.get_host(event.source_host_id)
    service = environment.get_service(event.service_id)

    if source_host is None or service is None:
        return None

    destination_host = environment.get_host(event.destination_host_id or service.target_host_id)

    if destination_host is None:
        return None

    return ZeekFlowContext(
        uid=_stable_zeek_uid(scenario, f"http:{event.event_id}"),
        source_ip=source_host.primary_ip,
        source_port=_stable_client_port(scenario, f"http:{event.event_id}"),
        destination_ip=destination_host.primary_ip,
        destination_port=service.port,
        network_protocol=service.transport_protocol,
        application_protocol=service.application_protocol,
        source_host_id=source_host.id,
        destination_host_id=destination_host.id,
        timestamp=event.timestamp,
    )


def _dns_conn_record(
    event: DnsLookupEvent,
    flow_context: ZeekFlowContext,
    sequence_order: int,
) -> dict[str, Any]:
    """
    Build a Zeek conn.log record for a DNS lookup.

    Args:
        event (DnsLookupEvent): Source DNS event.
        flow_context (ZeekFlowContext): Shared flow context.
        sequence_order (int): Deterministic source event sequence order.

    Returns:
        dict[str, Any]: Zeek conn.log record.
    """
    response_size = 120 + 16 * len(event.resolved_addresses or ())

    return _conn_record(
        event=event,
        flow_context=flow_context,
        timestamp=event.timestamp,
        duration=0.025,
        service="dns",
        orig_bytes=_authored_or_default(flow_context.orig_bytes, 78),
        resp_bytes=_authored_or_default(flow_context.resp_bytes, response_size),
        history="Dd",
        orig_pkts=_authored_or_default(flow_context.orig_pkts, 1),
        resp_pkts=_authored_or_default(flow_context.resp_pkts, 1),
        ip_header_bytes=28,
        sequence_order=sequence_order,
    )


def _connection_record(
    event: NetworkConnectionEvent,
    flow_context: ZeekFlowContext,
    web_requests: tuple[WebRequestEvent, ...],
    sequence_order: int,
) -> dict[str, Any]:
    """
    Build a Zeek conn.log record for a source-neutral connection event.

    Args:
        event (NetworkConnectionEvent): Source connection event.
        flow_context (ZeekFlowContext): Shared flow context.
        web_requests (tuple[WebRequestEvent, ...]): HTTP requests that reuse the connection.
        sequence_order (int): Deterministic source event sequence order.

    Returns:
        dict[str, Any]: Zeek conn.log record.
    """
    return _web_flow_conn_record(
        event=event,
        flow_context=flow_context,
        web_requests=web_requests,
        timestamp=event.timestamp,
        sequence_order=sequence_order,
    )


def _http_sibling_conn_record(
    event: WebRequestEvent,
    flow_context: ZeekFlowContext,
    web_requests: tuple[WebRequestEvent, ...],
    sequence_order: int,
) -> dict[str, Any]:
    """
    Build a Zeek conn.log sibling record for HTTP events without a connection event.

    Args:
        event (WebRequestEvent): Source HTTP event that needs a sibling connection record.
        flow_context (ZeekFlowContext): Shared flow context.
        web_requests (tuple[WebRequestEvent, ...]): HTTP requests sharing the synthesized connection.
        sequence_order (int): Deterministic source event sequence order.

    Returns:
        dict[str, Any]: Zeek conn.log record.
    """
    return _web_flow_conn_record(
        event=event,
        flow_context=flow_context,
        web_requests=web_requests,
        timestamp=flow_context.timestamp,
        sequence_order=sequence_order,
    )


def _web_flow_conn_record(
    event: SourceNeutralEvent,
    flow_context: ZeekFlowContext,
    web_requests: tuple[WebRequestEvent, ...],
    timestamp: datetime,
    sequence_order: int,
) -> dict[str, Any]:
    """
    Build a Zeek conn.log record for a TCP flow carrying zero or more HTTP requests.

    Args:
        event (SourceNeutralEvent): Source event responsible for the connection row.
        flow_context (ZeekFlowContext): Shared flow context.
        web_requests (tuple[WebRequestEvent, ...]): HTTP requests that reuse the connection.
        timestamp (datetime): Connection start timestamp.
        sequence_order (int): Deterministic source event sequence order.

    Returns:
        dict[str, Any]: Zeek conn.log record.
    """
    if web_requests:
        last_request_time = max(web_request.timestamp for web_request in web_requests)
        duration = max((last_request_time - timestamp).total_seconds() + 0.05, 0.001)
        orig_bytes = sum(_http_request_size(web_request) for web_request in web_requests)
        resp_bytes = sum(_http_response_size(web_request) for web_request in web_requests)
    else:
        duration = 0.050
        orig_bytes = 60
        resp_bytes = 60

    return _conn_record(
        event=event,
        flow_context=flow_context,
        timestamp=timestamp,
        duration=duration,
        service=flow_context.application_protocol,
        orig_bytes=_authored_or_default(flow_context.orig_bytes, orig_bytes),
        resp_bytes=_authored_or_default(flow_context.resp_bytes, resp_bytes),
        history="ShADadFf",
        orig_pkts=_authored_or_default(flow_context.orig_pkts, max(1, ceil(orig_bytes / 1200))),
        resp_pkts=_authored_or_default(flow_context.resp_pkts, max(1, ceil(resp_bytes / 1200))),
        ip_header_bytes=40,
        sequence_order=sequence_order,
    )


def _conn_record(
    event: SourceNeutralEvent,
    flow_context: ZeekFlowContext,
    timestamp: datetime,
    duration: float,
    service: str,
    orig_bytes: int,
    resp_bytes: int,
    history: str,
    orig_pkts: int,
    resp_pkts: int,
    ip_header_bytes: int,
    sequence_order: int,
) -> dict[str, Any]:
    """
    Build a Zeek conn.log record from normalized flow facts.

    Args:
        event (SourceNeutralEvent): Source event that caused the connection record.
        flow_context (ZeekFlowContext): Shared flow context.
        timestamp (datetime): Zeek record timestamp.
        duration (float): Connection duration in seconds.
        service (str): Zeek service value.
        orig_bytes (int): Originator payload bytes.
        resp_bytes (int): Responder payload bytes.
        history (str): Zeek history value.
        orig_pkts (int): Originator packet count.
        resp_pkts (int): Responder packet count.
        ip_header_bytes (int): Per-packet network and transport header estimate.
        sequence_order (int): Deterministic source event sequence order.

    Returns:
        dict[str, Any]: Zeek conn.log record.
    """
    return {
        "_scenario_id": event.scenario_id,
        "_event_type": event.event_type,
        "_sequence_order": sequence_order,
        "ts": timestamp,
        "uid": flow_context.uid,
        "id.orig_h": flow_context.source_ip,
        "id.orig_p": flow_context.source_port,
        "id.resp_h": flow_context.destination_ip,
        "id.resp_p": flow_context.destination_port,
        "proto": flow_context.network_protocol,
        "service": service,
        "duration": duration,
        "orig_bytes": orig_bytes,
        "resp_bytes": resp_bytes,
        "conn_state": "SF",
        "local_orig": True,
        "local_resp": True,
        "missed_bytes": 0,
        "history": history,
        "orig_pkts": orig_pkts,
        "orig_ip_bytes": orig_bytes + orig_pkts * ip_header_bytes,
        "resp_pkts": resp_pkts,
        "resp_ip_bytes": resp_bytes + resp_pkts * ip_header_bytes,
        "tunnel_parents": [],
        "ip_proto": _ip_protocol_number(flow_context.network_protocol),
    }


def _dns_record(
    event: DnsLookupEvent,
    flow_context: ZeekFlowContext,
    sequence_order: int,
) -> dict[str, Any]:
    """
    Build a Zeek dns.log record from a source-neutral DNS lookup.

    Args:
        event (DnsLookupEvent): Source DNS event.
        flow_context (ZeekFlowContext): Shared flow context.
        sequence_order (int): Deterministic source event sequence order.

    Returns:
        dict[str, Any]: Zeek dns.log record.
    """
    rcode_name = (event.rcode or "NOERROR").upper()
    answers = event.resolved_addresses or []
    dns = event.dns
    flags = dns.flags if dns is not None and dns.flags is not None else {}
    trans_id = _authored_or_default(
        getattr(dns, "trans_id", None),
        _stable_count(event.scenario_id, event.event_id, modulo=65536),
    )

    return {
        "_scenario_id": event.scenario_id,
        "_event_type": event.event_type,
        "_sequence_order": sequence_order,
        "ts": event.timestamp,
        "uid": flow_context.uid,
        "id.orig_h": flow_context.source_ip,
        "id.orig_p": flow_context.source_port,
        "id.resp_h": flow_context.destination_ip,
        "id.resp_p": flow_context.destination_port,
        "proto": flow_context.network_protocol,
        "trans_id": trans_id,
        "rtt": _authored_or_default(getattr(dns, "rtt", None), 0.025),
        "query": event.query_name,
        "qclass": 1,
        "qclass_name": "C_INTERNET",
        "qtype": _dns_query_type_number(event.query_type),
        "qtype_name": event.query_type.upper(),
        "rcode": _dns_rcode_number(rcode_name),
        "rcode_name": rcode_name,
        "AA": flags.get("AA", False),
        "TC": flags.get("TC", False),
        "RD": flags.get("RD", True),
        "RA": flags.get("RA", True),
        "Z": 0,
        "answers": answers,
        "TTLs": _dns_ttls(event, answers),
        "rejected": event.status != "success" or rcode_name not in {"NOERROR", "NXDOMAIN"},
    }


def _http_record(
    event: WebRequestEvent,
    flow_context: ZeekFlowContext,
    environment: Environment,
    trans_depth: int,
    sequence_order: int,
) -> dict[str, Any]:
    """
    Build a Zeek http.log record from a source-neutral web request.

    Args:
        event (WebRequestEvent): Source HTTP request event.
        flow_context (ZeekFlowContext): Shared flow context.
        environment (Environment): Environment used to resolve service names.
        trans_depth (int): HTTP transaction depth for the connection.
        sequence_order (int): Deterministic source event sequence order.

    Returns:
        dict[str, Any]: Zeek http.log record.
    """
    service = environment.require_service(event.service_id)
    response_file_name = _response_file_name(event)
    response_mime_type = _response_mime_type(event, response_file_name)
    response_file_id = None
    http = event.http

    if response_file_name is not None:
        response_file_id = "F" + sha1(f"{event.scenario_id}:{event.event_id}:file".encode("utf-8")).hexdigest()[:10]

    return {
        "_scenario_id": event.scenario_id,
        "_event_type": event.event_type,
        "_sequence_order": sequence_order,
        "ts": event.timestamp,
        "uid": flow_context.uid,
        "id.orig_h": flow_context.source_ip,
        "id.orig_p": flow_context.source_port,
        "id.resp_h": flow_context.destination_ip,
        "id.resp_p": flow_context.destination_port,
        "trans_depth": trans_depth,
        "method": event.method,
        "host": service.names[0],
        "uri": _http_uri(event),
        "referrer": _header_value(event, "referer"),
        "version": _authored_or_default(getattr(http, "version", None), "1.1"),
        "user_agent": _authored_or_default(
            getattr(http, "user_agent", None),
            _header_value(event, "user-agent") or "Mozilla/5.0 log-generator/0.1",
        ),
        "request_body_len": 0,
        "response_body_len": _http_response_size(event),
        "status_code": event.status_code,
        "status_msg": _http_status_message(event.status_code),
        "tags": [],
        "resp_fuids": [response_file_id] if response_file_id is not None else None,
        "resp_filenames": [response_file_name] if response_file_name is not None else None,
        "resp_mime_types": [response_mime_type] if response_mime_type is not None else None,
    }


def _environment_for_scenario(scenario: Scenario) -> Environment:
    """
    Return the built-in environment supported by the Phase 3 Zeek writer.

    Args:
        scenario (Scenario): Scenario requesting Zeek output.

    Returns:
        Environment: Matching environment definition.
    """
    if scenario.environment_id != "linux-mini-lab":
        raise ValueError("Zeek output currently supports only the linux-mini-lab environment")

    environment = build_linux_mini_lab()

    if scenario.environment_version != environment.version:
        raise ValueError("Zeek output currently supports linux-mini-lab version 0.1")

    return environment


def _service_for_event(environment: Environment, event: SourceNeutralEvent, default_service_id: str) -> Service:
    """
    Resolve an event service with a deterministic fallback.

    Args:
        environment (Environment): Environment containing services.
        event (SourceNeutralEvent): Event that may carry a service ID.
        default_service_id (str): Service ID to use when the event omits one.

    Returns:
        Service: Resolved service.
    """
    service_id = getattr(event, "service_id", None) or default_service_id

    return environment.require_service(service_id)


def _flow_is_visible(environment: Environment, flow_context: ZeekFlowContext) -> bool:
    """
    Return whether zeek-sensor-01 can observe a flow.

    Args:
        environment (Environment): Environment containing host zones and visibility rules.
        flow_context (ZeekFlowContext): Flow context to evaluate.

    Returns:
        bool: True when the Phase 3 Zeek sensor should emit records for the flow.
    """
    source_host = environment.get_host(flow_context.source_host_id)
    destination_host = environment.get_host(flow_context.destination_host_id)

    if source_host is None or destination_host is None:
        return False

    for visibility in environment.sensor_visibility:
        if visibility.sensor_id != ZEEK_SENSOR_ID:
            continue

        if visibility.source_zone_id != source_host.zone_id:
            continue

        if visibility.destination_zone_id in {destination_host.zone_id, "any"}:
            return visibility.visible

    return False


def _web_requests_for_connection(
    events: Iterable[SourceNeutralEvent],
    connection_event_id: str,
) -> tuple[WebRequestEvent, ...]:
    """
    Return web requests that reuse a connection event.

    Args:
        events (Iterable[SourceNeutralEvent]): Events to inspect.
        connection_event_id (str): Parent connection event ID.

    Returns:
        tuple[WebRequestEvent, ...]: Matching web requests.
    """
    web_requests = []

    for event in events:
        if isinstance(event, WebRequestEvent) and event.parent_event_id == connection_event_id:
            web_requests.append(event)

    return tuple(sorted(web_requests, key=lambda web_request: web_request.timestamp))


def _web_requests_by_http_flow_key(
    ordered_scenario_events: tuple[ScenarioEvent, ...],
    events_by_id: Mapping[str, SourceNeutralEvent],
) -> dict[str, tuple[WebRequestEvent, ...]]:
    """
    Group HTTP requests by the Zeek flow that will carry them.

    Args:
        ordered_scenario_events (tuple[ScenarioEvent, ...]): Scenario events in deterministic order.
        events_by_id (Mapping[str, SourceNeutralEvent]): Events keyed by source-neutral event ID.

    Returns:
        dict[str, tuple[WebRequestEvent, ...]]: HTTP requests grouped by deterministic flow key.
    """
    grouped_requests: dict[str, list[WebRequestEvent]] = {}

    for scenario_event in ordered_scenario_events:
        event = scenario_event.event

        if not isinstance(event, WebRequestEvent):
            continue

        flow_key = _http_flow_key(event, events_by_id)
        grouped_requests.setdefault(flow_key, []).append(event)

    return {flow_key: tuple(web_requests) for flow_key, web_requests in grouped_requests.items()}


def _web_request_uses_connection_event(
    event: WebRequestEvent,
    events_by_id: Mapping[str, SourceNeutralEvent],
) -> bool:
    """
    Return whether an HTTP event is backed by an explicit source-neutral connection event.

    Args:
        event (WebRequestEvent): HTTP event to inspect.
        events_by_id (Mapping[str, SourceNeutralEvent]): Events keyed by source-neutral event ID.

    Returns:
        bool: True when the HTTP event's parent is a network connection event.
    """
    if event.parent_event_id is None:
        return False

    return isinstance(events_by_id.get(event.parent_event_id), NetworkConnectionEvent)


def _dns_flow_key(event: DnsLookupEvent) -> str:
    """
    Return the deterministic flow key for a DNS event.

    Args:
        event (DnsLookupEvent): DNS event to key.

    Returns:
        str: Flow key.
    """
    return f"dns:{event.event_id}"


def _connection_flow_key(event: NetworkConnectionEvent) -> str:
    """
    Return the deterministic flow key for a connection event.

    Args:
        event (NetworkConnectionEvent): Connection event to key.

    Returns:
        str: Flow key.
    """
    return f"conn:{event.event_id}"


def _http_flow_key(
    event: WebRequestEvent,
    events_by_id: Mapping[str, SourceNeutralEvent],
) -> str:
    """
    Return the deterministic flow key for an HTTP event.

    Args:
        event (WebRequestEvent): HTTP event to key.
        events_by_id (Mapping[str, SourceNeutralEvent]): Events keyed by source-neutral event ID.

    Returns:
        str: Flow key.
    """
    if _web_request_uses_connection_event(event, events_by_id):
        return _http_connection_flow_key(str(event.parent_event_id))

    return _http_standalone_flow_key(event)


def _http_connection_flow_key(connection_event_id: str) -> str:
    """
    Return the HTTP flow key for requests backed by a connection event.

    Args:
        connection_event_id (str): Source-neutral connection event ID.

    Returns:
        str: Flow key.
    """
    return f"http:connection:{connection_event_id}"


def _http_standalone_flow_key(event: WebRequestEvent) -> str:
    """
    Return the HTTP flow key for a request that needs a synthesized connection.

    Args:
        event (WebRequestEvent): HTTP event to key.

    Returns:
        str: Flow key.
    """
    return f"http:standalone:{event.event_id}"


def _record_sequence_order(record: Mapping[str, Any]) -> int:
    """
    Return the deterministic sequence order carried by a generated Zeek record.

    Args:
        record (Mapping[str, Any]): Zeek record to inspect.

    Returns:
        int: Source-neutral scenario sequence order, or zero for legacy caller-built records.
    """
    sequence_order = record.get("_sequence_order", 0)

    if is_integer(sequence_order):
        return int(sequence_order)

    return 0


def _stable_zeek_uid(scenario: Scenario, key: str) -> str:
    """
    Derive a stable Zeek UID from scenario and flow identity.

    Args:
        scenario (Scenario): Scenario owning the flow.
        key (str): Flow-specific key.

    Returns:
        str: Zeek-safe connection UID.
    """
    return "C" + sha1(f"{scenario.id}:{scenario.seed}:{key}".encode("utf-8")).hexdigest()[:11]


def _stable_client_port(scenario: Scenario, key: str) -> int:
    """
    Derive a stable ephemeral client source port for a flow.

    Args:
        scenario (Scenario): Scenario owning the flow.
        key (str): Flow-specific key.

    Returns:
        int: TCP/UDP source port in the ephemeral range.
    """
    return 49152 + _stable_count(scenario.id, f"{scenario.seed}:{key}", modulo=16384)


def _context_source_port(network: Any, scenario: Scenario, key: str) -> int:
    """
    Return an authored source port or the deterministic flow default.

    Args:
        network (Any): Optional source-neutral network context.
        scenario (Scenario): Scenario owning the flow.
        key (str): Flow-specific key.

    Returns:
        int: Source port for the flow.
    """
    source_port = _context_count(network, "source_port")

    if source_port is not None:
        return source_port

    return _stable_client_port(scenario, key)


def _context_count(context: Any, field_name: str) -> Optional[int]:
    """
    Return an optional integer field from a source-neutral context object.

    Args:
        context (Any): Optional context object.
        field_name (str): Field name to read.

    Returns:
        Optional[int]: Context value when present.
    """
    if context is None:
        return None

    return getattr(context, field_name, None)


def _authored_or_default(authored_value: Any, default_value: Any) -> Any:
    """
    Return an authored override when present, otherwise a deterministic default.

    Args:
        authored_value (Any): Optional authored value.
        default_value (Any): Default value to use when the authored value is omitted.

    Returns:
        Any: Authored value or default value.
    """
    if authored_value is not None:
        return authored_value

    return default_value


def _stable_count(scenario_id: str, key: str, modulo: int) -> int:
    """
    Derive a stable non-negative integer below a modulo.

    Args:
        scenario_id (str): Scenario identifier.
        key (str): Value-specific key.
        modulo (int): Exclusive upper bound.

    Returns:
        int: Deterministic count value.
    """
    digest = sha1(f"{scenario_id}:{key}".encode("utf-8")).hexdigest()

    return int(digest[:8], 16) % modulo


def _ip_protocol_number(network_protocol: str) -> int:
    """
    Return the IP protocol number for a transport protocol.

    Args:
        network_protocol (str): Transport protocol name.

    Returns:
        int: IP protocol number.
    """
    if network_protocol.lower() == "udp":
        return 17

    if network_protocol.lower() == "tcp":
        return 6

    return 0


def _dns_query_type_number(query_type: str) -> int:
    """
    Return the DNS query type number for common query types.

    Args:
        query_type (str): DNS query type name.

    Returns:
        int: DNS query type number.
    """
    query_types = {
        "A": 1,
        "NS": 2,
        "CNAME": 5,
        "SOA": 6,
        "PTR": 12,
        "MX": 15,
        "TXT": 16,
        "AAAA": 28,
    }

    return query_types.get(query_type.upper(), 1)


def _dns_rcode_number(rcode_name: str) -> int:
    """
    Return the DNS response code number for common response names.

    Args:
        rcode_name (str): DNS response code name.

    Returns:
        int: DNS response code number.
    """
    rcodes = {
        "NOERROR": 0,
        "FORMERR": 1,
        "SERVFAIL": 2,
        "NXDOMAIN": 3,
        "NOTIMP": 4,
        "REFUSED": 5,
    }

    return rcodes.get(rcode_name.upper(), 0)


def _dns_ttls(event: DnsLookupEvent, answers: list[str]) -> list[float]:
    """
    Return authored DNS TTLs or deterministic defaults for each answer.

    Args:
        event (DnsLookupEvent): DNS event to inspect.
        answers (list[str]): DNS answers emitted for the event.

    Returns:
        list[float]: TTL values for Zeek dns.log.
    """
    if event.dns is not None and event.dns.ttls is not None:
        return list(event.dns.ttls)

    return [300.0 for _ in answers]


def _http_uri(event: WebRequestEvent) -> str:
    """
    Build the HTTP URI value from path and optional query string.

    Args:
        event (WebRequestEvent): HTTP event to inspect.

    Returns:
        str: URI value for Zeek http.log.
    """
    if event.query_string:
        return f"{event.path}?{event.query_string}"

    return event.path


def _header_value(event: WebRequestEvent, header_name: str) -> Optional[str]:
    """
    Return a request header by case-insensitive name.

    Args:
        event (WebRequestEvent): HTTP event to inspect.
        header_name (str): Header name to read.

    Returns:
        Optional[str]: Header value when present.
    """
    if event.request_headers is None:
        return None

    normalized_header_name = header_name.lower()

    for key, value in event.request_headers.items():
        if key.lower() == normalized_header_name:
            return value

    return None


def _http_request_size(event: WebRequestEvent) -> int:
    """
    Estimate HTTP request bytes deterministically from request fields.

    Args:
        event (WebRequestEvent): HTTP event to inspect.

    Returns:
        int: Estimated request payload bytes.
    """
    header_size = 120

    if event.request_headers:
        header_size += sum(len(name) + len(value) + 4 for name, value in event.request_headers.items())

    return header_size + len(event.method) + len(_http_uri(event))


def _http_response_size(event: WebRequestEvent) -> int:
    """
    Estimate HTTP response body bytes from status and route metadata.

    Args:
        event (WebRequestEvent): HTTP event to inspect.

    Returns:
        int: Estimated response body bytes.
    """
    if event.http is not None and event.http.response_body_len is not None:
        return event.http.response_body_len

    metadata = event.metadata or {}

    if "response_body_len" in metadata:
        return int(metadata["response_body_len"])

    if metadata.get("download_classification") == "download":
        return 32768

    if event.status_code == 403:
        return 512

    if event.status_code == 404:
        return 384

    return 2048


def _response_file_name(event: WebRequestEvent) -> Optional[str]:
    """
    Return the downloaded response file name when the event represents a download.

    Args:
        event (WebRequestEvent): HTTP event to inspect.

    Returns:
        Optional[str]: File name when available.
    """
    metadata = event.metadata or {}
    file_name = metadata.get("file_name")

    if isinstance(file_name, str) and file_name:
        return file_name

    return None


def _response_mime_type(event: WebRequestEvent, file_name: Optional[str]) -> Optional[str]:
    """
    Return a deterministic response MIME type for http.log file metadata.

    Args:
        event (WebRequestEvent): HTTP event to inspect.
        file_name (Optional[str]): Download file name, when present.

    Returns:
        Optional[str]: MIME type when file metadata should be emitted.
    """
    if event.http is not None and event.http.response_content_type:
        return event.http.response_content_type

    if event.response_content_type:
        return event.response_content_type

    if file_name is None:
        return None

    if file_name.endswith(".tar.gz") or file_name.endswith(".tgz"):
        return "application/gzip"

    return "application/octet-stream"


def _http_status_message(status_code: int) -> str:
    """
    Return a common HTTP status message.

    Args:
        status_code (int): HTTP status code.

    Returns:
        str: HTTP status message.
    """
    status_messages = {
        200: "OK",
        201: "Created",
        204: "No Content",
        301: "Moved Permanently",
        302: "Found",
        400: "Bad Request",
        401: "Unauthorized",
        403: "Forbidden",
        404: "Not Found",
        500: "Internal Server Error",
        502: "Bad Gateway",
        503: "Service Unavailable",
    }

    return status_messages.get(status_code, "Unknown")


def _scenario_ids_for_records(records: list[dict[str, Any]]) -> tuple[str, ...]:
    """
    Return first-seen scenario IDs for a set of Zeek records.

    Args:
        records (list[dict[str, Any]]): Zeek records to inspect.

    Returns:
        tuple[str, ...]: Scenario IDs.
    """
    scenario_ids = []

    for record in records:
        scenario_id = str(record["_scenario_id"])
        if scenario_id not in scenario_ids:
            scenario_ids.append(scenario_id)

    return tuple(scenario_ids)


def _zeek_record_sort_key(record: Mapping[str, Any]) -> tuple[Any, int, str]:
    """
    Return deterministic ordering for Zeek records.

    Args:
        record (Mapping[str, Any]): Zeek record to sort.

    Returns:
        tuple[Any, int, str]: Timestamp followed by sequence order and UID fallback.
    """
    return record["ts"], _record_sequence_order(record), str(record["uid"])


def render_zeek_header(stream_name: str, opened_at: datetime) -> str:
    """
    Render the native Zeek TSV header rows for a stream.

    Args:
        stream_name (str): Zeek stream path such as ``conn``, ``dns``, or ``http``.
        opened_at (datetime): Deterministic wall-clock time for the ``#open`` row.

    Returns:
        str: Header rows ending with a newline.
    """
    return "\n".join(build_zeek_header_lines(stream_name, opened_at)) + "\n"


def build_zeek_header_lines(stream_name: str, opened_at: datetime) -> tuple[str, ...]:
    """
    Build the native Zeek TSV header rows for a stream.

    Args:
        stream_name (str): Zeek stream path such as ``conn``, ``dns``, or ``http``.
        opened_at (datetime): Deterministic wall-clock time for the ``#open`` row.

    Returns:
        tuple[str, ...]: Header rows without trailing newline characters.
    """
    schema = schema_for_stream(stream_name)
    field_names = zeek_schema_field_names(schema)
    field_types = zeek_schema_field_types(schema)

    return (
        f"#separator {ZEEK_SEPARATOR_DIRECTIVE}",
        f"#set_separator{ZEEK_FIELD_SEPARATOR}{ZEEK_SET_SEPARATOR}",
        f"#empty_field{ZEEK_FIELD_SEPARATOR}{ZEEK_EMPTY_FIELD}",
        f"#unset_field{ZEEK_FIELD_SEPARATOR}{ZEEK_UNSET_FIELD}",
        f"#path{ZEEK_FIELD_SEPARATOR}{schema.path}",
        f"#open{ZEEK_FIELD_SEPARATOR}{format_zeek_header_time(opened_at)}",
        f"#fields{ZEEK_FIELD_SEPARATOR}{ZEEK_FIELD_SEPARATOR.join(field_names)}",
        f"#types{ZEEK_FIELD_SEPARATOR}{ZEEK_FIELD_SEPARATOR.join(field_types)}",
    )


def render_zeek_close(closed_at: datetime) -> str:
    """
    Render the native Zeek TSV close row.

    Args:
        closed_at (datetime): Deterministic wall-clock time for the ``#close`` row.

    Returns:
        str: Zeek ``#close`` row without a trailing newline.
    """
    return f"#close{ZEEK_FIELD_SEPARATOR}{format_zeek_header_time(closed_at)}"


def render_zeek_record(stream_name: str, record: Mapping[str, Any]) -> str:
    """
    Render one Zeek record in schema field order.

    Args:
        stream_name (str): Zeek stream path such as ``conn``, ``dns``, or ``http``.
        record (Mapping[str, Any]): Record keyed by Zeek field name.

    Returns:
        str: TSV row without a trailing newline.
    """
    schema = schema_for_stream(stream_name)
    values = []

    for field in schema.fields:
        values.append(render_zeek_value(record.get(field.name), field.zeek_type))

    return ZEEK_FIELD_SEPARATOR.join(values)


def render_zeek_value(value: Any, zeek_type: str) -> str:
    """
    Render a Python value according to a Zeek TSV type.

    Args:
        value (Any): Python value to render.
        zeek_type (str): Zeek type such as ``time``, ``string``, ``set[string]``, or ``vector[interval]``.

    Returns:
        str: Zeek TSV field text.
    """
    if zeek_type.startswith("set["):
        return render_zeek_set(value, _collection_inner_type(zeek_type, "set"))

    if zeek_type.startswith("vector["):
        return render_zeek_vector(value, _collection_inner_type(zeek_type, "vector"))

    if value is None:
        return render_zeek_unset()

    if zeek_type == "time":
        return format_zeek_timestamp(value)

    if zeek_type == "interval":
        return render_zeek_interval(value)

    if zeek_type == "bool":
        return render_zeek_bool(value)

    if zeek_type == "count":
        return render_zeek_count(value)

    if zeek_type == "port":
        return render_zeek_port(value)

    if zeek_type in {"addr", "enum", "string"}:
        return render_zeek_string(value)

    raise ValueError(f"unsupported Zeek type '{zeek_type}'")


def render_zeek_unset() -> str:
    """
    Render Zeek's unset-field marker.

    Returns:
        str: Zeek unset-field marker.
    """
    return ZEEK_UNSET_FIELD


def render_zeek_empty() -> str:
    """
    Render Zeek's empty-field marker.

    Returns:
        str: Zeek empty-field marker.
    """
    return ZEEK_EMPTY_FIELD


def render_zeek_bool(value: Optional[bool]) -> str:
    """
    Render a Zeek boolean value.

    Args:
        value (Optional[bool]): Boolean value to render, or None for unset.

    Returns:
        str: ``T``, ``F``, or the unset marker.
    """
    if value is None:
        return render_zeek_unset()

    if not isinstance(value, bool):
        raise ValueError(f"expected bool for Zeek bool field, got {type(value).__name__}")

    if value:
        return "T"

    return "F"


def render_zeek_count(value: Optional[int]) -> str:
    """
    Render a non-negative Zeek count value.

    Args:
        value (Optional[int]): Count value to render, or None for unset.

    Returns:
        str: Decimal count text or the unset marker.
    """
    if value is None:
        return render_zeek_unset()

    if not is_integer(value):
        raise ValueError(f"expected integer for Zeek count field, got {type(value).__name__}")

    if not is_non_negative_integer(value):
        raise ValueError("Zeek count fields must be non-negative")

    return str(value)


def render_zeek_port(value: Optional[int]) -> str:
    """
    Render a Zeek port value.

    Args:
        value (Optional[int]): Port value to render, or None for unset.

    Returns:
        str: Decimal port text or the unset marker.
    """
    if value is None:
        return render_zeek_unset()

    count_value = render_zeek_count(value)

    if not is_port_number(value):
        raise ValueError("Zeek port fields must be between 0 and 65535")

    return count_value


def render_zeek_interval(value: Any) -> str:
    """
    Render a Zeek interval value as seconds with six fractional digits.

    Args:
        value (Any): ``timedelta`` or numeric seconds value to render, or None for unset.

    Returns:
        str: Interval seconds text or the unset marker.
    """
    if value is None:
        return render_zeek_unset()

    if isinstance(value, timedelta):
        seconds = value.total_seconds()
    elif isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"expected timedelta or numeric seconds for Zeek interval, got {type(value).__name__}")
    else:
        seconds = float(value)

    if seconds < 0:
        raise ValueError("Zeek interval fields must be non-negative")

    return f"{seconds:.6f}"


def render_zeek_string(value: Optional[Any], reject_set_separator: bool = False) -> str:
    """
    Render a Zeek string-like value.

    Args:
        value (Optional[Any]): Value to render, or None for unset.
        reject_set_separator (bool): Whether to reject the configured set separator.

    Returns:
        str: Safe Zeek TSV string, empty marker, or unset marker.
    """
    if value is None:
        return render_zeek_unset()

    text = str(value)

    if text == "":
        return render_zeek_empty()

    _validate_safe_zeek_text(text, reject_set_separator=reject_set_separator)

    return text


def render_zeek_set(values: Optional[Iterable[Any]], element_type: str = "string") -> str:
    """
    Render a Zeek set value.

    Args:
        values (Optional[Iterable[Any]]): Set values to render, or None for unset.
        element_type (str): Zeek type for each set element.

    Returns:
        str: Set field text, empty marker, or unset marker.
    """
    if values is None:
        return render_zeek_unset()

    value_list = _coerce_collection_values(values, "set")

    if not value_list:
        return render_zeek_empty()

    rendered_values = [_render_collection_element(value, element_type) for value in value_list]

    return ZEEK_SET_SEPARATOR.join(sorted(rendered_values))


def render_zeek_vector(values: Optional[Iterable[Any]], element_type: str = "string") -> str:
    """
    Render a Zeek vector value.

    Args:
        values (Optional[Iterable[Any]]): Vector values to render, or None for unset.
        element_type (str): Zeek type for each vector element.

    Returns:
        str: Vector field text, empty marker, or unset marker.
    """
    if values is None:
        return render_zeek_unset()

    value_list = _coerce_collection_values(values, "vector")

    if not value_list:
        return render_zeek_empty()

    rendered_values = [_render_collection_element(value, element_type) for value in value_list]

    return ZEEK_SET_SEPARATOR.join(rendered_values)


def format_zeek_timestamp(value: Any) -> str:
    """
    Render a Zeek timestamp as epoch seconds with six fractional digits.

    Args:
        value (Any): Timezone-aware ``datetime`` or numeric epoch seconds.

    Returns:
        str: Epoch seconds with six fractional digits.
    """
    if isinstance(value, datetime):
        seconds = normalize_utc_timestamp(value).timestamp()
    elif isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"expected datetime or numeric epoch seconds for Zeek time, got {type(value).__name__}")
    else:
        seconds = float(value)

    return f"{seconds:.6f}"


def format_zeek_header_time(timestamp: datetime) -> str:
    """
    Render a Zeek header wall-clock timestamp.

    Args:
        timestamp (datetime): Timezone-aware timestamp to render.

    Returns:
        str: UTC wall-clock timestamp in Zeek header format.
    """
    return normalize_utc_timestamp(timestamp).strftime("%Y-%m-%d-%H-%M-%S")


def _collection_inner_type(zeek_type: str, expected_collection_type: str) -> str:
    """
    Return the inner type for a Zeek collection type.

    Args:
        zeek_type (str): Zeek collection type such as ``set[string]``.
        expected_collection_type (str): Expected collection prefix.

    Returns:
        str: Inner Zeek element type.
    """
    prefix = f"{expected_collection_type}["

    if not zeek_type.startswith(prefix) or not zeek_type.endswith("]"):
        raise ValueError(f"expected Zeek {expected_collection_type} type, got '{zeek_type}'")

    inner_type = zeek_type[len(prefix):-1]

    if not inner_type:
        raise ValueError(f"Zeek {expected_collection_type} type must include an inner type")

    return inner_type


def _coerce_collection_values(values: Iterable[Any], collection_name: str) -> list[Any]:
    """
    Convert collection values into a list while rejecting scalar strings.

    Args:
        values (Iterable[Any]): Candidate collection values.
        collection_name (str): Human-readable collection name for validation errors.

    Returns:
        list[Any]: Collection values as a list.
    """
    if isinstance(values, (str, bytes)):
        raise ValueError(f"Zeek {collection_name} fields require an iterable of elements, not a scalar string")

    return list(values)


def _render_collection_element(value: Any, element_type: str) -> str:
    """
    Render one Zeek collection element.

    Args:
        value (Any): Collection element value.
        element_type (str): Zeek type for the element.

    Returns:
        str: Safe collection element text.
    """
    if value is None:
        raise ValueError("Zeek collection elements must not be unset")

    if element_type in {"addr", "enum", "string"}:
        return render_zeek_string(value, reject_set_separator=True)

    rendered_value = render_zeek_value(value, element_type)
    _validate_safe_zeek_text(rendered_value, reject_set_separator=True)

    if rendered_value in {ZEEK_EMPTY_FIELD, ZEEK_UNSET_FIELD}:
        raise ValueError("Zeek collection elements must be concrete values")

    return rendered_value


def _validate_safe_zeek_text(text: str, reject_set_separator: bool = False) -> None:
    """
    Validate text can be represented safely in the configured Zeek TSV format.

    Args:
        text (str): Candidate text value.
        reject_set_separator (bool): Whether to reject the configured set separator.

    Returns:
        None: Raises ValueError when the text is unsafe.
    """
    if any(character in text for character in (ZEEK_FIELD_SEPARATOR, "\n", "\r")):
        raise ValueError("Zeek TSV values must not contain tabs or newlines")

    if reject_set_separator and ZEEK_SET_SEPARATOR in text:
        raise ValueError("Zeek collection elements must not contain the set separator")


__all__ = [
    "ZEEK_EMPTY_FIELD",
    "ZEEK_FIELD_SEPARATOR",
    "ZEEK_SEPARATOR_DIRECTIVE",
    "ZEEK_SET_SEPARATOR",
    "ZEEK_SENSOR_ID",
    "ZEEK_STREAM_SCHEMAS",
    "ZEEK_STREAM_FILE_NAMES",
    "ZEEK_UNSET_FIELD",
    "ZeekFlowContext",
    "ZeekField",
    "ZeekOmittedStream",
    "ZeekStreamSchema",
    "ZeekWriteResult",
    "ZeekWrittenFile",
    "build_zeek_header_lines",
    "build_zeek_records",
    "format_zeek_header_time",
    "format_zeek_timestamp",
    "render_zeek_bool",
    "render_zeek_close",
    "render_zeek_count",
    "render_zeek_empty",
    "render_zeek_header",
    "render_zeek_interval",
    "render_zeek_log",
    "render_zeek_port",
    "render_zeek_record",
    "render_zeek_set",
    "render_zeek_string",
    "render_zeek_unset",
    "render_zeek_value",
    "render_zeek_vector",
    "schema_for_stream",
    "write_zeek_logs",
    "zeek_schema_field_names",
    "zeek_schema_field_types",
]
