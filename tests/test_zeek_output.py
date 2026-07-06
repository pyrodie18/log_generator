"""
Tests for Zeek native TSV schema and rendering helpers.
"""

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from log_generator.core.scenarios import (
    Scenario,
    ScenarioEvent,
    build_benign_internal_web_scenario,
    build_local_account_misuse_web_scenario,
)
from log_generator.core.events import DnsLookupEvent, LinuxLocalLoginEvent, NetworkConnectionEvent, WebRequestEvent
from log_generator.scenario_yaml import build_scenario_from_yaml_text
from log_generator.output.zeek import (
    ZEEK_EMPTY_FIELD,
    ZEEK_UNSET_FIELD,
    build_zeek_header_lines,
    format_zeek_header_time,
    format_zeek_timestamp,
    render_zeek_bool,
    render_zeek_interval,
    render_zeek_log,
    render_zeek_record,
    render_zeek_set,
    render_zeek_string,
    render_zeek_value,
    render_zeek_vector,
    schema_for_stream,
    write_zeek_logs,
    zeek_schema_field_names,
    zeek_schema_field_types,
)
from support import read_zeek_records


def test_zeek_conn_schema_matches_minimum_field_target() -> None:
    """
    Verify the conn stream schema matches the Phase 3 minimum field target.

    Returns:
        None: This test asserts schema fields and types directly.
    """
    schema = schema_for_stream("conn")

    assert zeek_schema_field_names(schema) == (
        "ts",
        "uid",
        "id.orig_h",
        "id.orig_p",
        "id.resp_h",
        "id.resp_p",
        "proto",
        "service",
        "duration",
        "orig_bytes",
        "resp_bytes",
        "conn_state",
        "local_orig",
        "local_resp",
        "missed_bytes",
        "history",
        "orig_pkts",
        "orig_ip_bytes",
        "resp_pkts",
        "resp_ip_bytes",
        "tunnel_parents",
        "ip_proto",
    )
    assert zeek_schema_field_types(schema) == (
        "time",
        "string",
        "addr",
        "port",
        "addr",
        "port",
        "enum",
        "string",
        "interval",
        "count",
        "count",
        "string",
        "bool",
        "bool",
        "count",
        "string",
        "count",
        "count",
        "count",
        "count",
        "set[string]",
        "count",
    )


def test_zeek_dns_schema_matches_minimum_field_target() -> None:
    """
    Verify the dns stream schema matches the Phase 3 minimum field target.

    Returns:
        None: This test asserts schema fields and types directly.
    """
    schema = schema_for_stream("dns")

    assert zeek_schema_field_names(schema) == (
        "ts",
        "uid",
        "id.orig_h",
        "id.orig_p",
        "id.resp_h",
        "id.resp_p",
        "proto",
        "trans_id",
        "rtt",
        "query",
        "qclass",
        "qclass_name",
        "qtype",
        "qtype_name",
        "rcode",
        "rcode_name",
        "AA",
        "TC",
        "RD",
        "RA",
        "Z",
        "answers",
        "TTLs",
        "rejected",
    )
    assert zeek_schema_field_types(schema) == (
        "time",
        "string",
        "addr",
        "port",
        "addr",
        "port",
        "enum",
        "count",
        "interval",
        "string",
        "count",
        "string",
        "count",
        "string",
        "count",
        "string",
        "bool",
        "bool",
        "bool",
        "bool",
        "count",
        "vector[string]",
        "vector[interval]",
        "bool",
    )


def test_zeek_http_schema_matches_minimum_field_target() -> None:
    """
    Verify the http stream schema matches the Phase 3 minimum field target.

    Returns:
        None: This test asserts schema fields and types directly.
    """
    schema = schema_for_stream("http")

    assert zeek_schema_field_names(schema) == (
        "ts",
        "uid",
        "id.orig_h",
        "id.orig_p",
        "id.resp_h",
        "id.resp_p",
        "trans_depth",
        "method",
        "host",
        "uri",
        "referrer",
        "version",
        "user_agent",
        "request_body_len",
        "response_body_len",
        "status_code",
        "status_msg",
        "tags",
        "resp_fuids",
        "resp_filenames",
        "resp_mime_types",
    )
    assert zeek_schema_field_types(schema) == (
        "time",
        "string",
        "addr",
        "port",
        "addr",
        "port",
        "count",
        "string",
        "string",
        "string",
        "string",
        "string",
        "string",
        "count",
        "count",
        "count",
        "string",
        "set[string]",
        "vector[string]",
        "vector[string]",
        "vector[string]",
    )


def test_zeek_log_header_and_close_rows_are_native_tsv() -> None:
    """
    Verify native Zeek header rows and close rows render deterministically.

    Returns:
        None: This test asserts rendered log text directly.
    """
    generated_at = datetime(2026, 1, 15, 14, 0, 3, tzinfo=timezone.utc)
    rendered_log = render_zeek_log("conn", (), generated_at)
    lines = rendered_log.splitlines()

    assert lines[:8] == [
        "#separator \\x09",
        "#set_separator\t,",
        "#empty_field\t(empty)",
        "#unset_field\t-",
        "#path\tconn",
        "#open\t2026-01-15-14-00-03",
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\t"
        "orig_bytes\tresp_bytes\tconn_state\tlocal_orig\tlocal_resp\tmissed_bytes\thistory\torig_pkts\t"
        "orig_ip_bytes\tresp_pkts\tresp_ip_bytes\ttunnel_parents\tip_proto",
        "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tinterval\tcount\tcount\tstring\tbool\t"
        "bool\tcount\tstring\tcount\tcount\tcount\tcount\tset[string]\tcount",
    ]
    assert lines[-1] == "#close\t2026-01-15-14-00-03"
    assert rendered_log.endswith("\n")


@pytest.mark.parametrize("stream_name", ["conn", "dns", "http"])
def test_zeek_header_rows_use_schema_for_each_stream(stream_name: str) -> None:
    """
    Verify every supported stream starts with the expected native header block.

    Args:
        stream_name (str): Zeek stream to render.

    Returns:
        None: This test asserts rendered header rows directly.
    """
    generated_at = datetime(2026, 1, 15, 14, 0, 3, tzinfo=timezone.utc)
    schema = schema_for_stream(stream_name)
    lines = build_zeek_header_lines(stream_name, generated_at)

    assert lines[0] == "#separator \\x09"
    assert lines[4] == f"#path\t{stream_name}"
    assert lines[5] == "#open\t2026-01-15-14-00-03"
    assert lines[6] == "#fields\t" + "\t".join(zeek_schema_field_names(schema))
    assert lines[7] == "#types\t" + "\t".join(zeek_schema_field_types(schema))


def test_zeek_timestamp_and_header_time_rendering_are_deterministic() -> None:
    """
    Verify Zeek timestamp helpers use UTC and six fractional digits.

    Returns:
        None: This test asserts timestamp formatting directly.
    """
    timestamp = datetime(1970, 1, 1, 0, 0, 1, 123456, tzinfo=timezone.utc)
    offset_timestamp = datetime(2026, 1, 15, 9, 0, 3, tzinfo=timezone(timedelta(hours=-5)))

    assert format_zeek_timestamp(timestamp) == "1.123456"
    assert format_zeek_timestamp(1) == "1.000000"
    assert format_zeek_header_time(offset_timestamp) == "2026-01-15-14-00-03"


def test_zeek_scalar_render_helpers_cover_unset_empty_boolean_and_interval() -> None:
    """
    Verify scalar render helpers cover required Zeek TSV representations.

    Returns:
        None: This test asserts scalar value rendering directly.
    """
    assert render_zeek_value(None, "string") == ZEEK_UNSET_FIELD
    assert render_zeek_string("") == ZEEK_EMPTY_FIELD
    assert render_zeek_bool(True) == "T"
    assert render_zeek_bool(False) == "F"
    assert render_zeek_bool(None) == ZEEK_UNSET_FIELD
    assert render_zeek_interval(timedelta(milliseconds=25)) == "0.025000"
    assert render_zeek_interval(2.5) == "2.500000"


def test_zeek_set_and_vector_rendering_are_stable() -> None:
    """
    Verify Zeek collection helpers render empty and populated values.

    Returns:
        None: This test asserts collection rendering directly.
    """
    assert render_zeek_set([]) == ZEEK_EMPTY_FIELD
    assert render_zeek_set({"beta", "alpha"}) == "alpha,beta"
    assert render_zeek_vector(["first", "second"]) == "first,second"
    assert render_zeek_vector([timedelta(milliseconds=1), timedelta(milliseconds=2)], "interval") == (
        "0.001000,0.002000"
    )
    assert render_zeek_value(["10.10.20.10"], "vector[string]") == "10.10.20.10"


def test_zeek_record_rendering_uses_schema_order_and_unset_missing_fields() -> None:
    """
    Verify record rendering follows schema order and treats omitted fields as unset.

    Returns:
        None: This test asserts rendered record text directly.
    """
    timestamp = datetime(1970, 1, 1, 0, 0, 1, tzinfo=timezone.utc)
    row = render_zeek_record(
        "http",
        {
            "ts": timestamp,
            "uid": "CZ6XWv",
            "id.orig_h": "10.10.10.10",
            "id.orig_p": 49152,
            "id.resp_h": "10.10.20.20",
            "id.resp_p": 80,
            "trans_depth": 1,
            "method": "GET",
            "host": "web-server-01.internal",
            "uri": "/",
            "version": "1.1",
            "request_body_len": 0,
            "response_body_len": 128,
            "status_code": 200,
            "status_msg": "OK",
            "tags": [],
        },
    )

    assert row.split("\t") == [
        "1.000000",
        "CZ6XWv",
        "10.10.10.10",
        "49152",
        "10.10.20.20",
        "80",
        "1",
        "GET",
        "web-server-01.internal",
        "/",
        "-",
        "1.1",
        "-",
        "0",
        "128",
        "200",
        "OK",
        "(empty)",
        "-",
        "-",
        "-",
    ]


def test_zeek_rendering_rejects_unsafe_tsv_values() -> None:
    """
    Verify unsafe TSV and collection values fail before rendering ambiguous output.

    Returns:
        None: This test asserts validation failures directly.
    """
    with pytest.raises(ValueError, match="tabs or newlines"):
        render_zeek_string("bad\tvalue")

    with pytest.raises(ValueError, match="set separator"):
        render_zeek_set({"bad,value"})

    with pytest.raises(ValueError, match="non-negative"):
        render_zeek_value(-1, "count")

    with pytest.raises(ValueError, match="between 0 and 65535"):
        render_zeek_value(70000, "port")


def test_zeek_writer_generates_visible_benign_dns_and_http_streams(tmp_path: Path) -> None:
    """
    Verify the Zeek writer emits linked conn, dns, and http records for the benign web scenario.

    Args:
        tmp_path (Path): Pytest temporary output directory.

    Returns:
        None: This test asserts generated Zeek files and record relationships.
    """
    scenario = replace(
        build_benign_internal_web_scenario(),
        output_families=("generic-normalized", "zeek"),
    )
    generated_at = datetime(2026, 1, 15, 14, 0, 3, tzinfo=timezone.utc)

    result = write_zeek_logs(tmp_path, (scenario,), generated_at=generated_at)
    conn_records = read_zeek_records(tmp_path / "logs" / "zeek-sensor-01" / "zeek" / "conn.log")
    dns_records = read_zeek_records(tmp_path / "logs" / "zeek-sensor-01" / "zeek" / "dns.log")
    http_records = read_zeek_records(tmp_path / "logs" / "zeek-sensor-01" / "zeek" / "http.log")

    assert [zeek_file.stream_name for zeek_file in result.files] == ["conn", "dns", "http"]
    assert result.omitted_streams == ()
    assert len(conn_records) == 2
    assert len(dns_records) == 1
    assert len(http_records) == 1
    assert dns_records[0]["query"] == "web-server-01.internal"
    assert dns_records[0]["uid"] == conn_records[0]["uid"]
    assert dns_records[0]["id.orig_p"] == conn_records[0]["id.orig_p"]
    assert http_records[0]["method"] == "GET"
    assert http_records[0]["uri"] == "/"
    assert http_records[0]["status_code"] == "200"
    assert http_records[0]["uid"] == conn_records[1]["uid"]
    assert http_records[0]["id.orig_p"] == conn_records[1]["id.orig_p"]


def test_zeek_writer_skips_scenarios_that_do_not_request_zeek(tmp_path: Path) -> None:
    """
    Verify the public Zeek writer does not create source-specific paths unless Zeek is requested.

    Args:
        tmp_path (Path): Pytest temporary output directory.

    Returns:
        None: This test asserts the writer's requested-family gate directly.
    """
    scenario = build_benign_internal_web_scenario()

    result = write_zeek_logs(
        tmp_path,
        (scenario,),
        generated_at=datetime(2026, 1, 15, 14, 0, 3, tzinfo=timezone.utc),
    )

    assert result.files == ()
    assert result.omitted_streams == ()
    assert not (tmp_path / "logs" / "zeek-sensor-01").exists()


def test_zeek_writer_prefers_authored_shared_detail_overrides(tmp_path: Path) -> None:
    """
    Verify authored source-neutral flow, DNS, and HTTP details override generated Zeek defaults.

    Args:
        tmp_path (Path): Pytest temporary output directory.

    Returns:
        None: This test asserts generated Zeek records consume authored shared details.
    """
    scenario = build_scenario_from_yaml_text(
        """
schema_version: scenario/v0.1
id: scenario-authored-shared-details
name: Authored Shared Details
seed: 4444
environment:
  id: linux-mini-lab
  version: "0.1"
time_range:
  start: 2026-01-15T14:00:00Z
  end: 2026-01-15T14:00:10Z
output_families:
  - zeek
events:
  - id: evt-shared-web-003
    type: web_request
    at: +3s
    actor: user-alice
    source_host: linux-ws-01
    service: svc-web-http
    method: GET
    path: /admin/archive.tar.gz
    network:
      source_port: 55000
      orig_bytes: 1234
      resp_bytes: 5678
      orig_pkts: 3
      resp_pkts: 4
    dns:
      trans_id: 4242
      rtt: 0.125
      ttls:
        - 60
      flags:
        AA: true
        RD: false
        RA: true
    http:
      user_agent: ExactAgent/1.0
      version: "1.0"
      response_body_len: 9876
      response_content_type: text/plain
"""
    )
    generated_at = datetime(2026, 1, 15, 14, 0, 3, tzinfo=timezone.utc)

    write_zeek_logs(tmp_path, (scenario,), generated_at=generated_at)
    conn_records = read_zeek_records(tmp_path / "logs" / "zeek-sensor-01" / "zeek" / "conn.log")
    dns_records = read_zeek_records(tmp_path / "logs" / "zeek-sensor-01" / "zeek" / "dns.log")
    http_records = read_zeek_records(tmp_path / "logs" / "zeek-sensor-01" / "zeek" / "http.log")
    http_conn_record = conn_records[1]

    assert dns_records[0]["trans_id"] == "4242"
    assert dns_records[0]["rtt"] == "0.125000"
    assert dns_records[0]["AA"] == "T"
    assert dns_records[0]["RD"] == "F"
    assert dns_records[0]["TTLs"] == "60.000000"
    assert http_conn_record["id.orig_p"] == "55000"
    assert http_conn_record["orig_bytes"] == "1234"
    assert http_conn_record["resp_bytes"] == "5678"
    assert http_conn_record["orig_pkts"] == "3"
    assert http_conn_record["resp_pkts"] == "4"
    assert http_records[0]["uid"] == http_conn_record["uid"]
    assert http_records[0]["id.orig_p"] == "55000"
    assert http_records[0]["version"] == "1.0"
    assert http_records[0]["user_agent"] == "ExactAgent/1.0"
    assert http_records[0]["response_body_len"] == "9876"
    assert http_records[0]["resp_mime_types"] == "text/plain"


def test_zeek_writer_reuses_http_connection_for_misuse_sequence(tmp_path: Path) -> None:
    """
    Verify multiple HTTP requests on the misuse scenario reuse one connection UID with increasing depths.

    Args:
        tmp_path (Path): Pytest temporary output directory.

    Returns:
        None: This test asserts generated Zeek HTTP transaction relationships.
    """
    scenario = replace(build_local_account_misuse_web_scenario(), output_families=("zeek",))
    generated_at = datetime(2026, 1, 15, 3, 12, 29, tzinfo=timezone.utc)

    write_zeek_logs(tmp_path, (scenario,), generated_at=generated_at)
    conn_records = read_zeek_records(tmp_path / "logs" / "zeek-sensor-01" / "zeek" / "conn.log")
    http_records = read_zeek_records(tmp_path / "logs" / "zeek-sensor-01" / "zeek" / "http.log")
    http_connection_uid = conn_records[1]["uid"]

    assert [record["uri"] for record in http_records] == ["/admin", "/admin/archive.tar.gz"]
    assert [record["trans_depth"] for record in http_records] == ["1", "2"]
    assert {record["uid"] for record in http_records} == {http_connection_uid}
    assert http_records[1]["resp_filenames"] == "archive.tar.gz"
    assert http_records[1]["resp_mime_types"] == "application/gzip"


def test_zeek_writer_builds_sibling_connection_for_standalone_http_event(tmp_path: Path) -> None:
    """
    Verify a source-neutral HTTP event without a connection parent still produces a sibling conn.log row.

    Args:
        tmp_path (Path): Pytest temporary output directory.

    Returns:
        None: This test asserts generated Zeek HTTP and connection relationships.
    """
    timestamp = datetime(2026, 1, 15, 14, 0, 2, tzinfo=timezone.utc)
    scenario = Scenario(
        id="scenario-standalone-http",
        name="Standalone HTTP",
        seed=9090,
        environment_id="linux-mini-lab",
        environment_version="0.1",
        start_time=timestamp,
        output_families=("zeek",),
        events=(
            ScenarioEvent(
                sequence_order=1,
                event=WebRequestEvent(
                    event_id="evt-standalone-http-001",
                    scenario_id="scenario-standalone-http",
                    timestamp=timestamp,
                    status="success",
                    correlation_id="corr-standalone-http",
                    source_host_id="linux-ws-01",
                    destination_host_id="web-server-01",
                    service_id="svc-web-http",
                    method="GET",
                    path="/about",
                    status_code=200,
                ),
            ),
        ),
    )

    result = write_zeek_logs(tmp_path, (scenario,), generated_at=timestamp)
    conn_records = read_zeek_records(tmp_path / "logs" / "zeek-sensor-01" / "zeek" / "conn.log")
    http_records = read_zeek_records(tmp_path / "logs" / "zeek-sensor-01" / "zeek" / "http.log")

    assert [zeek_file.stream_name for zeek_file in result.files] == ["conn", "http"]
    assert [stream.log_stream for stream in result.omitted_streams] == ["dns.log"]
    assert len(conn_records) == 1
    assert len(http_records) == 1
    assert conn_records[0]["proto"] == "tcp"
    assert conn_records[0]["service"] == "http"
    assert http_records[0]["uid"] == conn_records[0]["uid"]
    assert http_records[0]["id.orig_p"] == conn_records[0]["id.orig_p"]


def test_zeek_writer_filters_invisible_flows_and_host_only_events(tmp_path: Path) -> None:
    """
    Verify the Zeek mapper skips flows outside sensor visibility and local-only login events.

    Args:
        tmp_path (Path): Pytest temporary output directory.

    Returns:
        None: This test asserts no Zeek files are written for invisible or host-only events.
    """
    start_time = datetime(2026, 1, 15, 14, 0, 0, tzinfo=timezone.utc)
    scenario = Scenario(
        id="scenario-invisible-zeek",
        name="Invisible Zeek Inputs",
        seed=9191,
        environment_id="linux-mini-lab",
        environment_version="0.1",
        start_time=start_time,
        output_families=("zeek",),
        events=(
            ScenarioEvent(
                sequence_order=1,
                event=LinuxLocalLoginEvent(
                    event_id="evt-local-login-001",
                    scenario_id="scenario-invisible-zeek",
                    timestamp=start_time,
                    status="success",
                    correlation_id="corr-invisible",
                    actor_user_id="user-alice",
                    target_host_id="linux-ws-01",
                    login_method="local_console",
                ),
            ),
            ScenarioEvent(
                sequence_order=2,
                event=NetworkConnectionEvent(
                    event_id="evt-invisible-conn-002",
                    scenario_id="scenario-invisible-zeek",
                    timestamp=datetime(2026, 1, 15, 14, 0, 1, tzinfo=timezone.utc),
                    status="success",
                    correlation_id="corr-invisible",
                    source_host_id="zeek-sensor-01",
                    source_ip="10.10.30.31",
                    destination_host_id="web-server-01",
                    destination_ip="10.10.20.21",
                    service_id="svc-web-http",
                    destination_port=80,
                    network_protocol="tcp",
                    application_protocol="http",
                ),
            ),
        ),
    )

    result = write_zeek_logs(tmp_path, (scenario,), generated_at=start_time)

    assert result.files == ()
    assert [stream.log_stream for stream in result.omitted_streams] == ["conn.log", "dns.log", "http.log"]
    assert not (tmp_path / "logs" / "zeek-sensor-01").exists()


def test_zeek_records_with_matching_timestamps_follow_sequence_order(tmp_path: Path) -> None:
    """
    Verify same-timestamp records are ordered by source-neutral sequence order before UID fallback.

    Args:
        tmp_path (Path): Pytest temporary output directory.

    Returns:
        None: This test asserts deterministic Zeek row ordering.
    """
    timestamp = datetime(2026, 1, 15, 14, 0, 0, tzinfo=timezone.utc)
    scenario = Scenario(
        id="scenario-zeek-ordering",
        name="Zeek Ordering",
        seed=101,
        environment_id="linux-mini-lab",
        environment_version="0.1",
        start_time=timestamp,
        output_families=("zeek",),
        events=(
            ScenarioEvent(
                sequence_order=1,
                event=DnsLookupEvent(
                    event_id="evt-a",
                    scenario_id="scenario-zeek-ordering",
                    timestamp=timestamp,
                    status="success",
                    correlation_id="corr-ordering",
                    source_host_id="linux-ws-01",
                    destination_host_id="lab-dns-01",
                    service_id="svc-dns",
                    query_name="first.internal",
                    query_type="A",
                    resolved_addresses=["10.10.20.21"],
                ),
            ),
            ScenarioEvent(
                sequence_order=2,
                event=DnsLookupEvent(
                    event_id="evt-b",
                    scenario_id="scenario-zeek-ordering",
                    timestamp=timestamp,
                    status="success",
                    correlation_id="corr-ordering",
                    source_host_id="linux-ws-01",
                    destination_host_id="lab-dns-01",
                    service_id="svc-dns",
                    query_name="second.internal",
                    query_type="A",
                    resolved_addresses=["10.10.20.21"],
                ),
            ),
        ),
    )

    write_zeek_logs(tmp_path, (scenario,), generated_at=timestamp)
    dns_records = read_zeek_records(tmp_path / "logs" / "zeek-sensor-01" / "zeek" / "dns.log")

    assert [record["query"] for record in dns_records] == ["first.internal", "second.internal"]


def test_zeek_writer_omits_empty_streams_without_creating_files(tmp_path: Path) -> None:
    """
    Verify Zeek-only runs with no visible network events record omitted streams without empty files.

    Args:
        tmp_path (Path): Pytest temporary output directory.

    Returns:
        None: This test asserts omitted stream behavior.
    """
    misuse_scenario = build_local_account_misuse_web_scenario()
    scenario = replace(misuse_scenario, events=misuse_scenario.events[:1], output_families=("zeek",))

    result = write_zeek_logs(
        tmp_path,
        (scenario,),
        generated_at=datetime(2026, 1, 15, 3, 12, 29, tzinfo=timezone.utc),
    )

    assert result.files == ()
    assert [stream.log_stream for stream in result.omitted_streams] == ["conn.log", "dns.log", "http.log"]
    assert not (tmp_path / "logs" / "zeek-sensor-01").exists()
