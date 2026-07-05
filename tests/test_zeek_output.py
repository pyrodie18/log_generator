"""
Tests for Zeek native TSV schema and rendering helpers.
"""

from datetime import datetime, timedelta, timezone

import pytest

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
    zeek_schema_field_names,
    zeek_schema_field_types,
)


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
