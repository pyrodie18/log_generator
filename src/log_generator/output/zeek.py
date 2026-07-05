"""
Zeek native TSV schema and rendering helpers.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Iterable, Mapping, Optional

from log_generator.core.events import normalize_utc_timestamp


ZEEK_FIELD_SEPARATOR = "\t"
ZEEK_SEPARATOR_DIRECTIVE = r"\x09"
ZEEK_SET_SEPARATOR = ","
ZEEK_EMPTY_FIELD = "(empty)"
ZEEK_UNSET_FIELD = "-"


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

    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"expected integer for Zeek count field, got {type(value).__name__}")

    if value < 0:
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

    if value > 65535:
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
    "ZEEK_STREAM_SCHEMAS",
    "ZEEK_UNSET_FIELD",
    "ZeekField",
    "ZeekStreamSchema",
    "build_zeek_header_lines",
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
    "zeek_schema_field_names",
    "zeek_schema_field_types",
]
