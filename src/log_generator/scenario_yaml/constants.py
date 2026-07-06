"""
Constants for YAML scenario parsing and validation.
"""

import re

from log_generator.output.jsonl import SOURCE_SPECIFIC_OUTPUT_FAMILIES


SUPPORTED_SCHEMA_VERSION = "scenario/v0.1"
DEFAULT_OUTPUT_FAMILIES = ("generic-normalized",)
SUPPORTED_OUTPUT_FAMILIES = frozenset((*DEFAULT_OUTPUT_FAMILIES, "zeek"))
UNSUPPORTED_SOURCE_SPECIFIC_OUTPUT_FAMILIES = SOURCE_SPECIFIC_OUTPUT_FAMILIES - SUPPORTED_OUTPUT_FAMILIES
SUPPORTED_EVENT_TYPES = frozenset({"web_request", "linux_local_login"})
TOP_LEVEL_FIELDS = frozenset(
    {
        "schema_version",
        "id",
        "name",
        "description",
        "seed",
        "environment",
        "time_range",
        "output_families",
        "events",
        "attack_chain",
        "answer_key",
        "metadata",
        "noise_profiles",
    }
)
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
EVENT_TYPE_FIELDS = {
    "web_request": frozenset(
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
    "linux_local_login": frozenset(
        {
            "login_method",
            "source_ip",
        }
    ),
}
SAFE_IDENTIFIER_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
DURATION_RE = re.compile(r"^\+?(?P<amount>\d+)(?P<unit>ms|s|m|h)$")
ATTACK_TECHNIQUE_ID_RE = re.compile(r"^T\d+$")
ATTACK_CHAIN_FIELDS = frozenset(
    {
        "id",
        "name",
        "primary_event_id",
        "supporting_event_ids",
        "technique_id",
        "technique_name",
    }
)
ANSWER_KEY_FIELDS = frozenset(
    {
        "label",
        "primary_event_id",
        "supporting_event_ids",
        "description",
    }
)
