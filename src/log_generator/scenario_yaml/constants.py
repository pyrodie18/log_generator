"""
Constants for YAML scenario parsing and validation.
"""

import re

from log_generator.output.registry import (
    DEFAULT_OUTPUT_FAMILIES as REGISTRY_DEFAULT_OUTPUT_FAMILIES,
    supported_output_families,
    unsupported_source_specific_output_families,
)


SUPPORTED_SCHEMA_VERSION = "scenario/v0.1"
DEFAULT_OUTPUT_FAMILIES = REGISTRY_DEFAULT_OUTPUT_FAMILIES
SUPPORTED_OUTPUT_FAMILIES = supported_output_families()
UNSUPPORTED_SOURCE_SPECIFIC_OUTPUT_FAMILIES = unsupported_source_specific_output_families()
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
