"""
YAML scenario loading, validation, and generation interface.
"""

from log_generator.scenario_yaml.api import (
    build_scenario_from_yaml_text,
    generate_from_yaml,
    load_scenario_from_yaml,
    load_scenario_yaml,
    parse_scenario_yaml_text,
)
from log_generator.scenario_yaml.builders import build_scenario_from_parsed_yaml
from log_generator.scenario_yaml.constants import (
    DEFAULT_OUTPUT_FAMILIES,
    SUPPORTED_OUTPUT_FAMILIES,
    SUPPORTED_SCHEMA_VERSION,
    UNSUPPORTED_SOURCE_SPECIFIC_OUTPUT_FAMILIES,
)
from log_generator.scenario_yaml.errors import ScenarioYamlError, ScenarioYamlValidationError
from log_generator.scenario_yaml.models import ParsedScenarioYaml, ParsedYamlEvent
from log_generator.scenario_yaml.parser import parse_scenario_yaml_document


__all__ = [
    "DEFAULT_OUTPUT_FAMILIES",
    "ParsedScenarioYaml",
    "ParsedYamlEvent",
    "SUPPORTED_OUTPUT_FAMILIES",
    "SUPPORTED_SCHEMA_VERSION",
    "ScenarioYamlError",
    "ScenarioYamlValidationError",
    "UNSUPPORTED_SOURCE_SPECIFIC_OUTPUT_FAMILIES",
    "build_scenario_from_parsed_yaml",
    "build_scenario_from_yaml_text",
    "generate_from_yaml",
    "load_scenario_yaml",
    "load_scenario_from_yaml",
    "parse_scenario_yaml_document",
    "parse_scenario_yaml_text",
]
