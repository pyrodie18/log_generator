"""
Public YAML scenario loading and generation helpers.
"""

from datetime import datetime
from pathlib import Path
from typing import Optional

from log_generator.core.scenarios import Scenario
from log_generator.output.manifest import write_output_manifest
from log_generator.scenario_yaml.builders import build_scenario_from_parsed_yaml
from log_generator.scenario_yaml.models import EnvironmentRegistry, ParsedScenarioYaml
from log_generator.scenario_yaml.parser import parse_scenario_yaml_document


def load_scenario_yaml(
    path: Path,
    environment_registry: Optional[EnvironmentRegistry] = None,
) -> ParsedScenarioYaml:
    """
    Load and validate a single YAML scenario document from disk.

    Args:
        path (Path): YAML scenario file to read.
        environment_registry (Optional[EnvironmentRegistry]): Environment registry overrides.

    Returns:
        ParsedScenarioYaml: Parsed scenario with resolved top-level metadata and event timing.
    """
    return parse_scenario_yaml_text(
        path.read_text(encoding="utf-8"),
        environment_registry=environment_registry,
    )


def load_scenario_from_yaml(
    path: Path,
    environment_registry: Optional[EnvironmentRegistry] = None,
) -> Scenario:
    """
    Load a YAML scenario file and return an expanded source-neutral scenario.

    Args:
        path (Path): YAML scenario file to read.
        environment_registry (Optional[EnvironmentRegistry]): Environment registry overrides.

    Returns:
        Scenario: Expanded source-neutral scenario.
    """
    parsed = load_scenario_yaml(path, environment_registry=environment_registry)

    return build_scenario_from_parsed_yaml(parsed, environment_registry=environment_registry)


def generate_from_yaml(
    path: Path,
    output_root: Path,
    run_id: Optional[str] = None,
    generated_at: Optional[datetime] = None,
    environment_registry: Optional[EnvironmentRegistry] = None,
) -> Path:
    """
    Generate the requested output tree from a YAML scenario file.

    Args:
        path (Path): YAML scenario file to load.
        output_root (Path): Root output directory to write.
        run_id (Optional[str]): Run ID to include in the manifest. A deterministic default is used when omitted.
        generated_at (Optional[datetime]): UTC generation timestamp to include in the manifest.
        environment_registry (Optional[EnvironmentRegistry]): Environment registry overrides.

    Returns:
        Path: Path to the written manifest file.
    """
    scenario = load_scenario_from_yaml(path, environment_registry=environment_registry)

    if run_id is None:
        run_id = _default_run_id(scenario)

    return write_output_manifest(output_root, (scenario,), run_id=run_id, generated_at=generated_at)


def parse_scenario_yaml_text(
    text: str,
    environment_registry: Optional[EnvironmentRegistry] = None,
) -> ParsedScenarioYaml:
    """
    Parse and validate a single YAML scenario document from text.

    Args:
        text (str): YAML scenario document text.
        environment_registry (Optional[EnvironmentRegistry]): Environment registry overrides.

    Returns:
        ParsedScenarioYaml: Parsed scenario with resolved top-level metadata and event timing.
    """
    from log_generator.scenario_yaml.parser import _load_yaml_document

    document = _load_yaml_document(text)

    return parse_scenario_yaml_document(document, environment_registry=environment_registry)


def build_scenario_from_yaml_text(
    text: str,
    environment_registry: Optional[EnvironmentRegistry] = None,
) -> Scenario:
    """
    Parse YAML scenario text and convert it into an expanded source-neutral scenario.

    Args:
        text (str): YAML scenario document text.
        environment_registry (Optional[EnvironmentRegistry]): Environment registry overrides.

    Returns:
        Scenario: Expanded source-neutral scenario.
    """
    parsed = parse_scenario_yaml_text(text, environment_registry=environment_registry)

    return build_scenario_from_parsed_yaml(parsed, environment_registry=environment_registry)


def _default_run_id(scenario: Scenario) -> str:
    """
    Build a deterministic default run ID for a YAML-generated scenario.

    Args:
        scenario (Scenario): Scenario being generated.

    Returns:
        str: Stable run ID.
    """
    return f"run-{scenario.id}"
