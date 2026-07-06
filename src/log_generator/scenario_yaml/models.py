"""
Parsed YAML scenario model definitions.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Mapping, Optional

from log_generator.core.environment import Environment
from log_generator.scenario_yaml.constants import DEFAULT_OUTPUT_FAMILIES


@dataclass(frozen=True)
class ParsedYamlEvent:
    """
    Represent one structurally valid authored YAML event with resolved timing.
    """

    event_id: str
    event_type: str
    timestamp: datetime
    source_index: int
    raw: dict[str, Any]
    after: Optional[str] = None
    delay: Optional[timedelta] = None


@dataclass(frozen=True)
class ParsedScenarioYaml:
    """
    Represent a structurally valid YAML scenario document.
    """

    schema_version: str
    scenario_id: str
    name: str
    seed: int
    environment_id: str
    environment_version: str
    start_time: datetime
    events: tuple[ParsedYamlEvent, ...]
    end_time: Optional[datetime] = None
    output_families: tuple[str, ...] = DEFAULT_OUTPUT_FAMILIES
    description: Optional[str] = None
    attack_chain: tuple[dict[str, Any], ...] = ()
    answer_key: tuple[dict[str, Any], ...] = ()
    metadata: Optional[dict[str, Any]] = None


EnvironmentRegistry = Mapping[str, Environment]
