"""
Error types for YAML scenario parsing and validation.
"""

from dataclasses import dataclass
from typing import Any, Optional


@dataclass(frozen=True)
class ScenarioYamlValidationError:
    """
    Represent one YAML scenario validation error.
    """

    scenario_id: Optional[str]
    field_path: str
    invalid_value: Any
    reason: str

    def __str__(self) -> str:
        """
        Render the validation error for CLI and test output.

        Returns:
            str: Human-readable validation error.
        """
        prefix = self.scenario_id or "<unknown-scenario>"

        return f"{prefix} {self.field_path}: {self.invalid_value!r} is invalid because {self.reason}"


class ScenarioYamlError(ValueError):
    """
    Represent one or more YAML scenario validation errors.
    """

    def __init__(self, errors: list[ScenarioYamlValidationError]) -> None:
        """
        Initialize the exception from validation errors.

        Args:
            errors (list[ScenarioYamlValidationError]): Validation errors to expose.

        Returns:
            None: The exception is initialized.
        """
        self.errors = errors
        super().__init__("\n".join(str(error) for error in errors))
