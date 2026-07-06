"""
Error types for YAML scenario parsing and validation.
"""

from log_generator.core.validation_errors import ValidationIssue, ValidationIssueError


class ScenarioYamlValidationError(ValidationIssue):
    """
    Represent one YAML scenario validation error.
    """

    def __str__(self) -> str:
        """
        Render the validation error for CLI and test output.

        Returns:
            str: Human-readable validation error.
        """
        return f"{self.message_prefix()} {self.field_path}: {self.invalid_value!r} is invalid because {self.reason}"


class ScenarioYamlError(ValidationIssueError[ScenarioYamlValidationError]):
    """
    Represent one or more YAML scenario validation errors.
    """
