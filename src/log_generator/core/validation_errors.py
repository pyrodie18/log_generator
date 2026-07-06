"""
Shared validation error primitives.
"""

from dataclasses import dataclass
from typing import Any, Generic, Iterable, Optional, TypeVar


@dataclass(frozen=True)
class ValidationIssue:
    """
    Represent one structured validation issue.
    """

    scenario_id: Optional[str]
    field_path: str
    invalid_value: Any
    reason: str

    def message_prefix(self) -> str:
        """
        Return the scenario identifier prefix used in rendered messages.

        Returns:
            str: Scenario identifier or unknown-scenario placeholder.
        """
        return self.scenario_id or "<unknown-scenario>"


IssueT = TypeVar("IssueT", bound=ValidationIssue)


class ValidationIssueCollection(Generic[IssueT]):
    """
    Collect structured validation issues while preserving insertion order.
    """

    def __init__(self, issues: Optional[Iterable[IssueT]] = None) -> None:
        """
        Initialize the validation issue collection.

        Args:
            issues (Optional[Iterable[IssueT]]): Initial issues to include.

        Returns:
            None: The collection is initialized.
        """
        self._issues = list(issues or ())

    def append(self, issue: IssueT) -> None:
        """
        Append one validation issue.

        Args:
            issue (IssueT): Validation issue to append.

        Returns:
            None: The issue is appended.
        """
        self._issues.append(issue)

    def extend(self, issues: Iterable[IssueT]) -> None:
        """
        Append several validation issues.

        Args:
            issues (Iterable[IssueT]): Validation issues to append.

        Returns:
            None: The issues are appended.
        """
        self._issues.extend(issues)

    def to_list(self) -> list[IssueT]:
        """
        Return collected validation issues as a list.

        Returns:
            list[IssueT]: Collected validation issues.
        """
        return list(self._issues)

    def __bool__(self) -> bool:
        """
        Return whether the collection contains any issues.

        Returns:
            bool: True when at least one issue is present.
        """
        return bool(self._issues)

    def __len__(self) -> int:
        """
        Return the number of collected issues.

        Returns:
            int: Number of collected issues.
        """
        return len(self._issues)


class ValidationIssueError(ValueError, Generic[IssueT]):
    """
    Represent one or more validation issues as an exception.
    """

    def __init__(self, errors: Iterable[IssueT]) -> None:
        """
        Initialize the exception from validation issues.

        Args:
            errors (Iterable[IssueT]): Validation issues to expose.

        Returns:
            None: The exception is initialized.
        """
        self.errors = list(errors)
        super().__init__("\n".join(str(error) for error in self.errors))
