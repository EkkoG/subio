from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Generic, TypeVar

from subio_v2.core.nodes import Node


class IssueSeverity(StrEnum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


@dataclass(frozen=True)
class IssueDraft:
    """Target-independent diagnostic details produced during capability checks."""

    severity: IssueSeverity
    message: str
    field: str | None = None
    suggestion: str | None = None
    code: str = "conversion"


@dataclass
class TargetCheckResult:
    supported: bool
    warnings: list[IssueDraft] = field(default_factory=list)

    def add_issue(
        self,
        severity: IssueSeverity,
        message: str,
        field: str | None = None,
        suggestion: str | None = None,
        code: str = "conversion",
    ) -> None:
        self.warnings.append(
            IssueDraft(severity, message, field, suggestion, code)
        )

    def add_error(
        self,
        message: str,
        field: str | None = None,
        suggestion: str | None = None,
        code: str = "conversion",
    ) -> None:
        self.add_issue(IssueSeverity.ERROR, message, field, suggestion, code)
        self.supported = False

    def has_errors(self) -> bool:
        return any(issue.severity == IssueSeverity.ERROR for issue in self.warnings)

    def has_warnings(self) -> bool:
        return any(
            issue.severity in {IssueSeverity.WARNING, IssueSeverity.INFO}
            for issue in self.warnings
        )


@dataclass(frozen=True)
class ConversionIssue:
    severity: IssueSeverity
    node: str | None
    protocol: str | None
    source: str | None
    target: str | None
    field: str | None
    message: str
    suggestion: str | None = None
    stage: str = "capability"
    code: str = "conversion"
    artifact: str | None = None
    user: str | None = None


@dataclass
class ParseResult:
    nodes: list[Node]
    issues: list[ConversionIssue] = field(default_factory=list)


ContentT = TypeVar("ContentT")


@dataclass
class TargetEncodingResult(Generic[ContentT]):
    content: ContentT | None
    supported_node: Node | None
    issues: list[ConversionIssue] = field(default_factory=list)


@dataclass
class EmissionResult(Generic[ContentT]):
    content: ContentT
    supported_nodes: list[Node]
    issues: list[ConversionIssue] = field(default_factory=list)
    extras: dict[str, Any] = field(default_factory=dict)

    @property
    def errors(self) -> list[ConversionIssue]:
        return [issue for issue in self.issues if issue.severity == IssueSeverity.ERROR]


@dataclass
class WorkflowResult:
    generated: list[str] = field(default_factory=list)
    uploaded: list[str] = field(default_factory=list)
    issues: list[ConversionIssue] = field(default_factory=list)

    @property
    def warnings(self) -> list[ConversionIssue]:
        return [
            issue
            for issue in self.issues
            if issue.severity in {IssueSeverity.INFO, IssueSeverity.WARNING}
        ]

    @property
    def errors(self) -> list[ConversionIssue]:
        return [issue for issue in self.issues if issue.severity == IssueSeverity.ERROR]
