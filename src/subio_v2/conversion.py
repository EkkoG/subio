from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Generic, TypeVar

from subio_v2.model.nodes import Node


class IssueSeverity(StrEnum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


@dataclass(frozen=True)
class ConversionIssue:
    severity: IssueSeverity
    node: str | None
    protocol: str | None
    source: str | None
    target: str
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
    resources: dict[str, Any] = field(default_factory=dict)


ContentT = TypeVar("ContentT")


@dataclass
class EmissionResult(Generic[ContentT]):
    content: ContentT
    supported_nodes: list[Node]
    issues: list[ConversionIssue] = field(default_factory=list)
    extras: dict[str, Any] = field(default_factory=dict)
    emitted_resource_keys: list[str] = field(default_factory=list)

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
