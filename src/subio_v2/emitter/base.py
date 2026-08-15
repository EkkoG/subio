from abc import ABC, abstractmethod
from typing import Any, List, Optional

from subio_v2.capabilities.checker import (
    CapabilityChecker,
    CheckResult,
    WarningLevel,
)
from subio_v2.conversion import ConversionIssue, EmissionResult, IssueSeverity
from subio_v2.model.nodes import Node
from subio_v2.utils.logger import logger


_SEVERITY_BY_WARNING_LEVEL = {
    WarningLevel.INFO: IssueSeverity.INFO,
    WarningLevel.WARNING: IssueSeverity.WARNING,
    WarningLevel.ERROR: IssueSeverity.ERROR,
}


class BaseEmitter(ABC):
    """Base class for checked, structured subscription emitters."""

    platform: str = ""

    def __init__(self):
        self._checker: Optional[CapabilityChecker] = None
        if self.platform:
            self._checker = CapabilityChecker(self.platform)

    @abstractmethod
    def emit(self, nodes: List[Node]) -> Any:
        """Compatibility API returning only emitted content."""

    @abstractmethod
    def emit_result(self, nodes: List[Node]) -> EmissionResult[Any]:
        """Return content, actually emitted nodes, and structured issues."""

    def check_node(self, node: Node) -> CheckResult:
        if not self._checker:
            return CheckResult(supported=True)
        return self._checker.check_node(node)

    def issue_for_node(
        self,
        node: Node,
        severity: IssueSeverity,
        message: str,
        *,
        field: str | None = None,
        suggestion: str | None = None,
        stage: str = "emit",
        code: str = "conversion",
    ) -> ConversionIssue:
        return ConversionIssue(
            severity=severity,
            node=node.name,
            protocol=node.type.value,
            source=node.source_provider,
            target=self.platform,
            field=field,
            message=message,
            suggestion=suggestion,
            stage=stage,
            code=code,
        )

    def emit_with_check(
        self, nodes: List[Node]
    ) -> tuple[List[Node], List[ConversionIssue]]:
        """Run capability checks exactly once and return normalized issues."""
        supported_nodes: list[Node] = []
        issues: list[ConversionIssue] = []

        for node in nodes:
            result = self.check_node(node)
            for warning in result.warnings:
                issues.append(
                    self.issue_for_node(
                        node,
                        _SEVERITY_BY_WARNING_LEVEL[warning.level],
                        warning.message,
                        field=warning.field,
                        suggestion=warning.suggestion,
                        stage="capability",
                        code=warning.code,
                    )
                )

            if result.supported:
                supported_nodes.append(node)
            elif not result.has_errors():
                issues.append(
                    self.issue_for_node(
                        node,
                        IssueSeverity.ERROR,
                        f"Node is not supported by {self.platform}",
                        field="type",
                        stage="capability",
                    )
                )

            surge_extension = node.source_extensions.get("surge", {})
            if self.platform != "surge" and (
                surge_extension.get("parameters")
                or surge_extension.get("semantic_fields")
            ):
                fields = sorted(
                    {
                        *surge_extension.get("semantic_fields", []),
                        *(key for key, _ in surge_extension.get("parameters", [])),
                    }
                )
                issues.append(
                    self.issue_for_node(
                        node,
                        IssueSeverity.WARNING,
                        "Surge-only fields cannot be represented by this target: "
                        + ", ".join(fields),
                        field="source_extensions.surge",
                        stage="conversion",
                        code="conversion.unconsumed-source-field",
                    )
                )

        return supported_nodes, issues

    @staticmethod
    def log_issues(issues: List[ConversionIssue]) -> None:
        for issue in issues:
            location = f" Node '{issue.node}'" if issue.node else ""
            detail = issue.message
            if issue.suggestion:
                detail += f" ({issue.suggestion})"
            message = f"[{issue.target}]{location}: {detail}"
            if issue.severity in {IssueSeverity.ERROR, IssueSeverity.WARNING}:
                logger.warning(message)
            else:
                logger.dim(message)
