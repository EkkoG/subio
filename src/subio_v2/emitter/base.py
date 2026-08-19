from abc import ABC, abstractmethod
from typing import Any, List

from subio_v2.capabilities.checker import CheckResult
from subio_v2.conversion import ConversionIssue, EmissionResult, IssueSeverity
from subio_v2.conversion_service import NodeConversionService
from subio_v2.model.nodes import Node
from subio_v2.platforms import normalize_platform
from subio_v2.utils.logger import logger


class BaseEmitter(ABC):
    """Base class for checked, structured subscription emitters."""

    platform: str = ""

    def __init__(self):
        self.platform = normalize_platform(self.platform)
        self._conversion = NodeConversionService(self.platform)
        self.target_context = self._conversion.target_context

    def emit_content(self, nodes: List[Node]) -> Any:
        """Return emitted content and raise target-specific emit errors."""
        result = self.emit_result(nodes)
        self._raise_emit_error(result)
        self.log_issues(result.issues)
        return result.content

    @abstractmethod
    def emit_result(self, nodes: List[Node]) -> EmissionResult[Any]:
        """Return content, actually emitted nodes, and structured issues."""

    def _raise_emit_error(self, result: EmissionResult[Any]) -> None:
        """Raise target-specific errors for content-only emission."""

    def check_node(self, node: Node) -> CheckResult:
        return self._conversion.check_node(node)

    @staticmethod
    def template_context(nodes: List[Node]) -> dict[str, Any]:
        return {"proxies_names": [node.name for node in nodes]}

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
        return self._conversion.issue_for_node(
            node,
            severity,
            message,
            field=field,
            suggestion=suggestion,
            stage=stage,
            code=code,
        )

    def emit_with_check(
        self, nodes: List[Node]
    ) -> tuple[List[Node], List[ConversionIssue]]:
        """Run target checks exactly once and return normalized issues."""
        return self._conversion.select(nodes, self.check_node)

    @staticmethod
    def log_issues(issues: List[ConversionIssue]) -> None:
        for issue in issues:
            if issue.code.startswith("ruleset."):
                location = (
                    f"Ruleset '{issue.source}'" if issue.source else "Ruleset"
                )
                context = []
                if issue.field:
                    context.append(issue.field)
                if issue.target:
                    context.append(f"target '{issue.target}'")
                if context:
                    location += f" ({', '.join(context)})"
            elif issue.node:
                location = f"Node '{issue.node}'"
            elif issue.source:
                location = f"Source '{issue.source}'"
            else:
                location = "Conversion"

            detail = issue.message
            if issue.suggestion:
                detail += f" ({issue.suggestion})"
            message = f"{location}: {detail}"
            if issue.severity == IssueSeverity.ERROR:
                logger.error(message)
            elif issue.severity == IssueSeverity.WARNING:
                logger.warning(message)
            else:
                logger.dim(message)
