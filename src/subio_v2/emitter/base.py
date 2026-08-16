from abc import ABC, abstractmethod
from typing import Any, List, Optional

from subio_v2.capabilities.checker import (
    CapabilityChecker,
    CheckResult,
)
from subio_v2.conversion import ConversionIssue, EmissionResult, IssueSeverity
from subio_v2.dialect import (
    dialect_context_for_platform,
    extension_semantic_fields,
)
from subio_v2.model.nodes import Node, SourcePassthroughNode
from subio_v2.platforms import normalize_platform
from subio_v2.utils.logger import logger

class BaseEmitter(ABC):
    """Base class for checked, structured subscription emitters."""

    platform: str = ""

    def __init__(self):
        self.platform = normalize_platform(self.platform)
        self.target_context = dialect_context_for_platform(self.platform)
        self._checker: Optional[CapabilityChecker] = None
        if self.platform:
            self._checker = CapabilityChecker(self.platform)

    def emit(self, nodes: List[Node]) -> Any:
        """Compatibility API returning only emitted content."""
        result = self.emit_result(nodes)
        self._raise_legacy_emit_error(result)
        self.log_issues(result.issues)
        return result.content

    @abstractmethod
    def emit_result(self, nodes: List[Node]) -> EmissionResult[Any]:
        """Return content, actually emitted nodes, and structured issues."""

    def _raise_legacy_emit_error(self, result: EmissionResult[Any]) -> None:
        """Compatibility hook for emitters that historically raised from emit()."""

    def check_node(self, node: Node) -> CheckResult:
        if not self._checker:
            return CheckResult(supported=True)
        return self._checker.check_node(node)

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
        return ConversionIssue(
            severity=severity,
            node=node.name,
            protocol=(
                node.original_type
                if isinstance(node, SourcePassthroughNode)
                else node.type.value
            ),
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
            if isinstance(node, SourcePassthroughNode):
                source_dialect = (
                    node.source_context.dialect if node.source_context else None
                )
                if source_dialect == self.target_context.dialect:
                    supported_nodes.append(node)
                else:
                    issues.append(
                        self.issue_for_node(
                            node,
                            IssueSeverity.WARNING,
                            "Source-bound proxy record was ignored: "
                            f"type '{node.original_type}', source dialect "
                            f"'{source_dialect or 'unknown'}', target "
                            f"'{self.target_context.dialect}'",
                            field="type",
                            stage="conversion",
                            code="conversion.ignored-source-passthrough",
                        )
                    )
                continue

            result = self.check_node(node)
            for warning in result.warnings:
                issues.append(
                    self.issue_for_node(
                        node,
                        warning.severity,
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

            for source_dialect, extension in node.source_extensions.items():
                if source_dialect == self.target_context.dialect:
                    continue
                fields = extension_semantic_fields(extension)
                if not fields:
                    continue
                issues.append(
                    self.issue_for_node(
                        node,
                        IssueSeverity.WARNING,
                        "Source-only fields cannot be represented by this target: "
                        + ", ".join(fields),
                        field=f"source_extensions.{source_dialect}",
                        stage="conversion",
                        code="conversion.unconsumed-source-field",
                    )
                )

            source_context = node.source_context
            if (
                node.extra
                and source_context is not None
                and source_context.dialect != self.target_context.dialect
            ):
                issues.append(
                    self.issue_for_node(
                        node,
                        IssueSeverity.WARNING,
                        "Source-only fields cannot be represented by this target: "
                        + ", ".join(sorted(node.extra)),
                        field=f"extra.{source_context.dialect}",
                        stage="conversion",
                        code="conversion.unconsumed-source-field",
                    )
                )

            transport = getattr(node, "transport", None)
            if (
                transport is not None
                and getattr(transport, "extra", None)
                and source_context is not None
                and source_context.dialect != self.target_context.dialect
            ):
                fields = sorted(
                    f"transport.{block}.{key}"
                    for block, values in transport.extra.items()
                    for key in values
                )
                issues.append(
                    self.issue_for_node(
                        node,
                        IssueSeverity.WARNING,
                        "Source-only fields cannot be represented by this target: "
                        + ", ".join(fields),
                        field=f"transport.extra.{source_context.dialect}",
                        stage="conversion",
                        code="conversion.unconsumed-source-field",
                    )
                )

        return supported_nodes, issues

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
