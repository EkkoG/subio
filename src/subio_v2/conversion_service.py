from collections.abc import Callable

from subio_v2.capabilities.checker import CapabilityChecker, CheckResult
from subio_v2.conversion import ConversionIssue, IssueSeverity
from subio_v2.dialect import dialect_context_for_platform, extension_semantic_fields
from subio_v2.model.nodes import Node, SourcePassthroughNode
from subio_v2.platforms import normalize_platform


class NodeConversionService:
    def __init__(self, platform: str):
        self.platform = normalize_platform(platform)
        self.target_context = dialect_context_for_platform(self.platform)
        self._checker = CapabilityChecker(self.platform)

    def check_node(self, node: Node) -> CheckResult:
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

    def select(
        self,
        nodes: list[Node],
        check_node: Callable[[Node], CheckResult] | None = None,
    ) -> tuple[list[Node], list[ConversionIssue]]:
        supported_nodes: list[Node] = []
        issues: list[ConversionIssue] = []
        check = check_node or self.check_node

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

            result = check(node)
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
