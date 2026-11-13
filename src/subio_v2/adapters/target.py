from subio_v2.adapters.catalog import (
    common_policy_for_format,
    get_target,
    normalize_format,
)
from subio_v2.core.dialect import extension_semantic_fields
from subio_v2.core.nodes import Node, SourcePassthroughNode
from subio_v2.core.results import (
    ConversionIssue,
    IssueSeverity,
    TargetCheckResult,
    TargetEncodingResult,
)
from subio_v2.core.validation import validate_node
from subio_v2.protocols import get_definition


class TargetValidationService:
    def __init__(self, platform: str):
        self.platform = normalize_format(platform)
        self.target = get_target(self.platform)
        self.common_policy = common_policy_for_format(self.platform)
        if self.target is None:
            raise ValueError(f"Unknown platform: {platform}")
        self.target_context = self.target.context
        self.protocol_codecs = self.target.codecs

    def _binding(self, node: Node):
        if isinstance(node, SourcePassthroughNode):
            return self.target.source_passthrough
        return self.target.codecs.get(node.type)

    def check_node(self, node: Node) -> TargetCheckResult:
        result = TargetCheckResult(supported=True)
        for error in validate_node(node, definition=get_definition(node.type)):
            result.add_error(error.message, field=error.field)
        binding = self._binding(node)
        if result.has_errors():
            check_input = (
                binding.precheck if binding is not None else self.target.precheck
            )
            result.warnings.extend(check_input(node))
            return result
        if binding is None:
            result.warnings.extend(self.target.precheck(node))
            if result.has_errors():
                result.supported = False
                return result
            supported = ", ".join(
                sorted(protocol.value for protocol in self.target.codecs)
            )
            result.add_error(
                f"Protocol '{node.type.value}' is not supported by {self.platform}",
                field="type",
                suggestion=f"Use a supported protocol: {supported}",
            )
            return result
        for issue in binding.check(node):
            result.warnings.append(issue)
            if issue.severity == IssueSeverity.ERROR:
                result.supported = False
        return result

    def encode_node(
        self, node: Node, *, context: object = None
    ) -> TargetEncodingResult[object]:
        selected, issues = self.select([node])
        if not selected:
            return TargetEncodingResult(
                content=None, supported_node=None, issues=issues
            )
        try:
            content = self._binding(node).encode(node, context)
        except Exception as exc:
            issues.append(
                self.issue_for_node(
                    node,
                    IssueSeverity.ERROR,
                    str(exc),
                    field=getattr(exc, "field", None),
                    code=getattr(exc, "code", "conversion"),
                    stage="emit",
                )
            )
            return TargetEncodingResult(
                content=None, supported_node=None, issues=issues
            )
        return TargetEncodingResult(content=content, supported_node=node, issues=issues)

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
    ) -> tuple[list[Node], list[ConversionIssue]]:
        supported_nodes: list[Node] = []
        issues: list[ConversionIssue] = []
        check = self.check_node

        for node in nodes:
            if isinstance(node, SourcePassthroughNode):
                source_dialect = (
                    node.source_context.dialect if node.source_context else None
                )
                if source_dialect == self.target_context.dialect:
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
