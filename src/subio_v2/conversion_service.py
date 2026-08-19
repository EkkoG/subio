from collections.abc import Callable

import subio_v2.protocols as protocol_registry
from subio_v2.capabilities.definitions import (
    get_platform_capabilities,
    normalize_protocol_name,
)
from subio_v2.conversion import (
    ConversionIssue,
    IssueSeverity,
    TargetCheckResult,
)
from subio_v2.dialect import dialect_context_for_platform, extension_semantic_fields
from subio_v2.model.nodes import (
    Node,
    SourcePassthroughNode,
    SurgePolicyOptions,
    VmessNode,
)
from subio_v2.platforms import normalize_platform
from subio_v2.validation import validate_node


class NodeConversionService:
    def __init__(self, platform: str):
        self.platform = normalize_platform(platform)
        self.target_context = dialect_context_for_platform(self.platform)
        self.capabilities = get_platform_capabilities(self.platform)
        if not self.capabilities:
            raise ValueError(f"Unknown platform: {platform}")

    def check_node(self, node: Node) -> TargetCheckResult:
        result = TargetCheckResult(supported=True)
        protocol = normalize_protocol_name(node.type.value)

        for error in validate_node(node):
            result.add_error(error.message, field=error.field)

        if result.has_errors():
            return result

        if protocol not in self.capabilities.get("protocols", set()):
            result.add_error(
                f"Protocol '{protocol}' is not supported by {self.platform}",
                field="type",
                suggestion=(
                    "Use a supported protocol: "
                    + ", ".join(sorted(self.capabilities.get("protocols", set())))
                ),
            )
            return result

        descriptor = protocol_registry.get(node.type)
        if descriptor:
            protocol_capabilities = self.capabilities.get(protocol, {})
            for warning in descriptor.check(
                node, protocol_capabilities, self.platform
            ):
                result.warnings.append(warning)
                if warning.severity == IssueSeverity.ERROR:
                    result.supported = False

        self._check_common_target_fields(node, result)
        return result

    def _check_common_target_fields(
        self, node: Node, result: TargetCheckResult
    ) -> None:
        global_features = self.capabilities.get("global_features", {})

        unsupported_fields: list[str] = []
        if self.platform != "surge":
            if node.surge_options != SurgePolicyOptions():
                unsupported_fields.append("surge_options")
            if node.shadow_tls.enabled:
                unsupported_fields.append("shadow_tls")
            if isinstance(node, VmessNode) and node.vmess_aead:
                unsupported_fields.append("vmess_aead")
        if self.platform not in {"mihomo", "clash", "stash", "surge"}:
            if node.interface_name:
                unsupported_fields.append("interface_name")
            if node.users:
                unsupported_fields.append("users")
        if self.platform not in {"mihomo", "clash", "stash"} and (
            node.routing_mark is not None
        ):
            unsupported_fields.append("routing_mark")
        if unsupported_fields:
            field_names = ", ".join(sorted(unsupported_fields))
            result.add_issue(
                IssueSeverity.WARNING,
                f"Node fields cannot be represented by {self.platform}: {field_names}",
                field=field_names,
                code="conversion.unsupported-platform-field",
            )

        if node.tfo and not global_features.get("tfo", False):
            result.add_issue(
                IssueSeverity.INFO,
                f"TFO is not supported by {self.platform}, will be ignored",
                field="tfo",
            )

        if node.mptcp and not global_features.get("mptcp", False):
            result.add_issue(
                IssueSeverity.INFO,
                f"MPTCP is not supported by {self.platform}, will be ignored",
                field="mptcp",
            )

        if node.dialer_proxy and not global_features.get("dialer_proxy", False):
            result.add_issue(
                IssueSeverity.INFO,
                f"Dialer proxy is not supported by {self.platform}, will be ignored",
                field="dialer_proxy",
            )

        if self.platform == "stash" and node.dialer_proxy and node.interface_name:
            result.add_error(
                "Stash dialer-proxy cannot be combined with interface-name",
                field="dialer_proxy",
                code="conversion.unsupported-field-combination",
            )

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
        check_node: Callable[[Node], TargetCheckResult] | None = None,
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
