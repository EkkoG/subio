from collections.abc import Callable, Mapping

import subio_v2.protocols as protocol_registry
from subio_v2.adapters.catalog import common_policy_for_format, get_target, normalize_format
from subio_v2.adapters.links.codecs import all_codecs as all_link_codecs
from subio_v2.adapters.singbox.endpoint import SINGBOX_ENDPOINT_CODECS
from subio_v2.adapters.singbox.outbound import SINGBOX_OUTBOUND_CODECS
from subio_v2.adapters.surge.codecs import SURGE_PROTOCOL_CODECS
from subio_v2.adapters.surge.validation import (
    SURGE_RESERVED_POLICY_NAMES,
    validate_surge_node,
    validate_surge_parameters,
)
from subio_v2.core.dialect import (
    dialect_context_for_platform,
    extension_semantic_fields,
)
from subio_v2.core.nodes import (
    HttpNode,
    Hysteria2Node,
    SSHNode,
    Node,
    ShadowsocksNode,
    SnellNode,
    SourcePassthroughNode,
    SurgePolicyOptions,
    VmessNode,
    VlessNode,
    WireguardNode,
)
from subio_v2.core.results import (
    ConversionIssue,
    IssueSeverity,
    TargetCheckResult,
    TargetEncodingResult,
)
from subio_v2.core.validation import validate_node


def _protocol_codecs_for_target(platform: str) -> dict:
    if platform in {"mihomo", "clash", "stash"}:
        return protocol_registry.target_codecs_for(platform)
    if platform == "surge":
        return dict(SURGE_PROTOCOL_CODECS)
    if platform in {"dae", "v2rayn"}:
        return {
            codec.protocol: codec
            for codec in all_link_codecs()
            if platform in codec.targets
        }
    if platform == "sing-box":
        return {**SINGBOX_OUTBOUND_CODECS, **SINGBOX_ENDPOINT_CODECS}
    return {}


class TargetValidationService:
    def __init__(self, platform: str):
        self.platform = normalize_format(platform)
        self.target_context = dialect_context_for_platform(self.platform)
        self.protocol_codecs = _protocol_codecs_for_target(self.platform)
        self.common_policy = common_policy_for_format(self.platform)
        self.target = get_target(self.platform)
        if self.common_policy is None or not self.protocol_codecs:
            raise ValueError(f"Unknown platform: {platform}")

    def check_node(self, node: Node) -> TargetCheckResult:
        if self.target is None or node.type not in self.target.codecs:
            return self._check_legacy_node(node)
        result = TargetCheckResult(supported=True)
        for error in validate_node(node, definition=protocol_registry.get_definition(node.type)):
            result.add_error(error.message, field=error.field)
        if result.has_errors():
            return result
        for issue in self.target.check_common(node) + self.target.codecs[node.type].check(node):
            result.warnings.append(issue)
            if issue.severity == IssueSeverity.ERROR:
                result.supported = False
        return result

    def _check_legacy_node(self, node: Node) -> TargetCheckResult:
        result = TargetCheckResult(supported=True)
        if (
            self.platform == "surge"
            and isinstance(node.name, str)
            and node.name.upper() in SURGE_RESERVED_POLICY_NAMES
        ):
            result.add_error(
                f"Surge built-in policy name '{node.name}' cannot be used for a node",
                field="name",
                code="conversion.reserved-policy-name",
            )
        for error in validate_node(
            node,
            definition=protocol_registry.get_definition(node.type),
        ):
            result.add_error(error.message, field=error.field)

        transport = getattr(node, "transport", None)
        for attr in ("grpc_mode", "grpc_authority"):
            value = getattr(transport, attr, None)
            if value is None:
                continue
            field = f"transport.{attr}"
            if transport.network_value != "grpc":
                result.add_error("gRPC parameters require the gRPC transport", field=field)
            elif not isinstance(value, str) or (attr == "grpc_mode" and value not in {"gun", "multi"}):
                result.add_error("Invalid gRPC parameter", field=field)
            elif not (isinstance(node, VlessNode) and self.platform in {"surge", "v2rayn", "dae"}):
                result.add_error(
                    f"This gRPC field cannot be represented by {self.platform}",
                    field=field, code="conversion.unsupported-platform-field",
                )

        if self.platform == "surge":
            for issue in validate_surge_node(node):
                result.warnings.append(issue)
                if issue.severity == IssueSeverity.ERROR:
                    result.supported = False

            if isinstance(node, SourcePassthroughNode):
                self._check_surge_source_passthrough(node, result)

        # Opaque source records have no target codec. Same-dialect callers still
        # need their typed common fields and known raw policy parameters checked.
        if isinstance(node, SourcePassthroughNode):
            return result

        if result.has_errors():
            return result

        target_codec = self.protocol_codecs.get(node.type)
        if target_codec is None:
            supported = ", ".join(
                sorted(protocol.value for protocol in self.protocol_codecs)
            )
            result.add_error(
                f"Protocol '{node.type.value}' is not supported by {self.platform}",
                field="type",
                suggestion=f"Use a supported protocol: {supported}",
            )
            return result

        if self.platform in {"mihomo", "clash", "stash", "sing-box"}:
            for warning in target_codec.check(node):
                result.warnings.append(warning)
                if warning.severity == IssueSeverity.ERROR:
                    result.supported = False
        elif clash_codec := protocol_registry.get(node.type):
            if self.platform in {"surge", "dae", "v2rayn"}:
                protocol_capabilities = (
                    dict(target_codec.target_constraints)
                    if self.platform == "surge"
                    else dict(target_codec.target_constraints.get(self.platform, {}))
                )
            else:
                protocol_capabilities = dict(
                    clash_codec.constraints_for_target(self.platform)
                )
            if self.platform == "surge" and isinstance(node, VmessNode):
                # Mihomo's auto cipher is Surge's default aes-128-gcm when emitted.
                protocol_capabilities["ciphers"] = set(
                    protocol_capabilities.get("ciphers", set())
                ) | {"auto"}
            for warning in clash_codec.check(node, protocol_capabilities, self.platform):
                result.warnings.append(warning)
                if warning.severity == IssueSeverity.ERROR:
                    result.supported = False

        self._check_common_target_fields(node, result)
        return result

    @staticmethod
    def _check_surge_source_passthrough(
        node: SourcePassthroughNode, result: TargetCheckResult
    ) -> None:
        source_context = node.source_context
        if source_context is None or source_context.dialect != "surge":
            return
        parameters = getattr(getattr(node.raw, "parameters", None), "last_values", None)
        if not isinstance(parameters, Mapping):
            return
        try:
            validate_surge_parameters(parameters, node.original_type or "external")
        except (TypeError, ValueError) as exc:
            result.add_error(
                f"Invalid Surge policy parameter: {exc}",
                field="parameters",
                code="conversion.invalid-value",
            )

    def encode_node(
        self,
        node: Node,
        encoder: Callable[[Node], object],
        check_node: Callable[[Node], TargetCheckResult] | None = None,
        *,
        context: object = None,
    ) -> TargetEncodingResult[object]:
        binding = self.target.codecs.get(node.type) if self.target is not None else None
        selected, issues = self.select([node], self.check_node if binding else check_node)
        if not selected:
            return TargetEncodingResult(
                content=None, supported_node=None, issues=issues
            )
        try:
            content = binding.encode(node, context) if binding else encoder(node)
        except Exception as exc:
            field = getattr(exc, "field", None)
            code = getattr(exc, "code", "conversion")
            issues.append(
                self.issue_for_node(
                    node,
                    IssueSeverity.ERROR,
                    str(exc),
                    field=field,
                    code=code,
                    stage="emit",
                )
            )
            return TargetEncodingResult(
                content=None, supported_node=None, issues=issues
            )
        return TargetEncodingResult(content=content, supported_node=node, issues=issues)

    def _check_common_target_fields(
        self, node: Node, result: TargetCheckResult
    ) -> None:
        global_features = self.common_policy.as_feature_map()

        if isinstance(node, WireguardNode) and self.platform != "surge":
            fields = extension_semantic_fields(node.source_extensions.get("surge", {}))
            if "wireguard.peers.keepalive" in fields:
                result.add_error(
                    "This target cannot preserve different per-peer keepalive settings",
                    field="persistent_keepalive", code="conversion.unsupported-platform-field",
                )

        if (
            isinstance(node, VlessNode)
            and self.platform in {"mihomo", "stash"}
            and node.tls.sni_disabled
        ):
            result.add_error(
                "This target cannot preserve the VLESS SNI disable setting",
                field="tls.sni_disabled", code="conversion.unsupported-platform-field",
            )

        if self.platform in {"dae", "v2rayn"}:
            transport = getattr(node, "transport", None)
            headers = getattr(transport, "headers", None)
            if headers and (
                transport.network_value not in {"ws", "http"}
                or set(headers) != {"Host"} or not isinstance(headers["Host"], str)
            ):
                result.add_error(
                    "Links can only preserve a single string Host header for WS/HTTP transport",
                    field="transport.headers", code="conversion.unsupported-platform-field",
                )
            if isinstance(node, HttpNode) and node.headers:
                result.add_error(
                    "HTTP links cannot preserve required headers",
                    field="headers", code="conversion.unsupported-platform-field",
                )
            tls = getattr(node, "tls", None)
            for attr in ("verify_name", "certificate_sha256", "client_cert_ref", "certificate", "private_key", "ech_opts", "sni_disabled"):
                if getattr(tls, attr, None):
                    result.add_error(
                        "Links cannot preserve this TLS setting",
                        field=f"tls.{attr}", code="conversion.unsupported-platform-field",
                    )
            if isinstance(node, Hysteria2Node):
                for attr in ("ports", "hop_interval"):
                    if getattr(node, attr) is not None:
                        result.add_error(
                            "This link cannot preserve port hopping",
                            field=attr, code="conversion.unsupported-platform-field",
                        )

        if isinstance(node, SSHNode) and self.platform in {"mihomo", "stash"} and node.server_fingerprints:
            result.add_error(
                "This target cannot preserve SSH server fingerprints",
                field="server_fingerprints", code="conversion.unsupported-platform-field",
            )
        if isinstance(node, ShadowsocksNode) and self.platform in {"mihomo", "clash", "stash", "dae", "v2rayn"} and node.udp_port is not None:
            result.add_error(
                "This target cannot preserve a separate UDP port",
                field="udp_port", code="conversion.unsupported-platform-field",
            )

        unsupported_fields: list[str] = []
        if self.platform != "surge":
            if node.surge_options != SurgePolicyOptions():
                unsupported_fields.append("surge_options")
            if node.shadow_tls.enabled:
                unsupported_fields.append("shadow_tls")
            if isinstance(node, VmessNode) and node.vmess_aead:
                unsupported_fields.append("vmess_aead")
            if isinstance(node, HttpNode) and node.always_use_connect is not None:
                unsupported_fields.append("always_use_connect")
            if isinstance(node, (ShadowsocksNode, SnellNode)) and node.obfs_uri:
                unsupported_fields.append("obfs_uri")
        if self.platform not in {"mihomo", "clash", "stash", "surge", "sing-box"}:
            if node.interface_name:
                unsupported_fields.append("interface_name")
        if self.platform not in {"mihomo", "clash", "stash", "surge"}:
            if node.users:
                unsupported_fields.append("users")
        if self.platform not in {"mihomo", "clash", "stash", "sing-box"} and (
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
