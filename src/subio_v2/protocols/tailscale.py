from __future__ import annotations

from typing import Any, Dict

from subio_v2.conversion import IssueDraft, IssueSeverity
from subio_v2.model.nodes import Node, Protocol, TailscaleNode
from subio_v2.protocols._base import StructuredClashProtocolCodec
from subio_v2.protocols._dialects import stash_fields
from subio_v2.protocols._fields import EmitPolicy, scalar_field, smux_group


class TailscaleCodec(StructuredClashProtocolCodec):
    protocol = Protocol.TAILSCALE
    clash_dialects = frozenset({"mihomo", "stash"})
    clash_type = "tailscale"
    dialect_fields = {
        "stash": stash_fields(
            "name", "type", "auth-key", "hostname", "control-url",
            "ephemeral", "exit-node", endpoint=False,
        )
    }
    fields = (
        scalar_field("hostname", emit_policy=EmitPolicy.NOT_NONE),
        scalar_field("auth-key", "auth_key", emit_policy=EmitPolicy.NOT_NONE),
        scalar_field("control-url", "control_url", emit_policy=EmitPolicy.NOT_NONE),
        scalar_field("state-dir", "state_dir", emit_policy=EmitPolicy.NOT_NONE),
        scalar_field("ephemeral", default=False, emit_policy=EmitPolicy.ALWAYS),
        scalar_field(
            "accept-routes",
            "accept_routes",
            default=False,
            emit_policy=EmitPolicy.ALWAYS,
        ),
        scalar_field("exit-node", "exit_node", emit_policy=EmitPolicy.NOT_NONE),
        scalar_field(
            "exit-node-allow-lan-access",
            "exit_node_allow_lan_access",
            default=False,
            emit_policy=EmitPolicy.ALWAYS,
        ),
        smux_group(),
    )

    def prepare_parse_kwargs(
        self, data: Dict[str, Any], kwargs: Dict[str, Any]
    ) -> Dict[str, Any]:
        kwargs["server"] = None
        kwargs["port"] = None
        if "udp" not in data:
            kwargs["udp"] = False
        return kwargs

    def after_emit(self, out: Dict[str, Any], node: Node) -> None:
        out.pop("server", None)
        out.pop("port", None)
        if isinstance(node, TailscaleNode) and node.exit_node == "none":
            out.pop("exit-node", None)

    def after_parse(self, node: Node, data: Dict[str, Any]) -> Node:
        if (
            isinstance(node, TailscaleNode)
            and node.source_context is not None
            and node.source_context.dialect == "stash"
            and "exit-node" not in data
        ):
            node.exit_node_auto_fallback = True
        return node

    def check(self, node: Node, proto_caps: dict, platform: str) -> list[IssueDraft]:
        if not isinstance(node, TailscaleNode):
            return []
        warnings: list[IssueDraft] = []
        if platform == "surge":
            if node.exit_node_auto_fallback:
                warnings.append(
                    IssueDraft(
                        severity=IssueSeverity.ERROR,
                        message=(
                            "Stash automatic exit-node fallback has no equivalent "
                            "Surge selection semantics"
                        ),
                        field="exit_node_auto_fallback",
                        code="conversion.unsupported-protocol-variant",
                    )
                )
            interactive_reference = bool(
                node.source_extensions.get("surge", {}).get(
                    "interactive_state_reference"
                )
            )
            if not node.auth_key and not (
                node.interactive_login and interactive_reference
            ):
                warnings.append(
                    IssueDraft(
                        severity=IssueSeverity.ERROR,
                        message=(
                            "Surge Tailscale output requires an auth-key or an "
                            "existing Surge interactive-login state reference"
                        ),
                        field="auth_key",
                    )
                )
            if node.interface_name:
                warnings.append(
                    IssueDraft(
                        severity=IssueSeverity.ERROR,
                        message="Surge Tailscale does not support interface binding",
                        field="interface_name",
                    )
                )
            if node.exit_node == "auto:any":
                warnings.append(
                    IssueDraft(
                        severity=IssueSeverity.ERROR,
                        message=(
                            "Mihomo exit-node 'auto:any' has no equivalent Surge "
                            "selection semantics"
                        ),
                        field="exit_node",
                        code="conversion.unsupported-protocol-variant",
                    )
                )
            for field, value in (
                ("state_dir", node.state_dir),
                ("ephemeral", node.ephemeral),
                ("accept_routes", node.accept_routes),
                ("exit_node_allow_lan_access", node.exit_node_allow_lan_access),
                ("routing_mark", node.routing_mark),
            ):
                if value:
                    warnings.append(
                        IssueDraft(
                            severity=IssueSeverity.WARNING,
                            message=f"Tailscale field '{field}' is Mihomo-only",
                            field=field,
                            code="conversion.unconsumed-source-field",
                        )
                    )
        elif platform == "mihomo":
            if node.exit_node_auto_fallback:
                warnings.append(
                    IssueDraft(
                        severity=IssueSeverity.ERROR,
                        message=(
                            "Stash automatic exit-node fallback cannot be represented "
                            "by Mihomo"
                        ),
                        field="exit_node_auto_fallback",
                        code="conversion.unsupported-protocol-variant",
                    )
                )
            if node.interactive_login:
                warnings.append(
                    IssueDraft(
                        severity=IssueSeverity.ERROR,
                        message=(
                            "Surge interactive-login references local identity state "
                            "and cannot be converted to Mihomo"
                        ),
                        field="interactive_login",
                        code="conversion.unsupported-auth-profile",
                    )
                )
            if node.exit_node == "auto":
                warnings.append(
                    IssueDraft(
                        severity=IssueSeverity.ERROR,
                        message=(
                            "Surge exit-node 'auto' only selects an unambiguous "
                            "candidate and cannot be represented by Mihomo auto:any"
                        ),
                        field="exit_node",
                        code="conversion.unsupported-protocol-variant",
                    )
                )
            for field, value in (
                ("derp_only", node.derp_only),
                ("auto_add_magic_dns_rule", node.auto_add_magic_dns_rule),
                ("idle_keepalive", node.idle_keepalive),
                ("prefer_ipv6", node.prefer_ipv6),
                ("dns_servers", node.dns_servers),
                ("mtu", node.mtu),
            ):
                is_explicit_auto_rule = (
                    field == "auto_add_magic_dns_rule" and value is not None
                )
                if is_explicit_auto_rule or (value is not None and value is not False):
                    warnings.append(
                        IssueDraft(
                            severity=IssueSeverity.WARNING,
                            message=f"Tailscale field '{field}' is Surge-only",
                            field=field,
                            code="conversion.unconsumed-source-field",
                        )
                    )
        elif platform == "stash":
            if node.interactive_login:
                warnings.append(
                    IssueDraft(
                        severity=IssueSeverity.ERROR,
                        message=(
                            "Surge interactive-login references local identity state "
                            "and cannot be converted to Stash"
                        ),
                        field="interactive_login",
                        code="conversion.unsupported-auth-profile",
                    )
                )
            if node.exit_node in {"auto", "auto:any"}:
                warnings.append(
                    IssueDraft(
                        severity=IssueSeverity.ERROR,
                        message=(
                            f"Tailscale exit-node selector '{node.exit_node}' has no "
                            "equivalent Stash selection semantics"
                        ),
                        field="exit_node",
                        code="conversion.unsupported-protocol-variant",
                    )
                )
            elif node.exit_node is None and not node.exit_node_auto_fallback:
                warnings.append(
                    IssueDraft(
                        severity=IssueSeverity.ERROR,
                        message=(
                            "Omitting exit-node enables automatic selection in Stash, "
                            "which differs from the source node"
                        ),
                        field="exit_node_auto_fallback",
                        code="conversion.unsupported-protocol-variant",
                    )
                )
            for field, value in (
                ("state_dir", node.state_dir),
                ("accept_routes", node.accept_routes),
                (
                    "exit_node_allow_lan_access",
                    node.exit_node_allow_lan_access,
                ),
                ("derp_only", node.derp_only),
                ("auto_add_magic_dns_rule", node.auto_add_magic_dns_rule),
                ("idle_keepalive", node.idle_keepalive),
                ("prefer_ipv6", node.prefer_ipv6),
                ("dns_servers", node.dns_servers),
                ("mtu", node.mtu),
                ("routing_mark", node.routing_mark),
                ("smux", node.smux.enabled),
            ):
                is_explicit_auto_rule = (
                    field == "auto_add_magic_dns_rule" and value is not None
                )
                if is_explicit_auto_rule or (value is not None and value is not False):
                    warnings.append(
                        IssueDraft(
                            severity=IssueSeverity.WARNING,
                            message=(
                                f"Tailscale field '{field}' is not supported by Stash"
                            ),
                            field=field,
                            code="conversion.unconsumed-source-field",
                        )
                    )
        return warnings


CODEC = TailscaleCodec()
