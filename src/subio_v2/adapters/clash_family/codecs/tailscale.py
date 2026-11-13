from __future__ import annotations

from typing import Any, Dict

from subio_v2.adapters.clash_family.codecs._base import StructuredClashProtocolCodec
from subio_v2.adapters.clash_family.codecs._dialects import stash_fields
from subio_v2.adapters.clash_family.codecs._fields import (
    EmitPolicy,
    scalar_field,
    smux_group,
)
from subio_v2.core.nodes import Node, Protocol, TailscaleNode
from subio_v2.core.results import IssueDraft, IssueSeverity
from subio_v2.protocols.tailscale import SPEC


class TailscaleCodec(StructuredClashProtocolCodec):
    spec = SPEC

    def stash_lossless_default(self, node: Node, key: str, value: object) -> bool:
        return value is False and key in {
            "udp",
            "accept-routes",
            "exit-node-allow-lan-access",
        }

    protocol = Protocol.TAILSCALE
    clash_dialects = frozenset({"mihomo", "stash"})
    clash_type = "tailscale"
    dialect_fields = {
        "stash": stash_fields(
            "name",
            "type",
            "auth-key",
            "hostname",
            "control-url",
            "ephemeral",
            "exit-node",
            endpoint=False,
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

    def _check_mihomo(self, node: Node) -> list[IssueDraft]:
        warnings: list[IssueDraft] = []
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
        return warnings

    def _check_stash(self, node: Node) -> list[IssueDraft]:
        warnings: list[IssueDraft] = []
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
        if node.exit_node in {"auto", "auto:any", "none"}:
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

    def checker_for_target(self, target: str):
        return {"mihomo": self._check_mihomo, "stash": self._check_stash}[target]


CODEC = TailscaleCodec()
