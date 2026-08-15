from __future__ import annotations

from collections.abc import Mapping, MutableMapping
from typing import Any, Dict

from subio_v2.model.nodes import MasqueMode, MasqueNode, Node, Protocol
from subio_v2.protocols import register
from subio_v2.protocols._base import NodeValidationError, StructuredProtocolDescriptor
from subio_v2.protocols._fields import (
    EmitPolicy,
    field_group,
    scalar_field,
    smux_group,
    tls_group,
)


def _parse_network(data: Mapping[str, Any]) -> dict[str, Any]:
    network = str(data.get("network") or "quic")
    if network == "h3-l4proxy":
        return {"mode": MasqueMode.H3_L4_PROXY, "transport": "h3"}
    if network == "h2":
        return {"mode": MasqueMode.CONNECT_IP, "transport": "h2"}
    if network == "quic":
        return {"mode": MasqueMode.CONNECT_IP, "transport": "h3"}
    return {"mode": MasqueMode.CONNECT_IP, "transport": network}


def _emit_network(out: MutableMapping[str, Any], node: Node) -> None:
    assert isinstance(node, MasqueNode)
    if node.mode == MasqueMode.H3_L4_PROXY:
        out["network"] = "h3-l4proxy"
    elif node.mode == MasqueMode.CONNECT_IP and node.transport == "h2":
        out["network"] = "h2"
    elif node.mode == MasqueMode.CONNECT_IP and node.transport != "h3":
        out["network"] = node.transport
    elif node.mode != MasqueMode.CONNECT_IP:
        raise ValueError("Unsupported Mihomo MASQUE mode or transport")


class MasqueDescriptor(StructuredProtocolDescriptor):
    protocol = Protocol.MASQUE
    clash_type = "masque"
    node_class = MasqueNode
    fields = (
        scalar_field("private-key", "private_key", emit_policy=EmitPolicy.NOT_NONE),
        scalar_field("public-key", "public_key", emit_policy=EmitPolicy.NOT_NONE),
        scalar_field("ip", "interface_ip", emit_policy=EmitPolicy.NOT_NONE),
        scalar_field("ipv6", "interface_ipv6", emit_policy=EmitPolicy.NOT_NONE),
        scalar_field("mtu", emit_policy=EmitPolicy.NOT_NONE),
        scalar_field(
            "remote-dns-resolve",
            "remote_dns_resolve",
            default=False,
            emit_policy=EmitPolicy.ALWAYS,
        ),
        scalar_field("dns", "dns_servers", emit_policy=EmitPolicy.NOT_NONE),
        scalar_field(
            "congestion-controller",
            "congestion_controller",
            emit_policy=EmitPolicy.NOT_NONE,
        ),
        scalar_field("cwnd", emit_policy=EmitPolicy.NOT_NONE),
        scalar_field("bbr-profile", "bbr_profile", emit_policy=EmitPolicy.NOT_NONE),
        scalar_field(
            "handshake-timeout", "handshake_timeout", emit_policy=EmitPolicy.NOT_NONE
        ),
        field_group(
            consumed_keys=("network",),
            node_attrs=("mode", "transport"),
            parse_kwargs=_parse_network,
            emit_into=_emit_network,
        ),
        tls_group(
            consumed_keys=(
                "sni",
                "skip-cert-verify",
                "fingerprint",
                "client-fingerprint",
                "alpn",
                "ech-opts",
            ),
            force_enabled=True,
        ),
        smux_group(),
    )

    def prepare_parse_kwargs(
        self, data: Dict[str, Any], kwargs: Dict[str, Any]
    ) -> Dict[str, Any]:
        if "udp" not in data:
            kwargs["udp"] = False
        return kwargs

    def after_emit(self, out: Dict[str, Any], node: Node) -> None:
        out.pop("tls", None)

    def validate(self, node: Node) -> list[NodeValidationError]:
        errors = super().validate(node)
        if not isinstance(node, MasqueNode):
            return errors
        if node.mode == MasqueMode.FORWARD_PROXY:
            if bool(node.username) != bool(node.password):
                errors.append(
                    NodeValidationError(
                        "username",
                        "MASQUE Basic authentication requires both username and password",
                    )
                )
            return errors
        for field in ("private_key", "public_key"):
            if not getattr(node, field):
                errors.append(
                    NodeValidationError(
                        field, f"MASQUE {node.mode.value} requires {field}"
                    )
                )
        if node.mode == MasqueMode.CONNECT_IP and not (
            node.interface_ip or node.interface_ipv6
        ):
            errors.append(
                NodeValidationError(
                    "interface_ip",
                    "MASQUE CONNECT-IP requires an IPv4 or IPv6 tunnel address",
                )
            )
        if node.mode == MasqueMode.H3_L4_PROXY and node.udp:
            errors.append(
                NodeValidationError(
                    "udp", "Mihomo h3-l4proxy mode does not support UDP"
                )
            )
        return errors

    def check(self, node: Node, proto_caps: dict, platform: str) -> list[Any]:
        if not isinstance(node, MasqueNode):
            return []
        from subio_v2.capabilities.checker import CapabilityWarning, WarningLevel

        supported = {
            "surge": {MasqueMode.FORWARD_PROXY},
            "clash-meta": {MasqueMode.CONNECT_IP, MasqueMode.H3_L4_PROXY},
        }.get(platform)
        if supported is not None and node.mode not in supported:
            return [
                CapabilityWarning(
                    level=WarningLevel.ERROR,
                    message=(
                        f"MASQUE mode '{node.mode.value}' is not supported by {platform}"
                    ),
                    field="mode",
                    code="conversion.unsupported-protocol-variant",
                )
            ]
        return []


register(MasqueDescriptor())
