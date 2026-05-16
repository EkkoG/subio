from __future__ import annotations

from typing import Any, Dict

from subio_v2.clash.helpers import (
    assign_extra,
    emit_base,
    emit_smux,
    emit_tls,
    emit_transport,
    merge_extra,
    parse_base_fields,
    parse_smux,
    parse_tls,
    parse_transport,
)
from subio_v2.model.nodes import Node, Protocol, TrojanNode
from subio_v2.protocols import register
from subio_v2.protocols._base import ProtocolDescriptor


class TrojanDescriptor(ProtocolDescriptor):
    protocol = Protocol.TROJAN
    clash_type = "trojan"
    node_class = TrojanNode

    def parse_clash(self, data: Dict[str, Any]) -> Node:
        tls = parse_tls(data)
        if data.get("network") == "grpc":
            tls.enabled = True
        handled = {
            "password",
            "tls",
            "servername",
            "sni",
            "alpn",
            "skip-cert-verify",
            "fingerprint",
            "client-fingerprint",
            "reality-opts",
            "ech-opts",
            "certificate",
            "private-key",
            "network",
            "ws-opts",
            "h2-opts",
            "http-opts",
            "grpc-opts",
            "smux",
        }
        node = TrojanNode(
            type=Protocol.TROJAN,
            password=data.get("password", ""),
            tls=tls,
            transport=parse_transport(data),
            smux=parse_smux(data),
            **parse_base_fields(data),
        )
        assign_extra(node, data, handled)
        return node

    def emit_clash(self, node: Node) -> Dict[str, Any]:
        if not isinstance(node, TrojanNode):
            raise TypeError(f"Expected TrojanNode, got {type(node)}")
        base = emit_base(node)
        base["password"] = node.password
        emit_tls(base, node.tls)
        emit_transport(base, node.transport)
        emit_smux(base, node.smux)
        return merge_extra(base, node)

    def check(self, node: Node, proto_caps: dict, platform: str) -> list[Any]:
        if not isinstance(node, TrojanNode):
            return []
        from subio_v2.capabilities.checker import CapabilityWarning, WarningLevel

        warnings: list[Any] = []
        supported_transports = proto_caps.get("transports", set())
        network = node.transport.network.value if node.transport and node.transport.network else "tcp"
        if supported_transports and network not in supported_transports:
            warnings.append(
                CapabilityWarning(
                    level=WarningLevel.ERROR,
                    message=f"Transport '{network}' is not supported by {platform}",
                    field="transport.network",
                    suggestion=f"Supported transports: {', '.join(sorted(supported_transports))}",
                )
            )
        if node.smux and node.smux.enabled and "smux" not in proto_caps.get("features", set()):
            warnings.append(
                CapabilityWarning(
                    level=WarningLevel.WARNING,
                    message=f"SMUX is not supported by {platform}, will be ignored",
                    field="smux",
                )
            )
        return warnings


register(TrojanDescriptor())
