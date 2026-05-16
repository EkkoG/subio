from __future__ import annotations

from typing import Any, Dict

from subio_v2.clash.helpers import (
    assign_extra,
    emit_base,
    emit_smux,
    emit_tls,
    merge_extra,
    parse_base_fields,
    parse_smux,
    parse_tls,
)
from subio_v2.model.nodes import Hysteria2Node, Node, Protocol
from subio_v2.protocols import register
from subio_v2.protocols._base import ProtocolDescriptor


class Hysteria2Descriptor(ProtocolDescriptor):
    protocol = Protocol.HYSTERIA2
    clash_type = "hysteria2"
    node_class = Hysteria2Node

    def parse_clash(self, data: Dict[str, Any]) -> Node:
        tls = parse_tls(data)
        tls.enabled = True
        handled = {
            "password",
            "ports",
            "hop-interval",
            "up",
            "down",
            "obfs",
            "obfs-password",
            "sni",
            "skip-cert-verify",
            "fingerprint",
            "certificate",
            "private-key",
            "alpn",
            "ech-opts",
            "smux",
        }
        node = Hysteria2Node(
            type=Protocol.HYSTERIA2,
            password=data.get("password", ""),
            ports=data.get("ports"),
            hop_interval=data.get("hop-interval"),
            up=data.get("up"),
            down=data.get("down"),
            obfs=data.get("obfs"),
            obfs_password=data.get("obfs-password"),
            tls=tls,
            smux=parse_smux(data),
            **parse_base_fields(data),
        )
        assign_extra(node, data, handled)
        return node

    def emit_clash(self, node: Node) -> Dict[str, Any]:
        if not isinstance(node, Hysteria2Node):
            raise TypeError(f"Expected Hysteria2Node, got {type(node)}")
        base = emit_base(node)
        base["password"] = node.password
        if node.ports:
            base["ports"] = node.ports
        if node.hop_interval is not None:
            base["hop-interval"] = node.hop_interval
        if node.up:
            base["up"] = node.up
        if node.down:
            base["down"] = node.down
        if node.obfs:
            base["obfs"] = node.obfs
        if node.obfs_password:
            base["obfs-password"] = node.obfs_password
        emit_tls(base, node.tls)
        emit_smux(base, node.smux)
        return merge_extra(base, node)

    def check(self, node: Node, proto_caps: dict, platform: str) -> list[Any]:
        if not isinstance(node, Hysteria2Node):
            return []
        from subio_v2.capabilities.checker import CapabilityWarning, WarningLevel

        warnings: list[Any] = []
        if node.obfs and "obfs" not in proto_caps.get("features", set()):
            warnings.append(
                CapabilityWarning(
                    level=WarningLevel.WARNING,
                    message=f"Obfs is not supported for Hysteria2 on {platform}, will be ignored",
                    field="obfs",
                )
            )
        return warnings


register(Hysteria2Descriptor())
