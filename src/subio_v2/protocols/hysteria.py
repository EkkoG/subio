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
from subio_v2.model.nodes import HysteriaNode, Node, Protocol
from subio_v2.protocols import register
from subio_v2.protocols._base import ProtocolDescriptor


class HysteriaDescriptor(ProtocolDescriptor):
    protocol = Protocol.HYSTERIA
    clash_type = "hysteria"
    node_class = HysteriaNode

    def parse_clash(self, data: Dict[str, Any]) -> Node:
        tls = parse_tls(data, default_enabled=True)
        handled = {
            "ports",
            "protocol",
            "obfs-protocol",
            "up",
            "down",
            "up-speed",
            "down-speed",
            "auth-str",
            "auth",
            "obfs",
            "sni",
            "skip-cert-verify",
            "fingerprint",
            "certificate",
            "private-key",
            "alpn",
            "ech-opts",
            "hop-interval",
            "recv-window-conn",
            "recv-window",
            "disable-mtu-discovery",
            "fast-open",
            "smux",
        }
        node = HysteriaNode(
            type=Protocol.HYSTERIA,
            ports=data.get("ports"),
            hysteria_protocol=data.get("protocol"),
            obfs_protocol=data.get("obfs-protocol"),
            up=data.get("up", ""),
            down=data.get("down", ""),
            up_speed=data.get("up-speed"),
            down_speed=data.get("down-speed"),
            auth_str=data.get("auth-str"),
            auth=data.get("auth"),
            obfs=data.get("obfs"),
            hop_interval=data.get("hop-interval"),
            tls=tls,
            smux=parse_smux(data),
            **parse_base_fields(data),
        )
        assign_extra(node, data, handled)
        return node

    def emit_clash(self, node: Node) -> Dict[str, Any]:
        if not isinstance(node, HysteriaNode):
            raise TypeError(f"Expected HysteriaNode, got {type(node)}")
        base = emit_base(node)
        if node.ports:
            base["ports"] = node.ports
        if node.hysteria_protocol:
            base["protocol"] = node.hysteria_protocol
        if node.obfs_protocol:
            base["obfs-protocol"] = node.obfs_protocol
        if node.up:
            base["up"] = node.up
        if node.down:
            base["down"] = node.down
        if node.up_speed is not None:
            base["up-speed"] = node.up_speed
        if node.down_speed is not None:
            base["down-speed"] = node.down_speed
        if node.auth_str:
            base["auth-str"] = node.auth_str
        if node.auth:
            base["auth"] = node.auth
        if node.obfs:
            base["obfs"] = node.obfs
        if node.hop_interval is not None:
            base["hop-interval"] = node.hop_interval
        emit_tls(base, node.tls)
        emit_smux(base, node.smux)
        return merge_extra(base, node)

    def check(self, node: Node, proto_caps: dict, platform: str) -> list[Any]:
        if not isinstance(node, HysteriaNode):
            return []
        from subio_v2.capabilities.checker import CapabilityWarning, WarningLevel

        warnings: list[Any] = []
        if node.obfs and "obfs" not in proto_caps.get("features", set()):
            warnings.append(
                CapabilityWarning(
                    level=WarningLevel.WARNING,
                    message=f"Obfs is not supported for Hysteria on {platform}, will be ignored",
                    field="obfs",
                )
            )
        return warnings


register(HysteriaDescriptor())
