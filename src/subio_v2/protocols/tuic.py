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
from subio_v2.model.nodes import Node, Protocol, TUICNode
from subio_v2.protocols import register
from subio_v2.protocols._base import ProtocolDescriptor


class TUICDescriptor(ProtocolDescriptor):
    protocol = Protocol.TUIC
    clash_type = "tuic"
    node_class = TUICNode

    def parse_clash(self, data: Dict[str, Any]) -> Node:
        tls = parse_tls(data, default_enabled=True)
        version = None
        if data.get("uuid") or data.get("password"):
            version = 5
        elif data.get("token"):
            version = 4
        handled = {
            "token",
            "uuid",
            "password",
            "smux",
            "tls",
            "sni",
            "skip-cert-verify",
            "fingerprint",
            "client-fingerprint",
            "alpn",
            "certificate",
            "private-key",
            "ech-opts",
            "disable-sni",
        }
        node = TUICNode(
            type=Protocol.TUIC,
            token=data.get("token"),
            password=data.get("password"),
            uuid=data.get("uuid"),
            version=version,
            tls=tls,
            smux=parse_smux(data),
            **parse_base_fields(data),
        )
        assign_extra(node, data, handled)
        return node

    def emit_clash(self, node: Node) -> Dict[str, Any]:
        if not isinstance(node, TUICNode):
            raise TypeError(f"Expected TUICNode, got {type(node)}")
        base = emit_base(node)
        if node.token:
            base["token"] = node.token
        if node.uuid:
            base["uuid"] = node.uuid
        if node.password:
            base["password"] = node.password
        emit_tls(base, node.tls)
        emit_smux(base, node.smux)
        return merge_extra(base, node)

    def check(self, node: Node, proto_caps: dict, platform: str) -> list[Any]:
        if not isinstance(node, TUICNode):
            return []
        from subio_v2.capabilities.checker import CapabilityWarning, WarningLevel

        warnings: list[Any] = []
        if node.version:
            supported_versions = proto_caps.get("versions", set())
            if supported_versions and node.version not in supported_versions:
                warnings.append(
                    CapabilityWarning(
                        level=WarningLevel.ERROR,
                        message=f"TUIC version {node.version} is not supported by {platform}",
                        field="version",
                        suggestion=(
                            f"Supported versions: {', '.join(str(v) for v in sorted(supported_versions))}"
                        ),
                    )
                )
        return warnings


register(TUICDescriptor())
