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
from subio_v2.model.nodes import Node, Protocol, VmessNode
from subio_v2.protocols import register
from subio_v2.protocols._base import ProtocolDescriptor


class VmessDescriptor(ProtocolDescriptor):
    protocol = Protocol.VMESS
    clash_type = "vmess"
    node_class = VmessNode

    def parse_clash(self, data: Dict[str, Any]) -> Node:
        tls = parse_tls(data)
        if data.get("network") == "grpc":
            tls.enabled = True
        handled = {
            "uuid",
            "alterId",
            "cipher",
            "global-padding",
            "packet-encoding",
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
        node = VmessNode(
            type=Protocol.VMESS,
            uuid=data.get("uuid", ""),
            alter_id=int(data.get("alterId", 0) or 0),
            cipher=data.get("cipher", "auto"),
            global_padding=bool(data.get("global-padding", False)),
            packet_encoding=data.get("packet-encoding"),
            tls=tls,
            transport=parse_transport(data),
            smux=parse_smux(data),
            **parse_base_fields(data),
        )
        assign_extra(node, data, handled)
        return node

    def emit_clash(self, node: Node) -> Dict[str, Any]:
        if not isinstance(node, VmessNode):
            raise TypeError(f"Expected VmessNode, got {type(node)}")
        base = emit_base(node)
        base.update(
            {
                "uuid": node.uuid,
                "alterId": node.alter_id,
                "cipher": node.cipher,
            }
        )
        if node.global_padding:
            base["global-padding"] = True
        if node.packet_encoding:
            base["packet-encoding"] = node.packet_encoding
        emit_tls(base, node.tls)
        emit_transport(base, node.transport)
        emit_smux(base, node.smux)
        return merge_extra(base, node)

    def check(self, node: Node, proto_caps: dict, platform: str) -> list[Any]:
        if not isinstance(node, VmessNode):
            return []
        from subio_v2.capabilities.checker import CapabilityWarning, WarningLevel

        warnings: list[Any] = []
        supported_ciphers = proto_caps.get("ciphers", set())
        if node.cipher and node.cipher not in supported_ciphers:
            warnings.append(
                CapabilityWarning(
                    level=WarningLevel.WARNING,
                    message=f"Cipher '{node.cipher}' may not be supported, using 'auto'",
                    field="cipher",
                )
            )

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


register(VmessDescriptor())
