from __future__ import annotations

from typing import Any

from subio_v2.model.nodes import Network, Node, Protocol, VmessNode
from subio_v2.protocols import register
from subio_v2.protocols._base import StructuredProtocolDescriptor
from subio_v2.protocols._fields import (
    EmitPolicy,
    scalar_field,
    smux_group,
    tls_group,
    transport_group,
)


class VmessDescriptor(StructuredProtocolDescriptor):
    protocol = Protocol.VMESS
    clash_type = "vmess"
    node_class = VmessNode
    fields = (
        scalar_field("uuid", default="", emit_policy=EmitPolicy.ALWAYS, required=True),
        scalar_field(
            "alterId",
            "alter_id",
            default=0,
            decode=lambda value: int(value or 0),
            emit_policy=EmitPolicy.ALWAYS,
        ),
        scalar_field("cipher", default="auto", emit_policy=EmitPolicy.ALWAYS),
        scalar_field(
            "global-padding",
            "global_padding",
            default=False,
            decode=bool,
            emit_policy=EmitPolicy.TRUTHY,
        ),
        scalar_field(
            "packet-encoding", "packet_encoding", emit_policy=EmitPolicy.TRUTHY
        ),
        tls_group(),
        transport_group(
            consumed_keys=(
                "network",
                "ws-opts",
                "h2-opts",
                "http-opts",
                "grpc-opts",
            )
        ),
        smux_group(),
    )

    def check(self, node: Node, proto_caps: dict, platform: str) -> list[Any]:
        if not isinstance(node, VmessNode):
            return []
        from subio_v2.capabilities.checker import CapabilityWarning, WarningLevel

        warnings: list[Any] = []
        supported_ciphers = proto_caps.get("ciphers", set())
        if node.cipher and node.cipher not in supported_ciphers:
            warnings.append(
                CapabilityWarning(
                    level=WarningLevel.ERROR,
                    message=f"Cipher '{node.cipher}' is not supported by {platform}",
                    field="cipher",
                )
            )

        supported_transports = proto_caps.get("transports", set())
        network = node.transport.network_value if node.transport else "tcp"
        unknown_network = node.transport and not isinstance(
            node.transport.network, Network
        )
        if (
            supported_transports
            and network not in supported_transports
            and not (platform == "mihomo" and unknown_network)
        ):
            warnings.append(
                CapabilityWarning(
                    level=WarningLevel.ERROR,
                    message=f"Transport '{network}' is not supported by {platform}",
                    field="transport.network",
                    suggestion=f"Supported transports: {', '.join(sorted(supported_transports))}",
                )
            )

        if (
            node.smux
            and node.smux.enabled
            and "smux" not in proto_caps.get("features", set())
        ):
            warnings.append(
                CapabilityWarning(
                    level=WarningLevel.WARNING,
                    message=f"SMUX is not supported by {platform}, will be ignored",
                    field="smux",
                )
            )
        if (
            node.tls
            and node.tls.reality_opts
            and "reality" not in proto_caps.get("features", set())
        ):
            warnings.append(
                CapabilityWarning(
                    level=WarningLevel.ERROR,
                    message=f"Reality is not supported for VMess on {platform}",
                    field="reality",
                )
            )
        return warnings


register(VmessDescriptor())
