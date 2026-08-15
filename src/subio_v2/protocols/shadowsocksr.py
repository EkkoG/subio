from __future__ import annotations

from typing import Any

from subio_v2.model.nodes import Node, Protocol, ShadowsocksRNode
from subio_v2.protocols import register
from subio_v2.protocols._base import StructuredProtocolDescriptor
from subio_v2.protocols._fields import EmitPolicy, scalar_field, smux_group


class ShadowsocksRDescriptor(StructuredProtocolDescriptor):
    protocol = Protocol.SHADOWSOCKSR
    clash_type = "ssr"
    node_class = ShadowsocksRNode
    fields = (
        scalar_field(
            "cipher", default="", emit_policy=EmitPolicy.ALWAYS, required=True
        ),
        scalar_field(
            "password", default="", emit_policy=EmitPolicy.ALWAYS, required=True
        ),
        scalar_field("obfs", default="", emit_policy=EmitPolicy.ALWAYS),
        scalar_field(
            "protocol", "ssr_protocol", default="", emit_policy=EmitPolicy.ALWAYS
        ),
        scalar_field("obfs-param", "obfs_param", emit_policy=EmitPolicy.TRUTHY),
        scalar_field("protocol-param", "protocol_param", emit_policy=EmitPolicy.TRUTHY),
        smux_group(),
    )

    def check(self, node: Node, proto_caps: dict, platform: str) -> list[Any]:
        if not isinstance(node, ShadowsocksRNode):
            return []
        supported_ciphers = proto_caps.get("ciphers", set())
        if not supported_ciphers or node.cipher in supported_ciphers:
            return []
        from subio_v2.capabilities.checker import CapabilityWarning, WarningLevel

        return [
            CapabilityWarning(
                level=WarningLevel.ERROR,
                message=f"Cipher '{node.cipher}' is not supported by {platform}",
                field="cipher",
                suggestion=f"Supported ciphers: {', '.join(sorted(supported_ciphers))}",
            )
        ]


register(ShadowsocksRDescriptor())
