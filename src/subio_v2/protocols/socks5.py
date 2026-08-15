from __future__ import annotations

from typing import Any

from subio_v2.model.nodes import Node, Protocol, Socks5Node
from subio_v2.protocols import register
from subio_v2.protocols._base import StructuredProtocolDescriptor
from subio_v2.protocols._fields import EmitPolicy, scalar_field, tls_group


class Socks5Descriptor(StructuredProtocolDescriptor):
    protocol = Protocol.SOCKS5
    clash_type = "socks5"
    node_class = Socks5Node
    fields = (
        scalar_field("username", emit_policy=EmitPolicy.TRUTHY),
        scalar_field("password", emit_policy=EmitPolicy.TRUTHY),
        tls_group(
            consumed_keys=(
                "tls",
                "sni",
                "skip-cert-verify",
                "fingerprint",
                "client-fingerprint",
                "name-cert-verify",
                "alpn",
                "certificate",
                "private-key",
            )
        ),
    )

    def check(self, node: Node, proto_caps: dict, platform: str) -> list[Any]:
        if not isinstance(node, Socks5Node):
            return []
        if not node.tls or not node.tls.enabled:
            return []
        if "tls" in proto_caps.get("features", set()):
            return []

        from subio_v2.capabilities.checker import CapabilityWarning, WarningLevel

        return [
            CapabilityWarning(
                level=WarningLevel.ERROR,
                message=f"SOCKS5 TLS is not supported by {platform}",
                field="tls",
            )
        ]


register(Socks5Descriptor())
