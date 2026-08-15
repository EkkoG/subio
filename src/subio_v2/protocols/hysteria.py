from __future__ import annotations

from typing import Any

from subio_v2.model.nodes import HysteriaNode, Node, Protocol
from subio_v2.protocols import register
from subio_v2.protocols._base import StructuredProtocolDescriptor
from subio_v2.protocols._fields import (
    EmitPolicy,
    scalar_field,
    smux_group,
    tls_group,
)


class HysteriaDescriptor(StructuredProtocolDescriptor):
    protocol = Protocol.HYSTERIA
    clash_type = "hysteria"
    node_class = HysteriaNode
    fields = (
        scalar_field("ports", emit_policy=EmitPolicy.TRUTHY),
        scalar_field("protocol", "hysteria_protocol", emit_policy=EmitPolicy.TRUTHY),
        scalar_field("obfs-protocol", "obfs_protocol", emit_policy=EmitPolicy.TRUTHY),
        scalar_field("up", default="", emit_policy=EmitPolicy.TRUTHY),
        scalar_field("down", default="", emit_policy=EmitPolicy.TRUTHY),
        scalar_field("up-speed", "up_speed", emit_policy=EmitPolicy.NOT_NONE),
        scalar_field("down-speed", "down_speed", emit_policy=EmitPolicy.NOT_NONE),
        scalar_field("auth-str", "auth_str", emit_policy=EmitPolicy.TRUTHY),
        scalar_field("auth", emit_policy=EmitPolicy.TRUTHY),
        scalar_field("obfs", emit_policy=EmitPolicy.TRUTHY),
        scalar_field("hop-interval", "hop_interval", emit_policy=EmitPolicy.NOT_NONE),
        tls_group(
            consumed_keys=(
                "sni",
                "skip-cert-verify",
                "fingerprint",
                "name-cert-verify",
                "certificate",
                "private-key",
                "alpn",
                "ech-opts",
            ),
            default_enabled=True,
        ),
        smux_group(),
    )

    def check(self, node: Node, proto_caps: dict, platform: str) -> list[Any]:
        if not isinstance(node, HysteriaNode):
            return []
        from subio_v2.capabilities.checker import CapabilityWarning, WarningLevel

        warnings: list[Any] = []
        if node.obfs and "obfs" not in proto_caps.get("features", set()):
            warnings.append(
                CapabilityWarning(
                    level=WarningLevel.ERROR,
                    message=f"Obfs is not supported for Hysteria on {platform}",
                    field="obfs",
                )
            )
        return warnings


register(HysteriaDescriptor())
