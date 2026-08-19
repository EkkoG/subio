from __future__ import annotations

from subio_v2.conversion import IssueDraft, IssueSeverity
from subio_v2.model.nodes import Hysteria2Node, Node, Protocol
from subio_v2.protocols._base import StructuredProtocolDescriptor
from subio_v2.protocols._fields import (
    EmitPolicy,
    scalar_field,
    smux_group,
    tls_group,
)


class Hysteria2Descriptor(StructuredProtocolDescriptor):
    protocol = Protocol.HYSTERIA2
    clash_type = "hysteria2"
    fields = (
        scalar_field(
            "password", default="", emit_policy=EmitPolicy.ALWAYS, required=True
        ),
        scalar_field("ports", emit_policy=EmitPolicy.TRUTHY),
        scalar_field("hop-interval", "hop_interval", emit_policy=EmitPolicy.NOT_NONE),
        scalar_field("up", emit_policy=EmitPolicy.TRUTHY),
        scalar_field("down", emit_policy=EmitPolicy.TRUTHY),
        scalar_field("obfs", emit_policy=EmitPolicy.TRUTHY),
        scalar_field("obfs-password", "obfs_password", emit_policy=EmitPolicy.TRUTHY),
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
            force_enabled=True,
        ),
        smux_group(),
    )

    def check(self, node: Node, proto_caps: dict, platform: str) -> list[IssueDraft]:
        if not isinstance(node, Hysteria2Node):
            return []
        warnings: list[IssueDraft] = []
        if node.obfs and "obfs" not in proto_caps.get("features", set()):
            warnings.append(
                IssueDraft(
                    severity=IssueSeverity.ERROR,
                    message=f"Obfs is not supported for Hysteria2 on {platform}",
                    field="obfs",
                )
            )
        elif node.obfs:
            supported_modes = proto_caps.get("obfs_modes", set())
            if supported_modes and node.obfs not in supported_modes:
                warnings.append(
                    IssueDraft(
                        severity=IssueSeverity.ERROR,
                        message=(
                            f"Hysteria2 obfs mode '{node.obfs}' is not supported by {platform}"
                        ),
                        field="obfs",
                    )
                )
            if not node.obfs_password:
                warnings.append(
                    IssueDraft(
                        severity=IssueSeverity.ERROR,
                        message="Hysteria2 obfs requires a password",
                        field="obfs_password",
                    )
                )
        if platform != "stash" and node.dialer_proxy and node.ports:
            warnings.append(
                IssueDraft(
                    severity=IssueSeverity.ERROR,
                    message="Hysteria2 port hopping cannot be combined with underlying-proxy",
                    field="ports",
                )
            )
        return warnings


DESCRIPTOR = Hysteria2Descriptor()
