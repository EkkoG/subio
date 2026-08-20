from __future__ import annotations

from subio_v2.conversion import IssueDraft, IssueSeverity
from subio_v2.model.nodes import HysteriaNode, Node, Protocol
from subio_v2.protocols._base import StructuredClashProtocolCodec
from subio_v2.protocols._dialects import stash_fields
from subio_v2.protocols._fields import (
    EmitPolicy,
    scalar_field,
    smux_group,
    tls_group,
)
from subio_v2.protocols.spec import ProtocolSpec

SPEC = ProtocolSpec(
    protocol=Protocol.HYSTERIA,
    node_class=HysteriaNode,
    user_override_fields=frozenset({"server", "port", "auth", "auth_str"}),
    terminal_native_user_override_fields=frozenset({"server", "port", "auth", "auth_str"}),
    terminal_native_fields=frozenset(
        {"auth", "auth_str", "down", "down_speed", "hop_interval", "hysteria_protocol", "obfs", "obfs_protocol", "ports", "smux", "tls", "up", "up_speed"}
    ),
)


class HysteriaCodec(StructuredClashProtocolCodec):
    spec = SPEC

    def post_stash_emit(
        self, data: dict[str, object], node: Node
    ) -> tuple[dict[str, object], tuple[str, ...]]:
        from subio_v2.clash.stash import _mbps_value

        dropped: list[str] = []
        for source, target in (("up", "up-speed"), ("down", "down-speed")):
            if source not in data:
                continue
            value = _mbps_value(data.pop(source))
            if target in data or value is None:
                dropped.append(source)
            else:
                data[target] = value
        return data, tuple(sorted(dropped))
    protocol = Protocol.HYSTERIA
    clash_dialects = frozenset({"mihomo", "stash"})
    clash_type = "hysteria"
    dialect_fields = {
        "stash": stash_fields(
            "ports",
            "hop-interval",
            "up-speed",
            "down-speed",
            "auth-str",
            "auth",
            "protocol",
            "obfs",
            tls=True,
        )
    }
    target_constraints = {
        "mihomo": {"features": {"obfs"}},
        "stash": {"features": {"obfs"}},
    }
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

    def check(self, node: Node, proto_caps: dict, platform: str) -> list[IssueDraft]:
        if not isinstance(node, HysteriaNode):
            return []
        warnings: list[IssueDraft] = []
        if node.obfs and "obfs" not in proto_caps.get("features", set()):
            warnings.append(
                IssueDraft(
                    severity=IssueSeverity.ERROR,
                    message=f"Obfs is not supported for Hysteria on {platform}",
                    field="obfs",
                )
            )
        return warnings


CODEC = HysteriaCodec()
