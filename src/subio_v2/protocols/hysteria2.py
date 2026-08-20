from __future__ import annotations

from subio_v2.conversion import IssueDraft, IssueSeverity
from subio_v2.model.nodes import Hysteria2Node, Node, Protocol
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
    protocol=Protocol.HYSTERIA2,
    node_class=Hysteria2Node,
    user_override_fields=frozenset({"server", "port", "password", "obfs_password"}),
    terminal_native_user_override_fields=frozenset({"server", "port", "password", "obfs_password"}),
    terminal_native_fields=frozenset({"down", "hop_interval", "obfs", "obfs_password", "password", "ports", "smux", "tls", "up"}),
)


class Hysteria2Codec(StructuredClashProtocolCodec):
    spec = SPEC
    stash_input_aliases = {
        "auth": "password",
        "up-speed": "up",
        "down-speed": "down",
    }
    stash_output_aliases = {
        "password": "auth",
        "up": "up-speed",
        "down": "down-speed",
    }

    def post_stash_emit(
        self, data: dict[str, object], node: Node
    ) -> tuple[dict[str, object], tuple[str, ...]]:
        from subio_v2.clash.stash import _mbps_value

        dropped: list[str] = []
        for key in ("up-speed", "down-speed"):
            if key not in data:
                continue
            value = _mbps_value(data[key])
            if value is None:
                data.pop(key, None)
                dropped.append(key)
            else:
                data[key] = value
        return data, tuple(sorted(dropped))
    protocol = Protocol.HYSTERIA2
    clash_dialects = frozenset({"mihomo", "stash"})
    clash_type = "hysteria2"
    dialect_fields = {
        "stash": stash_fields(
            "ports",
            "hop-interval",
            "auth",
            "fast-open",
            "obfs",
            "obfs-password",
            "up-speed",
            "down-speed",
            tls=True,
        )
    }
    target_constraints = {
        "mihomo": {"features": {"obfs"}},
        "stash": {
            "features": {"obfs"},
            "obfs_modes": {"salamander", "gecko"},
        },
    }
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


CODEC = Hysteria2Codec()
