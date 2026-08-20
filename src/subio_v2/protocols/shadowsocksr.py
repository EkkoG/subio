from __future__ import annotations

from subio_v2.core.results import IssueDraft, IssueSeverity
from subio_v2.core.nodes import Node, Protocol, ShadowsocksRNode
from subio_v2.protocols._base import StructuredClashProtocolCodec
from subio_v2.protocols._dialects import stash_fields
from subio_v2.protocols._fields import EmitPolicy, scalar_field, smux_group
from subio_v2.protocols.spec import ProtocolSpec
from subio_v2.protocols.values import SS_CIPHERS_STASH

SPEC = ProtocolSpec(
    protocol=Protocol.SHADOWSOCKSR,
    node_class=ShadowsocksRNode,
    user_override_fields=frozenset({"server", "port", "cipher", "password"}),
    terminal_native_user_override_fields=frozenset({"server", "port", "cipher", "password"}),
    terminal_native_fields=frozenset({"cipher", "obfs", "obfs_param", "password", "protocol_param", "smux", "ssr_protocol"}),
)


class ShadowsocksRCodec(StructuredClashProtocolCodec):
    spec = SPEC
    protocol = Protocol.SHADOWSOCKSR
    clash_dialects = frozenset({"mihomo", "stash"})
    clash_type = "ssr"
    dialect_fields = {
        "stash": stash_fields(
            "cipher",
            "password",
            "obfs",
            "protocol",
            "obfs-param",
            "protocol-param",
        )
    }
    target_constraints = {"stash": {"ciphers": SS_CIPHERS_STASH}}
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

    def check(self, node: Node, proto_caps: dict, platform: str) -> list[IssueDraft]:
        if not isinstance(node, ShadowsocksRNode):
            return []
        supported_ciphers = proto_caps.get("ciphers", set())
        if not supported_ciphers or node.cipher in supported_ciphers:
            return []
        return [
            IssueDraft(
                severity=IssueSeverity.ERROR,
                message=f"Cipher '{node.cipher}' is not supported by {platform}",
                field="cipher",
                suggestion=f"Supported ciphers: {', '.join(sorted(supported_ciphers))}",
            )
        ]


CODEC = ShadowsocksRCodec()
