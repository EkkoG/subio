from __future__ import annotations

from subio_v2.conversion import IssueDraft, IssueSeverity
from subio_v2.model.nodes import Node, Protocol, Socks5Node
from subio_v2.protocols._base import StructuredClashProtocolCodec
from subio_v2.protocols._dialects import stash_fields
from subio_v2.protocols._fields import EmitPolicy, scalar_field, tls_group
from subio_v2.protocols.spec import ProtocolSpec

SPEC = ProtocolSpec(
    protocol=Protocol.SOCKS5,
    node_class=Socks5Node,
    user_override_fields=frozenset({"server", "port", "username", "password"}),
    terminal_native_user_override_fields=frozenset({"server", "port", "username", "password"}),
    terminal_native_fields=frozenset({"password", "tls", "username"}),
)


class Socks5Codec(StructuredClashProtocolCodec):
    spec = SPEC
    protocol = Protocol.SOCKS5
    clash_dialects = frozenset({"mihomo", "clash", "stash"})
    clash_type = "socks5"
    dialect_fields = {
        "stash": stash_fields("username", "password", tls=True)
    }
    target_constraints = {
        "clash": {"features": {"tls"}},
        "mihomo": {"features": {"tls"}},
        "stash": {"features": {"tls"}},
        "surge": {"features": {"tls"}},
    }
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

    def check(self, node: Node, proto_caps: dict, platform: str) -> list[IssueDraft]:
        if not isinstance(node, Socks5Node):
            return []
        if not node.tls or not node.tls.enabled:
            return []
        if "tls" in proto_caps.get("features", set()):
            return []

        return [
            IssueDraft(
                severity=IssueSeverity.ERROR,
                message=f"SOCKS5 TLS is not supported by {platform}",
                field="tls",
            )
        ]


CODEC = Socks5Codec()
