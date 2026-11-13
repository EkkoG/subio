from __future__ import annotations

from subio_v2.adapters.clash_family.codecs._base import StructuredClashProtocolCodec
from subio_v2.adapters.clash_family.codecs._dialects import stash_fields
from subio_v2.adapters.clash_family.codecs._fields import (
    EmitPolicy,
    scalar_field,
    tls_group,
)
from subio_v2.core.nodes import Node, Protocol, Socks5Node
from subio_v2.core.results import IssueDraft, IssueSeverity
from subio_v2.protocols.socks5 import SPEC


class Socks5Codec(StructuredClashProtocolCodec):
    spec = SPEC
    protocol = Protocol.SOCKS5
    clash_dialects = frozenset({"mihomo", "clash", "stash"})
    clash_type = "socks5"
    dialect_fields = {"stash": stash_fields("username", "password", tls=True)}
    target_constraints = {
        "clash": {"features": {"tls"}},
        "mihomo": {"features": {"tls"}},
        "stash": {"features": {"tls"}},
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
