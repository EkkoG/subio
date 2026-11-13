from subio_v2.adapters.clash_family.codecs._base import StructuredClashProtocolCodec
from subio_v2.adapters.clash_family.codecs._dialects import stash_fields
from subio_v2.adapters.clash_family.codecs._fields import (
    EmitPolicy,
    scalar_field,
    tls_group,
)
from subio_v2.core.nodes import Node, Protocol
from subio_v2.protocols.juicity import SPEC


class JuicityCodec(StructuredClashProtocolCodec):
    spec = SPEC

    def stash_lossless_default(self, node: Node, key: str, value: object) -> bool:
        return key == "udp" and node.udp

    protocol = Protocol.JUICITY
    clash_type = "juicity"
    dialect_fields = {
        "stash": stash_fields(
            "name",
            "type",
            "server",
            "port",
            "uuid",
            "password",
            "skip-cert-verify",
            "server-cert-fingerprint",
            "sni",
            "alpn",
            "dialer-proxy",
            "interface-name",
            endpoint=False,
        )
    }
    clash_dialects = frozenset({"stash"})
    fields = (
        scalar_field("uuid", default="", emit_policy=EmitPolicy.ALWAYS),
        scalar_field("password", default="", emit_policy=EmitPolicy.ALWAYS),
        tls_group(
            consumed_keys=(
                "sni",
                "skip-cert-verify",
                "fingerprint",
                "alpn",
            ),
            force_enabled=True,
        ),
    )


CODEC = JuicityCodec()
