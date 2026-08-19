from subio_v2.model.nodes import Protocol
from subio_v2.protocols._base import StructuredClashProtocolCodec
from subio_v2.protocols._dialects import stash_fields
from subio_v2.protocols._fields import EmitPolicy, scalar_field, tls_group


class JuicityCodec(StructuredClashProtocolCodec):
    protocol = Protocol.JUICITY
    clash_type = "juicity"
    dialect_fields = {
        "stash": stash_fields(
            "name", "type", "server", "port", "uuid", "password",
            "skip-cert-verify", "server-cert-fingerprint", "sni", "alpn",
            "dialer-proxy", "interface-name", endpoint=False,
        )
    }
    clash_dialects = frozenset({"stash"})
    fields = (
        scalar_field("uuid", default="", emit_policy=EmitPolicy.ALWAYS, required=True),
        scalar_field(
            "password", default="", emit_policy=EmitPolicy.ALWAYS, required=True
        ),
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
