from subio_v2.model.nodes import JuicityNode, Protocol
from subio_v2.protocols import register
from subio_v2.protocols._base import StructuredProtocolDescriptor
from subio_v2.protocols._fields import EmitPolicy, scalar_field, tls_group


class JuicityDescriptor(StructuredProtocolDescriptor):
    protocol = Protocol.JUICITY
    clash_type = "juicity"
    node_class = JuicityNode
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


register(JuicityDescriptor())
