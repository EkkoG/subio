from __future__ import annotations

from subio_v2.model.nodes import AnyTLSNode, Protocol
from subio_v2.protocols import register
from subio_v2.protocols._base import StructuredProtocolDescriptor
from subio_v2.protocols._fields import EmitPolicy, scalar_field, tls_group


class AnyTLSDescriptor(StructuredProtocolDescriptor):
    protocol = Protocol.ANYTLS
    clash_type = "anytls"
    node_class = AnyTLSNode
    fields = (
        scalar_field(
            "password", default="", emit_policy=EmitPolicy.ALWAYS, required=True
        ),
        tls_group(
            consumed_keys=(
                "sni",
                "skip-cert-verify",
                "fingerprint",
                "client-fingerprint",
                "alpn",
                "certificate",
                "private-key",
            ),
            force_enabled=True,
        ),
        scalar_field(
            "idle-session-check-interval",
            "idle_session_check_interval",
            emit_policy=EmitPolicy.NOT_NONE,
        ),
        scalar_field(
            "idle-session-timeout",
            "idle_session_timeout",
            emit_policy=EmitPolicy.NOT_NONE,
        ),
        scalar_field(
            "min-idle-session",
            "min_idle_session",
            emit_policy=EmitPolicy.NOT_NONE,
        ),
    )


register(AnyTLSDescriptor())
