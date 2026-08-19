from __future__ import annotations

from subio_v2.model.nodes import Protocol
from subio_v2.protocols import register
from subio_v2.protocols._base import StructuredProtocolDescriptor
from subio_v2.protocols._fields import (
    EmitPolicy,
    scalar_field,
    smux_group,
    tls_group,
)


class GostRelayDescriptor(StructuredProtocolDescriptor):
    protocol = Protocol.GOST_RELAY
    clash_type = "gost-relay"
    fields = (
        scalar_field("forward", default=False, emit_policy=EmitPolicy.ALWAYS),
        scalar_field("mux", default=False, emit_policy=EmitPolicy.ALWAYS),
        scalar_field("username", emit_policy=EmitPolicy.NOT_NONE),
        scalar_field("password", emit_policy=EmitPolicy.NOT_NONE),
        tls_group(
            consumed_keys=(
                "tls",
                "sni",
                "skip-cert-verify",
                "name-cert-verify",
                "fingerprint",
                "certificate",
                "private-key",
                "client-fingerprint",
            )
        ),
        smux_group(),
    )


register(GostRelayDescriptor())
