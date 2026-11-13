from __future__ import annotations

from subio_v2.adapters.clash_family.codecs._base import StructuredClashProtocolCodec
from subio_v2.adapters.clash_family.codecs._fields import (
    EmitPolicy,
    scalar_field,
    smux_group,
    tls_group,
)
from subio_v2.core.nodes import Protocol
from subio_v2.protocols.gost_relay import SPEC


class GostRelayCodec(StructuredClashProtocolCodec):
    spec = SPEC
    protocol = Protocol.GOST_RELAY
    clash_type = "gost-relay"
    target_constraints = {"mihomo": {"features": {"smux"}}}
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


CODEC = GostRelayCodec()
