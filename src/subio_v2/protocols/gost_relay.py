from __future__ import annotations

from subio_v2.model.nodes import GostRelayNode, Protocol
from subio_v2.protocols._base import StructuredClashProtocolCodec
from subio_v2.protocols._fields import (
    EmitPolicy,
    scalar_field,
    smux_group,
    tls_group,
)
from subio_v2.protocols.spec import ProtocolSpec

SPEC = ProtocolSpec(
    protocol=Protocol.GOST_RELAY,
    node_class=GostRelayNode,
    user_override_fields=frozenset({"server", "port", "username", "password"}),
    terminal_native_user_override_fields=frozenset(
        {"server", "port", "username", "password"}
    ),
    terminal_native_fields=frozenset({"forward", "mux", "password", "smux", "tls", "username"}),
)


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
