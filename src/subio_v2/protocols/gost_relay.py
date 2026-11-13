from __future__ import annotations

from subio_v2.core.nodes import GostRelayNode, Protocol
from subio_v2.protocols.spec import ProtocolSpec

SPEC = ProtocolSpec(
    protocol=Protocol.GOST_RELAY,
    node_class=GostRelayNode,
    user_override_fields=frozenset({"server", "port", "username", "password"}),
    terminal_native_user_override_fields=frozenset(
        {"server", "port", "username", "password"}
    ),
    terminal_native_fields=frozenset(
        {"forward", "mux", "password", "smux", "tls", "username"}
    ),
)
