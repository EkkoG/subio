from __future__ import annotations

from subio_v2.core.nodes import Protocol, VlessNode
from subio_v2.protocols.spec import ProtocolSpec

SPEC = ProtocolSpec(
    protocol=Protocol.VLESS,
    required_fields=("uuid",),
    node_class=VlessNode,
    user_override_fields=frozenset({"server", "port", "uuid"}),
    terminal_native_user_override_fields=frozenset({"server", "port", "uuid"}),
    terminal_native_fields=frozenset(
        {"flow", "packet_encoding", "smux", "tls", "transport", "uuid"}
    ),
)
