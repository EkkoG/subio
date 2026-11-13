from __future__ import annotations

from subio_v2.core.nodes import DNSNode, Protocol
from subio_v2.protocols.spec import ProtocolSpec

SPEC = ProtocolSpec(
    protocol=Protocol.DNS,
    node_class=DNSNode,
    requires_endpoint=False,
    user_override_fields=frozenset({"server", "port"}),
    terminal_native_fields=frozenset({"smux"}),
)
