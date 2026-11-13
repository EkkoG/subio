from __future__ import annotations

from subio_v2.core.nodes import Protocol, RejectNode
from subio_v2.protocols.spec import ProtocolSpec

SPEC = ProtocolSpec(
    protocol=Protocol.REJECT,
    node_class=RejectNode,
    requires_endpoint=False,
    user_override_fields=frozenset({"server", "port"}),
    terminal_native_fields=frozenset({"mode", "smux"}),
)
