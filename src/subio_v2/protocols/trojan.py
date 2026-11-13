from __future__ import annotations

from subio_v2.core.nodes import Protocol, TrojanNode
from subio_v2.protocols.spec import ProtocolSpec

SPEC = ProtocolSpec(
    protocol=Protocol.TROJAN,
    required_fields=("password",),
    node_class=TrojanNode,
    user_override_fields=frozenset({"server", "port", "password"}),
    terminal_native_user_override_fields=frozenset({"server", "port", "password"}),
    terminal_native_fields=frozenset({"password", "smux", "tls", "transport"}),
)
