from __future__ import annotations

from subio_v2.core.nodes import Protocol, Socks5Node
from subio_v2.protocols.spec import ProtocolSpec

SPEC = ProtocolSpec(
    protocol=Protocol.SOCKS5,
    node_class=Socks5Node,
    user_override_fields=frozenset({"server", "port", "username", "password"}),
    terminal_native_user_override_fields=frozenset(
        {"server", "port", "username", "password"}
    ),
    terminal_native_fields=frozenset({"password", "tls", "username"}),
)
