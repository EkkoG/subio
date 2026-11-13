from __future__ import annotations

from subio_v2.core.nodes import Hysteria2Node, Protocol
from subio_v2.protocols.spec import ProtocolSpec

SPEC = ProtocolSpec(
    protocol=Protocol.HYSTERIA2,
    required_fields=("password",),
    node_class=Hysteria2Node,
    user_override_fields=frozenset({"server", "port", "password", "obfs_password"}),
    terminal_native_user_override_fields=frozenset(
        {"server", "port", "password", "obfs_password"}
    ),
    terminal_native_fields=frozenset(
        {
            "down",
            "hop_interval",
            "obfs",
            "obfs_password",
            "password",
            "ports",
            "smux",
            "tls",
            "up",
        }
    ),
)
