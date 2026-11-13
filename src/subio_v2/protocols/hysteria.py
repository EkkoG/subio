from __future__ import annotations

from subio_v2.core.nodes import HysteriaNode, Protocol
from subio_v2.protocols.spec import ProtocolSpec

SPEC = ProtocolSpec(
    protocol=Protocol.HYSTERIA,
    node_class=HysteriaNode,
    user_override_fields=frozenset({"server", "port", "auth", "auth_str"}),
    terminal_native_user_override_fields=frozenset(
        {"server", "port", "auth", "auth_str"}
    ),
    terminal_native_fields=frozenset(
        {
            "auth",
            "auth_str",
            "down",
            "down_speed",
            "hop_interval",
            "hysteria_protocol",
            "obfs",
            "obfs_protocol",
            "ports",
            "smux",
            "tls",
            "up",
            "up_speed",
        }
    ),
)
