from __future__ import annotations

from subio_v2.core.nodes import HttpNode, Protocol
from subio_v2.protocols.spec import ProtocolSpec

SPEC = ProtocolSpec(
    protocol=Protocol.HTTP,
    node_class=HttpNode,
    user_override_fields=frozenset({"server", "port", "username", "password"}),
    terminal_native_user_override_fields=frozenset(
        {"server", "port", "username", "password"}
    ),
    terminal_native_fields=frozenset(
        {
            "always_use_connect",
            "headers",
            "max_streams",
            "password",
            "tls",
            "username",
            "variant",
        }
    ),
)
