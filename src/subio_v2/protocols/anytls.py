from __future__ import annotations

from subio_v2.core.nodes import AnyTLSNode, Protocol
from subio_v2.protocols.spec import ProtocolSpec

SPEC = ProtocolSpec(
    protocol=Protocol.ANYTLS,
    required_fields=("password",),
    node_class=AnyTLSNode,
    user_override_fields=frozenset({"server", "port", "password"}),
    terminal_native_user_override_fields=frozenset({"server", "port", "password"}),
    terminal_native_fields=frozenset(
        {
            "idle_session_check_interval",
            "idle_session_timeout",
            "min_idle_session",
            "password",
            "reuse",
            "tls",
        }
    ),
)
