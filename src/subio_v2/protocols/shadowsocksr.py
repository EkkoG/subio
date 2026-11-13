from __future__ import annotations

from subio_v2.core.nodes import Protocol, ShadowsocksRNode
from subio_v2.protocols.spec import ProtocolSpec

SPEC = ProtocolSpec(
    protocol=Protocol.SHADOWSOCKSR,
    required_fields=("cipher", "password"),
    node_class=ShadowsocksRNode,
    user_override_fields=frozenset({"server", "port", "cipher", "password"}),
    terminal_native_user_override_fields=frozenset(
        {"server", "port", "cipher", "password"}
    ),
    terminal_native_fields=frozenset(
        {
            "cipher",
            "obfs",
            "obfs_param",
            "password",
            "protocol_param",
            "smux",
            "ssr_protocol",
        }
    ),
)
