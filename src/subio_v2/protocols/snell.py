from __future__ import annotations

from subio_v2.core.nodes import Protocol, SnellNode
from subio_v2.protocols.spec import ProtocolSpec

SPEC = ProtocolSpec(
    protocol=Protocol.SNELL,
    required_fields=("psk",),
    node_class=SnellNode,
    user_override_fields=frozenset({"server", "port", "psk"}),
    terminal_native_user_override_fields=frozenset({"server", "port", "psk"}),
    terminal_native_fields=frozenset(
        {
            "mode",
            "obfs",
            "obfs_host",
            "obfs_opts",
            "obfs_uri",
            "psk",
            "reuse",
            "smux",
            "tls",
            "udp_port",
            "version",
        }
    ),
)
