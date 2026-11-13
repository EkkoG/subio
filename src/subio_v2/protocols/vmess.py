from __future__ import annotations

from subio_v2.core.nodes import Protocol, VmessNode
from subio_v2.protocols.spec import ProtocolSpec

SPEC = ProtocolSpec(
    protocol=Protocol.VMESS,
    required_fields=("uuid",),
    node_class=VmessNode,
    user_override_fields=frozenset({"server", "port", "uuid", "alter_id", "cipher"}),
    terminal_native_user_override_fields=frozenset(
        {"server", "port", "uuid", "alter_id", "cipher"}
    ),
    terminal_native_fields=frozenset(
        {
            "alter_id",
            "cipher",
            "global_padding",
            "packet_encoding",
            "smux",
            "tls",
            "transport",
            "uuid",
            "vmess_aead",
        }
    ),
)
