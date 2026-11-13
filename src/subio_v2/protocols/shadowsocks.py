from __future__ import annotations

from subio_v2.core.nodes import Node, Protocol, ShadowsocksNode
from subio_v2.core.validation import NodeValidationError
from subio_v2.protocols.spec import ProtocolSpec


def _validate(node: Node) -> list[NodeValidationError]:
    if (
        isinstance(node, ShadowsocksNode)
        and node.cipher != "none"
        and (node.password is None or node.password == "")
    ):
        return [NodeValidationError("password", "Required field 'password' is missing")]
    return []


SPEC = ProtocolSpec(
    protocol=Protocol.SHADOWSOCKS,
    required_fields=("cipher",),
    validator=_validate,
    node_class=ShadowsocksNode,
    user_override_fields=frozenset({"server", "port", "cipher", "password"}),
    terminal_native_user_override_fields=frozenset(
        {"server", "port", "cipher", "password"}
    ),
    terminal_native_fields=frozenset(
        {
            "cipher",
            "obfs_uri",
            "password",
            "plugin",
            "plugin_opts",
            "smux",
            "udp_port",
        }
    ),
)
