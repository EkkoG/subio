from __future__ import annotations


from subio_v2.core.nodes import NaiveNode, Protocol
from subio_v2.protocols.spec import ProtocolSpec


SPEC = ProtocolSpec(
    protocol=Protocol.NAIVE,
    node_class=NaiveNode,
    user_override_fields=frozenset({"server", "port", "username", "password"}),
    terminal_native_excluded_fields=frozenset({"username", "password", "tls"}),
    native_public=False,
)
