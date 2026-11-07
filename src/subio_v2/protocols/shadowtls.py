from __future__ import annotations


from subio_v2.core.nodes import Protocol, ShadowTLSNode
from subio_v2.protocols.spec import ProtocolSpec


SPEC = ProtocolSpec(
    protocol=Protocol.SHADOWTLS,
    node_class=ShadowTLSNode,
    user_override_fields=frozenset({"server", "port", "password"}),
    terminal_native_excluded_fields=frozenset({"version", "password", "tls"}),
    native_public=False,
)
