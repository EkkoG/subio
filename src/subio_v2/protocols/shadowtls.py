from __future__ import annotations

from typing import Any

from subio_v2.core.nodes import Node, Protocol, ShadowTLSNode
from subio_v2.protocols._base import ClashProtocolCodec
from subio_v2.protocols.spec import ProtocolSpec

SPEC = ProtocolSpec(
    protocol=Protocol.SHADOWTLS,
    node_class=ShadowTLSNode,
    user_override_fields=frozenset({"server", "port", "password"}),
    terminal_native_excluded_fields=frozenset({"version", "password", "tls"}),
    native_public=False,
)


class ShadowTLSCodec(ClashProtocolCodec):
    spec = SPEC
    protocol = Protocol.SHADOWTLS
    clash_type = "shadowtls"
    dynamic_clash_type = True
    clash_dialects = frozenset()

    def parse_clash(self, data: dict[str, Any], context=None) -> Node:
        raise ValueError("Standalone ShadowTLS is not a Clash-family protocol")

    def emit_clash(self, node: Node, context=None) -> dict[str, Any]:
        raise ValueError("Standalone ShadowTLS is not a Clash-family protocol")


CODEC = ShadowTLSCodec()
