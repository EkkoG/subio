from __future__ import annotations

from typing import Any

from subio_v2.core.nodes import NaiveNode, Node, Protocol
from subio_v2.protocols._base import ClashProtocolCodec
from subio_v2.protocols.spec import ProtocolSpec

SPEC = ProtocolSpec(
    protocol=Protocol.NAIVE,
    node_class=NaiveNode,
    user_override_fields=frozenset({"server", "port", "username", "password"}),
    terminal_native_excluded_fields=frozenset({"username", "password", "tls"}),
    native_public=False,
)


class NaiveCodec(ClashProtocolCodec):
    spec = SPEC
    protocol = Protocol.NAIVE
    clash_type = "naive"
    dynamic_clash_type = True
    clash_dialects = frozenset()

    def parse_clash(self, data: dict[str, Any], context=None) -> Node:
        raise ValueError("Naive is not a Clash-family protocol")

    def emit_clash(self, node: Node, context=None) -> dict[str, Any]:
        raise ValueError("Naive is not a Clash-family protocol")


CODEC = NaiveCodec()
