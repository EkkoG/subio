from __future__ import annotations

import copy
from typing import Any, Dict

from subio_v2.clash.helpers import emit_passthrough, parse_base_fields
from subio_v2.model.nodes import ClashPassthroughNode, Node, Protocol
from subio_v2.dialect import DialectContext
from subio_v2.protocols import register
from subio_v2.protocols._base import ProtocolDescriptor


class PassthroughDescriptor(ProtocolDescriptor):
    node_class = ClashPassthroughNode
    passthrough = True

    def __init__(self, protocol: Protocol, clash_type: str):
        self.protocol = protocol
        self.clash_type = clash_type

    def parse_clash(
        self, data: Dict[str, Any], context: DialectContext | None = None
    ) -> Node:
        context = context or DialectContext("mihomo", "yaml")
        node = ClashPassthroughNode(
            type=self.protocol,
            raw=copy.deepcopy(data),
            clash_type=data.get("type"),
            **parse_base_fields(data),
        )
        node.source_context = context
        return node

    def emit_clash(
        self, node: Node, context: DialectContext | None = None
    ) -> Dict[str, Any]:
        if not isinstance(node, ClashPassthroughNode):
            raise TypeError(f"Expected ClashPassthroughNode, got {type(node)}")
        return emit_passthrough(node, context or DialectContext("mihomo", "yaml"))


for _protocol, _clash_type in (
    (Protocol.GOST_RELAY, "gost-relay"),
    (Protocol.REMATCH, "rematch"),
    (Protocol.SHADOWQUIC, "shadowquic"),
    (Protocol.SUDOKU, "sudoku"),
    (Protocol.OPENVPN, "openvpn"),
    (Protocol.DNS, "dns"),
):
    register(PassthroughDescriptor(protocol=_protocol, clash_type=_clash_type))
