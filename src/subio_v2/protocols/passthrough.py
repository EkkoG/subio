from __future__ import annotations

import copy
from typing import Any, Dict

from subio_v2.clash.helpers import emit_passthrough, parse_base_fields
from subio_v2.model.nodes import ClashPassthroughNode, Node, Protocol
from subio_v2.protocols import register
from subio_v2.protocols._base import ProtocolDescriptor


class PassthroughDescriptor(ProtocolDescriptor):
    node_class = ClashPassthroughNode
    passthrough = True

    def __init__(self, protocol: Protocol, clash_type: str):
        self.protocol = protocol
        self.clash_type = clash_type

    def parse_clash(self, data: Dict[str, Any]) -> Node:
        return ClashPassthroughNode(
            type=self.protocol, raw=copy.deepcopy(data), **parse_base_fields(data)
        )

    def emit_clash(self, node: Node) -> Dict[str, Any]:
        if not isinstance(node, ClashPassthroughNode):
            raise TypeError(f"Expected ClashPassthroughNode, got {type(node)}")
        return emit_passthrough(node)


for _protocol, _clash_type in (
    (Protocol.MIERU, "mieru"),
    (Protocol.SUDOKU, "sudoku"),
    (Protocol.MASQUE, "masque"),
    (Protocol.TRUSTTUNNEL, "trusttunnel"),
    (Protocol.OPENVPN, "openvpn"),
    (Protocol.TAILSCALE, "tailscale"),
    (Protocol.DIRECT, "direct"),
    (Protocol.DNS, "dns"),
):
    register(PassthroughDescriptor(protocol=_protocol, clash_type=_clash_type))
