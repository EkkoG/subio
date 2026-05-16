from __future__ import annotations

from typing import Any, Dict

from subio_v2.clash.helpers import (
    assign_extra,
    emit_base,
    emit_smux,
    merge_extra,
    parse_base_fields,
    parse_smux,
)
from subio_v2.model.nodes import Node, Protocol, ShadowsocksRNode
from subio_v2.protocols import register
from subio_v2.protocols._base import ProtocolDescriptor


class ShadowsocksRDescriptor(ProtocolDescriptor):
    protocol = Protocol.SHADOWSOCKSR
    clash_type = "ssr"
    node_class = ShadowsocksRNode

    def parse_clash(self, data: Dict[str, Any]) -> Node:
        handled = {
            "cipher",
            "password",
            "obfs",
            "protocol",
            "obfs-param",
            "protocol-param",
            "smux",
        }
        node = ShadowsocksRNode(
            type=Protocol.SHADOWSOCKSR,
            cipher=data.get("cipher", ""),
            password=data.get("password", ""),
            obfs=data.get("obfs", ""),
            ssr_protocol=data.get("protocol", ""),
            obfs_param=data.get("obfs-param"),
            protocol_param=data.get("protocol-param"),
            smux=parse_smux(data),
            **parse_base_fields(data),
        )
        assign_extra(node, data, handled)
        return node

    def emit_clash(self, node: Node) -> Dict[str, Any]:
        if not isinstance(node, ShadowsocksRNode):
            raise TypeError(f"Expected ShadowsocksRNode, got {type(node)}")
        base = emit_base(node)
        base.update(
            {
                "cipher": node.cipher,
                "password": node.password,
                "obfs": node.obfs,
                "protocol": node.ssr_protocol,
            }
        )
        if node.obfs_param:
            base["obfs-param"] = node.obfs_param
        if node.protocol_param:
            base["protocol-param"] = node.protocol_param
        emit_smux(base, node.smux)
        return merge_extra(base, node)


register(ShadowsocksRDescriptor())
