from __future__ import annotations

from typing import Any, Dict

from subio_v2.clash.helpers import (
    assign_extra,
    emit_base,
    emit_tls,
    merge_extra,
    parse_base_fields,
    parse_tls,
)
from subio_v2.model.nodes import Node, Protocol, Socks5Node
from subio_v2.protocols import register
from subio_v2.protocols._base import ProtocolDescriptor


class Socks5Descriptor(ProtocolDescriptor):
    protocol = Protocol.SOCKS5
    clash_type = "socks5"
    node_class = Socks5Node

    def parse_clash(self, data: Dict[str, Any]) -> Node:
        handled = {
            "username",
            "password",
            "tls",
            "sni",
            "skip-cert-verify",
            "fingerprint",
            "client-fingerprint",
            "alpn",
            "certificate",
            "private-key",
        }
        node = Socks5Node(
            type=Protocol.SOCKS5,
            username=data.get("username"),
            password=data.get("password"),
            tls=parse_tls(data),
            **parse_base_fields(data),
        )
        assign_extra(node, data, handled)
        return node

    def emit_clash(self, node: Node) -> Dict[str, Any]:
        if not isinstance(node, Socks5Node):
            raise TypeError(f"Expected Socks5Node, got {type(node)}")
        base = emit_base(node)
        if node.username:
            base["username"] = node.username
        if node.password:
            base["password"] = node.password
        emit_tls(base, node.tls)
        return merge_extra(base, node)


register(Socks5Descriptor())
