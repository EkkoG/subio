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
from subio_v2.model.nodes import HttpNode, Node, Protocol
from subio_v2.protocols import register
from subio_v2.protocols._base import ProtocolDescriptor


class HttpDescriptor(ProtocolDescriptor):
    protocol = Protocol.HTTP
    clash_type = "http"
    node_class = HttpNode

    def parse_clash(self, data: Dict[str, Any]) -> Node:
        handled = {
            "username",
            "password",
            "headers",
            "tls",
            "sni",
            "skip-cert-verify",
            "fingerprint",
            "client-fingerprint",
            "alpn",
            "certificate",
            "private-key",
        }
        node = HttpNode(
            type=Protocol.HTTP,
            username=data.get("username"),
            password=data.get("password"),
            headers=data.get("headers"),
            tls=parse_tls(data),
            **parse_base_fields(data),
        )
        assign_extra(node, data, handled)
        return node

    def emit_clash(self, node: Node) -> Dict[str, Any]:
        if not isinstance(node, HttpNode):
            raise TypeError(f"Expected HttpNode, got {type(node)}")
        base = emit_base(node)
        if node.username:
            base["username"] = node.username
        if node.password:
            base["password"] = node.password
        if node.headers:
            base["headers"] = node.headers
        emit_tls(base, node.tls)
        return merge_extra(base, node)


register(HttpDescriptor())
