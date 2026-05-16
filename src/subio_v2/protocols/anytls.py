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
from subio_v2.model.nodes import AnyTLSNode, Node, Protocol
from subio_v2.protocols import register
from subio_v2.protocols._base import ProtocolDescriptor


class AnyTLSDescriptor(ProtocolDescriptor):
    protocol = Protocol.ANYTLS
    clash_type = "anytls"
    node_class = AnyTLSNode

    def parse_clash(self, data: Dict[str, Any]) -> Node:
        tls = parse_tls(data)
        tls.enabled = True
        handled = {
            "password",
            "sni",
            "skip-cert-verify",
            "fingerprint",
            "client-fingerprint",
            "alpn",
            "certificate",
            "private-key",
            "idle-session-check-interval",
            "idle-session-timeout",
            "min-idle-session",
        }
        node = AnyTLSNode(
            type=Protocol.ANYTLS,
            password=data.get("password", ""),
            tls=tls,
            idle_session_check_interval=data.get("idle-session-check-interval"),
            idle_session_timeout=data.get("idle-session-timeout"),
            min_idle_session=data.get("min-idle-session"),
            **parse_base_fields(data),
        )
        assign_extra(node, data, handled)
        return node

    def emit_clash(self, node: Node) -> Dict[str, Any]:
        if not isinstance(node, AnyTLSNode):
            raise TypeError(f"Expected AnyTLSNode, got {type(node)}")
        base = emit_base(node)
        base["password"] = node.password
        emit_tls(base, node.tls)
        if node.idle_session_check_interval is not None:
            base["idle-session-check-interval"] = node.idle_session_check_interval
        if node.idle_session_timeout is not None:
            base["idle-session-timeout"] = node.idle_session_timeout
        if node.min_idle_session is not None:
            base["min-idle-session"] = node.min_idle_session
        return merge_extra(base, node)


register(AnyTLSDescriptor())
