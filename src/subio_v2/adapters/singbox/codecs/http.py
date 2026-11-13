from __future__ import annotations

from typing import Any

from subio_v2.adapters.singbox.codecs._base import (
    SingBoxOutboundCodec,
)
from subio_v2.adapters.singbox.codecs._fields import (
    _emit_tls,
    _keys,
    _optional_string,
    _parse_tls,
)
from subio_v2.core.nodes import (
    HttpNode,
    Node,
    Protocol,
)


def _parse_http(data: dict[str, Any]) -> dict[str, Any]:
    return {
        "username": _optional_string(data, "username"),
        "password": _optional_string(data, "password"),
        "tls": _parse_tls(data.get("tls"), force_enabled=False),
    }


def _emit_http(out: dict[str, Any], node: Node) -> None:
    if node.username:
        out["username"] = node.username
    if node.password:
        out["password"] = node.password
    if node.tls.enabled or node.tls.server_name or node.tls.alpn:
        out["tls"] = _emit_tls(node.tls)


CODEC = SingBoxOutboundCodec(
    "http",
    Protocol.HTTP,
    HttpNode,
    _keys("username", "password", "tls"),
    _keys("username", "password", "tls"),
    parse_fields=_parse_http,
    emit_fields=_emit_http,
    tcp_only=True,
)
