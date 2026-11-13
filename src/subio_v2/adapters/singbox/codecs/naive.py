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
    NaiveNode,
    Node,
    Protocol,
)


def _parse_naive(data: dict[str, Any]) -> dict[str, Any]:
    return {
        "username": _optional_string(data, "username"),
        "password": _optional_string(data, "password"),
        "tls": _parse_tls(data.get("tls"), force_enabled=True),
    }


def _emit_naive(out: dict[str, Any], node: Node) -> None:
    if node.username:
        out["username"] = node.username
    if node.password:
        out["password"] = node.password
    out["tls"] = _emit_tls(node.tls)


CODEC = SingBoxOutboundCodec(
    "naive",
    Protocol.NAIVE,
    NaiveNode,
    _keys("username", "password", "tls"),
    _keys("username", "password", "tls"),
    parse_fields=_parse_naive,
    emit_fields=_emit_naive,
    tcp_only=True,
    force_tls=True,
)
