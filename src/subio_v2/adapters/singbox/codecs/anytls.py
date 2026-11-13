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
    AnyTLSNode,
    Node,
    Protocol,
)


def _parse_anytls(data: dict[str, Any]) -> dict[str, Any]:
    return {
        "password": _optional_string(data, "password") or "",
        "tls": _parse_tls(data.get("tls"), force_enabled=True),
    }


def _emit_anytls(out: dict[str, Any], node: Node) -> None:
    out["password"] = node.password
    out["tls"] = _emit_tls(node.tls)


CODEC = SingBoxOutboundCodec(
    "anytls",
    Protocol.ANYTLS,
    AnyTLSNode,
    _keys("password", "tls"),
    _keys("password", "tls"),
    parse_fields=_parse_anytls,
    emit_fields=_emit_anytls,
    tcp_only=True,
    force_tls=True,
)
