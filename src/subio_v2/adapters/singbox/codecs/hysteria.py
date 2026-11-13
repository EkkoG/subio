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
    HysteriaNode,
    Node,
    Protocol,
)


def _parse_hysteria(data: dict[str, Any]) -> dict[str, Any]:
    return {
        "auth": _optional_string(data, "auth"),
        "auth_str": _optional_string(data, "auth_str"),
        "obfs": _optional_string(data, "obfs"),
        "tls": _parse_tls(data.get("tls"), force_enabled=True),
    }


def _emit_hysteria(out: dict[str, Any], node: Node) -> None:
    if node.auth:
        out["auth"] = node.auth
    if node.auth_str:
        out["auth_str"] = node.auth_str
    if node.obfs:
        out["obfs"] = node.obfs
    out["tls"] = _emit_tls(node.tls)


CODEC = SingBoxOutboundCodec(
    "hysteria",
    Protocol.HYSTERIA,
    HysteriaNode,
    _keys("auth", "auth_str", "obfs", "tls"),
    _keys("auth", "auth_str", "obfs", "tls"),
    parse_fields=_parse_hysteria,
    emit_fields=_emit_hysteria,
    force_tls=True,
)
