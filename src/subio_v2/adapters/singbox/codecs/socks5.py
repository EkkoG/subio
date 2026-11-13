from __future__ import annotations

from typing import Any

from subio_v2.adapters.singbox.codecs._base import (
    SingBoxOutboundCodec,
)
from subio_v2.adapters.singbox.codecs._fields import (
    SingBoxCodecError,
    _keys,
    _optional_string,
)
from subio_v2.core.nodes import (
    Node,
    Protocol,
    Socks5Node,
)


def _parse_socks5(data: dict[str, Any]) -> dict[str, Any]:
    version = _optional_string(data, "version") or "5"
    if version != "5":
        raise SingBoxCodecError(
            "version",
            "Only SOCKS5 can be represented by the SubIO SOCKS node",
            "parse.singbox.unsupported-protocol-variant",
        )
    return {
        "username": _optional_string(data, "username"),
        "password": _optional_string(data, "password"),
    }


def _emit_socks5(out: dict[str, Any], node: Node) -> None:
    out["version"] = "5"
    if node.username:
        out["username"] = node.username
    if node.password:
        out["password"] = node.password


CODEC = SingBoxOutboundCodec(
    "socks",
    Protocol.SOCKS5,
    Socks5Node,
    _keys("version", "username", "password", "network"),
    _keys("username", "password"),
    parse_fields=_parse_socks5,
    emit_fields=_emit_socks5,
    network=True,
)
