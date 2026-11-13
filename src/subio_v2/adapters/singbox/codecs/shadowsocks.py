from __future__ import annotations

from typing import Any

from subio_v2.adapters.singbox.codecs._base import (
    SingBoxOutboundCodec,
)
from subio_v2.adapters.singbox.codecs._fields import (
    _keys,
    _optional_enum_string,
    _optional_string,
)
from subio_v2.core.nodes import (
    Node,
    Protocol,
    ShadowsocksNode,
)

_SHADOWSOCKS_METHODS = frozenset(
    {
        "none",
        "aes-128-gcm",
        "aes-192-gcm",
        "aes-256-gcm",
        "chacha20-ietf-poly1305",
        "xchacha20-ietf-poly1305",
        "2022-blake3-aes-128-gcm",
        "2022-blake3-aes-256-gcm",
        "2022-blake3-chacha20-poly1305",
        "aes-128-ctr",
        "aes-192-ctr",
        "aes-256-ctr",
        "aes-128-cfb",
        "aes-192-cfb",
        "aes-256-cfb",
        "rc4-md5",
        "chacha20-ietf",
        "xchacha20",
    }
)


def _parse_shadowsocks(data: dict[str, Any]) -> dict[str, Any]:
    return {
        "cipher": _optional_enum_string(data, "method", _SHADOWSOCKS_METHODS) or "",
        "password": _optional_string(data, "password") or "",
    }


def _emit_shadowsocks(out: dict[str, Any], node: Node) -> None:
    out["method"] = node.cipher
    out["password"] = node.password


def _check_shadowsocks(node: Node) -> list[str]:
    unsupported = []
    if isinstance(node, ShadowsocksNode) and node.cipher not in _SHADOWSOCKS_METHODS:
        unsupported.append("cipher")
    return unsupported


CODEC = SingBoxOutboundCodec(
    "shadowsocks",
    Protocol.SHADOWSOCKS,
    ShadowsocksNode,
    _keys("method", "password", "network"),
    _keys("cipher", "password"),
    parse_fields=_parse_shadowsocks,
    emit_fields=_emit_shadowsocks,
    check_fields=_check_shadowsocks,
    network=True,
)
