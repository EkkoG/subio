from __future__ import annotations

from typing import Any

from subio_v2.adapters.singbox.codecs._base import (
    SingBoxOutboundCodec,
)
from subio_v2.adapters.singbox.codecs._fields import (
    _emit_tls,
    _keys,
    _optional_bool,
    _optional_enum_string,
    _optional_int,
    _optional_string,
    _parse_tls,
)
from subio_v2.core.nodes import (
    Node,
    Protocol,
    VmessNode,
)

_VMESS_SECURITY_VALUES = frozenset(
    {"auto", "none", "zero", "aes-128-cfb", "aes-128-gcm", "chacha20-poly1305"}
)


_VMESS_PACKET_ENCODINGS = frozenset({"packetaddr", "xudp"})


def _parse_vmess(data: dict[str, Any]) -> dict[str, Any]:
    return {
        "uuid": _optional_string(data, "uuid") or "",
        "cipher": _optional_enum_string(data, "security", _VMESS_SECURITY_VALUES)
        or "auto",
        "alter_id": _optional_int(data, "alter_id") or 0,
        "global_padding": _optional_bool(data, "global_padding"),
        "packet_encoding": _optional_enum_string(
            data, "packet_encoding", _VMESS_PACKET_ENCODINGS
        ),
        "tls": _parse_tls(data.get("tls"), force_enabled=False),
    }


def _emit_vmess(out: dict[str, Any], node: Node) -> None:
    out["uuid"] = node.uuid
    out["security"] = node.cipher
    if node.alter_id:
        out["alter_id"] = node.alter_id
    if node.global_padding:
        out["global_padding"] = True
    if node.packet_encoding:
        out["packet_encoding"] = node.packet_encoding
    if node.tls.enabled or node.tls.server_name or node.tls.alpn:
        out["tls"] = _emit_tls(node.tls)


def _check_vmess(node: Node) -> list[str]:
    unsupported = []
    if isinstance(node, VmessNode):
        if node.cipher not in _VMESS_SECURITY_VALUES:
            unsupported.append("cipher")
        if (
            node.packet_encoding is not None
            and node.packet_encoding not in _VMESS_PACKET_ENCODINGS
        ):
            unsupported.append("packet_encoding")
    return unsupported


CODEC = SingBoxOutboundCodec(
    "vmess",
    Protocol.VMESS,
    VmessNode,
    _keys(
        "uuid",
        "security",
        "alter_id",
        "global_padding",
        "network",
        "tls",
        "packet_encoding",
    ),
    _keys("uuid", "alter_id", "cipher", "global_padding", "tls", "packet_encoding"),
    parse_fields=_parse_vmess,
    emit_fields=_emit_vmess,
    check_fields=_check_vmess,
    network=True,
)
