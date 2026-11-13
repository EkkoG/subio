from __future__ import annotations

from typing import Any

from subio_v2.adapters.checks import vless_security_requirements
from subio_v2.adapters.singbox.codecs._base import (
    SingBoxOutboundCodec,
)
from subio_v2.adapters.singbox.codecs._fields import (
    _emit_tls,
    _keys,
    _optional_string,
    _parse_tls,
    SingBoxCodecError,
)
from subio_v2.core.nodes import (
    Node,
    Protocol,
    VlessNode,
)


def _parse_vless(data: dict[str, Any]) -> dict[str, Any]:
    flow = _optional_string(data, "flow")
    if flow not in {None, "", "xtls-rprx-vision"}:
        raise SingBoxCodecError("flow", "Unsupported sing-box VLESS flow", "parse.singbox.invalid-field")
    return {
        "uuid": _optional_string(data, "uuid") or "",
        "flow": flow,
        "packet_encoding": _optional_string(data, "packet_encoding"),
        "tls": _parse_tls(data.get("tls"), force_enabled=False),
    }


def _emit_vless(out: dict[str, Any], node: Node) -> None:
    out["uuid"] = node.uuid
    if node.flow:
        out["flow"] = node.flow
    if node.packet_encoding is not None:
        out["packet_encoding"] = node.packet_encoding
    if node.tls.enabled or node.tls.server_name or node.tls.alpn:
        out["tls"] = _emit_tls(node.tls)


def _check_vless(node: Node) -> list[str]:
    fields = [issue.field for issue in vless_security_requirements(node)]
    if node.flow not in {None, "", "xtls-rprx-vision"}:
        fields.append("flow")
    if node.packet_encoding not in {None, "", "xudp", "packetaddr"}:
        fields.append("packet_encoding")
    return fields


CODEC = SingBoxOutboundCodec(
    "vless",
    Protocol.VLESS,
    VlessNode,
    _keys("uuid", "flow", "network", "tls", "packet_encoding"),
    _keys("uuid", "flow", "tls", "packet_encoding"),
    parse_fields=_parse_vless,
    emit_fields=_emit_vless,
    check_fields=_check_vless,
    network=True,
)
