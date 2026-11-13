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
    Node,
    Protocol,
    TrojanNode,
)


def _parse_trojan(data: dict[str, Any]) -> dict[str, Any]:
    return {
        "password": _optional_string(data, "password") or "",
        "tls": _parse_tls(data.get("tls"), force_enabled=False),
    }


def _emit_trojan(out: dict[str, Any], node: Node) -> None:
    out["password"] = node.password
    if node.tls.enabled or node.tls.server_name or node.tls.alpn:
        out["tls"] = _emit_tls(node.tls)


CODEC = SingBoxOutboundCodec(
    "trojan",
    Protocol.TROJAN,
    TrojanNode,
    _keys("password", "network", "tls"),
    _keys("password", "tls"),
    parse_fields=_parse_trojan,
    emit_fields=_emit_trojan,
    network=True,
)
