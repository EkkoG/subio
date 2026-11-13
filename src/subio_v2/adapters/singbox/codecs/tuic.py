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
    TUICNode,
)


def _parse_tuic(data: dict[str, Any]) -> dict[str, Any]:
    return {
        "uuid": _optional_string(data, "uuid"),
        "password": _optional_string(data, "password"),
        "version": 5,
        "tls": _parse_tls(data.get("tls"), force_enabled=True),
    }


def _emit_tuic(out: dict[str, Any], node: Node) -> None:
    out["uuid"] = node.uuid
    out["password"] = node.password
    out["tls"] = _emit_tls(node.tls)


def _check_tuic(node: Node) -> list[str]:
    unsupported = []
    if isinstance(node, TUICNode) and (node.version not in {None, 5} or node.token):
        unsupported.append("version")
    return unsupported


CODEC = SingBoxOutboundCodec(
    "tuic",
    Protocol.TUIC,
    TUICNode,
    _keys("uuid", "password", "network", "tls"),
    _keys("uuid", "password", "version", "tls"),
    parse_fields=_parse_tuic,
    emit_fields=_emit_tuic,
    check_fields=_check_tuic,
    network=True,
    force_tls=True,
)
