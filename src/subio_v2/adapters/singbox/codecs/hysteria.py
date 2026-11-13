from __future__ import annotations

import re
from typing import Any

from subio_v2.adapters.singbox.codecs._base import (
    SingBoxOutboundCodec,
)
from subio_v2.adapters.singbox.codecs._fields import (
    _emit_tls,
    _keys,
    _optional_string,
    _optional_int,
    _parse_tls,
    SingBoxCodecError,
)
from subio_v2.core.nodes import (
    HysteriaNode,
    Node,
    Protocol,
)


def _valid_bandwidth(value: object) -> bool:
    if not isinstance(value, str):
        return False
    match = re.fullmatch(r"([0-9]+)\s*(bps|Bps|Kbps|KBps|Mbps|MBps|Gbps|GBps|Tbps|TBps)", value)
    return match is not None and any(digit != "0" for digit in match[1])


def _check_bandwidth(node: Node) -> list[str]:
    unsupported = []
    for attr, speed in (("up", "up_speed"), ("down", "down_speed")):
        value, mbps = getattr(node, attr), getattr(node, speed)
        if value is not None and not _valid_bandwidth(value):
            unsupported.append(attr)
        if mbps is not None and (type(mbps) is not int or mbps <= 0):
            unsupported.append(speed)
        if value is None and mbps is None:
            unsupported.append(attr)
    return unsupported


def _parse_hysteria(data: dict[str, Any]) -> dict[str, Any]:
    fields = {
        "up": _optional_string(data, "up"),
        "down": _optional_string(data, "down"),
        "up_speed": _optional_int(data, "up_mbps"),
        "down_speed": _optional_int(data, "down_mbps"),
        "auth": _optional_string(data, "auth"),
        "auth_str": _optional_string(data, "auth_str"),
        "obfs": _optional_string(data, "obfs"),
        "tls": _parse_tls(data.get("tls"), force_enabled=True),
    }
    invalid = _check_bandwidth(HysteriaNode(name="__bandwidth__", **fields))
    if invalid:
        raise SingBoxCodecError(invalid[0], "Hysteria requires positive up and down bandwidth", "parse.singbox.invalid-field")
    return fields


def _emit_hysteria(out: dict[str, Any], node: Node) -> None:
    for attr, key in (("up", "up"), ("down", "down"),
                      ("up_speed", "up_mbps"), ("down_speed", "down_mbps")):
        value = getattr(node, attr)
        if value is not None:
            out[key] = value
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
    _keys("auth", "auth_str", "obfs", "tls", "up", "down", "up_mbps", "down_mbps"),
    _keys("auth", "auth_str", "obfs", "tls", "up", "down", "up_speed", "down_speed"),
    parse_fields=_parse_hysteria,
    emit_fields=_emit_hysteria,
    check_fields=_check_bandwidth,
    force_tls=True,
)
