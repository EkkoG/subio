from __future__ import annotations

from typing import Any

from subio_v2.adapters.singbox.codecs._base import (
    SingBoxOutboundCodec,
)
from subio_v2.adapters.singbox.codecs._fields import (
    SingBoxCodecError,
    _keys,
    _optional_enum_string,
    _optional_int,
    _optional_string,
)
from subio_v2.core.nodes import (
    Node,
    Protocol,
    SnellNode,
)

_SNELL_V4_OBFS_MODES = frozenset({"none", "http", "tls"})


_SNELL_V6_MODES = frozenset({"default", "unshaped", "unsafe-raw"})


def _parse_snell(data: dict[str, Any]) -> dict[str, Any]:
    version = _optional_int(data, "version")
    if version not in {4, 6}:
        raise SingBoxCodecError(
            "version",
            "Sing-box Snell version must be 4 or 6",
            "parse.singbox.unsupported-protocol-variant",
        )
    out = {
        "psk": _optional_string(data, "psk") or "",
        "version": version,
        "reuse": data.get("reuse"),
    }
    if "reuse" in data and type(data["reuse"]) is not bool:
        raise SingBoxCodecError(
            "reuse",
            "Sing-box field 'reuse' must be a boolean",
            "parse.singbox.invalid-field",
        )
    if version == 4:
        if "mode" in data:
            raise SingBoxCodecError(
                "mode",
                "Sing-box Snell v4 does not support mode",
                "parse.singbox.unsupported-protocol-variant",
            )
        out["obfs"] = _optional_enum_string(data, "obfs_mode", _SNELL_V4_OBFS_MODES)
        out["obfs_host"] = _optional_string(data, "obfs_host")
    else:
        for field in ("obfs_mode", "obfs_host"):
            if field in data:
                raise SingBoxCodecError(
                    field,
                    f"Sing-box Snell v6 does not support {field}",
                    "parse.singbox.unsupported-protocol-variant",
                )
        out["mode"] = _optional_enum_string(data, "mode", _SNELL_V6_MODES)
    return out


def _emit_snell(out: dict[str, Any], node: Node) -> None:
    out["version"] = node.version
    out["psk"] = node.psk
    if node.reuse is not None:
        out["reuse"] = node.reuse
    if node.version == 4:
        if node.obfs:
            out["obfs_mode"] = node.obfs
        if node.obfs_host:
            out["obfs_host"] = node.obfs_host
    elif node.mode:
        out["mode"] = node.mode


def _check_snell(node: Node) -> list[str]:
    unsupported = []
    if isinstance(node, SnellNode):
        if node.version not in {4, 6}:
            unsupported.append("version")
        elif node.version == 4 and node.obfs not in {None, *_SNELL_V4_OBFS_MODES}:
            unsupported.append("obfs")
        elif node.version == 4 and node.mode is not None:
            unsupported.append("mode")
        elif node.version == 6:
            if node.mode not in {None, *_SNELL_V6_MODES}:
                unsupported.append("mode")
            if node.obfs is not None:
                unsupported.append("obfs")
            if node.obfs_host is not None:
                unsupported.append("obfs_host")
    return unsupported


CODEC = SingBoxOutboundCodec(
    "snell",
    Protocol.SNELL,
    SnellNode,
    _keys("version", "psk", "reuse", "network", "obfs_mode", "obfs_host", "mode"),
    _keys("psk", "version", "reuse", "mode", "obfs", "obfs_host"),
    parse_fields=_parse_snell,
    emit_fields=_emit_snell,
    check_fields=_check_snell,
    network=True,
)
