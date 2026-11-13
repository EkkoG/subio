from __future__ import annotations

from typing import Any

from subio_v2.adapters.singbox.codecs._base import (
    SingBoxOutboundCodec,
)
from subio_v2.adapters.singbox.codecs._fields import (
    SingBoxCodecError,
    _emit_tls,
    _keys,
    _optional_int,
    _optional_string,
    _parse_tls,
)
from subio_v2.core.nodes import (
    Node,
    Protocol,
    ShadowTLSNode,
)


def _parse_shadowtls(data: dict[str, Any]) -> dict[str, Any]:
    version = _optional_int(data, "version") or 1
    if version not in {1, 2, 3}:
        raise SingBoxCodecError(
            "version",
            "ShadowTLS version must be 1, 2, or 3",
            "parse.singbox.invalid-field",
        )
    password = _optional_string(data, "password")
    if version == 1 and password:
        raise SingBoxCodecError(
            "password",
            "ShadowTLS v1 does not support a password",
            "parse.singbox.unsupported-protocol-variant",
        )
    if "tls" not in data:
        raise SingBoxCodecError(
            "tls",
            "ShadowTLS requires an enabled TLS object",
            "parse.singbox.invalid-field",
        )
    tls = _parse_tls(data["tls"], force_enabled=True)
    if not tls.enabled:
        raise SingBoxCodecError(
            "tls.enabled",
            "ShadowTLS requires TLS to be enabled",
            "parse.singbox.unsupported-protocol-variant",
        )
    return {
        "version": version,
        "password": password,
        "tls": tls,
    }


def _emit_shadowtls(out: dict[str, Any], node: Node) -> None:
    out["version"] = node.version
    if node.password:
        out["password"] = node.password
    out["tls"] = _emit_tls(node.tls)


def _check_shadowtls(node: Node) -> list[str]:
    unsupported = []
    if isinstance(node, ShadowTLSNode):
        if node.version not in {1, 2, 3}:
            unsupported.append("version")
        if node.version == 1 and node.password:
            unsupported.append("password")
    return unsupported


CODEC = SingBoxOutboundCodec(
    "shadowtls",
    Protocol.SHADOWTLS,
    ShadowTLSNode,
    _keys("version", "password", "tls"),
    _keys("version", "password", "tls"),
    parse_fields=_parse_shadowtls,
    emit_fields=_emit_shadowtls,
    check_fields=_check_shadowtls,
    tcp_only=True,
    force_tls=True,
)
