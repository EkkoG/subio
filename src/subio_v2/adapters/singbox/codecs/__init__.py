from __future__ import annotations

from typing import Any

from subio_v2.adapters.singbox.codecs import (
    anytls,
    direct,
    http,
    hysteria,
    hysteria2,
    naive,
    openconnect,
    openvpn,
    reject,
    shadowsocks,
    shadowtls,
    snell,
    socks5,
    ssh,
    tailscale,
    trojan,
    tuic,
    vless,
    vmess,
    wireguard,
)
from subio_v2.adapters.singbox.codecs._fields import SingBoxCodecError
from subio_v2.core.nodes import Node

_OUTBOUND_CODECS = (
    anytls.CODEC,
    reject.CODEC,
    direct.CODEC,
    http.CODEC,
    hysteria.CODEC,
    hysteria2.CODEC,
    naive.CODEC,
    shadowsocks.CODEC,
    shadowtls.CODEC,
    snell.CODEC,
    socks5.CODEC,
    ssh.CODEC,
    trojan.CODEC,
    tuic.CODEC,
    vless.CODEC,
    vmess.CODEC,
)

_ENDPOINT_CODECS = (
    openconnect.CODEC,
    openvpn.CODEC,
    wireguard.CODEC,
    tailscale.CODEC,
)

SINGBOX_OUTBOUND_CODECS = {codec.protocol: codec for codec in _OUTBOUND_CODECS}
SINGBOX_OUTBOUND_CODECS_BY_TYPE = {
    codec.singbox_type: codec for codec in _OUTBOUND_CODECS
}


def encode_outbound(node: Node) -> dict[str, Any]:
    codec = SINGBOX_OUTBOUND_CODECS.get(node.type)
    if codec is None:
        raise SingBoxCodecError(
            "type",
            f"Protocol '{node.type.value}' is not supported by sing-box",
            "conversion.unsupported-protocol",
        )
    return codec.encode(node)


SINGBOX_ENDPOINT_CODECS = {codec.protocol: codec for codec in _ENDPOINT_CODECS}
SINGBOX_ENDPOINT_CODECS_BY_TYPE = {
    codec.singbox_type: codec for codec in _ENDPOINT_CODECS
}


def encode_endpoint(node: Node) -> dict[str, Any]:
    codec = SINGBOX_ENDPOINT_CODECS.get(node.type)
    if codec is None:
        raise SingBoxCodecError(
            "type",
            f"Protocol '{node.type.value}' is not supported as a sing-box endpoint",
            "conversion.unsupported-protocol",
        )
    return codec.encode(node)
