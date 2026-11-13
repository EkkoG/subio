from __future__ import annotations

from subio_v2.core.nodes import Protocol
from subio_v2.protocols import (
    anytls,
    direct,
    dns,
    gost_relay,
    http,
    hysteria,
    hysteria2,
    juicity,
    masque,
    mieru,
    naive,
    openconnect,
    openvpn,
    reject,
    rematch,
    shadowquic,
    shadowsocks,
    shadowsocksr,
    shadowtls,
    snell,
    socks5,
    ssh,
    sudoku,
    tailscale,
    trojan,
    trusttunnel,
    tuic,
    vless,
    vmess,
    wireguard,
)
from subio_v2.protocols.definitions import ProtocolDefinition
from subio_v2.protocols.spec import ProtocolSpec

__all__ = ["ProtocolDefinition", "ProtocolSpec", "all_definitions", "get_definition"]

_SPECS: tuple[ProtocolSpec, ...] = (
    anytls.SPEC,
    direct.SPEC,
    dns.SPEC,
    gost_relay.SPEC,
    http.SPEC,
    hysteria.SPEC,
    hysteria2.SPEC,
    juicity.SPEC,
    masque.SPEC,
    mieru.SPEC,
    naive.SPEC,
    openconnect.SPEC,
    openvpn.SPEC,
    reject.SPEC,
    rematch.SPEC,
    shadowquic.SPEC,
    shadowtls.SPEC,
    shadowsocks.SPEC,
    shadowsocksr.SPEC,
    snell.SPEC,
    socks5.SPEC,
    ssh.SPEC,
    sudoku.SPEC,
    tailscale.SPEC,
    trojan.SPEC,
    trusttunnel.SPEC,
    tuic.SPEC,
    vless.SPEC,
    vmess.SPEC,
    wireguard.SPEC,
)

_definitions = {spec.protocol: spec for spec in _SPECS}


def get_definition(protocol: Protocol) -> ProtocolSpec | None:
    return _definitions.get(protocol)


def all_definitions() -> tuple[ProtocolSpec, ...]:
    return tuple(_definitions.values())
