from __future__ import annotations

from collections.abc import Iterable

from subio_v2.model.nodes import Protocol
from subio_v2.protocols._base import ProtocolDescriptor
from subio_v2.protocols.definitions import (
    ProtocolDefinition,
    all_definitions,
    get_definition,
)

__all__ = [
    "ProtocolDefinition",
    "all",
    "all_definitions",
    "by_clash_type",
    "get",
    "get_definition",
    "register",
]

_registry: dict[Protocol, ProtocolDescriptor] = {}
_clash_type_index: dict[str, ProtocolDescriptor] = {}
_bootstrapped = False


def register(desc: ProtocolDescriptor) -> None:
    existing_protocol = _registry.get(desc.protocol)
    if existing_protocol is not None and existing_protocol is not desc:
        raise ValueError(f"Protocol already registered: {desc.protocol.value}")
    existing_type = _clash_type_index.get(desc.clash_type)
    if existing_type is not None and existing_type is not desc:
        raise ValueError(f"Clash type already registered: {desc.clash_type}")
    if get_definition(desc.protocol) is None:
        raise ValueError(f"Protocol has no definition: {desc.protocol!r}")
    _registry[desc.protocol] = desc
    if not desc.dynamic_clash_type:
        _clash_type_index[desc.clash_type] = desc


def _bootstrap() -> None:
    global _bootstrapped
    if _bootstrapped:
        return
    # Keep this list explicit so grep/rg can discover every descriptor authority.
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
        openvpn,
        reject,
        rematch,
        shadowquic,
        shadowsocks,
        shadowsocksr,
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

    for module in (
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
        openvpn,
        reject,
        rematch,
        shadowquic,
        shadowsocks,
        shadowsocksr,
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
    ):
        register(module.DESCRIPTOR)

    _bootstrapped = True


def get(protocol: Protocol) -> ProtocolDescriptor | None:
    _bootstrap()
    return _registry.get(protocol)


def by_clash_type(clash_type: str) -> ProtocolDescriptor | None:
    _bootstrap()
    return _clash_type_index.get(clash_type)


def all() -> Iterable[ProtocolDescriptor]:
    _bootstrap()
    return _registry.values()
