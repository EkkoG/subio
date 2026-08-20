from __future__ import annotations

from collections.abc import Iterable

from subio_v2.model.nodes import Protocol
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
from subio_v2.protocols._base import ClashProtocolCodec
from subio_v2.protocols.definitions import (
    ProtocolDefinition,
)
from subio_v2.protocols.definitions import (
    all_definitions as legacy_all_definitions,
)
from subio_v2.protocols.definitions import (
    get_definition as legacy_get_definition,
)
from subio_v2.protocols.spec import ProtocolSpec

__all__ = [
    "ProtocolDefinition",
    "ProtocolSpec",
    "all",
    "all_definitions",
    "by_clash_type",
    "get",
    "get_definition",
    "register",
]

_CODECS: tuple[ClashProtocolCodec, ...] = (
    anytls.CODEC,
    direct.CODEC,
    dns.CODEC,
    gost_relay.CODEC,
    http.CODEC,
    hysteria.CODEC,
    hysteria2.CODEC,
    juicity.CODEC,
    masque.CODEC,
    mieru.CODEC,
    openvpn.CODEC,
    reject.CODEC,
    rematch.CODEC,
    shadowquic.CODEC,
    shadowsocks.CODEC,
    shadowsocksr.CODEC,
    snell.CODEC,
    socks5.CODEC,
    ssh.CODEC,
    sudoku.CODEC,
    tailscale.CODEC,
    trojan.CODEC,
    trusttunnel.CODEC,
    tuic.CODEC,
    vless.CODEC,
    vmess.CODEC,
    wireguard.CODEC,
)

_registry: dict[Protocol, ClashProtocolCodec] = {}
_clash_type_index: dict[str, ClashProtocolCodec] = {}


def register(codec: ClashProtocolCodec) -> None:
    existing_protocol = _registry.get(codec.protocol)
    if existing_protocol is not None and existing_protocol is not codec:
        raise ValueError(f"Protocol already registered: {codec.protocol.value}")
    existing_type = _clash_type_index.get(codec.clash_type)
    if existing_type is not None and existing_type is not codec:
        raise ValueError(f"Clash type already registered: {codec.clash_type}")
    if codec.spec is None and legacy_get_definition(codec.protocol) is None:
        raise ValueError(f"Protocol has no definition: {codec.protocol!r}")
    _registry[codec.protocol] = codec
    if not codec.dynamic_clash_type:
        _clash_type_index[codec.clash_type] = codec


for _codec in _CODECS:
    register(_codec)


def get(protocol: Protocol) -> ClashProtocolCodec | None:
    return _registry.get(protocol)


def get_definition(protocol: Protocol) -> ProtocolSpec | None:
    codec = _registry.get(protocol)
    if codec is not None and codec.spec is not None:
        return codec.spec
    return legacy_get_definition(protocol)


def all_definitions() -> tuple[ProtocolSpec, ...]:
    definitions = {item.protocol: item for item in legacy_all_definitions()}
    for codec in _registry.values():
        if codec.spec is not None:
            definitions[codec.protocol] = codec.spec
    return tuple(definitions.values())


def by_clash_type(clash_type: str) -> ClashProtocolCodec | None:
    return _clash_type_index.get(clash_type)


def all() -> Iterable[ClashProtocolCodec]:
    return _registry.values()
