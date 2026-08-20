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
from subio_v2.protocols._base import ClashProtocolCodec, ClashTargetCodec
from subio_v2.protocols.definitions import ProtocolDefinition
from subio_v2.protocols.spec import ProtocolSpec

__all__ = [
    "ProtocolDefinition",
    "ProtocolSpec",
    "all",
    "all_definitions",
    "by_clash_type",
    "get",
    "get_definition",
    "target_codec",
    "target_codecs_for",
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
    if codec.spec is None:
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
    return None


def target_codec(target: str, protocol: Protocol) -> ClashTargetCodec | None:
    codec = _registry.get(protocol)
    if codec is None or not codec.supports_dialect(target):
        return None
    return ClashTargetCodec(target=target, protocol_codec=codec)


def target_codecs_for(target: str) -> dict[Protocol, ClashTargetCodec]:
    return {
        protocol: ClashTargetCodec(target=target, protocol_codec=codec)
        for protocol, codec in _registry.items()
        if codec.supports_dialect(target)
    }


def all_definitions() -> tuple[ProtocolSpec, ...]:
    return tuple(
        codec.spec for codec in _registry.values() if codec.spec is not None
    )


def by_clash_type(clash_type: str) -> ClashProtocolCodec | None:
    return _clash_type_index.get(clash_type)


def all() -> Iterable[ClashProtocolCodec]:
    return _registry.values()
