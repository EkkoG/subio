from __future__ import annotations

from typing import Iterable

from subio_v2.model.nodes import Protocol
from subio_v2.protocols._base import ProtocolDescriptor

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
    _registry[desc.protocol] = desc
    if not desc.dynamic_clash_type:
        _clash_type_index[desc.clash_type] = desc


def _bootstrap() -> None:
    global _bootstrapped
    if _bootstrapped:
        return
    # Imported for side-effect registration.
    # Keep this list explicit so grep/rg can quickly discover all descriptors.
    from subio_v2.protocols import (  # noqa: F401
        anytls,
        direct,
        http,
        hysteria,
        hysteria2,
        masque,
        passthrough,
        shadowsocks,
        shadowsocksr,
        snell,
        socks5,
        ssh,
        trojan,
        trusttunnel,
        tuic,
        tailscale,
        vless,
        vmess,
        wireguard,
    )

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
