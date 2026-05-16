from __future__ import annotations

from typing import Iterable

from subio_v2.model.nodes import Protocol
from subio_v2.protocols._base import ProtocolDescriptor

_registry: dict[Protocol, ProtocolDescriptor] = {}
_clash_type_index: dict[str, ProtocolDescriptor] = {}
_bootstrapped = False


def register(desc: ProtocolDescriptor) -> None:
    _registry[desc.protocol] = desc
    _clash_type_index[desc.clash_type] = desc


def _bootstrap() -> None:
    global _bootstrapped
    if _bootstrapped:
        return
    _bootstrapped = True

    # Imported for side-effect registration.
    # Keep this list explicit so grep/rg can quickly discover all descriptors.
    from subio_v2.protocols import (  # noqa: F401
        anytls,
        http,
        hysteria,
        hysteria2,
        passthrough,
        shadowsocks,
        shadowsocksr,
        snell,
        socks5,
        ssh,
        trojan,
        tuic,
        vless,
        vmess,
        wireguard,
    )


def get(protocol: Protocol) -> ProtocolDescriptor | None:
    _bootstrap()
    return _registry.get(protocol)


def by_clash_type(clash_type: str) -> ProtocolDescriptor | None:
    _bootstrap()
    return _clash_type_index.get(clash_type)


def all() -> Iterable[ProtocolDescriptor]:
    _bootstrap()
    return _registry.values()
