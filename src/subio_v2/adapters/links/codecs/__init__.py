from types import MappingProxyType

from subio_v2.core.nodes import Node, Protocol

from . import (
    anytls,
    http,
    hysteria2,
    shadowsocks,
    socks5,
    trojan,
    tuic,
    vless,
    vmess,
)
from ._base import LinkCodec

_CODECS = (
    shadowsocks.CODEC,
    vmess.CODEC,
    vless.CODEC,
    trojan.CODEC,
    socks5.CODEC,
    http.CODEC,
    hysteria2.CODEC,
    tuic.CODEC,
    anytls.CODEC,
)

_BY_PROTOCOL = MappingProxyType({codec.protocol: codec for codec in _CODECS})
if len(_BY_PROTOCOL) != len(_CODECS):
    raise RuntimeError("Duplicate link codec protocol")

_BY_SCHEME = MappingProxyType(
    {scheme: codec for codec in _CODECS for scheme in codec.schemes}
)
if len(_BY_SCHEME) != sum(len(codec.schemes) for codec in _CODECS):
    raise RuntimeError("Duplicate link codec scheme")


def all_codecs() -> tuple[LinkCodec, ...]:
    return _CODECS


def protocols_for_target(target: str) -> frozenset[str]:
    return frozenset(
        codec.protocol.value for codec in _CODECS if target in codec.targets
    )


def build_url(node: Node, *, target: str | None = None) -> str | None:
    codec = _BY_PROTOCOL.get(node.type)
    if codec is None or (target is not None and target not in codec.targets):
        return None
    return codec.build(node)


def get_codec(protocol: Protocol) -> LinkCodec | None:
    return _BY_PROTOCOL.get(protocol)


def parse_url(line: str) -> Node | None:
    scheme = line.partition("://")[0].lower()
    codec = _BY_SCHEME.get(scheme)
    return codec.parse(line) if codec and codec.parse else None


def input_schemes() -> frozenset[str]:
    return frozenset(_BY_SCHEME)
