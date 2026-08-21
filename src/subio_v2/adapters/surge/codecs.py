from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Any

from subio_v2.adapters.surge.emitters import (
    emit_anytls,
    emit_direct,
    emit_http,
    emit_hysteria2,
    emit_masque,
    emit_reject,
    emit_shadowsocks,
    emit_snell,
    emit_socks5,
    emit_ssh,
    emit_tailscale,
    emit_trojan,
    emit_trust_tunnel,
    emit_tuic,
    emit_vmess,
    emit_wireguard,
)
from subio_v2.adapters.surge.parsers import (
    parse_anytls,
    parse_http,
    parse_hysteria2,
    parse_shadowsocks,
    parse_snell,
    parse_socks5,
    parse_ssh,
    parse_trojan,
    parse_tuic,
    parse_vmess,
)
from subio_v2.core.nodes import Protocol

DEFAULT_SURGE_TARGET = "latest"


class SurgePolicyKind(StrEnum):
    NODE = "node"
    DOCUMENT = "document"


class SurgeUdpBehavior(StrEnum):
    EXPLICIT = "explicit"
    AUTOMATIC = "automatic"
    VERSIONED = "versioned"
    UNSUPPORTED = "unsupported"


@dataclass(frozen=True)
class SurgeCodecSpec:
    keyword: str
    protocol: Protocol | None
    policy_kind: SurgePolicyKind
    udp_behavior: SurgeUdpBehavior
    consumed_parameters: frozenset[str] = frozenset()
    emitted_parameters: frozenset[str] = frozenset()
    normalized_parameters: tuple[tuple[str, str], ...] = ()
    multi_value_parameters: frozenset[str] = frozenset()
    target_constraints: Mapping[str, Any] = MappingProxyType({})
    parser: Callable[[Any], Any] | None = None
    emitter: Callable[[Any, dict[int, str]], list[str]] | None = None

    @property
    def parameter_path_sources(self) -> frozenset[str]:
        return self.emitted_parameters | frozenset(
            source for source, _ in self.normalized_parameters
        )


def _spec(
    keyword: str,
    *,
    protocol: Protocol | None,
    kind: SurgePolicyKind = SurgePolicyKind.NODE,
    udp: SurgeUdpBehavior,
    consumed: tuple[str, ...] = (),
    emitted: tuple[str, ...] | None = None,
    normalized: tuple[tuple[str, str], ...] = (),
    multi: tuple[str, ...] = (),
    constraints: Mapping[str, Any] | None = None,
    parser: Callable[[Any], Any] | None = None,
    emitter: Callable[[Any, dict[int, str]], list[str]] | None = None,
) -> SurgeCodecSpec:
    return SurgeCodecSpec(
        keyword=keyword,
        protocol=protocol,
        policy_kind=kind,
        udp_behavior=udp,
        consumed_parameters=frozenset(consumed),
        emitted_parameters=frozenset(consumed if emitted is None else emitted),
        normalized_parameters=normalized,
        multi_value_parameters=frozenset(multi),
        target_constraints=MappingProxyType(dict(constraints or {})),
        parser=parser,
        emitter=emitter,
    )


SURGE_COMMON_PARAMETERS = frozenset(
    {
        "interface",
        "allow-other-interface",
        "dns-follow-interface",
        "no-error-alert",
        "ip-version",
        "hybrid",
        "tfo",
        "tos",
        "ecn",
        "block-quic",
        "test-url",
        "test-timeout",
        "test-udp",
        "underlying-proxy",
        "skip-cert-verify",
        "sni",
        "server-cert-verify-name",
        "server-cert-fingerprint-sha256",
        "alpn",
        "client-cert",
        "shadow-tls-password",
        "shadow-tls-sni",
        "shadow-tls-version",
    }
)
SURGE_COMMON_PARAMETER_PATHS = SURGE_COMMON_PARAMETERS


SURGE_CODEC_SPECS = (
    _spec(
        "ss",
        protocol=Protocol.SHADOWSOCKS,
        udp=SurgeUdpBehavior.EXPLICIT,
        parser=parse_shadowsocks,
        emitter=emit_shadowsocks,
        consumed=(
            "encrypt-method",
            "password",
            "udp-relay",
            "udp-port",
            "obfs",
            "obfs-host",
            "obfs-uri",
        ),
        constraints={"ciphers": {
            "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
            "aes-128-cfb", "aes-128-ctr", "aes-128-gcm", "aes-192-cfb",
            "aes-192-ctr", "aes-192-gcm", "aes-256-cfb", "aes-256-ctr",
            "aes-256-gcm", "chacha20", "chacha20-ietf",
            "chacha20-ietf-poly1305", "none", "rc4", "rc4-md5", "salsa20",
            "xchacha20-ietf-poly1305",
        }, "plugins": {"obfs"}},
    ),
    _spec(
        "vmess",
        protocol=Protocol.VMESS,
        udp=SurgeUdpBehavior.AUTOMATIC,
        parser=parse_vmess,
        emitter=emit_vmess,
        consumed=(
            "username",
            "encrypt-method",
            "vmess-aead",
            "tls",
            "ws",
            "ws-path",
            "ws-headers",
        ),
        constraints={
            "ciphers": {"aes-128-gcm", "chacha20-ietf-poly1305"},
            "transports": {"tcp", "ws"},
        },
    ),
    _spec(
        "trojan",
        protocol=Protocol.TROJAN,
        udp=SurgeUdpBehavior.AUTOMATIC,
        parser=parse_trojan,
        emitter=emit_trojan,
        consumed=("password", "ws", "ws-path", "ws-headers"),
        constraints={"transports": {"tcp", "ws"}},
    ),
    _spec(
        "socks5",
        protocol=Protocol.SOCKS5,
        udp=SurgeUdpBehavior.EXPLICIT,
        parser=parse_socks5,
        emitter=emit_socks5,
        consumed=("username", "password", "udp-relay"),
        constraints={"features": {"tls"}},
    ),
    _spec(
        "socks5-tls",
        protocol=Protocol.SOCKS5,
        udp=SurgeUdpBehavior.EXPLICIT,
        parser=parse_socks5,
        emitter=emit_socks5,
        consumed=("username", "password", "udp-relay"),
        constraints={"features": {"tls"}},
    ),
    _spec(
        "http",
        protocol=Protocol.HTTP,
        udp=SurgeUdpBehavior.UNSUPPORTED,
        parser=parse_http,
        emitter=emit_http,
        consumed=("username", "password", "headers", "always-use-connect"),
        constraints={"features": {"tls", "h2-connect", "connect-udp"}},
    ),
    _spec(
        "https",
        protocol=Protocol.HTTP,
        udp=SurgeUdpBehavior.UNSUPPORTED,
        parser=parse_http,
        emitter=emit_http,
        consumed=("username", "password", "headers", "always-use-connect"),
        constraints={"features": {"tls", "h2-connect", "connect-udp"}},
    ),
    _spec(
        "h2-connect",
        protocol=Protocol.HTTP,
        udp=SurgeUdpBehavior.EXPLICIT,
        parser=parse_http,
        emitter=emit_http,
        consumed=("username", "password", "headers", "max-streams", "udp-relay"),
        constraints={"features": {"tls", "h2-connect", "connect-udp"}},
    ),
    _spec(
        "anytls",
        protocol=Protocol.ANYTLS,
        udp=SurgeUdpBehavior.AUTOMATIC,
        parser=parse_anytls,
        emitter=emit_anytls,
        consumed=("password", "reuse"),
    ),
    _spec(
        "ssh",
        protocol=Protocol.SSH,
        udp=SurgeUdpBehavior.UNSUPPORTED,
        parser=parse_ssh,
        emitter=emit_ssh,
        consumed=(
            "username",
            "password",
            "private-key",
            "idle-timeout",
            "server-fingerprint",
        ),
        multi=("server-fingerprint",),
        constraints={"auth_methods": {"password", "private_key"}},
    ),
    _spec(
        "snell",
        protocol=Protocol.SNELL,
        udp=SurgeUdpBehavior.VERSIONED,
        parser=parse_snell,
        emitter=emit_snell,
        consumed=(
            "psk",
            "version",
            "reuse",
            "udp-port",
            "mode",
            "obfs",
            "obfs-host",
            "obfs-uri",
        ),
        constraints={
            "obfs_modes": {"http", "tls"},
            "obfs_modes_by_version": {
                1: {"http", "tls"}, 2: {"http", "tls"}, 3: {"http", "tls"},
                4: {"http"}, 5: {"http"}, 6: set(),
            },
            "reuse_versions": {4, 5, 6},
            "versions": {1, 2, 3, 4, 5, 6},
        },
    ),
    _spec(
        "tuic",
        protocol=Protocol.TUIC,
        udp=SurgeUdpBehavior.AUTOMATIC,
        parser=parse_tuic,
        emitter=emit_tuic,
        consumed=("token", "version", "port-hopping", "port-hopping-interval"),
        constraints={"versions": {4, 5}},
    ),
    _spec(
        "tuic-v5",
        protocol=Protocol.TUIC,
        udp=SurgeUdpBehavior.AUTOMATIC,
        parser=parse_tuic,
        emitter=emit_tuic,
        consumed=("uuid", "password", "port-hopping", "port-hopping-interval"),
        constraints={"versions": {4, 5}},
    ),
    _spec(
        "hysteria2",
        protocol=Protocol.HYSTERIA2,
        udp=SurgeUdpBehavior.AUTOMATIC,
        parser=parse_hysteria2,
        emitter=emit_hysteria2,
        consumed=(
            "password",
            "download-bandwidth",
            "upload-bandwidth",
            "up",
            "down",
            "salamander-password",
            "gecko-password",
            "obfs",
            "obfs-password",
            "port-hopping",
            "port-hopping-interval",
        ),
        emitted=(
            "password",
            "download-bandwidth",
            "upload-bandwidth",
            "salamander-password",
            "gecko-password",
            "port-hopping",
            "port-hopping-interval",
        ),
        normalized=(
            ("up", "upload-bandwidth"),
            ("down", "download-bandwidth"),
            ("obfs", "salamander-password/gecko-password"),
            ("obfs-password", "salamander-password/gecko-password"),
        ),
        constraints={"features": {"obfs"}, "obfs_modes": {"salamander", "gecko"}},
    ),
    _spec(
        "wireguard",
        protocol=Protocol.WIREGUARD,
        udp=SurgeUdpBehavior.AUTOMATIC,
        emitter=emit_wireguard,
        consumed=("section-name",),
    ),
    _spec(
        "tailscale",
        protocol=Protocol.TAILSCALE,
        udp=SurgeUdpBehavior.AUTOMATIC,
        emitter=emit_tailscale,
        consumed=("section-name",),
    ),
    _spec(
        "masque",
        protocol=Protocol.MASQUE,
        udp=SurgeUdpBehavior.AUTOMATIC,
        emitter=emit_masque,
        consumed=(
            "username",
            "password",
            "port-hopping",
            "port-hopping-interval",
        ),
    ),
    _spec(
        "trust-tunnel",
        protocol=Protocol.TRUSTTUNNEL,
        udp=SurgeUdpBehavior.UNSUPPORTED,
        emitter=emit_trust_tunnel,
        consumed=("username", "password", "headers", "max-streams", "h3", "ws"),
    ),
    _spec(
        "direct",
        protocol=Protocol.DIRECT,
        udp=SurgeUdpBehavior.AUTOMATIC,
        emitter=emit_direct,
    ),
    *(
        _spec(
            keyword,
            protocol=Protocol.REJECT,
            udp=SurgeUdpBehavior.UNSUPPORTED,
            emitter=emit_reject,
            constraints={
                "modes": {"reject", "reject-drop", "reject-no-drop", "reject-tinygif"}
            },
        )
        for keyword in (
            "reject",
            "reject-drop",
            "reject-no-drop",
            "reject-tinygif",
        )
    ),
)

SURGE_CODEC_BY_KEYWORD = {spec.keyword: spec for spec in SURGE_CODEC_SPECS}
if len(SURGE_CODEC_BY_KEYWORD) != len(SURGE_CODEC_SPECS):
    raise RuntimeError("Duplicate Surge codec keyword")

SURGE_PROTOCOL_CODECS = {}
for _spec_item in SURGE_CODEC_SPECS:
    if _spec_item.protocol is not None and _spec_item.protocol not in SURGE_PROTOCOL_CODECS:
        SURGE_PROTOCOL_CODECS[_spec_item.protocol] = _spec_item

SURGE_NODE_PROTOCOLS = frozenset(
    spec.protocol.value
    for spec in SURGE_CODEC_SPECS
    if spec.policy_kind == SurgePolicyKind.NODE and spec.protocol is not None
)
SURGE_PROTOCOL_PARAMETERS = {
    spec.keyword: spec.consumed_parameters
    for spec in SURGE_CODEC_SPECS
    if spec.policy_kind == SurgePolicyKind.NODE
}
SURGE_MULTI_VALUE_PARAMETERS = {
    spec.keyword: spec.multi_value_parameters
    for spec in SURGE_CODEC_SPECS
    if spec.multi_value_parameters
}
SURGE_BUILTIN_ALIAS_TYPES = frozenset(
    {"direct", "reject", "reject-drop", "reject-no-drop", "reject-tinygif"}
)

def get_surge_codec(keyword: str) -> SurgeCodecSpec | None:
    return SURGE_CODEC_BY_KEYWORD.get(keyword.lower())


def get_surge_protocol_codec(protocol: Protocol) -> SurgeCodecSpec | None:
    return SURGE_PROTOCOL_CODECS.get(protocol)
