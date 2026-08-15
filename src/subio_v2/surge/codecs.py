from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from subio_v2.model.nodes import Protocol


DEFAULT_SURGE_TARGET = "latest"


class SurgePolicyKind(StrEnum):
    NODE = "node"
    DOCUMENT = "document"
    EXTERNAL = "external"


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
    emitter_handler: str | None = None
    consumed_parameters: frozenset[str] = frozenset()
    emitted_parameters: frozenset[str] = frozenset()
    normalized_parameters: tuple[tuple[str, str], ...] = ()
    multi_value_parameters: frozenset[str] = frozenset()

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
    handler: str | None = None,
    consumed: tuple[str, ...] = (),
    emitted: tuple[str, ...] | None = None,
    normalized: tuple[tuple[str, str], ...] = (),
    multi: tuple[str, ...] = (),
) -> SurgeCodecSpec:
    return SurgeCodecSpec(
        keyword=keyword,
        protocol=protocol,
        policy_kind=kind,
        udp_behavior=udp,
        emitter_handler=handler,
        consumed_parameters=frozenset(consumed),
        emitted_parameters=frozenset(consumed if emitted is None else emitted),
        normalized_parameters=normalized,
        multi_value_parameters=frozenset(multi),
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
        handler="_parts_ss",
        consumed=(
            "encrypt-method",
            "password",
            "udp-relay",
            "udp-port",
            "obfs",
            "obfs-host",
        ),
    ),
    _spec(
        "vmess",
        protocol=Protocol.VMESS,
        udp=SurgeUdpBehavior.AUTOMATIC,
        handler="_parts_vmess",
        consumed=(
            "username",
            "encrypt-method",
            "vmess-aead",
            "tls",
            "ws",
            "ws-path",
            "ws-headers",
        ),
    ),
    _spec(
        "trojan",
        protocol=Protocol.TROJAN,
        udp=SurgeUdpBehavior.AUTOMATIC,
        handler="_parts_trojan",
        consumed=("password", "ws", "ws-path", "ws-headers"),
    ),
    _spec(
        "socks5",
        protocol=Protocol.SOCKS5,
        udp=SurgeUdpBehavior.EXPLICIT,
        handler="_parts_socks5",
        consumed=("username", "password", "udp-relay"),
    ),
    _spec(
        "socks5-tls",
        protocol=Protocol.SOCKS5,
        udp=SurgeUdpBehavior.EXPLICIT,
        handler="_parts_socks5",
        consumed=("username", "password", "udp-relay"),
    ),
    _spec(
        "http",
        protocol=Protocol.HTTP,
        udp=SurgeUdpBehavior.UNSUPPORTED,
        handler="_parts_http",
        consumed=("username", "password"),
    ),
    _spec(
        "https",
        protocol=Protocol.HTTP,
        udp=SurgeUdpBehavior.UNSUPPORTED,
        handler="_parts_http",
        consumed=("username", "password"),
    ),
    _spec(
        "h2-connect",
        protocol=Protocol.HTTP,
        udp=SurgeUdpBehavior.EXPLICIT,
        handler="_parts_http",
        consumed=("username", "password", "headers", "max-streams", "udp-relay"),
    ),
    _spec(
        "anytls",
        protocol=Protocol.ANYTLS,
        udp=SurgeUdpBehavior.AUTOMATIC,
        handler="_parts_anytls",
        consumed=("password", "reuse"),
    ),
    _spec(
        "ssh",
        protocol=Protocol.SSH,
        udp=SurgeUdpBehavior.UNSUPPORTED,
        handler="_parts_ssh",
        consumed=(
            "username",
            "password",
            "private-key",
            "idle-timeout",
            "server-fingerprint",
        ),
        multi=("server-fingerprint",),
    ),
    _spec(
        "snell",
        protocol=Protocol.SNELL,
        udp=SurgeUdpBehavior.VERSIONED,
        handler="_parts_snell",
        consumed=(
            "psk",
            "version",
            "reuse",
            "udp-port",
            "mode",
            "obfs",
            "obfs-host",
        ),
    ),
    _spec(
        "tuic",
        protocol=Protocol.TUIC,
        udp=SurgeUdpBehavior.AUTOMATIC,
        handler="_parts_tuic",
        consumed=("token", "version", "port-hopping", "port-hopping-interval"),
    ),
    _spec(
        "tuic-v5",
        protocol=Protocol.TUIC,
        udp=SurgeUdpBehavior.AUTOMATIC,
        handler="_parts_tuic",
        consumed=("uuid", "password", "port-hopping", "port-hopping-interval"),
    ),
    _spec(
        "hysteria2",
        protocol=Protocol.HYSTERIA2,
        udp=SurgeUdpBehavior.AUTOMATIC,
        handler="_parts_hysteria2",
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
    ),
    _spec(
        "wireguard",
        protocol=Protocol.WIREGUARD,
        udp=SurgeUdpBehavior.AUTOMATIC,
        handler="_parts_wireguard",
        consumed=("section-name",),
    ),
    _spec(
        "tailscale",
        protocol=Protocol.TAILSCALE,
        udp=SurgeUdpBehavior.AUTOMATIC,
        handler="_parts_tailscale",
        consumed=("section-name",),
    ),
    _spec(
        "masque",
        protocol=Protocol.MASQUE,
        udp=SurgeUdpBehavior.AUTOMATIC,
        handler="_parts_masque",
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
        handler="_parts_trust_tunnel",
        consumed=("username", "password", "headers", "max-streams", "h3", "ws"),
    ),
    _spec(
        "direct",
        protocol=Protocol.DIRECT,
        kind=SurgePolicyKind.DOCUMENT,
        udp=SurgeUdpBehavior.AUTOMATIC,
    ),
    *(
        _spec(
            keyword,
            protocol=None,
            kind=SurgePolicyKind.DOCUMENT,
            udp=SurgeUdpBehavior.UNSUPPORTED,
        )
        for keyword in (
            "reject",
            "reject-drop",
            "reject-no-drop",
            "reject-tinygif",
        )
    ),
    _spec(
        "external",
        protocol=None,
        kind=SurgePolicyKind.EXTERNAL,
        udp=SurgeUdpBehavior.EXPLICIT,
        consumed=("exec", "local-port", "args", "addresses", "udp-relay"),
        multi=("args", "addresses"),
    ),
)


SURGE_CODEC_BY_KEYWORD = {spec.keyword: spec for spec in SURGE_CODEC_SPECS}
if len(SURGE_CODEC_BY_KEYWORD) != len(SURGE_CODEC_SPECS):
    raise RuntimeError("Duplicate Surge codec keyword")

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

_handlers: dict[Protocol, str] = {}
for _codec in SURGE_CODEC_SPECS:
    if _codec.policy_kind != SurgePolicyKind.NODE:
        continue
    if _codec.protocol is None or _codec.emitter_handler is None:
        raise RuntimeError(f"Incomplete Surge node codec: {_codec.keyword}")
    existing_handler = _handlers.get(_codec.protocol)
    if existing_handler is not None and existing_handler != _codec.emitter_handler:
        raise RuntimeError(
            f"Conflicting Surge emitter handlers for {_codec.protocol.value}"
        )
    _handlers[_codec.protocol] = _codec.emitter_handler
SURGE_EMITTER_HANDLERS = dict(_handlers)


def get_surge_codec(keyword: str) -> SurgeCodecSpec | None:
    return SURGE_CODEC_BY_KEYWORD.get(keyword.lower())
