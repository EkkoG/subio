from collections.abc import Callable
from dataclasses import dataclass

from subio_v2.adapters.surge.syntax import SurgeProxyRecord
from subio_v2.core.nodes import (
    AnyTLSNode,
    HttpNode,
    HttpVariant,
    Hysteria2Node,
    Network,
    Node,
    Protocol,
    ShadowsocksNode,
    SnellNode,
    Socks5Node,
    SSHNode,
    TLSSettings,
    TransportSettings,
    TrojanNode,
    TUICNode,
    VmessNode,
)
from subio_v2.adapters.surge.validation import _strict_bool


@dataclass(frozen=True)
class SurgeProtocolParseContext:
    record: SurgeProxyRecord
    server: str
    port: int

    @property
    def keyword(self) -> str:
        return self.record.type.lower()

    @property
    def values(self) -> dict[str, str]:
        return self.record.parameters.last_values

    @property
    def positional(self) -> list[str]:
        return list(self.record.positional[2:])

    def get_bool(self, key: str, default: bool = False) -> bool:
        value = self.values.get(key)
        return default if value is None else _strict_bool(value, key)

    def get_int(self, key: str) -> int | None:
        value = self.values.get(key)
        return None if value is None else int(value)

    def build_tls(self, *, enabled: bool = False) -> TLSSettings:
        values = self.values
        sni = values.get("sni")
        alpn = values.get("alpn")
        return TLSSettings(
            enabled=enabled or self.get_bool("tls", False),
            server_name=None if sni == "off" else sni,
            skip_cert_verify=self.get_bool("skip-cert-verify", False),
            alpn=(
                [item.strip() for item in alpn.split(",")]
                if alpn and "," in alpn
                else ([alpn] if alpn else None)
            ),
            sni_disabled=sni == "off",
            verify_name=values.get("server-cert-verify-name"),
            certificate_sha256=values.get("server-cert-fingerprint-sha256"),
            client_cert_ref=values.get("client-cert"),
        )

    def build_transport(self) -> TransportSettings:
        values = self.values
        transport = TransportSettings()
        if values.get("ws") != "true":
            return transport
        transport.network = Network.WS
        transport.path = values.get("ws-path")
        if values.get("ws-headers"):
            transport.headers = _parse_headers(values["ws-headers"])
        return transport


SurgeProtocolParser = Callable[[SurgeProtocolParseContext], Node | None]


def _parse_headers(value: str, *, separator: str = "|") -> dict[str, str]:
    headers: dict[str, str] = {}
    for item in value.split(separator):
        if ":" not in item:
            continue
        key, header_value = item.split(":", 1)
        headers[key.strip()] = header_value.strip()
    return headers


def parse_shadowsocks(context: SurgeProtocolParseContext) -> Node:
    values = context.values
    plugin = "obfs" if values.get("obfs") else None
    plugin_opts = (
        {
            "mode": values["obfs"],
            "host": values.get("obfs-host", ""),
        }
        if plugin
        else None
    )
    return ShadowsocksNode(
        name=context.record.name,
        type=Protocol.SHADOWSOCKS,
        server=context.server,
        port=context.port,
        cipher=values.get("encrypt-method") or "chacha20-ietf-poly1305",
        password=values.get("password") or "",
        udp_port=context.get_int("udp-port"),
        plugin=plugin,
        plugin_opts=plugin_opts,
        udp=context.get_bool("udp-relay", False),
        obfs_uri=values.get("obfs-uri"),
    )


def parse_vmess(context: SurgeProtocolParseContext) -> Node:
    values = context.values
    return VmessNode(
        name=context.record.name,
        type=Protocol.VMESS,
        server=context.server,
        port=context.port,
        uuid=values.get("username", ""),
        cipher=values.get("encrypt-method", "aes-128-gcm"),
        vmess_aead=context.get_bool("vmess-aead", False),
        tls=context.build_tls(),
        transport=context.build_transport(),
        udp=True,
    )


def parse_trojan(context: SurgeProtocolParseContext) -> Node:
    return TrojanNode(
        name=context.record.name,
        type=Protocol.TROJAN,
        server=context.server,
        port=context.port,
        password=context.values.get("password", ""),
        tls=context.build_tls(enabled=True),
        transport=context.build_transport(),
        udp=True,
    )


def parse_socks5(context: SurgeProtocolParseContext) -> Node:
    values = context.values
    positional = context.positional
    username = values.get("username") or (positional[0] if positional else None)
    password = values.get("password") or (
        positional[1] if len(positional) > 1 else None
    )
    return Socks5Node(
        name=context.record.name,
        type=Protocol.SOCKS5,
        server=context.server,
        port=context.port,
        username=username,
        password=password,
        tls=context.build_tls(enabled=context.keyword == "socks5-tls"),
        udp=context.get_bool("udp-relay", False),
    )


def parse_http(context: SurgeProtocolParseContext) -> Node:
    values = context.values
    positional = context.positional
    username = values.get("username") or (positional[0] if positional else None)
    password = values.get("password") or (
        positional[1] if len(positional) > 1 else None
    )
    return HttpNode(
        name=context.record.name,
        type=Protocol.HTTP,
        server=context.server,
        port=context.port,
        username=username,
        password=password,
        headers=(
            _parse_headers(
                values["headers"],
                separator=(
                    ";"
                    if context.keyword in {"http", "https", "h2-connect"}
                    else "|"
                ),
            )
            if values.get("headers")
            else None
        ),
        always_use_connect=(
            context.get_bool("always-use-connect")
            if values.get("always-use-connect") is not None
            else None
        ),
        variant=HttpVariant(context.keyword),
        max_streams=context.get_int("max-streams"),
        tls=context.build_tls(enabled=context.keyword in {"https", "h2-connect"}),
        udp=(
            context.get_bool("udp-relay", False)
            if context.keyword == "h2-connect"
            else False
        ),
    )


def parse_anytls(context: SurgeProtocolParseContext) -> Node:
    return AnyTLSNode(
        name=context.record.name,
        type=Protocol.ANYTLS,
        server=context.server,
        port=context.port,
        password=context.values.get("password", ""),
        reuse=context.get_bool("reuse", True),
        tls=context.build_tls(enabled=True),
        udp=True,
    )


def parse_ssh(context: SurgeProtocolParseContext) -> Node:
    values = context.values
    keystore_id = values.get("private-key") or None
    return SSHNode(
        name=context.record.name,
        type=Protocol.SSH,
        server=context.server,
        port=context.port,
        username=values.get("username", ""),
        password=values.get("password"),
        private_key=None,
        keystore_id=keystore_id,
        idle_timeout=context.get_int("idle-timeout"),
        server_fingerprints=[
            fingerprint
            for value in context.record.parameters.get_all("server-fingerprint")
            for fingerprint in value.split(",")
            if fingerprint
        ]
        or None,
        udp=False,
    )


def parse_snell(context: SurgeProtocolParseContext) -> Node:
    values = context.values
    try:
        version = int(values["version"]) if values.get("version") else None
    except (TypeError, ValueError):
        version = None
    return SnellNode(
        name=context.record.name,
        type=Protocol.SNELL,
        server=context.server,
        port=context.port,
        psk=values.get("psk", ""),
        version=version,
        reuse=(
            context.get_bool("reuse") if values.get("reuse") is not None else None
        ),
        udp_port=context.get_int("udp-port"),
        mode=values.get("mode"),
        obfs=values.get("obfs"),
        obfs_host=values.get("obfs-host"),
        obfs_uri=values.get("obfs-uri"),
        tls=TLSSettings(enabled=False),
        udp=bool(version and version >= 3),
    )


def parse_tuic(context: SurgeProtocolParseContext) -> Node:
    values = context.values
    try:
        version = (
            5
            if context.keyword == "tuic-v5"
            else (int(values["version"]) if values.get("version") else None)
        )
    except (TypeError, ValueError):
        version = None
    return TUICNode(
        name=context.record.name,
        type=Protocol.TUIC,
        server=context.server,
        port=context.port,
        token=values.get("token"),
        password=values.get("password"),
        uuid=values.get("uuid"),
        version=version,
        ports=values.get("port-hopping"),
        hop_interval=context.get_int("port-hopping-interval"),
        tls=context.build_tls(enabled=True),
        udp=True,
    )


def parse_hysteria2(context: SurgeProtocolParseContext) -> Node | None:
    values = context.values
    salamander_password = values.get("salamander-password")
    gecko_password = values.get("gecko-password")
    if salamander_password and gecko_password:
        return None
    if salamander_password:
        obfs, obfs_password = "salamander", salamander_password
    elif gecko_password:
        obfs, obfs_password = "gecko", gecko_password
    else:
        obfs = values.get("obfs")
        obfs_password = values.get("obfs-password")
    return Hysteria2Node(
        name=context.record.name,
        type=Protocol.HYSTERIA2,
        server=context.server,
        port=context.port,
        password=values.get("password", ""),
        up=values.get("upload-bandwidth") or values.get("up"),
        down=values.get("download-bandwidth") or values.get("down"),
        ports=values.get("port-hopping"),
        hop_interval=context.get_int("port-hopping-interval"),
        obfs=obfs,
        obfs_password=obfs_password,
        tls=context.build_tls(enabled=True),
        udp=True,
    )
