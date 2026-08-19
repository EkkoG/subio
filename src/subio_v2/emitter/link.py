"""
按协议构造标准订阅 URL 链接。

每个 build_*_url 函数遵循该协议的官方/事实标准 URI 形式，
不绑定任何特定消费方（v2rayN/dae/Clash）。各 emitter 通过
capabilities 决定接受哪些协议，再调用同一个 builder。
"""

import base64
import json
import urllib.parse
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from types import MappingProxyType

from subio_v2.model.nodes import (
    AnyTLSNode,
    HttpNode,
    Hysteria2Node,
    Network,
    Node,
    Protocol,
    ShadowsocksNode,
    Socks5Node,
    TrojanNode,
    TUICNode,
    VlessNode,
    VmessNode,
)


def _quote_name(name: str) -> str:
    return urllib.parse.quote(name, safe="")


def build_ss_url(node: ShadowsocksNode) -> str:
    """SIP002: ss://BASE64URL(method:password)@server:port[/?plugin=...]#name"""
    userinfo = f"{node.cipher}:{node.password}"
    userinfo_b64 = (
        base64.urlsafe_b64encode(userinfo.encode("utf-8")).decode("utf-8").rstrip("=")
    )
    url = f"ss://{userinfo_b64}@{node.server}:{node.port}"

    if node.plugin:
        # SIP003 plugin opt string: name;k=v;k=v...
        plugin_parts = [node.plugin]
        if node.plugin_opts:
            for k, v in node.plugin_opts.items():
                plugin_parts.append(f"{k}={v}")
        plugin_str = ";".join(plugin_parts)
        url += f"/?plugin={urllib.parse.quote(plugin_str, safe='')}"

    url += f"#{_quote_name(node.name)}"
    return url


def build_vmess_url(node: VmessNode) -> str:
    """v2rayN: vmess://BASE64(JSON)"""
    network = node.transport.network_value if node.transport else "tcp"
    data = {
        "v": "2",
        "ps": node.name,
        "add": node.server,
        "port": str(node.port),
        "id": node.uuid,
        "aid": str(node.alter_id),
        "scy": node.cipher or "auto",
        "net": network,
        "type": "none",
        "host": "",
        "path": "",
        "tls": "",
        "sni": "",
        "alpn": "",
    }

    if node.transport:
        if node.transport.network == Network.WS:
            if node.transport.path:
                data["path"] = node.transport.path
            if node.transport.headers and "Host" in node.transport.headers:
                data["host"] = node.transport.headers["Host"]
        elif node.transport.network == Network.H2:
            if node.transport.path:
                data["path"] = node.transport.path
            if node.transport.host:
                data["host"] = (
                    ",".join(node.transport.host)
                    if isinstance(node.transport.host, list)
                    else node.transport.host
                )
        elif node.transport.network == Network.GRPC:
            if node.transport.grpc_service_name:
                data["path"] = node.transport.grpc_service_name
        elif node.transport.network == Network.HTTP:
            if node.transport.path:
                data["path"] = (
                    node.transport.path
                    if isinstance(node.transport.path, str)
                    else ",".join(node.transport.path)
                )
            if node.transport.headers and "Host" in node.transport.headers:
                data["host"] = node.transport.headers["Host"]

    if node.tls and node.tls.enabled:
        data["tls"] = "tls"
        if node.tls.server_name:
            data["sni"] = node.tls.server_name
        if node.tls.alpn:
            data["alpn"] = ",".join(node.tls.alpn)

    json_str = json.dumps(data)
    return "vmess://" + base64.b64encode(json_str.encode("utf-8")).decode("utf-8")


def build_vless_url(node: VlessNode) -> str:
    """DuckSoft URI: vless://uuid@server:port?type=...&security=...&...#name"""
    network = node.transport.network_value if node.transport else "tcp"
    params: dict[str, str] = {"type": network}

    if node.tls and node.tls.enabled:
        if node.tls.reality_opts:
            params["security"] = "reality"
            pk = node.tls.reality_opts.get("public-key")
            sid = node.tls.reality_opts.get("short-id")
            if pk:
                params["pbk"] = pk
            if sid:
                params["sid"] = sid
        else:
            params["security"] = "tls"
        if node.tls.server_name:
            params["sni"] = node.tls.server_name
        if node.tls.client_fingerprint:
            params["fp"] = node.tls.client_fingerprint
        if node.tls.skip_cert_verify:
            params["allowInsecure"] = "1"
        if node.tls.alpn:
            params["alpn"] = ",".join(node.tls.alpn)
    else:
        params["security"] = "none"

    if node.flow:
        params["flow"] = node.flow

    if node.transport:
        if node.transport.network == Network.WS:
            if node.transport.path:
                params["path"] = node.transport.path
            if node.transport.headers and "Host" in node.transport.headers:
                params["host"] = node.transport.headers["Host"]
        elif node.transport.network == Network.GRPC:
            if node.transport.grpc_service_name:
                params["serviceName"] = node.transport.grpc_service_name
        elif node.transport.network == Network.H2:
            if node.transport.path:
                params["path"] = node.transport.path
            if node.transport.host:
                params["host"] = (
                    ",".join(node.transport.host)
                    if isinstance(node.transport.host, list)
                    else node.transport.host
                )
        elif node.transport.network == Network.HTTP:
            if node.transport.path:
                params["path"] = (
                    node.transport.path
                    if isinstance(node.transport.path, str)
                    else ",".join(node.transport.path)
                )
            if node.transport.headers and "Host" in node.transport.headers:
                params["host"] = node.transport.headers["Host"]

    query = urllib.parse.urlencode(params)
    return f"vless://{node.uuid}@{node.server}:{node.port}?{query}#{_quote_name(node.name)}"


def build_trojan_url(node: TrojanNode) -> str:
    """Trojan-GFW URI: trojan://password@server:port?sni=...&allowInsecure=1#name"""
    params: dict[str, str] = {}
    if node.tls and node.tls.enabled:
        if node.tls.server_name:
            params["sni"] = node.tls.server_name
        if node.tls.skip_cert_verify:
            params["allowInsecure"] = "1"
        if node.tls.alpn:
            params["alpn"] = ",".join(node.tls.alpn)

    if node.transport:
        if node.transport.network == Network.WS:
            params["type"] = "ws"
            if node.transport.path:
                params["path"] = node.transport.path
            if node.transport.headers and "Host" in node.transport.headers:
                params["host"] = node.transport.headers["Host"]
        elif node.transport.network == Network.GRPC:
            params["type"] = "grpc"
            if node.transport.grpc_service_name:
                params["serviceName"] = node.transport.grpc_service_name
        elif node.transport.network == Network.H2:
            params["type"] = "h2"
            if node.transport.path:
                params["path"] = node.transport.path
            if node.transport.host:
                params["host"] = (
                    ",".join(node.transport.host)
                    if isinstance(node.transport.host, list)
                    else node.transport.host
                )

    url = f"trojan://{urllib.parse.quote(node.password, safe='')}@{node.server}:{node.port}"
    if params:
        url += f"?{urllib.parse.urlencode(params)}"
    url += f"#{_quote_name(node.name)}"
    return url


def build_socks5_url(node: Socks5Node) -> str | None:
    """socks5://[user:pass@]server:port#name"""
    if node.tls and node.tls.enabled:
        # There is no interoperable SOCKS5-TLS subscription URI to emit here.
        return None
    if node.username or node.password:
        userinfo = f"{urllib.parse.quote(node.username or '', safe='')}:{urllib.parse.quote(node.password or '', safe='')}@"
    else:
        userinfo = ""
    return f"socks5://{userinfo}{node.server}:{node.port}#{_quote_name(node.name)}"


def build_http_url(node: HttpNode) -> str:
    """http(s)://[user:pass@]server:port#name"""
    scheme = "https" if (node.tls and node.tls.enabled) else "http"
    if node.username or node.password:
        userinfo = f"{urllib.parse.quote(node.username or '', safe='')}:{urllib.parse.quote(node.password or '', safe='')}@"
    else:
        userinfo = ""
    return f"{scheme}://{userinfo}{node.server}:{node.port}#{_quote_name(node.name)}"


def build_hysteria2_url(node: Hysteria2Node) -> str:
    """Hysteria2 URI: hysteria2://password@server:port/?sni=...&obfs=...#name"""
    params: dict[str, str] = {}
    if node.tls:
        if node.tls.server_name:
            params["sni"] = node.tls.server_name
        if node.tls.skip_cert_verify:
            params["insecure"] = "1"
        if node.tls.alpn:
            params["alpn"] = ",".join(node.tls.alpn)
    if node.obfs:
        params["obfs"] = node.obfs
        if node.obfs_password:
            params["obfs-password"] = node.obfs_password
    if node.up:
        params["up"] = node.up
    if node.down:
        params["down"] = node.down

    url = f"hysteria2://{urllib.parse.quote(node.password, safe='')}@{node.server}:{node.port}/"
    if params:
        url += f"?{urllib.parse.urlencode(params)}"
    url += f"#{_quote_name(node.name)}"
    return url


def build_tuic_url(node: TUICNode) -> str:
    """TUIC v5: tuic://uuid:password@server:port?...#name
    TUIC v4: tuic://token@server:port?...#name
    """
    params: dict[str, str] = {}
    if node.tls:
        if node.tls.server_name:
            params["sni"] = node.tls.server_name
        if node.tls.skip_cert_verify:
            params["allow_insecure"] = "1"
        if node.tls.alpn:
            params["alpn"] = ",".join(node.tls.alpn)

    if node.version == 5 or (node.uuid and node.password):
        userinfo = f"{node.uuid}:{urllib.parse.quote(node.password or '', safe='')}"
    else:
        userinfo = urllib.parse.quote(node.token or "", safe="")

    url = f"tuic://{userinfo}@{node.server}:{node.port}"
    if params:
        url += f"?{urllib.parse.urlencode(params)}"
    url += f"#{_quote_name(node.name)}"
    return url


def build_anytls_url(node: AnyTLSNode) -> str:
    """anytls://password@server:port/?sni=...#name"""
    params: dict[str, str] = {}
    if node.tls:
        if node.tls.server_name:
            params["sni"] = node.tls.server_name
        if node.tls.skip_cert_verify:
            params["insecure"] = "1"
        if node.tls.alpn:
            params["alpn"] = ",".join(node.tls.alpn)

    url = f"anytls://{urllib.parse.quote(node.password, safe='')}@{node.server}:{node.port}/"
    if params:
        url += f"?{urllib.parse.urlencode(params)}"
    url += f"#{_quote_name(node.name)}"
    return url


@dataclass(frozen=True)
class LinkCodecSpec:
    builder: Callable[[Node], str | None]
    targets: frozenset[str]


LINK_CODECS: Mapping[Protocol, LinkCodecSpec] = MappingProxyType(
    {
        Protocol.SHADOWSOCKS: LinkCodecSpec(build_ss_url, frozenset({"dae", "v2rayn"})),
        Protocol.VMESS: LinkCodecSpec(build_vmess_url, frozenset({"dae", "v2rayn"})),
        Protocol.VLESS: LinkCodecSpec(build_vless_url, frozenset({"dae", "v2rayn"})),
        Protocol.TROJAN: LinkCodecSpec(build_trojan_url, frozenset({"dae", "v2rayn"})),
        Protocol.SOCKS5: LinkCodecSpec(build_socks5_url, frozenset({"dae", "v2rayn"})),
        Protocol.HTTP: LinkCodecSpec(build_http_url, frozenset({"dae"})),
        Protocol.HYSTERIA2: LinkCodecSpec(build_hysteria2_url, frozenset({"dae"})),
        Protocol.TUIC: LinkCodecSpec(build_tuic_url, frozenset({"dae"})),
        Protocol.ANYTLS: LinkCodecSpec(build_anytls_url, frozenset({"dae"})),
    }
)
LINK_BUILDERS: Mapping[Protocol, Callable[[Node], str | None]] = MappingProxyType(
    {protocol: codec.builder for protocol, codec in LINK_CODECS.items()}
)


def link_protocols_for_target(target: str) -> frozenset[str]:
    return frozenset(
        protocol.value
        for protocol, codec in LINK_CODECS.items()
        if target in codec.targets
    )


def build_url(node: Node, *, target: str | None = None) -> str | None:
    """按 Node 类型分发到具体的 URL 构造函数。"""
    codec = LINK_CODECS.get(node.type)
    if codec is None or (target is not None and target not in codec.targets):
        return None
    return codec.builder(node)
