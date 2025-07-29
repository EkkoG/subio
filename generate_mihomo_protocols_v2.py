#!/usr/bin/env python3
"""Generate all mihomo-supported protocol combinations using Proxy objects."""

import sys

sys.path.insert(0, "/Users/ciel/Documents/workspace/clashio/src")

import yaml
from typing import List
from subio2.models.node import (
    Proxy,
    ShadowsocksProtocol,
    VmessProtocol,
    VlessProtocol,
    TrojanProtocol,
    HysteriaProtocol,
    Hysteria2Protocol,
    HttpProtocol,
    Socks5Protocol,
    WireGuardProtocol,
    TuicProtocol,
    SSHProtocol,
    SnellProtocol,
    MieruProtocol,
    AnyTLSProtocol,
    BasicAuth,
    TLSConfig,
    RealityConfig,
    Transport,
    WebSocketTransport,
    GRPCTransport,
    HTTP2Transport,
    QUICTransport,
    SmuxConfig,
    ECHConfig,
)
from subio2.renderers.clash.base import ClashRenderer


def generate_shadowsocks_proxies() -> List[Proxy]:
    """Generate Shadowsocks protocol proxies."""
    proxies = []

    # Basic variant
    proxy = Proxy(
        name="ss-basic",
        server="1.2.3.4",
        port=8388,
        protocol=ShadowsocksProtocol(method="aes-256-gcm", password="password123"),
    )
    proxies.append(proxy)

    # With UDP over TCP
    proxy_uot = Proxy(
        name="ss-uot",
        server="1.2.3.4",
        port=8389,
        protocol=ShadowsocksProtocol(
            method="aes-256-gcm",
            password="password123",
            udp_over_tcp=True,
            udp_over_tcp_version=2,
        ),
    )
    proxies.append(proxy_uot)

    # Plugin variants
    plugins = [
        ("obfs", {"mode": "tls", "host": "example.com"}),
        ("obfs", {"mode": "http", "host": "example.com"}),
        (
            "v2ray-plugin",
            {"mode": "websocket", "tls": True, "host": "example.com", "path": "/ws"},
        ),
        (
            "shadow-tls",
            {"version": 3, "host": "example.com", "password": "shadow-tls-password"},
        ),
        (
            "restls",
            {
                "version-hint": "tls13",
                "host": "example.com",
                "password": "restls-password",
            },
        ),
    ]

    for j, (plugin_name, plugin_opts) in enumerate(plugins):
        proxy = Proxy(
            name=f"ss-plugin-{plugin_name}-{j}",
            server="1.2.3.4",
            port=10388 + j,
            protocol=ShadowsocksProtocol(
                method="aes-256-gcm",
                password="password123",
                plugin=plugin_name,
                plugin_opts=plugin_opts,
            ),
        )
        proxies.append(proxy)

    return proxies


def generate_vmess_proxies() -> List[Proxy]:
    """Generate VMess protocol proxies."""
    proxies = []

    # Basic variant with TLS
    proxy = Proxy(
        name="vmess-basic",
        server="1.2.3.4",
        port=443,
        protocol=VmessProtocol(
            uuid="00000000-0000-0000-0000-000000000001", alter_id=0, security="auto"
        ),
        tls=TLSConfig(enabled=True, skip_cert_verify=True),
    )
    proxies.append(proxy)

    # With WebSocket
    proxy_ws = Proxy(
        name="vmess-ws",
        server="1.2.3.4",
        port=443,
        protocol=VmessProtocol(
            uuid="00000000-0000-0000-0000-000000000002", alter_id=0, security="auto"
        ),
        tls=TLSConfig(enabled=True, skip_cert_verify=True),
        transport=Transport(
            type="ws",
            ws=WebSocketTransport(path="/ws", headers={"Host": "example.com"}),
        ),
    )
    proxies.append(proxy_ws)

    # With gRPC
    proxy_grpc = Proxy(
        name="vmess-grpc",
        server="1.2.3.4",
        port=443,
        protocol=VmessProtocol(
            uuid="00000000-0000-0000-0000-000000000003", alter_id=0, security="auto"
        ),
        tls=TLSConfig(enabled=True, skip_cert_verify=True),
        transport=Transport(type="grpc", grpc=GRPCTransport(service_name="example")),
    )
    proxies.append(proxy_grpc)

    # With HTTP/2
    proxy_h2 = Proxy(
        name="vmess-h2",
        server="1.2.3.4",
        port=443,
        protocol=VmessProtocol(
            uuid="00000000-0000-0000-0000-000000000004", alter_id=0, security="auto"
        ),
        tls=TLSConfig(enabled=True, skip_cert_verify=True),
        transport=Transport(
            type="h2", h2=HTTP2Transport(path="/h2", host=["example.com"])
        ),
    )
    proxies.append(proxy_h2)

    # With QUIC
    proxy_quic = Proxy(
        name="vmess-quic",
        server="1.2.3.4",
        port=443,
        protocol=VmessProtocol(
            uuid="00000000-0000-0000-0000-000000000005", alter_id=0, security="auto"
        ),
        transport=Transport(
            type="quic",
            quic=QUICTransport(
                security="aes-128-gcm", key="password123", header={"type": "srtp"}
            ),
        ),
    )
    proxies.append(proxy_quic)

    # With Smux
    proxy_smux = Proxy(
        name="vmess-smux",
        server="1.2.3.4",
        port=443,
        protocol=VmessProtocol(
            uuid="00000000-0000-0000-0000-000000000006", alter_id=0, security="auto"
        ),
        tls=TLSConfig(enabled=True, skip_cert_verify=True),
        smux=SmuxConfig(
            enabled=True,
            protocol="h2mux",
            max_connections=4,
            min_streams=4,
            max_streams=1024,
            padding=False,
        ),
    )
    proxies.append(proxy_smux)

    return proxies


def generate_vless_proxies() -> List[Proxy]:
    """Generate VLESS protocol proxies."""
    proxies = []

    # Basic variant
    proxy = Proxy(
        name="vless-basic",
        server="1.2.3.4",
        port=443,
        protocol=VlessProtocol(
            uuid="00000000-0000-0000-0000-000000000001", encryption="none"
        ),
        tls=TLSConfig(enabled=True, skip_cert_verify=True),
    )
    proxies.append(proxy)

    # With flow control
    flows = ["xtls-rprx-direct", "xtls-rprx-vision"]
    for i, flow in enumerate(flows):
        proxy = Proxy(
            name=f"vless-{flow}",
            server="1.2.3.4",
            port=443 + i,
            protocol=VlessProtocol(
                uuid=f"0000000{i}-0000-0000-0000-000000000002",
                encryption="none",
                flow=flow,
            ),
            tls=TLSConfig(enabled=True, skip_cert_verify=True),
        )
        proxies.append(proxy)

    # With Reality
    proxy_reality = Proxy(
        name="vless-reality",
        server="1.2.3.4",
        port=443,
        protocol=VlessProtocol(
            uuid="00000000-0000-0000-0000-000000000003",
            encryption="none",
            flow="xtls-rprx-vision",
        ),
        tls=TLSConfig(enabled=True, client_fingerprint="chrome"),
        reality=RealityConfig(
            enabled=True,
            public_key="lCWWkpDHGPtWRRIe5Ww8nPbT0GpyLSS1RCWUpI0nYFw",
            short_id="6ba85179e30d4fc2",
        ),
    )
    proxies.append(proxy_reality)

    # With WebSocket
    proxy_ws = Proxy(
        name="vless-ws",
        server="1.2.3.4",
        port=443,
        protocol=VlessProtocol(
            uuid="00000000-0000-0000-0000-000000000004", encryption="none"
        ),
        tls=TLSConfig(enabled=True, skip_cert_verify=True),
        transport=Transport(type="ws", ws=WebSocketTransport(path="/ws")),
    )
    proxies.append(proxy_ws)

    # With gRPC
    proxy_grpc = Proxy(
        name="vless-grpc",
        server="1.2.3.4",
        port=443,
        protocol=VlessProtocol(
            uuid="00000000-0000-0000-0000-000000000005", encryption="none"
        ),
        tls=TLSConfig(enabled=True, skip_cert_verify=True),
        transport=Transport(type="grpc", grpc=GRPCTransport(service_name="example")),
    )
    proxies.append(proxy_grpc)

    return proxies


def generate_trojan_proxies() -> List[Proxy]:
    """Generate Trojan protocol proxies."""
    proxies = []

    # Basic variant
    proxy = Proxy(
        name="trojan-basic",
        server="1.2.3.4",
        port=443,
        protocol=TrojanProtocol(password="password123"),
        tls=TLSConfig(enabled=True, sni="example.com", skip_cert_verify=True),
    )
    proxies.append(proxy)

    # With WebSocket
    proxy_ws = Proxy(
        name="trojan-ws",
        server="1.2.3.4",
        port=443,
        protocol=TrojanProtocol(password="password123"),
        tls=TLSConfig(enabled=True, sni="example.com", skip_cert_verify=True),
        transport=Transport(type="ws", ws=WebSocketTransport(path="/ws")),
    )
    proxies.append(proxy_ws)

    # With gRPC
    proxy_grpc = Proxy(
        name="trojan-grpc",
        server="1.2.3.4",
        port=443,
        protocol=TrojanProtocol(password="password123"),
        tls=TLSConfig(enabled=True, sni="example.com", skip_cert_verify=True),
        transport=Transport(type="grpc", grpc=GRPCTransport(service_name="example")),
    )
    proxies.append(proxy_grpc)

    # With client fingerprint
    proxy_fp = Proxy(
        name="trojan-fingerprint",
        server="1.2.3.4",
        port=443,
        protocol=TrojanProtocol(password="password123"),
        tls=TLSConfig(
            enabled=True,
            sni="example.com",
            skip_cert_verify=True,
            client_fingerprint="firefox",
            alpn=["h2", "http/1.1"],
        ),
    )
    proxies.append(proxy_fp)

    return proxies


def generate_hysteria_proxies() -> List[Proxy]:
    """Generate Hysteria protocol proxies."""
    proxies = []

    # Hysteria v1 - auth
    proxy_v1_auth = Proxy(
        name="hysteria-v1-auth",
        server="1.2.3.4",
        port=443,
        protocol=HysteriaProtocol(
            auth="password123", protocol="udp", up_mbps="30 Mbps", down_mbps="100 Mbps"
        ),
        tls=TLSConfig(enabled=True, skip_cert_verify=True),
    )
    proxies.append(proxy_v1_auth)

    # Hysteria v1 - auth-str
    proxy_v1_authstr = Proxy(
        name="hysteria-v1-authstr",
        server="1.2.3.4",
        port=443,
        protocol=HysteriaProtocol(
            auth_str="base64authstring", protocol="wechat-video", obfs="obfuscation123"
        ),
        tls=TLSConfig(enabled=True, skip_cert_verify=True),
    )
    proxies.append(proxy_v1_authstr)

    # Hysteria v1 - with ALPN
    proxy_v1_alpn = Proxy(
        name="hysteria-v1-alpn",
        server="1.2.3.4",
        port=443,
        protocol=HysteriaProtocol(
            auth="password123",
            protocol="faketcp",
            recv_window=67108864,
            recv_window_conn=16777216,
        ),
        tls=TLSConfig(enabled=True, alpn=["h3"], ca="/path/to/ca.crt"),
    )
    proxies.append(proxy_v1_alpn)

    # Hysteria v2 - basic
    proxy_v2_basic = Proxy(
        name="hysteria2-basic",
        server="1.2.3.4",
        port=443,
        protocol=Hysteria2Protocol(password="password123"),
        tls=TLSConfig(enabled=True, skip_cert_verify=True),
    )
    proxies.append(proxy_v2_basic)

    # Hysteria v2 - with obfs
    proxy_v2_obfs = Proxy(
        name="hysteria2-obfs",
        server="1.2.3.4",
        port=443,
        protocol=Hysteria2Protocol(
            password="password123", obfs="salamander", obfs_password="obfspassword"
        ),
        tls=TLSConfig(enabled=True, skip_cert_verify=True),
    )
    proxies.append(proxy_v2_obfs)

    # Hysteria v2 - with bandwidth
    proxy_v2_bw = Proxy(
        name="hysteria2-bandwidth",
        server="1.2.3.4",
        port=443,
        protocol=Hysteria2Protocol(
            password="password123", up_mbps="30 Mbps", down_mbps="100 Mbps"
        ),
        tls=TLSConfig(
            enabled=True,
            skip_cert_verify=True,
            alpn=["h3"],
            client_fingerprint="chrome",
        ),
    )
    proxies.append(proxy_v2_bw)

    return proxies


def generate_wireguard_proxies() -> List[Proxy]:
    """Generate WireGuard protocol proxies."""
    proxies = []

    # Basic variant
    proxy = Proxy(
        name="wireguard-basic",
        server="162.159.192.1",
        port=2480,
        protocol=WireGuardProtocol(
            private_key="eCtXsJZ27+4PbhDkHnB923tkUn2Gj59wZw5wFA75MnU=",
            public_key="Cr8hWlKvtDt7nrvf+f0brNQQzabAqrjfBvas9pmowjo=",
            ip="172.16.0.2",
        ),
    )
    proxies.append(proxy)

    # With IPv6
    proxy_ipv6 = Proxy(
        name="wireguard-ipv6",
        server="162.159.192.1",
        port=2480,
        protocol=WireGuardProtocol(
            private_key="eCtXsJZ27+4PbhDkHnB923tkUn2Gj59wZw5wFA75MnU=",
            public_key="Cr8hWlKvtDt7nrvf+f0brNQQzabAqrjfBvas9pmowjo=",
            ip="172.16.0.2",
            ipv6="fd01:5ca1:ab1e:80fa:ab85:6eea:213f:f4a5",
            reserved=[0, 0, 0],
            mtu=1280,
        ),
    )
    proxies.append(proxy_ipv6)

    # With preshared key
    proxy_psk = Proxy(
        name="wireguard-psk",
        server="162.159.192.1",
        port=2480,
        protocol=WireGuardProtocol(
            private_key="eCtXsJZ27+4PbhDkHnB923tkUn2Gj59wZw5wFA75MnU=",
            public_key="Cr8hWlKvtDt7nrvf+f0brNQQzabAqrjfBvas9pmowjo=",
            preshared_key="Qq9DBa+nCZNEaGTy36nJvAfK9a1r0wPIc3gmVB21sG8=",
            ip="172.16.0.2",
        ),
    )
    proxies.append(proxy_psk)

    return proxies


def generate_tuic_proxies() -> List[Proxy]:
    """Generate TUIC protocol proxies."""
    proxies = []

    # V5 with UUID
    proxy_uuid = Proxy(
        name="tuic-v5-uuid",
        server="1.2.3.4",
        port=10443,
        protocol=TuicProtocol(
            uuid="00000000-0000-0000-0000-000000000001",
            password="password123",
            alpn=["h3"],
        ),
        tls=TLSConfig(enabled=True, skip_cert_verify=True),
    )
    proxies.append(proxy_uuid)

    # With token
    proxy_token = Proxy(
        name="tuic-token",
        server="1.2.3.4",
        port=10443,
        protocol=TuicProtocol(token="TOKEN123", alpn=["h3"]),
        tls=TLSConfig(enabled=True, skip_cert_verify=True),
    )
    proxies.append(proxy_token)

    # With advanced options
    proxy_advanced = Proxy(
        name="tuic-advanced",
        server="1.2.3.4",
        port=10443,
        protocol=TuicProtocol(
            uuid="00000000-0000-0000-0000-000000000002",
            password="password123",
            congestion_control="bbr",
            udp_relay_mode="quic",
            reduce_rtt=True,
            heartbeat_interval=10000,
            max_udp_relay_packet_size=1500,
            disable_sni=True,
        ),
        tls=TLSConfig(enabled=True, skip_cert_verify=True),
    )
    proxies.append(proxy_advanced)

    # With ECH
    proxy_ech = Proxy(
        name="tuic-ech",
        server="example.com",
        port=10443,
        protocol=TuicProtocol(
            uuid="00000000-0000-0000-0000-000000000003",
            password="password123",
            alpn=["h3"],
        ),
        tls=TLSConfig(
            enabled=True,
            skip_cert_verify=True,
            ech=ECHConfig(
                enabled=True,
                config="AEn+DQBFKwAgACABWIHUGj4u+PIggYXcR5JF0gYk3dCRioBW8uJq9H4mKAAIAAEAAQABAANAEnB1YmxpYy50bHMtZWNoLmRldgAA",
            ),
        ),
    )
    proxies.append(proxy_ech)

    return proxies


def generate_ssh_proxies() -> List[Proxy]:
    """Generate SSH protocol proxies."""
    proxies = []

    # Basic with password
    proxy_pw = Proxy(
        name="ssh-password",
        server="1.2.3.4",
        port=22,
        protocol=SSHProtocol(username="root", password="password123"),
    )
    proxies.append(proxy_pw)

    # With private key
    proxy_key = Proxy(
        name="ssh-privatekey",
        server="1.2.3.4",
        port=22,
        protocol=SSHProtocol(
            username="ubuntu",
            private_key="""-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA4e2D/qPN08pzTac+a8ZmlP1ziJOXk45CynMPtva0rtK/RB26
...
-----END RSA PRIVATE KEY-----""",
        ),
    )
    proxies.append(proxy_key)

    # With advanced options
    proxy_adv = Proxy(
        name="ssh-advanced",
        server="1.2.3.4",
        port=2222,
        protocol=SSHProtocol(
            username="admin",
            password="password123",
            host_key=["ssh-rsa AAAAB3NzaC1yc2EAAAA..."],
            host_key_algorithms=["ssh-rsa", "ssh-ed25519"],
            client_version="SSH-2.0-OpenSSH_8.9",
        ),
    )
    proxies.append(proxy_adv)

    return proxies


def generate_snell_proxies() -> List[Proxy]:
    """Generate Snell protocol proxies."""
    proxies = []

    # v1
    proxy_v1 = Proxy(
        name="snell-v1",
        server="1.2.3.4",
        port=44046,
        protocol=SnellProtocol(psk="yourpsk", version=1),
    )
    proxies.append(proxy_v1)

    # v2 with obfs
    proxy_v2 = Proxy(
        name="snell-v2-http",
        server="1.2.3.4",
        port=44046,
        protocol=SnellProtocol(
            psk="yourpsk", version=2, obfs_mode="http", obfs_host="bing.com"
        ),
    )
    proxies.append(proxy_v2)

    # v3 with tls obfs
    proxy_v3 = Proxy(
        name="snell-v3-tls",
        server="1.2.3.4",
        port=44046,
        protocol=SnellProtocol(
            psk="yourpsk", version=3, obfs_mode="tls", obfs_host="example.com"
        ),
    )
    proxies.append(proxy_v3)

    return proxies


def generate_mieru_proxies() -> List[Proxy]:
    """Generate Mieru protocol proxies."""
    proxies = []

    # Basic
    proxy_basic = Proxy(
        name="mieru-basic",
        server="1.2.3.4",
        port=2999,
        protocol=MieruProtocol(username="user", password="password", transport="TCP"),
    )
    proxies.append(proxy_basic)

    # With different multiplexing levels
    multiplexing_levels = [
        "MULTIPLEXING_OFF",
        "MULTIPLEXING_LOW",
        "MULTIPLEXING_MIDDLE",
        "MULTIPLEXING_HIGH",
    ]
    for i, level in enumerate(multiplexing_levels):
        proxy = Proxy(
            name=f"mieru-{level.lower()}",
            server="1.2.3.4",
            port=3000 + i,
            protocol=MieruProtocol(
                username="user",
                password="password",
                transport="TCP",
                multiplexing=level,
            ),
        )
        proxies.append(proxy)

    # With port range
    proxy_port_range = Proxy(
        name="mieru-port-range",
        server="1.2.3.4",
        port=2999,
        protocol=MieruProtocol(
            username="user",
            password="password",
            transport="TCP",
            port_range="2090-2099",
            multiplexing="MULTIPLEXING_HIGH",
        ),
    )
    proxies.append(proxy_port_range)

    return proxies


def generate_anytls_proxies() -> List[Proxy]:
    """Generate AnyTLS protocol proxies."""
    proxies = []

    # Basic
    proxy_basic = Proxy(
        name="anytls-basic",
        server="1.2.3.4",
        port=443,
        protocol=AnyTLSProtocol(password="secret123"),
        tls=TLSConfig(enabled=True, skip_cert_verify=True),
    )
    proxies.append(proxy_basic)

    # With client fingerprint
    proxy_fp = Proxy(
        name="anytls-fingerprint",
        server="1.2.3.4",
        port=443,
        protocol=AnyTLSProtocol(password="secret123"),
        tls=TLSConfig(
            enabled=True,
            client_fingerprint="chrome",
            sni="example.com",
            skip_cert_verify=True,
        ),
    )
    proxies.append(proxy_fp)

    # With session options
    proxy_session = Proxy(
        name="anytls-session",
        server="1.2.3.4",
        port=443,
        protocol=AnyTLSProtocol(
            password="secret123",
            idle_session_check_interval=60,
            idle_session_timeout=30,
            min_idle_session=5,
        ),
        tls=TLSConfig(enabled=True, skip_cert_verify=True),
    )
    proxies.append(proxy_session)

    return proxies


def generate_http_socks_proxies() -> List[Proxy]:
    """Generate HTTP/SOCKS protocol proxies."""
    proxies = []

    # HTTP without auth
    proxy_http_basic = Proxy(
        name="http-basic", server="1.2.3.4", port=8080, protocol=HttpProtocol()
    )
    proxies.append(proxy_http_basic)

    # HTTP with auth
    proxy_http_auth = Proxy(
        name="http-auth",
        server="1.2.3.4",
        port=8080,
        protocol=HttpProtocol(),
        auth=BasicAuth(username="user", password="pass"),
    )
    proxies.append(proxy_http_auth)

    # HTTPS
    proxy_https = Proxy(
        name="https",
        server="1.2.3.4",
        port=8443,
        protocol=HttpProtocol(tls=True),
        tls=TLSConfig(enabled=True, skip_cert_verify=True),
    )
    proxies.append(proxy_https)

    # SOCKS5 without auth
    proxy_socks_basic = Proxy(
        name="socks5-basic", server="1.2.3.4", port=1080, protocol=Socks5Protocol()
    )
    proxies.append(proxy_socks_basic)

    # SOCKS5 with auth
    proxy_socks_auth = Proxy(
        name="socks5-auth",
        server="1.2.3.4",
        port=1080,
        protocol=Socks5Protocol(),
        auth=BasicAuth(username="user", password="pass"),
    )
    proxies.append(proxy_socks_auth)

    # SOCKS5 with TLS
    proxy_socks_tls = Proxy(
        name="socks5-tls",
        server="1.2.3.4",
        port=1443,
        protocol=Socks5Protocol(tls=True),
        tls=TLSConfig(enabled=True, skip_cert_verify=True),
    )
    proxies.append(proxy_socks_tls)

    return proxies


def generate_special_combinations() -> List[Proxy]:
    """Generate special protocol combinations."""
    proxies = []

    # VMess with Reality (theoretical combination)
    proxy_vmess_reality = Proxy(
        name="special-vmess-reality",
        server="1.2.3.4",
        port=443,
        protocol=VmessProtocol(
            uuid="00000000-0000-0000-0000-000000000099", alter_id=0, security="auto"
        ),
        tls=TLSConfig(enabled=True, client_fingerprint="safari"),
        reality=RealityConfig(
            enabled=True,
            public_key="lCWWkpDHGPtWRRIe5Ww8nPbT0GpyLSS1RCWUpI0nYFw",
            short_id="6ba85179e30d4fc2",
        ),
    )
    proxies.append(proxy_vmess_reality)

    # Shadowsocks with WebSocket transport
    proxy_ss_ws = Proxy(
        name="special-ss-ws",
        server="1.2.3.4",
        port=443,
        protocol=ShadowsocksProtocol(method="aes-256-gcm", password="password123"),
        tls=TLSConfig(enabled=True, skip_cert_verify=True),
        transport=Transport(
            type="ws",
            ws=WebSocketTransport(path="/ws", headers={"Host": "example.com"}),
        ),
    )
    proxies.append(proxy_ss_ws)

    # Trojan with QUIC transport
    proxy_trojan_quic = Proxy(
        name="special-trojan-quic",
        server="1.2.3.4",
        port=443,
        protocol=TrojanProtocol(password="password123"),
        transport=Transport(
            type="quic",
            quic=QUICTransport(security="chacha20-poly1305", key="password123"),
        ),
    )
    proxies.append(proxy_trojan_quic)

    # VLESS with multiple transports and smux
    proxy_vless_multi = Proxy(
        name="special-vless-multi",
        server="1.2.3.4",
        port=443,
        protocol=VlessProtocol(
            uuid="00000000-0000-0000-0000-000000000098", encryption="none"
        ),
        tls=TLSConfig(enabled=True, skip_cert_verify=True),
        transport=Transport(type="grpc", grpc=GRPCTransport(service_name="example")),
        smux=SmuxConfig(
            enabled=True,
            protocol="yamux",
            max_connections=8,
            min_streams=4,
            max_streams=2048,
            padding=True,
            statistic=True,
            only_tcp=False,
        ),
    )
    proxies.append(proxy_vless_multi)

    return proxies


def main():
    """Generate the YAML file with all protocol combinations."""
    all_proxies = []

    # Generate all protocol proxies
    all_proxies.extend(generate_shadowsocks_proxies())
    all_proxies.extend(generate_vmess_proxies())
    all_proxies.extend(generate_vless_proxies())
    all_proxies.extend(generate_trojan_proxies())
    all_proxies.extend(generate_hysteria_proxies())
    all_proxies.extend(generate_wireguard_proxies())
    all_proxies.extend(generate_tuic_proxies())
    all_proxies.extend(generate_ssh_proxies())
    all_proxies.extend(generate_snell_proxies())
    all_proxies.extend(generate_mieru_proxies())
    all_proxies.extend(generate_anytls_proxies())
    all_proxies.extend(generate_http_socks_proxies())
    all_proxies.extend(generate_special_combinations())

    # Render using ClashRenderer
    renderer = ClashRenderer()  # noqa: F841
    rendered_proxies = []

    for proxy in all_proxies:
        proxy_dict = proxy.to_dict()
        rendered_proxies.append(proxy_dict)

    # Create the complete config
    config = {
        "proxies": rendered_proxies,
        "proxy-groups": [
            {
                "name": "All Proxies",
                "type": "select",
                "proxies": [proxy.name for proxy in all_proxies],
            },
            {
                "name": "Shadowsocks",
                "type": "select",
                "proxies": [
                    p.name
                    for p in all_proxies
                    if isinstance(p.protocol, ShadowsocksProtocol)
                ],
            },
            {
                "name": "VMess",
                "type": "select",
                "proxies": [
                    p.name for p in all_proxies if isinstance(p.protocol, VmessProtocol)
                ],
            },
            {
                "name": "VLESS",
                "type": "select",
                "proxies": [
                    p.name for p in all_proxies if isinstance(p.protocol, VlessProtocol)
                ],
            },
            {
                "name": "Trojan",
                "type": "select",
                "proxies": [
                    p.name
                    for p in all_proxies
                    if isinstance(p.protocol, TrojanProtocol)
                ],
            },
            {
                "name": "Hysteria",
                "type": "select",
                "proxies": [
                    p.name
                    for p in all_proxies
                    if isinstance(p.protocol, (HysteriaProtocol, Hysteria2Protocol))
                ],
            },
            {
                "name": "WireGuard",
                "type": "select",
                "proxies": [
                    p.name
                    for p in all_proxies
                    if isinstance(p.protocol, WireGuardProtocol)
                ],
            },
            {
                "name": "TUIC",
                "type": "select",
                "proxies": [
                    p.name for p in all_proxies if isinstance(p.protocol, TuicProtocol)
                ],
            },
            {
                "name": "SSH",
                "type": "select",
                "proxies": [
                    p.name for p in all_proxies if isinstance(p.protocol, SSHProtocol)
                ],
            },
            {
                "name": "Snell",
                "type": "select",
                "proxies": [
                    p.name for p in all_proxies if isinstance(p.protocol, SnellProtocol)
                ],
            },
            {
                "name": "Mieru",
                "type": "select",
                "proxies": [
                    p.name for p in all_proxies if isinstance(p.protocol, MieruProtocol)
                ],
            },
            {
                "name": "AnyTLS",
                "type": "select",
                "proxies": [
                    p.name
                    for p in all_proxies
                    if isinstance(p.protocol, AnyTLSProtocol)
                ],
            },
            {
                "name": "HTTP/SOCKS",
                "type": "select",
                "proxies": [
                    p.name
                    for p in all_proxies
                    if isinstance(p.protocol, (HttpProtocol, Socks5Protocol))
                ],
            },
            {
                "name": "Special Combinations",
                "type": "select",
                "proxies": [
                    p.name for p in all_proxies if p.name.startswith("special-")
                ],
            },
        ],
        "rules": ["MATCH,All Proxies"],
    }

    # Write to file
    with open("mihomo_all_protocols_v2.yaml", "w", encoding="utf-8") as f:
        yaml.dump(
            config, f, allow_unicode=True, default_flow_style=False, sort_keys=False
        )

    print(
        f"Generated mihomo_all_protocols_v2.yaml with {len(all_proxies)} proxy configurations"
    )
    print("Protocols covered:")
    protocol_counts = {}
    for proxy in all_proxies:
        ptype = proxy.protocol.get_type().value
        protocol_counts[ptype] = protocol_counts.get(ptype, 0) + 1

    for ptype, count in sorted(protocol_counts.items()):
        print(f"  - {ptype}: {count} variants")


if __name__ == "__main__":
    main()
