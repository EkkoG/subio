import pytest

from tests.support_target_views import all_platform_capabilities
from subio_v2.formats import get_emitter, get_parser

PLATFORM_CAPABILITIES = all_platform_capabilities()
from subio_v2.emitter.clash import ClashEmitter
from subio_v2.emitter.stash import StashEmitter
from subio_v2.parser.clash import ClashParser
from subio_v2.parser.stash import StashParser

STAGE9_PROTOCOLS = {
    "shadowsocks",
    "shadowsocksr",
    "vmess",
    "vless",
    "trojan",
    "http",
    "socks5",
    "snell",
    "wireguard",
    "hysteria",
    "hysteria2",
    "tuic",
    "ssh",
    "anytls",
    "direct",
}


def _stash_nodes():
    return {
        "proxies": [
            {
                "name": "ss",
                "type": "ss",
                "server": "ss.example.com",
                "port": 8388,
                "cipher": "2022-blake3-aes-128-gcm",
                "password": "secret",
                "udp": True,
                "plugin": "shadow-tls",
                "plugin-opts": {
                    "password": "shadow-secret",
                    "host": "apple.com",
                    "version": 3,
                },
            },
            {
                "name": "ssr",
                "type": "ssr",
                "server": "ssr.example.com",
                "port": 8388,
                "cipher": "chacha20-ietf",
                "password": "secret",
                "obfs": "http_simple",
                "protocol": "origin",
            },
            {
                "name": "socks",
                "type": "socks5",
                "server": "socks.example.com",
                "port": 443,
                "username": "user",
                "password": "secret",
                "tls": True,
                "server-cert-fingerprint": "AA:BB",
                "udp": True,
            },
            {
                "name": "http",
                "type": "http",
                "server": "http.example.com",
                "port": 443,
                "username": "user",
                "password": "secret",
                "headers": {"X-Test": "value"},
                "tls": True,
                "server-cert-fingerprint": "AA:BB",
            },
            {
                "name": "vmess",
                "type": "vmess",
                "server": "vmess.example.com",
                "port": 443,
                "uuid": "00000000-0000-0000-0000-000000000001",
                "cipher": "auto",
                "alterId": 0,
                "network": "http",
                "http-opts": {
                    "method": "GET",
                    "path": ["/transport"],
                    "headers": {"Host": ["vmess.example.com"]},
                },
                "tls": True,
                "sni": "vmess.example.com",
            },
            {
                "name": "snell",
                "type": "snell",
                "server": "snell.example.com",
                "port": 443,
                "psk": "secret",
                "version": 4,
                "reuse": True,
                "udp": True,
                "obfs-opts": {"mode": "http", "host": "bing.com"},
            },
            {
                "name": "trojan",
                "type": "trojan",
                "server": "trojan.example.com",
                "port": 443,
                "password": "secret",
                "network": "grpc",
                "grpc-opts": {"grpc-service-name": "service"},
                "sni": "trojan.example.com",
                "server-cert-fingerprint": "AA:BB",
            },
            {
                "name": "anytls",
                "type": "anytls",
                "server": "anytls.example.com",
                "port": 443,
                "password": "secret",
                "sni": "anytls.example.com",
                "server-cert-fingerprint": "AA:BB",
            },
            {
                "name": "hysteria",
                "type": "hysteria",
                "server": "hysteria.example.com",
                "port": 443,
                "up-speed": 100,
                "down-speed": 200,
                "auth-str": "secret",
                "protocol": "udp",
                "obfs": "obfs-secret",
                "sni": "hysteria.example.com",
            },
            {
                "name": "hysteria2",
                "type": "hysteria2",
                "server": "hysteria2.example.com",
                "port": 443,
                "auth": "secret",
                "fast-open": True,
                "obfs": "gecko",
                "obfs-password": "obfs-secret",
                "up-speed": 100,
                "down-speed": 200,
                "server-cert-fingerprint": "AA:BB",
            },
            {
                "name": "vless",
                "type": "vless",
                "server": "vless.example.com",
                "port": 443,
                "uuid": "00000000-0000-0000-0000-000000000002",
                "flow": "xtls-rprx-direct",
                "tls": True,
                "client-fingerprint": "chrome",
                "reality-opts": {"public-key": "public", "short-id": "abcd"},
                "network": "xhttp",
                "xhttp-opts": {
                    "mode": "stream-up",
                    "path": "/xhttp",
                    "host": "vless.example.com",
                    "headers": {"User-Agent": "Stash"},
                },
            },
            {
                "name": "tuic",
                "type": "tuic",
                "server": "tuic.example.com",
                "port": 443,
                "version": 5,
                "uuid": "00000000-0000-0000-0000-000000000003",
                "password": "secret",
                "ports": "443,8443-8450",
                "hop-interval": 30,
                "sni": "tuic.example.com",
                "alpn": ["h3"],
            },
            {
                "name": "wireguard",
                "type": "wireguard",
                "server": "wireguard.example.com",
                "port": 51820,
                "ip": "10.0.0.2",
                "private-key": "private",
                "public-key": "public",
                "preshared-key": "shared",
                "dns": ["1.1.1.1"],
                "mtu": 1420,
                "reserved": [0, 0, 0],
                "keepalive": 45,
                "dialer-proxy": "ss",
            },
            {
                "name": "ssh",
                "type": "ssh",
                "server": "ssh.example.com",
                "port": 22,
                "user": "root",
                "private-key": "private",
                "private-key-passphrase": "passphrase",
            },
            {
                "name": "direct",
                "type": "direct",
                "interface-name": "utun3",
            },
        ]
    }


def test_stage9_atomically_exposes_stash_parser_emitter_and_capabilities():
    assert isinstance(get_parser("stash"), StashParser)
    assert isinstance(get_emitter("stash"), StashEmitter)
    assert STAGE9_PROTOCOLS <= PLATFORM_CAPABILITIES["stash"]["protocols"]


def test_stash_shared_protocols_parse_emit_and_round_trip():
    parser = StashParser()
    parsed = parser.parse_result(_stash_nodes())

    assert parsed.issues == []
    assert {node.type.value for node in parsed.nodes} == STAGE9_PROTOCOLS

    emission = StashEmitter().emit_result(parsed.nodes)
    assert emission.errors == []
    by_name = {proxy["name"]: proxy for proxy in emission.content["proxies"]}
    assert set(by_name) == {proxy["name"] for proxy in _stash_nodes()["proxies"]}
    assert by_name["http"]["server-cert-fingerprint"] == "AA:BB"
    assert "fingerprint" not in by_name["http"]
    assert by_name["hysteria"]["up-speed"] == 100
    assert by_name["hysteria"]["down-speed"] == 200
    assert by_name["hysteria2"]["auth"] == "secret"
    assert by_name["hysteria2"]["up-speed"] == 100
    assert by_name["wireguard"]["keepalive"] == 45
    assert by_name["ssh"]["user"] == "root"
    assert by_name["tuic"]["version"] == 5
    assert by_name["tuic"]["ports"] == "443,8443-8450"
    assert by_name["vless"]["xhttp-opts"]["mode"] == "stream-up"
    assert by_name["direct"] == {
        "name": "direct",
        "type": "direct",
        "interface-name": "utun3",
    }

    reparsed = parser.parse_result(emission.content)
    assert reparsed.issues == []
    assert reparsed.nodes == parsed.nodes


def test_stash_semantic_aliases_convert_to_mihomo_names():
    parsed = StashParser().parse_result(_stash_nodes())
    emission = ClashEmitter("clash-meta").emit_result(parsed.nodes)
    assert len(emission.errors) == 1
    assert emission.errors[0].node == "vless"
    assert emission.errors[0].field == "flow"
    by_name = {proxy["name"]: proxy for proxy in emission.content["proxies"]}

    assert by_name["http"]["fingerprint"] == "AA:BB"
    assert by_name["hysteria2"]["password"] == "secret"
    assert by_name["wireguard"]["persistent-keepalive"] == 45
    assert by_name["ssh"]["username"] == "root"
    assert "version" not in by_name["tuic"]
    vless = next(node for node in parsed.nodes if node.name == "vless")
    vless.flow = "xtls-rprx-vision"
    converted = ClashEmitter("clash-meta").emit_result([vless])
    assert converted.errors == []
    assert converted.content["proxies"][0]["xhttp-opts"]["mode"] == "stream-up"


@pytest.mark.parametrize(
    ("proxy", "field"),
    [
        (
            {
                "name": "ss",
                "type": "ss",
                "server": "example.com",
                "port": 8388,
                "cipher": "2022-blake3-chacha20-poly1305",
                "password": "secret",
            },
            "cipher",
        ),
        (
            {
                "name": "vmess",
                "type": "vmess",
                "server": "example.com",
                "port": 443,
                "uuid": "00000000-0000-0000-0000-000000000001",
                "cipher": "zero",
            },
            "cipher",
        ),
        (
            {
                "name": "hysteria2",
                "type": "hysteria2",
                "server": "example.com",
                "port": 443,
                "auth": "secret",
                "obfs": "unknown",
                "obfs-password": "secret",
            },
            "obfs",
        ),
    ],
)
def test_stash_protocol_values_fail_closed(proxy, field):
    node = StashParser().parse_result({"proxies": [proxy]}).nodes[0]

    emission = StashEmitter().emit_result([node])

    assert emission.supported_nodes == []
    assert emission.errors[0].field == field


def test_stash_rejects_interface_and_dialer_combination():
    proxy = {
        "name": "http",
        "type": "http",
        "server": "example.com",
        "port": 80,
        "interface-name": "en0",
        "dialer-proxy": "upstream",
    }
    node = StashParser().parse_result({"proxies": [proxy]}).nodes[0]

    emission = StashEmitter().emit_result([node])

    assert emission.supported_nodes == []
    assert emission.errors[0].code == "conversion.unsupported-field-combination"


def test_mihomo_plugin_options_are_trimmed_to_stash_documented_fields():
    parsed = ClashParser().parse_result(
        {
            "proxies": [
                {
                    "name": "ss",
                    "type": "ss",
                    "server": "example.com",
                    "port": 8388,
                    "cipher": "aes-256-gcm",
                    "password": "secret",
                    "plugin": "v2ray-plugin",
                    "plugin-opts": {
                        "mode": "websocket",
                        "host": "example.com",
                        "path": "/ws",
                        "mux": 8,
                    },
                }
            ]
        }
    ).nodes[0]

    emission = StashEmitter().emit_result([parsed])

    assert emission.content["proxies"][0]["plugin-opts"] == {
        "mode": "websocket",
        "host": "example.com",
        "path": "/ws",
    }
    assert any(
        issue.code == "conversion.unconsumed-source-field"
        and "plugin-opts.mux" in issue.message
        for issue in emission.issues
    )
