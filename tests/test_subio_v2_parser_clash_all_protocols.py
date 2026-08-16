"""Round-trip tests for all Clash Meta proxy types (meta-json-schema)."""

import pytest

from subio_v2.emitter.clash import ClashEmitter
from subio_v2.emitter.stash import StashEmitter
from subio_v2.dialect import DialectContext
from subio_v2.parser.clash import ClashParser
from subio_v2.parser.stash import StashParser
from subio_v2.model.nodes import (
    DNSNode,
    DirectNode,
    GostRelayNode,
    MasqueNode,
    MieruNode,
    Protocol,
    RematchNode,
    ShadowQUICNode,
    SourcePassthroughNode,
    TailscaleNode,
    TrustTunnelNode,
)


def _roundtrip(yaml_text: str) -> list[dict]:
    nodes = ClashParser().parse(yaml_text)
    out = ClashEmitter().emit(nodes)
    return out["proxies"]


def test_all_clash_meta_proxy_types_parse_and_roundtrip():
    yaml_text = """
proxies:
  - {name: ss1, type: ss, server: s1, port: 100, cipher: aes-256-gcm, password: p}
  - {name: ssr1, type: ssr, server: s2, port: 101, cipher: aes-256-cfb, password: p2, obfs: tls1.2_ticket_auth, protocol: auth_aes128_sha1}
  - {name: vm1, type: vmess, server: s3, port: 443, uuid: u, cipher: auto, tls: true, sni: h}
  - {name: vl1, type: vless, server: s4, port: 443, uuid: v, tls: true, sni: h}
  - {name: tr1, type: trojan, server: s5, port: 443, password: tp, tls: true, sni: h}
  - {name: sk1, type: socks5, server: s6, port: 1080}
  - {name: ht1, type: http, server: s7, port: 8080}
  - {name: sn1, type: snell, server: s8, port: 9000, psk: key, version: 3, obfs-opts: {mode: tls, host: bing.com}}
  - {name: hy1, type: hysteria, server: s9, port: 8443, up: 10 Mbps, down: 50 Mbps, auth-str: secret}
  - {name: h21, type: hysteria2, server: s10, port: 8443, password: hpw, sni: h2}
  - {name: wg1, type: wireguard, server: s11, port: 51820, private-key: pk, public-key: pub, ip: 10.0.0.2/32}
  - {name: tc1, type: tuic, server: s12, port: 8443, uuid: 00000000-0000-0000-0000-000000000001, password: pw, sni: t}
  - {name: at1, type: anytls, server: s13, port: 8443, password: apw, sni: a}
  - {name: sh1, type: ssh, server: s14, port: 22, username: u, password: p}
  - {name: mr1, type: mieru, server: s15, port: 2999, transport: TCP, username: mu, password: mp}
  - {name: gr1, type: gost-relay, server: s15b, port: 443, forward: true, tls: true}
  - {name: rm1, type: rematch, target-rematch-name: streaming}
  - {name: sq1, type: shadowquic, server: s15c, port: 443, zero-rtt: true}
  - {name: sd1, type: sudoku, server: s16, port: 8443, key: mykey}
  - {name: mq1, type: masque, server: s17, port: 443, private-key: pk2, public-key: pub2, ip: 10.1.0.2/32}
  - {name: tt1, type: trusttunnel, server: s18, port: 443, username: tu, password: tp}
  - name: ov1
    type: openvpn
    server: s19
    port: 1194
    ca: ca-content
    tls-crypt: tc-content
    username: ou
  - {name: ts1, type: tailscale, auth-key: ak}
  - {name: dr1, type: direct}
  - {name: dn1, type: dns}
"""
    nodes = ClashParser().parse(yaml_text)
    assert len(nodes) == 25
    types = {n.type for n in nodes}
    assert Protocol.SHADOWSOCKS in types
    assert Protocol.SHADOWSOCKSR in types
    assert Protocol.MIERU in types
    assert Protocol.SUDOKU in types
    assert Protocol.TAILSCALE in types
    assert Protocol.DIRECT in types
    by_node_name = {node.name: node for node in nodes}
    assert isinstance(by_node_name["mq1"], MasqueNode)
    assert isinstance(by_node_name["mr1"], MieruNode)
    assert isinstance(by_node_name["gr1"], GostRelayNode)
    assert isinstance(by_node_name["rm1"], RematchNode)
    assert isinstance(by_node_name["sq1"], ShadowQUICNode)
    assert isinstance(by_node_name["tt1"], TrustTunnelNode)
    assert isinstance(by_node_name["ts1"], TailscaleNode)
    assert isinstance(by_node_name["dr1"], DirectNode)
    assert isinstance(by_node_name["dn1"], DNSNode)

    proxies = _roundtrip(yaml_text)
    assert len(proxies) == 25
    by_name = {p["name"]: p for p in proxies}
    assert by_name["ssr1"]["type"] == "ssr"
    assert by_name["sn1"]["obfs-opts"]["mode"] == "tls"
    assert by_name["hy1"]["type"] == "hysteria"
    assert by_name["mr1"]["transport"] == "TCP"
    assert by_name["ts1"]["type"] == "tailscale"
    assert by_name["dr1"]["type"] == "direct"


def test_shadowsocks_udp_over_tcp_fields_roundtrip():
    yaml_text = """
proxies:
  - name: ss-uot-enabled
    type: ss
    server: s
    port: 443
    cipher: chacha20-ietf-poly1305
    password: pw
    udp-over-tcp: true
    udp-over-tcp-version: 2
  - name: ss-uot-falsy
    type: ss
    server: s
    port: 443
    cipher: chacha20-ietf-poly1305
    password: pw
    udp-over-tcp: false
    udp-over-tcp-version: 0
"""
    nodes = ClashParser().parse(yaml_text)
    nodes_by_name = {node.name: node for node in nodes}
    assert nodes_by_name["ss-uot-enabled"].extra["udp-over-tcp"] is True
    assert nodes_by_name["ss-uot-enabled"].extra["udp-over-tcp-version"] == 2
    assert nodes_by_name["ss-uot-falsy"].extra["udp-over-tcp"] is False
    assert nodes_by_name["ss-uot-falsy"].extra["udp-over-tcp-version"] == 0

    proxies = ClashEmitter().emit(nodes)["proxies"]
    proxies_by_name = {proxy["name"]: proxy for proxy in proxies}
    assert proxies_by_name["ss-uot-enabled"]["udp-over-tcp"] is True
    assert proxies_by_name["ss-uot-enabled"]["udp-over-tcp-version"] == 2
    assert proxies_by_name["ss-uot-falsy"]["udp-over-tcp"] is False
    assert proxies_by_name["ss-uot-falsy"]["udp-over-tcp-version"] == 0


def test_tuic_extra_fields_roundtrip():
    yaml_text = """
proxies:
  - name: tuic-full
    type: tuic
    server: s
    port: 8443
    uuid: 00000000-0000-0000-0000-000000000001
    password: pw
    sni: host
    congestion-controller: bbr
    udp-relay-mode: quic
    heartbeat-interval: 15000
"""
    nodes = ClashParser().parse(yaml_text)
    assert nodes[0].type == Protocol.TUIC
    assert nodes[0].extra.get("congestion-controller") == "bbr"
    proxies = ClashEmitter().emit(nodes)["proxies"]
    assert proxies[0]["congestion-controller"] == "bbr"
    assert proxies[0]["udp-relay-mode"] == "quic"


def test_unknown_future_clash_type_is_preserved_for_mihomo_roundtrip():
    yaml_text = """
proxies:
  - name: future
    type: future-protocol
    server: example.com
    port: 443
    credential: secret
    future-opts:
      enabled: false
      count: 0
"""
    nodes = ClashParser().parse(yaml_text)

    assert len(nodes) == 1
    assert isinstance(nodes[0], SourcePassthroughNode)
    assert nodes[0].original_type == "future-protocol"
    assert nodes[0].raw["future-opts"] == {"enabled": False, "count": 0}

    proxies = ClashEmitter(platform="clash-meta").emit(nodes)["proxies"]
    assert proxies == [
        {
            "name": "future",
            "type": "future-protocol",
            "server": "example.com",
            "port": 443,
            "credential": "secret",
            "future-opts": {"enabled": False, "count": 0},
        }
    ]

    cross_platform = ClashEmitter(platform="clash").emit_result(nodes)
    assert cross_platform.content["proxies"] == []
    assert cross_platform.errors == []
    assert cross_platform.issues[0].code == "conversion.ignored-source-passthrough"


def test_clash_meta_source_context_is_normalized_to_mihomo():
    node = ClashParser(DialectContext("clash-meta", "yaml")).parse_result(
        {"proxies": [{"name": "future", "type": "future-protocol"}]}
    ).nodes[0]

    assert node.source_context.dialect == "mihomo"
    assert ClashEmitter("mihomo").emit_result([node]).supported_nodes == [node]


@pytest.mark.parametrize(
    ("parser", "emitter", "cross_emitter"),
    [
        (ClashParser(), ClashEmitter("mihomo"), StashEmitter()),
        (
            ClashParser(DialectContext("clash", "yaml")),
            ClashEmitter("clash"),
            ClashEmitter("mihomo"),
        ),
        (StashParser(), StashEmitter(), ClashEmitter("mihomo")),
    ],
)
def test_unknown_yaml_type_is_lossless_only_within_its_source_platform(
    parser, emitter, cross_emitter
):
    source = {
        "proxies": [
            {
                "name": "future",
                "type": "future-protocol",
                "enabled": False,
                "count": 0,
                "empty": "",
            }
        ]
    }

    node = parser.parse_result(source).nodes[0]
    same_platform = emitter.emit_result([node])
    cross_platform = cross_emitter.emit_result([node])

    assert same_platform.content == source
    assert same_platform.issues == []
    assert cross_platform.content["proxies"] == []
    assert cross_platform.errors == []
    assert cross_platform.issues[0].code == "conversion.ignored-source-passthrough"
