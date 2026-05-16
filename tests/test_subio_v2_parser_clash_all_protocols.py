"""Round-trip tests for all Clash Meta proxy types (meta-json-schema)."""

import yaml

from subio_v2.emitter.clash import ClashEmitter
from subio_v2.parser.clash import ClashParser
from subio_v2.model.nodes import Protocol


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
    assert len(nodes) == 22
    types = {n.type for n in nodes}
    assert Protocol.SHADOWSOCKS in types
    assert Protocol.SHADOWSOCKSR in types
    assert Protocol.MIERU in types
    assert Protocol.SUDOKU in types
    assert Protocol.TAILSCALE in types
    assert Protocol.DIRECT in types

    proxies = _roundtrip(yaml_text)
    assert len(proxies) == 22
    by_name = {p["name"]: p for p in proxies}
    assert by_name["ssr1"]["type"] == "ssr"
    assert by_name["sn1"]["obfs-opts"]["mode"] == "tls"
    assert by_name["hy1"]["type"] == "hysteria"
    assert by_name["mr1"]["transport"] == "TCP"
    assert by_name["ts1"]["type"] == "tailscale"
    assert by_name["dr1"]["type"] == "direct"


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
