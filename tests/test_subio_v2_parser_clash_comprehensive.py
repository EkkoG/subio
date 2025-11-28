import pytest
from subio_v2.parser.clash import ClashParser
from subio_v2.model.nodes import Protocol, Network


def test_clash_parser_all_supported_types_comprehensive():
    yaml_text = """
proxies:
  - {name: ss1, type: ss, server: s1, port: 100, cipher: aes-256-gcm, password: p}
  - name: vmess1
    type: vmess
    server: s2
    port: 200
    uuid: u2
    cipher: auto
    network: ws
    ws-opts:
      path: /ws
      headers: {Host: vhost}
    tls: true
    sni: vhost
  - name: vless1
    type: vless
    server: s3
    port: 300
    uuid: v-uuid
    flow: xtls-rprx-vision
    network: tcp
    tls: true
    sni: vhost
  - name: trojan1
    type: trojan
    server: s4
    port: 400
    password: tp
    tls: true
    sni: tro
  - name: socks1
    type: socks5
    server: s5
    port: 500
    username: u
    password: pw
    tls: false
  - name: http1
    type: http
    server: s6
    port: 600
    username: hu
    password: hpw
    headers: {User-Agent: UA}
    tls: true
    sni: hhost
  - name: wg1
    type: wireguard
    server: s7
    port: 700
    private-key: priv
    public-key: pub
    ip: ["10.0.0.2/32"]
  - name: anytls1
    type: anytls
    server: s8
    port: 800
    password: apw
    fingerprint: chrome
    idle-session-check-interval: 10
    idle-session-timeout: 30
    min-idle-session: 2
  - name: h2-1
    type: hysteria2
    server: s9
    port: 900
    password: hpw
    sni: h2host
    up: 10 Mbps
    down: 50 Mbps
    obfs: salamander
    obfs-password: abc
    ech-opts: {pqkem-grease: true}
  - name: ssh1
    type: ssh
    server: s10
    port: 22
    username: root
    password: rpw
"""
    nodes = ClashParser().parse(yaml_text)
    names = [n.name for n in nodes]
    assert names == [
        "ss1","vmess1","vless1","trojan1","socks1","http1","wg1","anytls1","h2-1","ssh1"
    ]
    # Validate types and selected fields
    assert nodes[0].type == Protocol.SHADOWSOCKS and nodes[0].cipher == "aes-256-gcm"
    assert nodes[1].type == Protocol.VMESS and nodes[1].transport.network == Network.WS and nodes[1].tls.enabled
    assert nodes[2].type == Protocol.VLESS and nodes[2].flow == "xtls-rprx-vision" and nodes[2].tls.enabled
    assert nodes[3].type == Protocol.TROJAN and nodes[3].tls.enabled and nodes[3].password == "tp"
    assert nodes[4].type == Protocol.SOCKS5 and nodes[4].username == "u" and nodes[4].password == "pw"
    assert nodes[5].type == Protocol.HTTP and nodes[5].tls.enabled and nodes[5].headers.get("User-Agent") == "UA"
    assert nodes[6].type == Protocol.WIREGUARD and nodes[6].private_key == "priv" and nodes[6].public_key == "pub"
    assert nodes[7].type == Protocol.ANYTLS and nodes[7].tls.enabled and nodes[7].password == "apw"
    assert nodes[8].type == Protocol.HYSTERIA2 and nodes[8].tls.enabled and nodes[8].obfs == "salamander"
    assert nodes[9].type == Protocol.SSH and nodes[9].username == "root"
