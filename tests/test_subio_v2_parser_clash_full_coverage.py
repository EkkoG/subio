import pytest
from subio_v2.parser.clash import ClashParser
from subio_v2.model.nodes import Protocol, Network


def test_clash_parser_additional_fields_full():
    yaml_text = """
proxies:
  - name: vm-full
    type: vmess
    server: s
    port: 443
    uuid: u
    cipher: auto
    global-padding: true
    packet-encoding: packetmix
    network: ws
    ws-opts:
      path: /ws
      headers: {Host: h}
      max-early-data: 2048
      early-data-header-name: Early-Data
    tls: true
    sni: s
    alpn: ["h2"]
    smux:
      enabled: true
      brutal-opts: {enabled: true, up: 5, down: 10}
  - name: vless-full
    type: vless
    server: s
    port: 443
    uuid: v
    packet-encoding: packetmix
    flow: xtls-rprx-vision
    network: grpc
    grpc-opts: {grpc-service-name: svc}
    tls: true
    sni: vhost
    fingerprint: firefox
    client-fingerprint: randomized
  - name: ss-basic
    type: ss
    server: s
    port: 1
    cipher: aes-256-gcm
    password: p
    udp: false
  - name: trojan-basic
    type: trojan
    server: s
    port: 2
    password: tp
    tls: true
  - name: socks-nocreds
    type: socks5
    server: s
    port: 3
  - name: http-no-tls
    type: http
    server: s
    port: 80
    headers: {X-H: XV}
  - name: wg-adv
    type: wireguard
    server: s
    port: 51820
    private-key: pk
    public-key: pub
    ip: ["10.0.0.2/32", "::/0"]
    reserved: [0,0,0]
    mtu: 1280
  - name: anytls-full
    type: anytls
    server: s
    port: 8443
    password: ap
    idle-session-check-interval: 15
    idle-session-timeout: 60
    min-idle-session: 3
  - name: h2-more
    type: hysteria2
    server: s
    port: 8443
    password: hpw
    sni: h2
    ports: 443,444-450
    hop-interval: 60
    up: 10 Mbps
    down: 40 Mbps
    obfs: salamander
    obfs-password: op
  - name: ssh-adv
    type: ssh
    server: s
    port: 22
    username: root
    private-key: /path/key
    private-key-passphrase: pass
    host-key: ["algo1","algo2"]
    host-key-algorithms: ["rsa","ed25519"]
"""
    nodes = ClashParser().parse(yaml_text)
    assert len(nodes) == 10
    vm = nodes[0]
    assert vm.type == Protocol.VMESS and vm.global_padding is True
    assert vm.packet_encoding == "packetmix"
    assert vm.transport.network == Network.WS and vm.transport.max_early_data == 2048
    assert vm.transport.early_data_header_name == "Early-Data"
    assert vm.smux.brutal_opts == {"enabled": True, "up": 5, "down": 10}

    vless = nodes[1]
    assert vless.type == Protocol.VLESS and vless.packet_encoding == "packetmix"
    assert vless.transport.network == Network.GRPC and vless.transport.grpc_service_name == "svc"

    ss = nodes[2]
    assert ss.type == Protocol.SHADOWSOCKS and ss.udp is False

    tro = nodes[3]
    assert tro.type == Protocol.TROJAN and tro.tls.enabled is True

    socks = nodes[4]
    assert socks.type == Protocol.SOCKS5 and socks.username is None and socks.password is None

    http = nodes[5]
    assert http.type == Protocol.HTTP and http.tls.enabled is False and http.headers["X-H"] == "XV"

    wg = nodes[6]
    assert wg.type == Protocol.WIREGUARD and wg.allowed_ips == ["10.0.0.2/32", "::/0"]

    anytls = nodes[7]
    assert anytls.type == Protocol.ANYTLS and anytls.tls.enabled is True
    assert anytls.idle_session_check_interval == 15 and anytls.min_idle_session == 3

    h2 = nodes[8]
    assert h2.type == Protocol.HYSTERIA2 and h2.ports == "443,444-450" and h2.hop_interval == 60

    ssh = nodes[9]
    assert ssh.type == Protocol.SSH and ssh.private_key == "/path/key"
    assert ssh.host_key_algorithms == ["rsa","ed25519"]
