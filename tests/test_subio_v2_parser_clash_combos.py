import pytest
from subio_v2.parser.clash import ClashParser
from subio_v2.model.nodes import Protocol, Network


def test_vmess_transports_ws_h2_http_grpc_and_smux_tls_fields():
    yaml_text = """
proxies:
  - name: vm-ws
    type: vmess
    server: s
    port: 443
    uuid: u
    network: ws
    ws-opts:
      path: /ws
      headers: {Host: h}
    tls: true
    sni: host
    alpn: ["h2","http/1.1"]
    fingerprint: chrome
    client-fingerprint: randomized
    smux:
      enabled: true
      protocol: smux
      max-connections: 8
      min-streams: 4
      max-streams: 16
      padding: true
  - name: vm-h2
    type: vmess
    server: s
    port: 443
    uuid: u2
    network: h2
    h2-opts:
      host: ["h2.example"]
      path: /h2p
    tls: true
    sni: h2.example
  - name: vm-http
    type: vmess
    server: s
    port: 80
    uuid: u3
    network: http
    http-opts:
      method: GET
      path: /http
      headers: {Host: hh}
  - name: vm-grpc
    type: vmess
    server: s
    port: 8443
    uuid: u4
    network: grpc
    grpc-opts:
      grpc-service-name: svc
"""
    nodes = ClashParser().parse(yaml_text)
    vm_ws, vm_h2, vm_http, vm_grpc = nodes
    # WS
    assert vm_ws.type == Protocol.VMESS and vm_ws.transport.network == Network.WS
    assert vm_ws.transport.path == "/ws" and vm_ws.transport.headers.get("Host") == "h"
    assert vm_ws.tls.enabled and vm_ws.tls.server_name == "host"
    assert vm_ws.tls.alpn == ["h2","http/1.1"]
    assert vm_ws.tls.fingerprint == "chrome" and vm_ws.tls.client_fingerprint == "randomized"
    assert vm_ws.smux.enabled and vm_ws.smux.max_connections == 8 and vm_ws.smux.padding
    # H2
    assert vm_h2.transport.network == Network.H2
    assert vm_h2.transport.host == ["h2.example"] and vm_h2.transport.path == "/h2p"
    # HTTP
    assert vm_http.transport.network == Network.HTTP
    assert vm_http.transport.method == "GET" and vm_http.transport.path == "/http"
    assert vm_http.transport.headers.get("Host") == "hh"
    # gRPC (tls is forced true when network is grpc)
    assert vm_grpc.transport.network == Network.GRPC
    assert vm_grpc.transport.grpc_service_name == "svc"
    assert vm_grpc.tls.enabled is True


def test_grpc_forces_tls_true():
    """When network is grpc, tls is forced to true for vmess/vless/trojan."""
    yaml_text = """
proxies:
  - name: vm-grpc-no-tls
    type: vmess
    server: s
    port: 8443
    uuid: u
    network: grpc
    tls: false
  - name: vless-grpc-no-tls
    type: vless
    server: s
    port: 8443
    uuid: u
    network: grpc
    tls: false
  - name: trojan-grpc-no-tls
    type: trojan
    server: s
    port: 8443
    password: p
    network: grpc
    tls: false
"""
    nodes = ClashParser().parse(yaml_text)
    vm, vless, trojan = nodes
    assert vm.transport.network == Network.GRPC and vm.tls.enabled is True
    assert vless.transport.network == Network.GRPC and vless.tls.enabled is True
    assert trojan.transport.network == Network.GRPC and trojan.tls.enabled is True


def test_vless_reality_and_tls_options_and_names():
    yaml_text = """
proxies:
  - name: v-reality
    type: vless
    server: r.example
    port: 443
    uuid: uv
    tls: true
    sni: r.example
    reality-opts:
      public-key: pk
      short-id: sid
  - name: v-tls
    type: vless
    server: t.example
    port: 443
    uuid: uv2
    tls: true
    sni: t.example
    alpn: ["h2"]
    skip-cert-verify: true
"""
    v_reality, v_tls = ClashParser().parse(yaml_text)
    assert v_reality.tls.enabled and v_reality.tls.reality_opts == {"public-key":"pk","short-id":"sid"}
    assert v_tls.tls.enabled and v_tls.tls.server_name == "t.example" and v_tls.tls.alpn == ["h2"]
    assert v_tls.tls.skip_cert_verify is True


def test_hysteria2_ech_opts_and_rates():
    yaml_text = """
proxies:
  - name: h2-ech
    type: hysteria2
    server: s
    port: 443
    password: p
    sni: h2
    up: 20 Mbps
    down: 100 Mbps
    ech-opts: {pqkem-grease: true}
    obfs: salamander
    obfs-password: op
"""
    h2n = ClashParser().parse(yaml_text)[0]
    assert h2n.tls.enabled and h2n.tls.ech_opts == {"pqkem-grease": True}
    assert h2n.up == "20 Mbps" and h2n.down == "100 Mbps"
    assert h2n.obfs == "salamander" and h2n.obfs_password == "op"


def test_socks5_tls_and_http_headers_tls():
    yaml_text = """
proxies:
  - name: socks-tls
    type: socks5
    server: s
    port: 123
    username: u
    password: p
    tls: true
    sni: sni
  - name: http-headers
    type: http
    server: h
    port: 80
    headers: {User-Agent: UA, X-Test: XV}
    tls: false
"""
    s_tls, http_h = ClashParser().parse(yaml_text)
    assert s_tls.type == Protocol.SOCKS5 and s_tls.tls.enabled and s_tls.tls.server_name == "sni"
    assert http_h.headers.get("User-Agent") == "UA" and http_h.headers.get("X-Test") == "XV"


def test_wireguard_allowed_ips_and_reserved():
    yaml_text = """
proxies:
  - name: wg
    type: wireguard
    server: s
    port: 51820
    private-key: pk
    public-key: pub
    ip: ["10.0.0.2/32","fd00::/8"]
"""
    wg = ClashParser().parse(yaml_text)[0]
    assert wg.allowed_ips == ["10.0.0.2/32","fd00::/8"]
