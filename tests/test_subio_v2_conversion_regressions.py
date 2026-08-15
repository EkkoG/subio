from subio_v2.conversion import IssueSeverity
from subio_v2.emitter import link
from subio_v2.emitter.clash import ClashEmitter
from subio_v2.emitter.dae import DaeEmitter
from subio_v2.emitter.surge import SurgeEmitter
from subio_v2.emitter.v2rayn import V2RayNEmitter
from subio_v2.model.nodes import (
    Network,
    TransportSettings,
    TrojanNode,
    VlessNode,
    Protocol,
)
from subio_v2.parser.clash import ClashParser


def _roundtrip(yaml_text: str) -> dict[str, dict]:
    nodes = ClashParser().parse(yaml_text)
    proxies = ClashEmitter().emit(nodes)["proxies"]
    return {proxy["name"]: proxy for proxy in proxies}


def test_clash_roundtrip_preserves_new_and_unknown_transports():
    proxies = _roundtrip(
        """
proxies:
  - name: vless-xhttp
    type: vless
    server: example.com
    port: 443
    uuid: u
    network: xhttp
    xhttp-opts:
      path: /x
      mode: stream-one
      no-grpc-header: false
  - name: vmess-future
    type: vmess
    server: example.com
    port: 443
    uuid: u
    network: future-transport
    future-opts: {mode: test}
"""
    )

    assert proxies["vless-xhttp"]["network"] == "xhttp"
    assert proxies["vless-xhttp"]["xhttp-opts"] == {
        "path": "/x",
        "mode": "stream-one",
        "no-grpc-header": False,
    }
    assert proxies["vmess-future"]["network"] == "future-transport"
    assert proxies["vmess-future"]["future-opts"] == {"mode": "test"}


def test_clash_roundtrip_preserves_unmodeled_nested_transport_fields():
    yaml_text = """
proxies:
  - name: vmess-ws
    type: vmess
    server: example.com
    port: 443
    uuid: u
    network: ws
    ws-opts:
      path: /ws
      v2ray-http-upgrade: false
      v2ray-http-upgrade-fast-open: true
  - name: trojan-grpc
    type: trojan
    server: example.com
    port: 443
    password: p
    network: grpc
    tls: false
    grpc-opts:
      grpc-service-name: svc
      grpc-user-agent: test-agent
      ping-interval: 0
      max-connections: 7
"""
    nodes = ClashParser().parse(yaml_text)
    assert nodes[0].transport.extra["ws-opts"] == {
        "v2ray-http-upgrade": False,
        "v2ray-http-upgrade-fast-open": True,
    }
    assert nodes[1].transport.extra["grpc-opts"] == {
        "grpc-user-agent": "test-agent",
        "ping-interval": 0,
        "max-connections": 7,
    }
    assert nodes[1].tls.enabled is False

    proxies = {proxy["name"]: proxy for proxy in ClashEmitter().emit(nodes)["proxies"]}
    assert proxies["vmess-ws"]["ws-opts"] == {
        "path": "/ws",
        "v2ray-http-upgrade": False,
        "v2ray-http-upgrade-fast-open": True,
    }
    assert proxies["trojan-grpc"]["grpc-opts"] == {
        "grpc-service-name": "svc",
        "grpc-user-agent": "test-agent",
        "ping-interval": 0,
        "max-connections": 7,
    }
    assert "tls" not in proxies["trojan-grpc"]


def test_clash_roundtrip_preserves_inactive_transport_option_blocks():
    proxies = _roundtrip(
        """
proxies:
  - name: vmess-multiple-opts
    type: vmess
    server: example.com
    port: 443
    uuid: u
    network: ws
    ws-opts:
      path: /ws
      headers: {Host: ws.example.com}
    http-opts:
      path: [/http]
      method: POST
      headers: {Host: http.example.com}
"""
    )

    assert proxies["vmess-multiple-opts"]["ws-opts"] == {
        "path": "/ws",
        "headers": {"Host": "ws.example.com"},
    }
    assert proxies["vmess-multiple-opts"]["http-opts"] == {
        "path": ["/http"],
        "method": "POST",
        "headers": {"Host": "http.example.com"},
    }


def test_clash_roundtrip_preserves_clash_only_protocol_fields():
    proxies = _roundtrip(
        """
proxies:
  - name: ss-fields
    type: ss
    server: example.com
    port: 443
    cipher: aes-256-gcm
    password: p
    client-fingerprint: chrome
    udp-over-tcp: true
    udp-over-tcp-version: 2
  - name: hysteria-fields
    type: hysteria
    server: example.com
    port: 443
    auth-str: p
    recv-window-conn: 123
    recv-window: 456
    disable-mtu-discovery: true
    fast-open: true
  - name: tuic-fields
    type: tuic
    server: example.com
    port: 443
    uuid: u
    password: p
    disable-sni: true
"""
    )

    assert proxies["ss-fields"]["client-fingerprint"] == "chrome"
    assert proxies["ss-fields"]["udp-over-tcp"] is True
    assert proxies["ss-fields"]["udp-over-tcp-version"] == 2
    assert proxies["hysteria-fields"]["recv-window-conn"] == 123
    assert proxies["hysteria-fields"]["recv-window"] == 456
    assert proxies["hysteria-fields"]["disable-mtu-discovery"] is True
    assert proxies["hysteria-fields"]["fast-open"] is True
    assert proxies["tuic-fields"]["disable-sni"] is True


def test_wireguard_interface_and_allowed_ips_roundtrip_independently():
    yaml_text = """
proxies:
  - name: wg-both
    type: wireguard
    server: example.com
    port: 51820
    private-key: private
    public-key: public
    ip: 10.0.0.2/32
    allowed-ips: [10.0.0.0/8, fd00::/8]
  - name: wg-allowed-only
    type: wireguard
    server: example.com
    port: 51820
    private-key: private
    public-key: public
    allowed-ips: [10.0.0.0/8]
"""
    nodes = ClashParser().parse(yaml_text)
    assert nodes[0].interface_ip == "10.0.0.2/32"
    assert nodes[0].allowed_ips == ["10.0.0.0/8", "fd00::/8"]
    assert nodes[1].interface_ip is None
    assert nodes[1].allowed_ips == ["10.0.0.0/8"]

    proxies = {proxy["name"]: proxy for proxy in ClashEmitter().emit(nodes)["proxies"]}
    assert proxies["wg-both"]["ip"] == "10.0.0.2/32"
    assert proxies["wg-both"]["allowed-ips"] == ["10.0.0.0/8", "fd00::/8"]
    assert "ip" not in proxies["wg-allowed-only"]
    assert proxies["wg-allowed-only"]["allowed-ips"] == ["10.0.0.0/8"]


def test_socks5_tls_is_rejected_when_link_format_cannot_represent_it():
    node = ClashParser().parse(
        """
proxies:
  - name: socks-tls
    type: socks5
    server: example.com
    port: 443
    tls: true
    sni: example.com
"""
    )[0]

    assert DaeEmitter().check_node(node).supported is False
    assert V2RayNEmitter().check_node(node).supported is False
    assert DaeEmitter().emit_subscription([node]) == ""
    assert V2RayNEmitter().emit_list([node]) == ""
    assert link.build_socks5_url(node) is None


def test_emission_result_normalizes_capability_issue_fields():
    node = ClashParser().parse(
        """
proxies:
  - name: socks-tls
    type: socks5
    server: example.com
    port: 443
    tls: true
"""
    )[0]
    node.source_provider = "source-a"

    result = V2RayNEmitter().emit_result([node])

    assert result.content == ""
    assert result.supported_nodes == []
    assert len(result.errors) == 1
    issue = result.errors[0]
    assert issue.severity == IssueSeverity.ERROR
    assert issue.node == "socks-tls"
    assert issue.protocol == "socks5"
    assert issue.source == "source-a"
    assert issue.target == "v2rayn"
    assert issue.field == "tls"
    assert issue.stage == "capability"


def test_link_builder_failure_becomes_error_issue(monkeypatch):
    node = ClashParser().parse(
        """
proxies:
  - name: ss-node
    type: ss
    server: example.com
    port: 8388
    cipher: aes-256-gcm
    password: p
"""
    )[0]
    node.source_provider = "source-b"
    monkeypatch.setattr("subio_v2.emitter.v2rayn.link.build_url", lambda _: None)

    result = V2RayNEmitter().emit_result([node])

    assert result.supported_nodes == []
    assert len(result.errors) == 1
    issue = result.errors[0]
    assert issue.source == "source-b"
    assert issue.target == "v2rayn"
    assert issue.stage == "emit"
    assert "No representable v2rayN link" in issue.message


def test_v2rayn_link_builders_match_declared_http_and_h2_capabilities():
    vless = VlessNode(
        name="vless-http",
        type=Protocol.VLESS,
        server="example.com",
        port=80,
        uuid="u",
        transport=TransportSettings(
            network=Network.HTTP,
            path=["/one", "/two"],
            headers={"Host": "cdn.example.com"},
        ),
    )
    trojan = TrojanNode(
        name="trojan-h2",
        type=Protocol.TROJAN,
        server="example.com",
        port=443,
        password="p",
        transport=TransportSettings(
            network=Network.H2,
            path="/h2",
            host=["h2.example.com"],
        ),
    )

    vless_url = link.build_vless_url(vless)
    trojan_url = link.build_trojan_url(trojan)

    assert "type=http" in vless_url
    assert "path=%2Fone%2C%2Ftwo" in vless_url
    assert "host=cdn.example.com" in vless_url
    assert "type=h2" in trojan_url
    assert "path=%2Fh2" in trojan_url
    assert "host=h2.example.com" in trojan_url


def test_semantic_features_are_errors_when_target_would_drop_them():
    hysteria2 = ClashParser().parse(
        """
proxies:
  - name: hy2-obfs
    type: hysteria2
    server: example.com
    port: 443
    password: p
    obfs: salamander
    obfs-password: secret
"""
    )[0]
    vmess = ClashParser().parse(
        """
proxies:
  - name: vmess-cipher
    type: vmess
    server: example.com
    port: 443
    uuid: u
    cipher: unsupported-cipher
"""
    )[0]

    assert SurgeEmitter().check_node(hysteria2).supported is True
    assert "salamander-password=secret" in SurgeEmitter().emit([hysteria2])
    assert V2RayNEmitter().check_node(vmess).supported is False
