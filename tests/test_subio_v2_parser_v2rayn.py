import pytest
from subio_v2.parser.v2rayn import V2RayNParser
from subio_v2.model.nodes import Protocol
import base64
import json


def b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def test_v2rayn_parse_vmess_uri():
    obj = {
        "v": "2",
        "ps": "vm",
        "add": "host",
        "port": "443",
        "id": "uuid-1",
        "aid": "0",
        "scy": "auto",
        "net": "ws",
        "path": "/p",
        "host": "h",
        "tls": "tls",
        "sni": "sni",
        "alpn": "h2,http/1.1",
    }
    uri = "vmess://" + b64(json.dumps(obj))
    node = V2RayNParser()._parse_line(uri)
    assert node and node.type == Protocol.VMESS
    assert node.transport.network.value == "ws"
    assert node.tls.enabled and node.tls.server_name == "sni"
    assert node.name == "vm"


def test_v2rayn_parse_ss_uri_plain_and_b64_userinfo():
    plain = "ss://aes-256-gcm:pass@server:1234#myname"
    node1 = V2RayNParser()._parse_line(plain)
    assert node1 and node1.type == Protocol.SHADOWSOCKS
    assert node1.cipher == "aes-256-gcm" and node1.password == "pass"
    assert node1.server == "server" and node1.port == 1234
    assert node1.name == "myname"

    # base64 userinfo
    userinfo = b64("aes-256-gcm:pass")
    b64uri = f"ss://{userinfo}@server:5678#n"
    node2 = V2RayNParser()._parse_line(b64uri)
    assert node2 and node2.port == 5678 and node2.name == "n"


def test_v2rayn_parse_trojan_and_vless():
    tro = "trojan://pass@t.example:443?sni=example.com&allowInsecure=1#tname"
    node_t = V2RayNParser()._parse_line(tro)
    assert node_t and node_t.type == Protocol.TROJAN and node_t.tls.enabled
    assert node_t.tls.server_name == "example.com" and node_t.tls.skip_cert_verify is True

    vless = "vless://uuid@vhost:8443?type=ws&security=tls&path=/x&host=h&sni=s#vname"
    node_v = V2RayNParser()._parse_line(vless)
    assert node_v and node_v.type == Protocol.VLESS and node_v.transport.network.value == "ws"
    assert node_v.tls.enabled and node_v.tls.server_name == "s"


def test_v2rayn_parse_subscription_base64_multiple_lines():
    content = "\n".join([
        "vmess://" + b64(json.dumps({"v":"2","ps":"n","add":"s","port":"80","id":"u"})),
        "ss://aes-256-gcm:pass@server:1234#n2",
    ])
    b64sub = b64(content)
    nodes = V2RayNParser().parse(b64sub)
    assert len(nodes) == 2


def test_v2rayn_invalid_content_type_exits():
    with pytest.raises(SystemExit):
        V2RayNParser().parse({"bad": "type"})
