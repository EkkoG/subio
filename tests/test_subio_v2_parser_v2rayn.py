import pytest
from subio_v2.emitter import link
from subio_v2.parser.v2rayn import V2RayNParser
from subio_v2.model.nodes import Network, Protocol
import base64
import json
import urllib.parse


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
    assert (
        node_t.tls.server_name == "example.com" and node_t.tls.skip_cert_verify is True
    )

    vless = "vless://uuid@vhost:8443?type=ws&security=tls&path=/x&host=h&sni=s#vname"
    node_v = V2RayNParser()._parse_line(vless)
    assert (
        node_v
        and node_v.type == Protocol.VLESS
        and node_v.transport.network.value == "ws"
    )
    assert node_v.tls.enabled and node_v.tls.server_name == "s"


def test_v2rayn_parse_subscription_base64_multiple_lines():
    content = "\n".join(
        [
            "vmess://"
            + b64(
                json.dumps({"v": "2", "ps": "n", "add": "s", "port": "80", "id": "u"})
            ),
            "ss://aes-256-gcm:pass@server:1234#n2",
        ]
    )
    b64sub = b64(content)
    nodes = V2RayNParser().parse_nodes(b64sub)
    assert len(nodes) == 2


def test_v2rayn_invalid_content_type_raises_value_error():
    with pytest.raises(ValueError, match="Invalid content type"):
        V2RayNParser().parse_nodes({"bad": "type"})


def test_vless_reality_grpc_codec_roundtrip_preserves_semantics():
    uri = (
        "vless://uuid@example.com:443?type=grpc&security=reality"
        "&serviceName=svc&sni=example.com&pbk=public&sid=short&fp=chrome#node"
    )
    node = V2RayNParser()._parse_line(uri)

    assert node is not None
    assert node.transport.network == Network.GRPC
    assert node.transport.grpc_service_name == "svc"
    assert node.tls.client_fingerprint == "chrome"
    assert node.tls.certificate_sha256 is None
    assert node.tls.reality_opts == {"public-key": "public", "short-id": "short"}

    rebuilt = urllib.parse.urlparse(link.build_vless_url(node))
    query = urllib.parse.parse_qs(rebuilt.query)
    assert query["security"] == ["reality"]
    assert query["serviceName"] == ["svc"]
    assert query["fp"] == ["chrome"]
    assert query["pbk"] == ["public"]
    assert query["sid"] == ["short"]


def test_vless_grpc_without_tls_is_not_upgraded():
    uri = "vless://uuid@example.com:80?type=grpc&security=none&serviceName=svc#node"
    node = V2RayNParser()._parse_line(uri)

    assert node is not None
    assert node.tls.enabled is False
    rebuilt = urllib.parse.urlparse(link.build_vless_url(node))
    query = urllib.parse.parse_qs(rebuilt.query)
    assert query["security"] == ["none"]
    assert query["serviceName"] == ["svc"]


def test_trojan_ws_codec_roundtrip_preserves_transport():
    uri = (
        "trojan://pass@example.com:443?type=ws&path=%2Fws"
        "&host=cdn.example.com&sni=example.com#node"
    )
    node = V2RayNParser()._parse_line(uri)

    assert node is not None
    assert node.transport.network == Network.WS
    assert node.transport.path == "/ws"
    assert node.transport.headers == {"Host": "cdn.example.com"}

    rebuilt = urllib.parse.urlparse(link.build_trojan_url(node))
    query = urllib.parse.parse_qs(rebuilt.query)
    assert query["type"] == ["ws"]
    assert query["path"] == ["/ws"]
    assert query["host"] == ["cdn.example.com"]


def test_vmess_grpc_codec_roundtrip_does_not_force_tls():
    payload = {
        "v": "2",
        "ps": "vmess-grpc",
        "add": "example.com",
        "port": "80",
        "id": "uuid",
        "aid": "0",
        "scy": "auto",
        "net": "grpc",
        "path": "svc",
        "tls": "",
    }
    node = V2RayNParser()._parse_line("vmess://" + b64(json.dumps(payload)))

    assert node is not None
    assert node.transport.network == Network.GRPC
    assert node.transport.grpc_service_name == "svc"
    assert node.tls.enabled is False

    encoded = link.build_vmess_url(node).removeprefix("vmess://")
    rebuilt = json.loads(base64.b64decode(encoded).decode("utf-8"))
    assert rebuilt["net"] == "grpc"
    assert rebuilt["path"] == "svc"
    assert rebuilt["tls"] == ""


def test_v2rayn_parse_result_reports_unparseable_links():
    valid = "ss://aes-256-gcm:pass@server:1234#valid"
    result = V2RayNParser().parse_result(f"{valid}\nunknown://payload#bad")

    assert [node.name for node in result.nodes] == ["valid"]
    assert len(result.issues) == 1
    assert result.issues[0].node == "bad"
    assert result.issues[0].protocol == "unknown"
    assert result.issues[0].code == "parse.link"
    assert result.issues[0].target is None
