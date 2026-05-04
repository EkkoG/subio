import base64
import json
import urllib.parse

import pytest

from subio_v2.emitter.dae import DaeEmitter
from subio_v2.emitter import link
from subio_v2.model.nodes import (
    Protocol,
    Network,
    TLSSettings,
    TransportSettings,
    ShadowsocksNode,
    VmessNode,
    VlessNode,
    TrojanNode,
    Socks5Node,
    HttpNode,
    Hysteria2Node,
    TUICNode,
    AnyTLSNode,
)


def _ss(name="ss-hk", server="hk.example.com", port=8388):
    return ShadowsocksNode(
        name=name,
        type=Protocol.SHADOWSOCKS,
        server=server,
        port=port,
        cipher="aes-256-gcm",
        password="p@ss",
    )


def _vmess(name="vm", server="vm.example.com", port=443):
    return VmessNode(
        name=name,
        type=Protocol.VMESS,
        server=server,
        port=port,
        uuid="11111111-1111-1111-1111-111111111111",
        alter_id=0,
        cipher="auto",
        transport=TransportSettings(network=Network.WS, path="/ray", headers={"Host": "vm.example.com"}),
        tls=TLSSettings(enabled=True, server_name="vm.example.com"),
    )


def _vless(name="vl"):
    return VlessNode(
        name=name,
        type=Protocol.VLESS,
        server="vl.example.com",
        port=443,
        uuid="22222222-2222-2222-2222-222222222222",
        flow="xtls-rprx-vision",
        tls=TLSSettings(enabled=True, server_name="vl.example.com"),
        transport=TransportSettings(network=Network.TCP),
    )


def _trojan(name="tj"):
    return TrojanNode(
        name=name,
        type=Protocol.TROJAN,
        server="tj.example.com",
        port=443,
        password="trojanpass",
        tls=TLSSettings(enabled=True, server_name="tj.example.com"),
    )


def _hysteria2(name="hy2"):
    return Hysteria2Node(
        name=name,
        type=Protocol.HYSTERIA2,
        server="hy.example.com",
        port=443,
        password="hypass",
        obfs="salamander",
        obfs_password="oo",
        tls=TLSSettings(enabled=True, server_name="hy.example.com"),
    )


def _tuic(name="tu"):
    return TUICNode(
        name=name,
        type=Protocol.TUIC,
        server="tu.example.com",
        port=443,
        uuid="33333333-3333-3333-3333-333333333333",
        password="tuicpass",
        version=5,
        tls=TLSSettings(enabled=True, server_name="tu.example.com"),
    )


def _anytls(name="at"):
    return AnyTLSNode(
        name=name,
        type=Protocol.ANYTLS,
        server="at.example.com",
        port=443,
        password="anytlspass",
        tls=TLSSettings(enabled=True, server_name="at.example.com"),
    )


def _socks5(name="s5"):
    return Socks5Node(
        name=name,
        type=Protocol.SOCKS5,
        server="s5.example.com",
        port=1080,
        username="u",
        password="p",
    )


def _http(name="hp"):
    return HttpNode(
        name=name,
        type=Protocol.HTTP,
        server="hp.example.com",
        port=8080,
        username="u",
        password="p",
    )


# ============== link.build_url 单协议测试 ==============


def test_build_ss_url_sip002():
    node = _ss()
    url = link.build_ss_url(node)
    assert url.startswith("ss://")
    head, _, frag = url.partition("#")
    assert frag == urllib.parse.quote(node.name, safe="")
    userinfo_b64 = head[len("ss://"): head.index("@")]
    decoded = base64.urlsafe_b64decode(userinfo_b64 + "=" * (-len(userinfo_b64) % 4)).decode()
    assert decoded == "aes-256-gcm:p@ss"
    assert "hk.example.com:8388" in head


def test_build_vmess_url_base64_json():
    node = _vmess()
    url = link.build_vmess_url(node)
    assert url.startswith("vmess://")
    payload = url[len("vmess://"):]
    data = json.loads(base64.b64decode(payload).decode())
    assert data["ps"] == node.name
    assert data["add"] == node.server
    assert data["port"] == "443"
    assert data["net"] == "ws"
    assert data["path"] == "/ray"
    assert data["host"] == "vm.example.com"
    assert data["tls"] == "tls"
    assert data["sni"] == "vm.example.com"


def test_build_vless_url_with_flow_and_tls():
    url = link.build_vless_url(_vless())
    assert url.startswith("vless://22222222-2222-2222-2222-222222222222@vl.example.com:443?")
    qs = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
    assert qs["security"] == ["tls"]
    assert qs["flow"] == ["xtls-rprx-vision"]
    assert qs["sni"] == ["vl.example.com"]


def test_build_trojan_url():
    url = link.build_trojan_url(_trojan())
    parsed = urllib.parse.urlparse(url)
    assert parsed.scheme == "trojan"
    assert parsed.hostname == "tj.example.com"
    assert parsed.port == 443
    qs = urllib.parse.parse_qs(parsed.query)
    assert qs["sni"] == ["tj.example.com"]


def test_build_hysteria2_url():
    url = link.build_hysteria2_url(_hysteria2())
    assert url.startswith("hysteria2://hypass@hy.example.com:443/?")
    qs = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
    assert qs["sni"] == ["hy.example.com"]
    assert qs["obfs"] == ["salamander"]
    assert qs["obfs-password"] == ["oo"]


def test_build_tuic_url_v5():
    url = link.build_tuic_url(_tuic())
    parsed = urllib.parse.urlparse(url)
    assert parsed.scheme == "tuic"
    # v5: uuid:password@host:port
    assert "33333333-3333-3333-3333-333333333333:tuicpass" in url
    qs = urllib.parse.parse_qs(parsed.query)
    assert qs["sni"] == ["tu.example.com"]


def test_build_anytls_url():
    url = link.build_anytls_url(_anytls())
    assert url.startswith("anytls://anytlspass@at.example.com:443/?")
    qs = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
    assert qs["sni"] == ["at.example.com"]


def test_build_socks5_and_http_urls():
    s = link.build_socks5_url(_socks5())
    assert s.startswith("socks5://u:p@s5.example.com:1080#")
    h = link.build_http_url(_http())
    assert h.startswith("http://u:p@hp.example.com:8080#")


# ============== DaeEmitter.emit ==============


def test_dae_emit_node_block_format():
    nodes = [_ss("hk"), _vmess("jp")]
    out = DaeEmitter().emit(nodes)
    lines = out.splitlines()
    assert len(lines) == 2
    assert lines[0].startswith("'hk': '") and lines[0].endswith("'")
    assert lines[1].startswith("'jp': '") and lines[1].endswith("'")
    # 每行内嵌的 link 必须以协议 scheme 起头
    assert "ss://" in lines[0]
    assert "vmess://" in lines[1]


def test_dae_emit_subscription_plaintext():
    nodes = [_ss("a"), _trojan("b")]
    sub = DaeEmitter().emit_subscription(nodes)
    lines = sub.splitlines()
    assert len(lines) == 2
    assert lines[0].startswith("ss://")
    assert lines[1].startswith("trojan://")
    # 不是 base64
    with pytest.raises(Exception):
        base64.b64decode(sub, validate=True)


def test_dae_emit_dialer_chain_appends_arrow():
    base_node = _ss("base")
    chained = _vmess("chained")
    chained.dialer_proxy = "base"
    out = DaeEmitter().emit([base_node, chained])
    lines = out.splitlines()
    base_line = next(line for line in lines if line.startswith("'base':"))
    chained_line = next(line for line in lines if line.startswith("'chained':"))
    assert " -> " in chained_line
    # base 节点本身不应有链
    assert " -> " not in base_line
    # chained 行末尾应当包含 base 的 ss URL
    assert "ss://" in chained_line


def test_dae_emit_dialer_chain_unknown_target_falls_back():
    chained = _vmess("orphan")
    chained.dialer_proxy = "missing"
    out = DaeEmitter().emit([chained])
    lines = out.splitlines()
    assert len(lines) == 1
    assert " -> " not in lines[0]


def test_dae_emit_filters_unsupported_protocols():
    """Hysteria2/TUIC/AnyTLS 在 dae 能力集中应被接受，输出对应 URL 行。"""
    nodes = [_hysteria2(), _tuic(), _anytls()]
    out = DaeEmitter().emit(nodes)
    assert "hysteria2://" in out
    assert "tuic://" in out
    assert "anytls://" in out
