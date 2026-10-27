import base64
import json
import urllib.parse

import pytest

from subio_v2.adapters.links import codecs as link
from subio_v2.adapters.links.dae import DaeEmitter
from subio_v2.adapters.links.v2rayn import V2RayNEmitter
from subio_v2.core.nodes import (
    AnyTLSNode,
    HttpNode,
    Hysteria2Node,
    Network,
    Protocol,
    ShadowsocksNode,
    Socks5Node,
    TLSSettings,
    TransportSettings,
    TrojanNode,
    TUICNode,
    VlessNode,
    VmessNode,
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
        transport=TransportSettings(
            network=Network.WS, path="/ray", headers={"Host": "vm.example.com"}
        ),
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
    url = link.build_url(node)
    assert url.startswith("ss://")
    head, _, frag = url.partition("#")
    assert frag == urllib.parse.quote(node.name, safe="")
    userinfo_b64 = head[len("ss://") : head.index("@")]
    decoded = base64.urlsafe_b64decode(
        userinfo_b64 + "=" * (-len(userinfo_b64) % 4)
    ).decode()
    assert decoded == "aes-256-gcm:p@ss"
    assert "hk.example.com:8388" in head


def test_build_vmess_url_base64_json():
    node = _vmess()
    url = link.build_url(node)
    assert url.startswith("vmess://")
    payload = url[len("vmess://") :]
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
    url = link.build_url(_vless())
    assert url.startswith(
        "vless://22222222-2222-2222-2222-222222222222@vl.example.com:443?"
    )
    qs = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
    assert qs["security"] == ["tls"]
    assert qs["flow"] == ["xtls-rprx-vision"]
    assert qs["sni"] == ["vl.example.com"]


def test_build_trojan_url():
    url = link.build_url(_trojan())
    parsed = urllib.parse.urlparse(url)
    assert parsed.scheme == "trojan"
    assert parsed.hostname == "tj.example.com"
    assert parsed.port == 443
    qs = urllib.parse.parse_qs(parsed.query)
    assert qs["sni"] == ["tj.example.com"]


def test_build_hysteria2_url():
    url = link.build_url(_hysteria2())
    assert url.startswith("hysteria2://hypass@hy.example.com:443/?")
    qs = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
    assert qs["sni"] == ["hy.example.com"]
    assert qs["obfs"] == ["salamander"]
    assert qs["obfs-password"] == ["oo"]


def test_build_tuic_url_v5():
    url = link.build_url(_tuic())
    parsed = urllib.parse.urlparse(url)
    assert parsed.scheme == "tuic"
    # v5: uuid:password@host:port
    assert "33333333-3333-3333-3333-333333333333:tuicpass" in url
    qs = urllib.parse.parse_qs(parsed.query)
    assert qs["sni"] == ["tu.example.com"]


def test_build_anytls_url():
    url = link.build_url(_anytls())
    assert url.startswith("anytls://anytlspass@at.example.com:443/?")
    qs = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
    assert qs["sni"] == ["at.example.com"]


def test_build_socks5_and_http_urls():
    s = link.build_url(_socks5())
    assert s.startswith("socks5://u:p@s5.example.com:1080#")
    h = link.build_url(_http())
    assert h.startswith("http://u:p@hp.example.com:8080#")


# ============== DaeEmitter.emit ==============


def test_dae_emit_node_block_format():
    nodes = [_ss("hk"), _vmess("jp")]
    out = DaeEmitter().emit_result(nodes).content
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
    out = DaeEmitter().emit_result([base_node, chained]).content
    lines = out.splitlines()
    base_line = next(line for line in lines if line.startswith("'base':"))
    chained_line = next(line for line in lines if line.startswith("'chained':"))
    assert " -> " in chained_line
    # base 节点本身不应有链
    assert " -> " not in base_line
    # chained 行末尾应当包含 base 的 ss URL
    assert "ss://" in chained_line


def test_dae_emit_dialer_chain_unknown_target_fails():
    chained = _vmess("orphan")
    chained.dialer_proxy = "missing"
    result = DaeEmitter().emit_result([chained])
    assert any("unknown dialer_proxy" in issue.message for issue in result.errors)


def test_dae_rejects_duplicate_node_names():
    result = DaeEmitter().emit_result([_ss("same"), _vmess("same")])
    assert any("Duplicate node name" in issue.message for issue in result.errors)


def test_dae_resolves_full_dialer_chain_and_rejects_cycles():
    base = _ss("base")
    middle = _vmess("middle")
    leaf = _trojan("leaf")
    middle.dialer_proxy = "base"
    leaf.dialer_proxy = "middle"

    out = DaeEmitter().emit_result([base, middle, leaf]).content
    leaf_line = next(line for line in out.splitlines() if line.startswith("'leaf':"))
    assert leaf_line.count(" -> ") == 2

    base.dialer_proxy = "leaf"
    result = DaeEmitter().emit_result([base, middle, leaf])
    assert any("Cyclic dae dialer chain" in issue.message for issue in result.errors)


def test_dae_emit_filters_unsupported_protocols():
    """Hysteria2/TUIC/AnyTLS 在 dae 能力集中应被接受，输出对应 URL 行。"""
    nodes = [_hysteria2(), _tuic(), _anytls()]
    out = DaeEmitter().emit_result(nodes).content
    assert "hysteria2://" in out
    assert "tuic://" in out
    assert "anytls://" in out


@pytest.mark.parametrize(
    "factory", [_ss, _http, _socks5, _anytls, _hysteria2, _trojan, _vless, _tuic]
)
def test_uri_builders_bracket_ipv6_authorities(factory):
    node = factory()
    node.server = "2001:db8::123"
    parsed = urllib.parse.urlsplit(link.build_url(node))
    assert parsed.hostname == node.server
    assert parsed.port == node.port
    assert f"@[{node.server}]:{node.port}" in parsed.netloc


@pytest.mark.parametrize(
    "server, hostname",
    [
        ("good.example", "good.example"),
        ("good.example.", "good.example."),
        ("localhost", "localhost"),
        ("node_name-1.example", "node_name-1.example"),
        ("192.0.2.1", "192.0.2.1"),
        ("::1", "::1"),
        ("[2001:db8::1]", "2001:db8::1"),
        ("::ffff:192.0.2.1", "::ffff:192.0.2.1"),
    ],
)
def test_uri_authorities_preserve_safe_neighbors(server, hostname):
    node = _socks5()
    node.server = server
    result = V2RayNEmitter().emit_result([node])
    assert not result.errors
    parsed = urllib.parse.urlsplit(result.fragments.plain_list)
    assert parsed.hostname == hostname
    assert parsed.port == 1080


@pytest.mark.parametrize(
    "server",
    [
        "good.example#fragment",
        "good.example?query=1",
        "good.example/path",
        "good.example@other.example",
        "good.example:1080",
        "good.example\\other",
        "good.example%23fragment",
        "good.example'",
        'good.example"',
        "good.example;extra",
        "good example",
        "good.example\n",
        "good.example\r",
        "good.example\t",
        "good.example\x00",
        "good.example\x7f",
        "good.example\u2028",
        "[example.com]",
        "[::1",
        "::1]",
        "[::1]:1080",
        "2001:db8::invalid",
        "fe80::1%eth0",
    ],
)
@pytest.mark.parametrize("emitter", [DaeEmitter, V2RayNEmitter])
def test_uri_authority_errors_are_structured_and_drop_nodes(server, emitter):
    node = _socks5()
    node.server = server
    result = emitter().emit_result([node])
    assert not result.supported_nodes
    assert not result.content
    assert len(result.errors) == 1
    issue = result.errors[0]
    assert issue.field == "server"
    assert issue.code == "conversion.invalid-value"
    assert issue.stage == "emit"
    assert server not in issue.message


def test_uri_userinfo_and_fragment_delimiters_decode_exactly_once():
    delimiters = "@:#?/%2F+=&'\" \\\u96ea"
    socks = _socks5()
    socks.username = "user" + delimiters
    socks.password = "password" + delimiters
    socks.name = "name" + delimiters
    parsed = urllib.parse.urlsplit(link.build_url(socks))
    assert parsed.hostname == socks.server
    assert urllib.parse.unquote(parsed.username) == socks.username
    assert urllib.parse.unquote(parsed.password) == socks.password
    assert urllib.parse.unquote(parsed.fragment) == socks.name

    for factory, field in ((_trojan, "password"), (_vless, "uuid")):
        node = factory()
        node.name = "name" + delimiters
        setattr(node, field, "credential" + delimiters)
        uri = link.build_url(node)
        parsed = urllib.parse.urlsplit(uri)
        assert parsed.hostname == node.server
        assert parsed.password is None
        assert urllib.parse.unquote(parsed.username) == getattr(node, field)
        decoded = link.parse_url(uri)
        assert decoded is not None
        assert getattr(decoded, field) == getattr(node, field)
        assert decoded.name == node.name

    tuic = _tuic()
    tuic.uuid = "uuid" + delimiters
    tuic.password = "password" + delimiters
    tuic.name = "name" + delimiters
    parsed = urllib.parse.urlsplit(link.build_url(tuic))
    assert parsed.hostname == tuic.server
    assert urllib.parse.unquote(parsed.username) == tuic.uuid
    assert urllib.parse.unquote(parsed.password) == tuic.password
    assert urllib.parse.unquote(parsed.fragment) == tuic.name

    ss = _ss()
    ss.password = "password" + delimiters
    ss.name = "name" + delimiters
    parsed = urllib.parse.urlsplit(link.build_url(ss))
    encoded = parsed.username
    userinfo = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)).decode()
    assert userinfo == f"{ss.cipher}:{ss.password}"
    assert urllib.parse.unquote(parsed.fragment) == ss.name
    decoded = link.parse_url(link.build_url(ss))
    assert decoded is not None
    assert decoded.password == ss.password
    assert decoded.name == ss.name


def test_vmess_json_base64_preserves_synthetic_scalars_without_uri_restrictions():
    value = "@:#?/%2F+=&'\" \\\n\t\u96ea {{ params.literal }}"
    node = _vmess(name=value, server=value)
    node.uuid = value
    node.transport.path = value
    node.transport.headers = {"Host": value}
    node.tls.server_name = value
    result = V2RayNEmitter().emit_result([node])
    assert not result.errors
    uri = base64.b64decode(result.content).decode()
    data = json.loads(base64.b64decode(uri.removeprefix("vmess://")))
    assert all(data[key] == value for key in ("ps", "add", "id", "path", "host", "sni"))
    decoded = link.parse_url(uri)
    assert decoded is not None
    assert (decoded.name, decoded.server, decoded.uuid) == (value, value, value)
    assert decoded.transport.path == value
    assert decoded.transport.headers == {"Host": value}
    assert decoded.tls.server_name == value


@pytest.mark.parametrize(
    "name",
    [
        "x': 'malformed",
        "single'quote",
        "trailing\\",
        "literal\\n",
        "line\nnext",
        "line\rnext",
        "tab\tvalue",
        "nul\x00value",
        "delete\x7fvalue",
        "next\u0085line",
        "line\u2028separator",
        "paragraph\u2029separator",
    ],
)
def test_dae_rejects_unsafe_quoted_wrapper_names(name):
    result = DaeEmitter().emit_result([_socks5(name)])
    assert not result.supported_nodes
    assert not result.content
    assert result.fragments.subscription == ""
    assert len(result.errors) == 1
    assert result.errors[0].field == "name"
    assert result.errors[0].code == "conversion.invalid-value"
    assert result.errors[0].stage == "emit"


def test_dae_preserves_safe_wrapper_name_neighbors():
    name = 'safe "double" : # & % {value} -> \u96ea'
    result = DaeEmitter().emit_result([_socks5(name)])
    assert not result.errors
    assert result.content.startswith(f"'{name}': 'socks5://")
    parsed = urllib.parse.urlsplit(result.fragments.subscription)
    assert urllib.parse.unquote(parsed.fragment) == name


@pytest.mark.parametrize("failure", ["name", "server"])
def test_dae_dialer_index_excludes_unrepresentable_nodes(failure):
    base = _socks5("base")
    if failure == "name":
        base.name = "unsafe'base"
    else:
        base.server = "good.example#fragment"
    leaf = _trojan("leaf")
    leaf.dialer_proxy = base.name
    result = DaeEmitter().emit_result([base, leaf])
    assert not result.content
    assert not result.supported_nodes
    assert {issue.field for issue in result.errors} == {failure, "dialer_proxy"}
    assert any("unknown dialer_proxy" in issue.message for issue in result.errors)
