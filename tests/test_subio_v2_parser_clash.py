import pytest
from subio_v2.parser.clash import ClashParser
from subio_v2.model.nodes import Protocol


def test_clash_parser_basic_nodes_yaml_string():
    yaml_text = """
proxies:
  - {name: ss1, type: ss, server: s1, port: 100, cipher: aes-256-gcm, password: p}
  - name: vm2
    type: vmess
    server: s2
    port: 200
    uuid: u2
    tls: true
    sni: vhost
    ws-opts:
      path: /ws
      headers:
        Host: vhost
    smux:
      enabled: true
    
  - name: tro3
    type: trojan
    server: s3
    port: 300
    password: tp
    
  - name: vless4
    type: vless
    server: s4
    port: 400
    uuid: u4
    flow: xtls-rprx-vision
    tls: true
    sni: v4
"""
    nodes = ClashParser().parse_nodes(yaml_text)
    names = [n.name for n in nodes]
    assert names == ["ss1", "vm2", "tro3", "vless4"]
    assert nodes[0].type == Protocol.SHADOWSOCKS and nodes[0].cipher == "aes-256-gcm"
    assert nodes[1].type == Protocol.VMESS and nodes[1].tls.enabled is True
    assert nodes[2].type == Protocol.TROJAN
    assert nodes[3].type == Protocol.VLESS and nodes[3].flow == "xtls-rprx-vision"


def test_clash_parser_invalid_yaml_raises_value_error():
    with pytest.raises(ValueError, match="YAML parse error"):
        ClashParser().parse_nodes("not: yaml: : :")


def test_clash_parser_missing_proxies_raises_value_error():
    with pytest.raises(ValueError, match="missing 'proxies'"):
        ClashParser().parse_nodes({"hello": "world"})


def test_clash_parser_ignores_bad_nodes_and_continues():
    yaml_text = """
proxies:
  - {name: ok, type: ss, server: s, port: 1, cipher: aes-256-gcm, password: p}
  - {name: bad, type: ss, server: s, port: notint}
"""
    nodes = ClashParser().parse_nodes(yaml_text)
    assert [n.name for n in nodes] == ["ok"]


def test_clash_parse_result_reports_bad_nodes_instead_of_silently_dropping_them():
    result = ClashParser().parse_result(
        """
proxies:
  - {name: ok, type: ss, server: s, port: 1, cipher: aes-256-gcm, password: p}
  - {name: bad, type: ss, server: s, port: notint, cipher: aes-256-gcm, password: p}
"""
    )

    assert [node.name for node in result.nodes] == ["ok"]
    assert len(result.issues) == 1
    assert result.issues[0].node == "bad"
    assert result.issues[0].stage == "parse"
    assert result.issues[0].code == "parse.node"


def test_clash_parse_result_raises_value_error_for_invalid_document():
    with pytest.raises(ValueError, match="missing 'proxies'"):
        ClashParser().parse_result({"not-proxies": []})
