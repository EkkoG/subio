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
    nodes = ClashParser().parse(yaml_text)
    names = [n.name for n in nodes]
    assert names == ["ss1", "vm2", "tro3", "vless4"]
    assert nodes[0].type == Protocol.SHADOWSOCKS and nodes[0].cipher == "aes-256-gcm"
    assert nodes[1].type == Protocol.VMESS and nodes[1].tls.enabled is True
    assert nodes[2].type == Protocol.TROJAN
    assert nodes[3].type == Protocol.VLESS and nodes[3].flow == "xtls-rprx-vision"


def test_clash_parser_invalid_yaml_exits():
    with pytest.raises(SystemExit):
        ClashParser().parse("not: yaml: : :")


def test_clash_parser_missing_proxies_exits():
    with pytest.raises(SystemExit):
        ClashParser().parse({"hello": "world"})


def test_clash_parser_ignores_bad_nodes_and_continues():
    yaml_text = """
proxies:
  - {name: ok, type: ss, server: s, port: 1, cipher: aes-256-gcm, password: p}
  - {name: bad, type: ss, server: s, port: notint}
"""
    nodes = ClashParser().parse(yaml_text)
    assert [n.name for n in nodes] == ["ok"]
