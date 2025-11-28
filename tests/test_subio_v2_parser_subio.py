import pytest
from subio_v2.parser.subio import SubioParser
from subio_v2.model.nodes import Protocol


def test_subio_parser_supports_multiple_formats_and_uses_clash_parser():
    proxies = [
        {"name": "n1", "type": "ss", "server": "s", "port": 1, "cipher": "aes-256-gcm", "password": "p"},
        {"name": "n2", "type": "vmess", "server": "s2", "port": 2, "uuid": "u"},
    ]
    # JSON
    content_json = "{" + "\"proxies\": " + str(proxies).replace("'", '"') + "}"
    nodes_json = SubioParser().parse(content_json)
    assert [n.name for n in nodes_json] == ["n1", "n2"]
    assert nodes_json[0].type == Protocol.SHADOWSOCKS

    # YAML
    content_yaml = "proxies:\n- {name: n1, type: ss, server: s, port: 1, cipher: aes-256-gcm, password: p}\n- {name: n2, type: vmess, server: s2, port: 2, uuid: u}"
    nodes_yaml = SubioParser().parse(content_yaml)
    assert len(nodes_yaml) == 2

    # JSON5
    content_json5 = "{proxies: [{name: n1, type: ss, server: s, port: 1, cipher: aes-256-gcm, password: p,},]}"
    nodes_json5 = SubioParser().parse(content_json5)
    assert len(nodes_json5) == 1

    # TOML
    content_toml = "proxies = [{name = \"n1\", type = \"ss\", server = \"s\", port = 1, cipher = \"aes-256-gcm\", password = \"p\"}]"
    nodes_toml = SubioParser().parse(content_toml)
    assert len(nodes_toml) == 1


def test_subio_parser_errors_on_missing_proxies_or_type():
    with pytest.raises(SystemExit):
        SubioParser().parse("{}")
    with pytest.raises(SystemExit):
        SubioParser().parse(123)
