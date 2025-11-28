import pytest
from subio_v2.parser.surge import SurgeParser
from subio_v2.model.nodes import Protocol


def test_surge_parser_proxy_section_and_no_sections():
    conf = """
[Proxy]
SS1 = ss, s1, 1000, encrypt-method=aes-256-gcm, password=p, udp-relay=true, obfs=http, obfs-host=h
VM2 = vmess, s2, 2000, username=u2, encrypt-method=auto, tls=true
TRO3 = trojan, s3, 3000, password=tp
SOCK = socks5, s4, 4000, username=user, password=pass
HTTP = https, s5, 5000, username=aa, password=bb
"""
    nodes = SurgeParser().parse(conf)
    names = [n.name for n in nodes]
    assert names == ["SS1", "VM2", "TRO3", "SOCK", "HTTP"]
    assert nodes[0].type == Protocol.SHADOWSOCKS and nodes[0].plugin == "obfs"
    assert nodes[1].type == Protocol.VMESS and nodes[1].tls.enabled
    assert nodes[2].type == Protocol.TROJAN and nodes[2].tls.enabled
    assert nodes[3].type == Protocol.SOCKS5 and nodes[3].username == "user"
    assert nodes[4].type == Protocol.HTTP and nodes[4].tls.enabled

    # No sections style line
    conf2 = "SSa = ss, s, 1, encrypt-method=aes-256-gcm, password=p\nBadLine"
    nodes2 = SurgeParser().parse(conf2)
    assert [n.name for n in nodes2] == ["SSa"]


def test_surge_parser_invalid_types_and_values_skip_line():
    conf = "Bad = vmess, s, notaport\n[Proxy]\nN = vmess, s, 80, tls=true"
    nodes = SurgeParser().parse(conf)
    assert [n.name for n in nodes] == ["N"]


def test_surge_invalid_content_type_exits():
    with pytest.raises(SystemExit):
        SurgeParser().parse({"not": "str"})
