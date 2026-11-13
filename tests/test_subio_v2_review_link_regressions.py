import base64

import pytest

from subio_v2.adapters.catalog import get_emitter, get_parser
from subio_v2.adapters.links import codecs as links
from subio_v2.adapters.links.parser import V2RayNParser
from subio_v2.core.nodes import (
    DirectNode, HysteriaNode, Hysteria2Node, Protocol, SSHNode,
)
from tests.test_subio_v2_link_nested_values import _node


@pytest.mark.parametrize('protocol,target', [
    ('vmess', 'v2rayn'), ('vless', 'v2rayn'), ('trojan', 'v2rayn'),
    ('anytls', 'dae'), ('tuic', 'dae'), ('hysteria2', 'dae'),
])
@pytest.mark.parametrize('field', ['certificate_sha256', 'verify_name', 'private_key'])
def test_link_targets_reject_unrepresentable_tls_identity(protocol, target, field):
    node = _node(protocol)
    setattr(node.tls, field, 'synthetic-identity')
    node.tls.skip_cert_verify = True
    result = get_emitter(target).emit_result([node])
    assert result.supported_nodes == []
    assert any(i.field == f'tls.{field}' for i in result.errors)


@pytest.mark.parametrize('protocol', ['vmess', 'vless', 'trojan'])
def test_links_reject_required_ws_headers(protocol):
    node = _node(protocol)
    node.transport.network = 'ws'
    node.transport.headers = {'Host': 'edge.test', 'Authorization': 'synthetic'}
    result = get_emitter('v2rayn').emit_result([node])
    assert result.supported_nodes == []
    assert any(i.field == 'transport.headers' for i in result.errors)


def test_http_link_rejects_required_headers():
    node = _node('http')
    node.headers = {'X-Proxy-Token': 'synthetic'}
    result = get_emitter('dae').emit_result([node])
    assert not result.supported_nodes
    assert any(i.field == 'headers' for i in result.errors)


@pytest.mark.parametrize('target', ['mihomo', 'stash'])
def test_ssh_server_fingerprints_cannot_be_dropped(target):
    node = SSHNode(name='ssh', server='example.test', port=22, username='u',
                   password='synthetic', server_fingerprints=['SHA256:synthetic'])
    result = get_emitter(target).emit_result([node])
    assert not result.supported_nodes
    assert any(i.field == 'server_fingerprints' for i in result.errors)


def test_ss_bare_plugin_flag_and_percent_credentials_roundtrip():
    parsed = V2RayNParser().parse_result(
        'ss://aes-128-gcm:abc%2Bdef%3D@example.test:443/'
        '?plugin=v2ray-plugin%3Btls%3Bhost%3Dedge.test#ss'
    )
    assert not parsed.issues
    node = parsed.nodes[0]
    assert node.password == 'abc+def='
    assert node.plugin_opts == {'tls': True, 'host': 'edge.test'}
    again = links.parse_url(links.build_url(node))
    assert again.password == node.password
    assert again.plugin_opts == node.plugin_opts


def test_legacy_ss_full_payload_base64():
    payload = base64.urlsafe_b64encode(b'aes-128-gcm:secret@[::1]:443').decode().rstrip('=')
    parsed = V2RayNParser().parse_result(f'ss://{payload}#legacy')
    assert not parsed.issues
    node = parsed.nodes[0]
    assert (node.server, node.port, node.cipher, node.password) == ('::1', 443, 'aes-128-gcm', 'secret')


def test_trojan_alpn_roundtrip():
    node = links.parse_url('trojan://pw@example.test:443?alpn=h2%2Chttp%2F1.1')
    assert node.tls.alpn == ['h2', 'http/1.1']
    assert links.parse_url(links.build_url(node)).tls.alpn == node.tls.alpn


def test_vless_tcp_http_disguise_is_rejected():
    result = V2RayNParser().parse_result(
        'vless://synthetic@example.test:443?type=tcp&security=none&headerType=http&host=front.test&path=%2F'
    )
    assert not result.nodes
    assert result.issues[0].code == 'parse.link'


@pytest.mark.parametrize('target', ['mihomo', 'stash', 'dae', 'v2rayn'])
def test_ss_separate_udp_port_is_rejected(target):
    node = _node('ss')
    node.udp_port = 8443
    result = get_emitter(target).emit_result([node])
    assert not result.supported_nodes
    assert any(i.field == 'udp_port' for i in result.errors)


@pytest.mark.parametrize('node', [
    DirectNode(name='tcp', udp=False),
    HysteriaNode(name='tcp', server='example.test', port=443, auth_str='synthetic', udp=False),
    Hysteria2Node(name='tcp', server='example.test', port=443, password='synthetic', udp=False),
])
def test_singbox_cannot_enable_disabled_udp(node):
    result = get_emitter('sing-box').emit_result([node])
    assert not result.supported_nodes
    assert any(i.field == 'udp' for i in result.errors)


@pytest.mark.parametrize('field,value', [('ports', '443,8443'), ('hop_interval', 10)])
def test_hysteria2_links_reject_hopping(field, value):
    node = _node('hysteria2')
    setattr(node, field, value)
    result = get_emitter('dae').emit_result([node])
    assert not result.supported_nodes
    assert any(i.field == field for i in result.errors)
