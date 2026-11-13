import base64
import json

import pytest

from subio_v2.adapters.catalog import get_emitter, get_parser
from subio_v2.adapters.links import codecs as links
from subio_v2.core.nodes import Network, SnellNode, TrustTunnelNode
from tests.test_subio_v2_link_nested_values import _node


def _vmess(**fields):
    data = {'ps': 'vm', 'add': 'example.test', 'port': 443, 'id': 'synthetic',
            'net': 'tcp', **fields}
    return 'vmess://' + base64.b64encode(json.dumps(data).encode()).decode()


def test_ss_percent_encoded_base64_padding():
    result = get_parser('v2rayn').parse_result('ss://YWVzLTEyOC1nY206cA%3D%3D@example.test:443#ss')
    assert not result.issues
    assert (result.nodes[0].cipher, result.nodes[0].password) == ('aes-128-gcm', 'p')


def test_bad_link_error_path_keeps_sibling():
    result = get_parser('v2rayn').parse_result('unknown://[#bad\nss://aes-128-gcm:p@example.test:443#good')
    assert [n.name for n in result.nodes] == ['good']
    assert len(result.issues) == 1 and result.issues[0].code == 'parse.link'


@pytest.mark.parametrize('suffix', ['', '&mode=stream-up'])
def test_xhttp_path_host_and_mode_are_preserved(suffix):
    result = get_parser('v2rayn').parse_result(
        'vless://synthetic@example.test:443?type=xhttp&security=tls&path=%2Fhidden&host=edge.test' + suffix)
    assert not result.issues
    transport = result.nodes[0].transport
    assert transport.path == '/hidden' and transport.host == 'edge.test'
    assert transport.xhttp_mode == ('stream-up' if suffix else None)
    output = get_emitter('mihomo').emit_result(result.nodes)
    assert not output.errors
    assert output.content['proxies'][0]['xhttp-opts']['path'] == '/hidden'


def test_vmess_tcp_http_disguise_is_rejected():
    result = get_parser('v2rayn').parse_result(_vmess(type='http', host='front.test', path='/hidden'))
    assert not result.nodes and result.issues[0].code == 'parse.link'


def test_vmess_h2_host_list_does_not_become_sni():
    node = links.parse_url(_vmess(net='h2', tls='tls', host='a.test,b.test'))
    assert node.transport.host == ['a.test', 'b.test']
    assert node.tls.server_name is None
    explicit = links.parse_url(_vmess(net='h2', tls='tls', host='a.test,b.test', sni='tls.test'))
    assert explicit.tls.server_name == 'tls.test'


def test_vmess_http_paths_roundtrip_as_list():
    node = _node('vmess')
    node.transport.network, node.transport.path = Network.HTTP, ['/one', '/two']
    again = links.parse_url(links.build_url(node))
    assert again.transport.path == ['/one', '/two']


def test_vmess_http_scalar_comma_is_rejected():
    node = _node('vmess')
    node.transport.network, node.transport.path = Network.HTTP, '/one,/two'
    result = get_emitter('v2rayn').emit_result([node])
    assert not result.supported_nodes and result.errors[0].field == 'transport.path'


def test_trojan_grpc_fields_reach_target_validation():
    parsed = get_parser('v2rayn').parse_result(
        'trojan://p@example.test:443?type=grpc&serviceName=svc&mode=multi&authority=grpc.test')
    assert not parsed.issues
    assert parsed.nodes[0].transport.grpc_mode == 'multi'
    assert parsed.nodes[0].transport.grpc_authority == 'grpc.test'
    result = get_emitter('v2rayn').emit_result(parsed.nodes)
    assert not result.supported_nodes
    assert {i.field for i in result.errors} >= {'transport.grpc_mode', 'transport.grpc_authority'}


@pytest.mark.parametrize('target', ['dae', 'surge'])
@pytest.mark.parametrize('field', ['min_idle_session', 'idle_session_timeout', 'idle_session_check_interval'])
def test_anytls_session_fields_cannot_disappear(target, field):
    node = _node('anytls')
    setattr(node, field, 5)
    result = get_emitter(target).emit_result([node])
    assert not result.supported_nodes and any(i.field == field for i in result.errors)


@pytest.mark.parametrize('kind,target', [('hysteria2', 'dae'), ('trojan', 'surge'), ('snell', 'surge')])
def test_automatic_udp_cannot_enable_explicitly_disabled_udp(kind, target):
    node = (SnellNode(name='s', server='example.test', port=443, version=3, psk='p')
            if kind == 'snell' else _node(kind))
    node.udp = False
    result = get_emitter(target).emit_result([node])
    assert not result.supported_nodes and any(i.field == 'udp' for i in result.errors)


@pytest.mark.parametrize('kind,target', [('ss', 'v2rayn'), ('vless', 'v2rayn'), ('hysteria2', 'dae'),
                                        ('ss', 'surge'), ('snell', 'surge'), ('trusttunnel', 'surge')])
def test_enabled_smux_cannot_disappear(kind, target):
    node = (SnellNode(name='s', server='example.test', port=443, version=3, psk='p')
            if kind == 'snell' else TrustTunnelNode(name='t', server='example.test', port=443,
                                                   username='u', password='p', udp=False)
            if kind == 'trusttunnel' else _node(kind))
    node.smux.enabled = True
    result = get_emitter(target).emit_result([node])
    assert not result.supported_nodes and any(i.field == 'smux' for i in result.errors)


def test_link_ip_version_cannot_disappear():
    node = _node('hysteria2')
    node.ip_version = 'ipv6'
    result = get_emitter('dae').emit_result([node])
    assert not result.supported_nodes and any(i.field == 'ip_version' for i in result.errors)


@pytest.mark.parametrize('field,value', [('ports', '443,8443'), ('hop_interval', 10)])
def test_tuic_link_hopping_cannot_disappear(field, value):
    node = _node('tuic')
    setattr(node, field, value)
    result = get_emitter('dae').emit_result([node])
    assert not result.supported_nodes and any(i.field == field for i in result.errors)


@pytest.mark.parametrize('kind,target', [('vmess', 'v2rayn'), ('vless', 'v2rayn'), ('trojan', 'surge'), ('vmess', 'surge')])
@pytest.mark.parametrize('field,value', [('method', 'POST'), ('max_early_data', 2048),
                                       ('early_data_header_name', 'Sec-WebSocket-Protocol')])
def test_transport_handshake_fields_cannot_disappear(kind, target, field, value):
    node = _node(kind)
    node.transport.network = Network.HTTP if field == 'method' else Network.WS
    setattr(node.transport, field, value)
    result = get_emitter(target).emit_result([node])
    assert not result.supported_nodes and any(i.field == f'transport.{field}' for i in result.errors)


@pytest.mark.parametrize('kind,target,field,value', [
    ('vmess', 'v2rayn', 'packet_encoding', 'packetaddr'),
    ('vmess', 'v2rayn', 'global_padding', True),
    ('vless', 'v2rayn', 'packet_encoding', 'packetaddr'),
    ('vmess', 'surge', 'packet_encoding', 'xudp'),
    ('vmess', 'surge', 'global_padding', True),
])
def test_packet_fields_cannot_disappear(kind, target, field, value):
    node = _node(kind)
    setattr(node, field, value)
    result = get_emitter(target).emit_result([node])
    assert not result.supported_nodes and any(i.field == field for i in result.errors)
