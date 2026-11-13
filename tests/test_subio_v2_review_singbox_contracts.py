import pytest

from subio_v2.adapters.catalog import get_emitter, get_parser
from subio_v2.core.nodes import HysteriaNode, Socks5Node
from tests.test_subio_v2_link_nested_values import _node
from tests.test_subio_v2_singbox_endpoint import _wireguard


def _outbound(kind, **fields):
    return {'type': kind, 'tag': 'node', 'server': 'example.test', 'server_port': 443, **fields}


def test_anytls_uses_udp_capable_default():
    node = _node('anytls')
    emitted = get_emitter('sing-box').emit_result([node])
    assert not emitted.errors and emitted.supported_nodes
    again = get_parser('sing-box').parse_result(emitted.content)
    assert not again.issues and again.nodes[0].udp is True


@pytest.mark.parametrize('fields', [{'up': '100 Mbps', 'down': '640 KBps'},
                                   {'up_mbps': 100, 'down_mbps': 200}])
def test_hysteria_bandwidth_parse_emit_roundtrip(fields):
    result = get_parser('sing-box').parse_result({'outbounds': [_outbound('hysteria', auth_str='p', **fields)]})
    assert not result.issues
    emitted = get_emitter('sing-box').emit_result(result.nodes)
    assert not emitted.errors
    payload = emitted.content['outbounds'][0]
    assert all(payload[key] == value for key, value in fields.items())
    again = get_parser('sing-box').parse_result(emitted.content)
    assert not again.issues and again.nodes == result.nodes


@pytest.mark.parametrize('fields', [{}, {'up': '1 Mbps'}, {'up_speed': 100, 'down_speed': 0},
                                   {'up': 'not-bandwidth', 'down': '1 Mbps'}])
def test_hysteria_missing_or_bad_bandwidth_is_rejected(fields):
    node = HysteriaNode(name='hy', server='example.test', port=443, auth_str='p', **fields)
    result = get_emitter('sing-box').emit_result([node])
    assert not result.supported_nodes
    assert any(i.field in {'up', 'down', 'up_speed', 'down_speed'} for i in result.errors)


@pytest.mark.parametrize('fields', [{}, {'up': '100 Mbps'},
                                   {'up_mbps': True, 'down_mbps': 100},
                                   {'up': '1 mbps', 'down': '100 Mbps'}])
def test_hysteria_parser_rejects_bad_bandwidth(fields):
    parsed = get_parser('sing-box').parse_result({'outbounds': [_outbound('hysteria', **fields)]})
    assert not parsed.nodes and parsed.issues


@pytest.mark.parametrize('field,value', [('interface_name', 123), ('dialer_proxy', []),
                                       ('tfo', 1), ('mptcp', 'true'), ('udp', 1)])
def test_outbound_common_types_match_parser(field, value):
    node = Socks5Node(name='socks', server='example.test', port=1080)
    setattr(node, field, value)
    result = get_emitter('sing-box').emit_result([node])
    assert not result.supported_nodes and any(i.field == field for i in result.errors)


def test_vless_explicit_empty_packet_encoding_roundtrip():
    result = get_parser('sing-box').parse_result({'outbounds': [_outbound('vless', uuid='synthetic', packet_encoding='')]})
    assert not result.issues
    emitted = get_emitter('sing-box').emit_result(result.nodes)
    assert not emitted.errors and emitted.content['outbounds'][0]['packet_encoding'] == ''


@pytest.mark.parametrize('target', ['sing-box', 'v2rayn', 'dae'])
@pytest.mark.parametrize('enabled,network', [(False, 'tcp'), (True, 'ws')])
def test_vless_vision_requires_tls_tcp(target, enabled, network):
    node = _node('vless')
    node.flow, node.tls.enabled, node.transport.network = 'xtls-rprx-vision', enabled, network
    result = get_emitter(target).emit_result([node])
    assert not result.supported_nodes and any(i.field == 'flow' for i in result.errors)


@pytest.mark.parametrize('target', ['v2rayn', 'dae'])
def test_links_require_reality_public_key(target):
    node = _node('vless')
    node.tls.reality_opts = {'short-id': 'abcd'}
    result = get_emitter(target).emit_result([node])
    assert not result.supported_nodes and any(i.field == 'tls.reality_opts.public-key' for i in result.errors)


def test_singbox_only_supports_its_vless_flow():
    node = _node('vless')
    node.flow = 'xtls-rprx-vision-udp443'
    result = get_emitter('sing-box').emit_result([node])
    assert not result.supported_nodes and any(i.field == 'flow' for i in result.errors)


@pytest.mark.parametrize('field,value', [('allowed_ips', ['not-a-prefix']),
                                       ('allowed_ips', ['10.0.0.1']),
                                       ('reserved', [1, 2]), ('reserved', [1, 2, 3, 4])])
def test_wireguard_bad_prefix_and_reserved_rejected_at_both_boundaries(field, value):
    raw = _wireguard()
    key = field
    original = raw['peers'][0].get(key)
    raw['peers'][0][key] = value
    parsed = get_parser('sing-box').parse_result({'endpoints': [raw]})
    assert not parsed.nodes and any(i.field.endswith(field) for i in parsed.issues)
    raw['peers'][0][key] = original
    valid = get_parser('sing-box').parse_result({'endpoints': [raw]})
    assert not valid.issues
    setattr(valid.nodes[0].peers[0], field, value)
    emitted = get_emitter('sing-box').emit_result(valid.nodes)
    assert not emitted.supported_nodes and any(i.field == f'peers[0].{field}' for i in emitted.errors)
