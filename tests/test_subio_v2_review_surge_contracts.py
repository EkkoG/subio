import pytest

from subio_v2.adapters.catalog import get_emitter, get_parser
from subio_v2.adapters.surge.syntax import (
    SurgeParameter, SurgeProxyRecord, serialize_proxy_line,
)
from subio_v2.core.nodes import (
    MasqueNode, SSHNode, Socks5Node, TailscaleNode, TrustTunnelNode,
    TUICNode, WireguardNode,
)


def _emit(node):
    return get_emitter('surge').emit_result([node])


def test_tuic_inferred_v5_keeps_credentials():
    node = TUICNode(name='tuic', server='example.test', port=443,
                    uuid='synthetic', password='secret')
    emitted = _emit(node)
    assert not emitted.errors
    parsed = get_parser('surge').parse_result('[Proxy]\n' + emitted.content)
    assert not parsed.issues
    assert parsed.nodes[0].version == 5
    assert (parsed.nodes[0].uuid, parsed.nodes[0].password) == ('synthetic', 'secret')


@pytest.mark.parametrize('factory', [Socks5Node, WireguardNode])
def test_multiple_servers_are_not_silently_reduced(factory):
    node = factory(name='node', server=['a.test', 'b.test'], port=443)
    if isinstance(node, WireguardNode):
        node.private_key, node.public_key, node.interface_ip = 'private', 'public', '10.0.0.2'
    result = _emit(node)
    assert not result.supported_nodes
    assert any(i.field == 'server' for i in result.errors)


@pytest.mark.parametrize('factory,field,value', [
    (MasqueNode, 'hop_interval', 0), (MasqueNode, 'hop_interval', True),
    (TrustTunnelNode, 'max_streams', 0), (TrustTunnelNode, 'max_streams', True),
    (TailscaleNode, 'mtu', 1500), (TailscaleNode, 'mtu', 575),
])
def test_numeric_output_contract_matches_input(factory, field, value):
    node = factory(name='node', server='example.test', port=443)
    if isinstance(node, TailscaleNode):
        node.auth_key = 'synthetic'
    if isinstance(node, TrustTunnelNode):
        node.username, node.password, node.udp = 'user', 'secret', False
    setattr(node, field, value)
    result = _emit(node)
    assert not result.supported_nodes
    assert any(i.field == field for i in result.errors)


@pytest.mark.parametrize('field,value', [
    ('connect_uri', '/connect'), ('private_key', 'private'), ('public_key', 'public'),
    ('interface_ip', '10.0.0.2'), ('interface_ipv6', '::1'), ('mtu', 1280),
    ('remote_dns_resolve', True), ('dns_servers', ['1.1.1.1']),
    ('congestion_controller', 'bbr'), ('cwnd', 10), ('bbr_profile', 'standard'),
    ('handshake_timeout', 10),
])
def test_masque_cannot_drop_typed_fields(field, value):
    node = MasqueNode(name='node', server='example.test', port=443)
    setattr(node, field, value)
    result = _emit(node)
    assert not result.supported_nodes and any(i.field == field for i in result.errors)


@pytest.mark.parametrize('node,field', [
    (SSHNode(name='ssh', server='example.test', port=22, username='user',
             private_key='encrypted', private_key_passphrase='secret'), 'private_key_passphrase'),
    (WireguardNode(name='wg', server='example.test', port=443,
                   private_key='private', public_key='public', interface_ip='10.0.0.2',
                   amnezia_wg_option={'jc': 4}), 'amnezia_wg_option'),
])
def test_unrepresentable_protocol_settings_are_errors(node, field):
    result = _emit(node)
    assert not result.supported_nodes and any(i.field == field for i in result.errors)


def test_ss_alias_accepts_shadowtls():
    parsed = get_parser('surge').parse_result(
        '[Proxy]\nss = ss, example.test, 443, encrypt-method=aes-128-gcm, '
        'password=secret, shadow-tls-password=outer, shadow-tls-version=3, shadow-tls-sni=example.test'
    )
    assert not parsed.issues and len(parsed.nodes) == 1
    assert not _emit(parsed.nodes[0]).errors


@pytest.mark.parametrize('separator', ['\n', '\r', '\v', '\f', '\x1c', '\x1d', '\x1e', '\x85', '\u2028', '\u2029'])
@pytest.mark.parametrize('part', ['name', 'type', 'positional', 'key', 'value'])
def test_proxy_serializer_rejects_every_document_line_separator(separator, part):
    value = 'a' + separator + 'b'
    record = SurgeProxyRecord(
        name=value if part == 'name' else 'node',
        type=value if part == 'type' else 'socks5',
        positional=(value if part == 'positional' else 'example.test', '443'),
        parameters=(SurgeParameter(value if part == 'key' else 'password',
                                   value if part == 'value' else 'secret'),),
    )
    with pytest.raises(ValueError):
        serialize_proxy_line(record)


@pytest.mark.parametrize('factory,fields', [
    (MasqueNode, {'hop_interval': 1}),
    (TrustTunnelNode, {'max_streams': 1, 'username': 'user', 'password': 'secret', 'udp': False}),
    (TailscaleNode, {'mtu': 1420, 'auth_key': 'synthetic'}),
    (Socks5Node, {'server': ['example.test']}),
])
def test_valid_neighbors_roundtrip(factory, fields):
    node = factory(name='node', port=443, **({'server': 'example.test'} | fields))
    result = _emit(node)
    assert not result.errors and result.supported_nodes
    parsed = get_parser('surge').parse_result('[Proxy]\n' + result.content)
    assert not parsed.issues and parsed.nodes
