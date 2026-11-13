import pytest

from subio_v2.adapters.catalog import get_emitter, get_parser
from subio_v2.core.dialect import DialectContext
from subio_v2.core.nodes import MasqueMode, MasqueNode, SSHNode, SnellNode


def _parse(kind, **fields):
    result = get_parser('mihomo').parse_result({'proxies': [{
        'type': kind, 'name': 'node', 'server': 'example.test', 'port': 443,
        **fields,
    }]})
    assert not result.issues
    return result.nodes[0]


@pytest.mark.parametrize('target', ['mihomo', 'stash'])
def test_ssh_timeout_cannot_be_silently_lost(target):
    node = SSHNode(name='ssh', server='example.test', port=22,
                   username='u', password='p', idle_timeout=60)
    result = get_emitter(target).emit_result([node])
    assert not result.supported_nodes
    assert any(i.field == 'idle_timeout' for i in result.errors)


@pytest.mark.parametrize('version,accepted', [(None, False), (1, False), (3, True), (4, True)])
def test_stash_checks_effective_snell_version(version, accepted):
    node = SnellNode(name='snell', server='example.test', port=443, psk='p', version=version)
    result = get_emitter('stash').emit_result([node])
    assert bool(result.supported_nodes) is accepted


def test_h3_l4proxy_requires_h3():
    node = MasqueNode(name='masque', server='example.test', port=443,
                      private_key='private', public_key='public', udp=False,
                      mode=MasqueMode.H3_L4_PROXY, transport='h2')
    result = get_emitter('mihomo').emit_result([node])
    assert not result.supported_nodes
    assert any(i.field == 'transport' for i in result.errors)


@pytest.mark.parametrize('kind,fields', [
    ('hysteria2', {'password': 'p'}),
    ('trusttunnel', {'username': 'u', 'password': 'p'}),
])
def test_mihomo_supported_smux_roundtrip(kind, fields):
    node = _parse(kind, smux={'enabled': True, 'max-connections': 7}, **fields)
    result = get_emitter('mihomo').emit_result([node])
    assert not result.errors
    assert result.content['proxies'][0]['smux']['max-connections'] == 7
    again = get_parser('mihomo').parse_result(result.content)
    assert not again.issues and again.nodes[0].smux.enabled


@pytest.mark.parametrize('enabled', [False, True])
def test_smux_unknown_fields_are_source_bound(enabled):
    node = _parse('ss', cipher='aes-128-gcm', password='p',
                  smux={'enabled': enabled, 'max-connections': 9, 'future-option': 1})
    node.smux.max_connections = 3
    result = get_emitter('mihomo').emit_result([node])
    assert not result.errors
    payload = result.content['proxies'][0]['smux']
    assert payload['future-option'] == 1 and payload['enabled'] is enabled
    assert payload['max-connections'] == 3
    cross = get_emitter('sing-box').emit_result([node])
    assert any(i.code == 'conversion.unconsumed-source-field' for i in cross.issues)
    assert 'future-option' not in str(cross.content)


@pytest.mark.parametrize('kind,fields', [
    ('vmess', {'uuid': 'synthetic'}), ('vless', {'uuid': 'synthetic'}),
    ('trojan', {'password': 'p'}),
])
def test_future_transport_only_replays_in_source_dialect(kind, fields):
    node = _parse(kind, network='future', **fields)
    assert get_emitter('mihomo').emit_result([node]).supported_nodes
    for source in [None, DialectContext('v2rayn', 'text'), DialectContext('stash', 'yaml')]:
        node.source_context = source
        result = get_emitter('mihomo').emit_result([node])
        assert not result.supported_nodes
        assert any(i.field == 'transport.network' for i in result.errors)


@pytest.mark.parametrize('field,value', [('ports', '443,8443'), ('hop-interval', 30)])
def test_masque_hopping_is_parsed_and_explicitly_checked(field, value):
    node = _parse('masque', **{'private-key': 'private', 'public-key': 'public',
                              'ip': '10.0.0.2', field: value})
    assert getattr(node, field.replace('-', '_')) == value
    for target in ['mihomo', 'stash']:
        result = get_emitter(target).emit_result([node])
        assert not result.supported_nodes
        assert any(i.field == field.replace('-', '_') for i in result.errors)


@pytest.mark.parametrize('cipher,accepted', [
    ('aes-256-cfb', True), ('rc4-md5', True),
    ('2022-blake3-aes-128-gcm', False), ('aes-128-gcm', False),
])
def test_stash_ssr_has_its_own_cipher_set(cipher, accepted):
    node = _parse('ssr', cipher=cipher, password='p', obfs='plain', protocol='origin')
    result = get_emitter('stash').emit_result([node])
    assert bool(result.supported_nodes) is accepted


@pytest.mark.parametrize('obfs,accepted', [('salamander', True), ('gecko', True), ('xor', False)])
def test_mihomo_hysteria2_obfs_enum(obfs, accepted):
    node = _parse('hysteria2', password='p', obfs=obfs, **{'obfs-password': 'p'})
    result = get_emitter('mihomo').emit_result([node])
    assert bool(result.supported_nodes) is accepted


def test_snell_unknown_obfs_fields_are_source_bound_and_model_wins():
    node = _parse('snell', psk='p', version=4,
                  **{'obfs-opts': {'mode': 'http', 'host': 'old.test', 'future-option': True}})
    node.obfs, node.obfs_host = 'tls', 'edited.test'
    result = get_emitter('mihomo').emit_result([node])
    assert not result.errors
    assert result.content['proxies'][0]['obfs-opts'] == {
        'mode': 'tls', 'host': 'edited.test', 'future-option': True,
    }
    cross = get_emitter('stash').emit_result([node])
    assert any(i.code == 'conversion.unconsumed-source-field' for i in cross.issues)
    assert 'future-option' not in str(cross.content)


@pytest.mark.parametrize('peer', [False, True])
@pytest.mark.parametrize('allowed', ['10.0.0.0/8', {}, 1, False])
def test_wireguard_invalid_allowed_ips_is_local_parse_error(peer, allowed):
    wireguard = {'name': 'bad', 'type': 'wireguard', 'server': 'example.test',
                 'port': 443, 'private-key': 'p', 'public-key': 'q', 'ip': '10.0.0.2'}
    if peer:
        wireguard['peers'] = [{'server': 'example.test', 'port': 443,
                              'public-key': 'q', 'allowed-ips': allowed}]
    else:
        wireguard['allowed-ips'] = allowed
    sibling = {'name': 'good', 'type': 'ss', 'server': 'example.test', 'port': 443,
               'cipher': 'aes-128-gcm', 'password': 'p'}
    result = get_parser('mihomo').parse_result({'proxies': [wireguard, sibling]})
    assert [n.name for n in result.nodes] == ['good']
    assert result.issues and result.issues[0].severity.value == 'error'
