import pytest

from subio_v2.adapters.catalog import get_emitter, get_parser
from subio_v2.adapters.surge.parser import SurgeParser


def test_inactive_transport_cannot_override_active_fields():
    parsed = get_parser('mihomo').parse_result({'proxies': [{
        'name': 'vm', 'type': 'vmess', 'server': 'example.test', 'port': 443,
        'uuid': 'synthetic', 'network': 'http',
        'ws-opts': {'path': '/stale', 'headers': {'Host': 'stale.test'}},
        'http-opts': {'path': ['/live'], 'headers': {'Host': ['live.test']}},
    }]})
    assert not parsed.issues
    result = get_emitter('mihomo').emit_result(parsed.nodes)
    proxy = result.content['proxies'][0]
    assert proxy['http-opts'] == {'path': ['/live'], 'headers': {'Host': ['live.test']}}
    assert proxy['ws-opts']['path'] == '/stale'


@pytest.mark.parametrize('value', [None, '', [], 1])
def test_missing_or_invalid_proxy_type_has_local_error(value):
    result = get_parser('mihomo').parse_result({'proxies': [{'name': 'bad', 'type': value}]})
    assert not result.nodes
    assert result.issues[0].field == 'proxies[0]'
    assert result.issues[0].severity.value == 'error'


def _wg(second=''):
    return SurgeParser().parse_result('''[Proxy]
wg = wireguard, section-name=office
[WireGuard office]
private-key = synthetic
self-ip = 10.0.0.2
peer = (public-key = peer-a, allowed-ips = 0.0.0.0/0, endpoint = a.test:443, client-id = 1/2/3, keepalive = 25)
''' + second)


def test_surge_different_keepalives_survive_or_are_rejected():
    parsed = _wg('peer = (public-key = peer-b, allowed-ips = 10.0.0.0/8, endpoint = b.test:443, keepalive = 60)')
    assert not parsed.issues
    assert parsed.nodes[0].persistent_keepalive is None
    result = get_emitter('surge').emit_result(parsed.nodes)
    assert not result.errors
    assert 'keepalive = 25' in result.content and 'keepalive = 60' in result.content
    result = get_emitter('mihomo').emit_result(parsed.nodes)
    assert not result.supported_nodes
    assert any(i.field == 'persistent_keepalive' for i in result.errors)


def test_cleared_wireguard_values_do_not_return_from_attachment():
    parsed = _wg()
    node = parsed.nodes[0]
    node.reserved = node.persistent_keepalive = None
    result = get_emitter('surge').emit_result([node])
    assert not result.errors
    assert 'client-id' not in result.content and 'keepalive' not in result.content
    again = SurgeParser().parse_result('[Proxy]\n' + result.content).nodes[0]
    assert again.reserved is None and again.persistent_keepalive is None


def test_stash_none_selector_cannot_enable_automatic_fallback():
    parsed = get_parser('stash').parse_result({'proxies': [{'name': 'ts', 'type': 'tailscale', 'auth-key': 'synthetic', 'exit-node': 'none'}]})
    assert not parsed.issues
    result = get_emitter('stash').emit_result(parsed.nodes)
    assert not result.supported_nodes
    assert any(i.field == 'exit_node' for i in result.errors)


@pytest.mark.parametrize('protocol,fields,block', [
    ('sudoku', {'key': 'synthetic', 'httpmask': {'mode': 'stream', 'future-option': True}}, 'httpmask'),
    ('wireguard', {'private-key': 'synthetic', 'ip': '10.0.0.2', 'peers': [{
        'server': 'peer.test', 'port': 443, 'public-key': 'public',
        'allowed-ips': ['0.0.0.0/0'], 'future-option': True,
    }]}, 'peers'),
])
def test_nested_unknown_fields_are_source_bound_and_typed_values_win(protocol, fields, block):
    parsed = get_parser('mihomo').parse_result({'proxies': [{
        'name': 'node', 'type': protocol, 'server': 'example.test', 'port': 443, **fields,
    }]})
    assert not parsed.issues
    node = parsed.nodes[0]
    if block == 'httpmask':
        node.httpmask.mode = 'poll'
    else:
        node.peers[0].server = 'edited.test'
    result = get_emitter('mihomo').emit_result([node])
    assert not result.errors
    payload = result.content['proxies'][0][block]
    payload = payload[0] if isinstance(payload, list) else payload
    assert payload['future-option'] is True
    assert payload['mode' if block == 'httpmask' else 'server'] == ('poll' if block == 'httpmask' else 'edited.test')
    cross = get_emitter('sing-box').emit_result([node])
    assert any(i.code in {'conversion.unconsumed-source-field', 'conversion'} for i in cross.issues)
