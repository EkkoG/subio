import pytest

from subio_v2.adapters.catalog import get_emitter, get_parser
from subio_v2.adapters.surge.parser import SurgeParser
from tests.test_subio_v2_review_fidelity import _wg


def test_keystore_valid_redefinition_clears_prior_syntax_error():
    result = SurgeParser(source_kind='local').parse_result('''[Proxy]
ssh = ssh, example.test, 22, username=user, private-key=k
[Keystore]
k = invalid
k = type=openssh-private-key, base64=S0VZ
''')
    assert not result.issues and result.nodes[0].private_key == 'KEY'


@pytest.mark.parametrize('multiple', [False, True])
def test_base64_wireguard_client_id_roundtrips_and_model_can_override(multiple):
    second = ('peer = (public-key = peer-b, allowed-ips = 10.0.0.0/8, endpoint = b.test:443, client-id = U4An)'
              if multiple else '')
    original = _wg(second)
    emitted = get_emitter('surge').emit_result(original.nodes).content.replace('1/2/3', 'U4An')
    parsed = SurgeParser().parse_result('[Proxy]\n' + emitted)
    assert not parsed.issues
    node = parsed.nodes[0]
    peer = node.peers[0] if multiple else node
    assert peer.reserved == [83, 128, 39]
    peer.reserved = [4, 5, 6]
    result = get_emitter('surge').emit_result([node])
    assert not result.errors and 'client-id = 4/5/6' in result.content
    again = SurgeParser().parse_result('[Proxy]\n' + result.content)
    assert not again.issues
    assert (again.nodes[0].peers[0] if multiple else again.nodes[0]).reserved == [4, 5, 6]


def test_unknown_wireguard_peer_field_is_preserved_and_diagnosed_across_targets():
    parsed = _wg(options='')
    content = get_emitter('surge').emit_result(parsed.nodes).content.replace('public-key = peer-a', 'future-peer-option = keep, public-key = peer-a')
    parsed = SurgeParser().parse_result('[Proxy]\n' + content)
    assert not parsed.issues
    assert 'future-peer-option = keep' in get_emitter('surge').emit_result(parsed.nodes).content
    cross = get_emitter('mihomo').emit_result(parsed.nodes)
    assert any(i.code == 'conversion.unconsumed-source-field' and 'future-peer-option' in i.message for i in cross.issues)


@pytest.mark.parametrize('parameters,field,expected', [
    ('skip-cert-verify=true, skip-cert-verify=false', 'skip_cert_verify', False),
    ('sni=old.test, sni=new.test', 'server_name', 'new.test'),
])
def test_consumed_duplicate_parameters_cannot_restore_stale_tls(parameters, field, expected):
    parsed = SurgeParser().parse_result('[Proxy]\nsocks = socks5-tls, example.test, 443, ' + parameters)
    assert not parsed.issues and getattr(parsed.nodes[0].tls, field) == expected
    emitted = get_emitter('surge').emit_result(parsed.nodes)
    assert not emitted.errors
    again = SurgeParser().parse_result('[Proxy]\n' + emitted.content)
    assert not again.issues and getattr(again.nodes[0].tls, field) == expected
    assert 'skip-cert-verify=true' not in emitted.content


def test_unknown_duplicates_and_owned_fingerprints_are_preserved():
    parsed = SurgeParser().parse_result('[Proxy]\nssh = ssh, example.test, 22, username=user, password=p, '
                                       'server-fingerprint=first, server-fingerprint=second, future=one, future=two')
    assert not parsed.issues
    result = get_emitter('surge').emit_result(parsed.nodes)
    assert not result.errors
    again = SurgeParser().parse_result('[Proxy]\n' + result.content)
    assert again.nodes[0].server_fingerprints == ['first', 'second']
    assert again.nodes[0].source_extensions['surge']['parameters'] == [('future', 'one'), ('future', 'two')]


@pytest.mark.parametrize('keepalive', [0, 25, None])
@pytest.mark.parametrize('source_bound', [False, True])
def test_shared_wireguard_keepalive_applies_to_all_explicit_peers(keepalive, source_bound):
    node = _wg('peer = (public-key = peer-b, allowed-ips = 10.0.0.0/8, endpoint = b.test:443, keepalive = 25)').nodes[0]
    if not source_bound:
        node.source_extensions.clear()
    node.persistent_keepalive = keepalive
    result = get_emitter('surge').emit_result([node])
    assert not result.errors
    again = SurgeParser().parse_result('[Proxy]\n' + result.content)
    assert not again.issues and again.nodes[0].persistent_keepalive == keepalive
    assert result.content.count('keepalive =') == (0 if keepalive is None else 2)


def test_shared_override_replaces_heterogeneous_source_keepalive():
    node = _wg('peer = (public-key = peer-b, allowed-ips = 10.0.0.0/8, endpoint = b.test:443, keepalive = 60)').nodes[0]
    node.persistent_keepalive = 10
    result = get_emitter('surge').emit_result([node])
    assert not result.errors and result.content.count('keepalive = 10') == 2


def test_opaque_source_client_id_is_not_silently_removed():
    content = get_emitter('surge').emit_result(_wg().nodes).content.replace('1/2/3', 'future-id')
    parsed = SurgeParser().parse_result('[Proxy]\n' + content)
    assert not parsed.issues
    assert 'client-id = future-id' in get_emitter('surge').emit_result(parsed.nodes).content
    cross = get_emitter('mihomo').emit_result(parsed.nodes)
    assert any(i.code == 'conversion.unconsumed-source-field' and 'client-id' in i.message for i in cross.issues)
