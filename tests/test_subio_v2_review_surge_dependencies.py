import pytest

from subio_v2.adapters.surge.emitter import SurgeEmitter
from subio_v2.adapters.surge.parser import SurgeParser
from subio_v2.core.nodes import HysteriaNode


def _source(kind, name, resource, value, dialer=None):
    if kind == 'keystore':
        import base64
        encoded = base64.b64encode(value.encode()).decode()
        content = f'''[Proxy]
{name} = ssh, example.test, 22, username=user, private-key={resource}
[Keystore]
{resource} = type=openssh-private-key, base64={encoded}
'''
    else:
        content = f'''[Proxy]
{name} = tailscale, section-name={resource}
[Tailscale {resource}]
auth-key = {value}
'''
    parsed = SurgeParser(source_kind='local').parse_result(content)
    assert not parsed.issues
    node = parsed.nodes[0]
    node.dialer_proxy = dialer
    return node


@pytest.mark.parametrize('kind', ['keystore', 'section'])
def test_known_rejected_dialer_cannot_reserve_attachment(kind):
    first = _source(kind, 'first', 'shared', 'FIRST', 'bad')
    second = _source(kind, 'second', 'shared', 'SECOND')
    bad = HysteriaNode(name='bad', server='example.test', port=443, auth_str='p')
    emitter = SurgeEmitter()
    result = emitter.emit_result([first, second, bad])
    assert [n.name for n in result.supported_nodes] == ['second']
    assert any(i.node == 'first' and i.field == 'dialer_proxy' for i in result.errors)
    assert not any(i.node == 'second' for i in result.errors)
    parsed = SurgeParser(source_kind='local').parse_result('[Proxy]\n' + result.content)
    assert not parsed.issues and [n.name for n in parsed.nodes] == ['second']
    assert emitter.emit_result([second]).content == result.content


@pytest.mark.parametrize('kind', ['keystore', 'section'])
def test_attachment_conflict_dependency_loss_releases_earlier_reservation(kind):
    root = _source(kind, 'root', 'other', 'ROOT')
    first = _source(kind, 'first', 'shared', 'FIRST', 'upstream')
    second = _source(kind, 'second', 'shared', 'SECOND')
    upstream = _source(kind, 'upstream', 'other', 'CONFLICT')
    result = SurgeEmitter().emit_result([root, first, second, upstream])
    assert [n.name for n in result.supported_nodes] == ['root', 'second']
    assert {(i.node, i.code) for i in result.errors} == {
        ('first', 'conversion.missing-dialer-proxy'),
        ('upstream', 'conversion.attachment-conflict'),
    }
    again = SurgeParser(source_kind='local').parse_result('[Proxy]\n' + result.content)
    assert not again.issues and [n.name for n in again.nodes] == ['root', 'second']


def test_cascading_dependency_loss_reconsiders_conflict_losers_in_source_order():
    root = _source('keystore', 'root', 'other', 'ROOT')
    first = _source('keystore', 'first', 'shared', 'FIRST', 'upstream')
    second = _source('keystore', 'second', 'shared', 'SECOND', 'dependent')
    third = _source('keystore', 'third', 'shared', 'THIRD')
    upstream = _source('keystore', 'upstream', 'other', 'CONFLICT')
    dependent = _source('keystore', 'dependent', 'dependent-key', 'DEPENDENT', 'first')
    result = SurgeEmitter().emit_result([root, first, second, third, upstream, dependent])
    assert [n.name for n in result.supported_nodes] == ['root', 'third']
    assert not any(i.node == 'third' for i in result.errors)
    assert 'dependent-key =' not in result.content


@pytest.mark.parametrize('same_value', [False, True])
def test_surviving_attachments_keep_source_order_conflict_semantics(same_value):
    first = _source('keystore', 'first', 'shared', 'FIRST')
    second = _source('keystore', 'second', 'shared', 'FIRST' if same_value else 'SECOND')
    result = SurgeEmitter().emit_result([first, second])
    assert [n.name for n in result.supported_nodes] == (['first', 'second'] if same_value else ['first'])
    assert result.content.count('shared =') == 1
