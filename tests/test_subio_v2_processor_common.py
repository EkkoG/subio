from subio_v2.processor.common import FilterProcessor, RenameProcessor
from subio_v2.model.nodes import ShadowsocksNode, Protocol


def make_node(name, users=None):
    return ShadowsocksNode(name=name, type=Protocol.SHADOWSOCKS, server="s", port=1, password="p", users=users)


def test_filter_processor_include_exclude_and_original_name(monkeypatch):
    # Prepare nodes with and without original_name
    n1 = make_node("香港-A")
    n2 = make_node("普通-香港")
    n3 = make_node("JP-1")
    # Simulate rename set original_name
    rp = RenameProcessor(prefix="PRE-", replace=[{"old": "普通-", "new": ""}])
    rp.process([n1, n2, n3])
    # Now filter: include HK, exclude PRE prefix shouldn't affect matching; uses original_name
    fp = FilterProcessor(include=r"香港|HK", exclude=r"普通")
    out = fp.process([n1, n2, n3])
    # n2 original_name contains 普通-香港, should be excluded; n1 included; n3 excluded
    names = sorted([n.name for n in out])
    assert names == ["PRE-香港-A"]


def test_rename_processor_prefix_suffix_and_replace():
    n = make_node("node-123")
    rp = RenameProcessor(prefix="[P] ", suffix=" [S]", replace=[{"old": "123", "new": "X"}])
    out = rp.process([n])
    assert out[0].name == "[P] node-X [S]"
    assert out[0].original_name == "node-123"
