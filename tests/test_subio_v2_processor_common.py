from subio_v2.core.nodes import Protocol, ShadowsocksNode
from subio_v2.workflow.config import FilterConfig, RenameConfig, RenameRule
from subio_v2.workflow.transforms import filter_nodes, rename_nodes


def make_node(name, users=None):
    return ShadowsocksNode(
        name=name,
        type=Protocol.SHADOWSOCKS,
        server="s",
        port=1,
        password="p",
        users=users,
    )


def test_filter_processor_include_exclude_and_original_name(monkeypatch):
    # Prepare nodes with and without original_name
    n1 = make_node("香港-A")
    n2 = make_node("普通-香港")
    n3 = make_node("JP-1")
    # Simulate rename set original_name
    rename_nodes(
        [n1, n2, n3],
        RenameConfig(add_prefix="PRE-", replace=(RenameRule("普通-", ""),)),
    )
    # Now filter: include HK, exclude PRE prefix shouldn't affect matching; uses original_name
    out = filter_nodes(
        [n1, n2, n3], FilterConfig(include=r"香港|HK", exclude=r"普通")
    )
    # n2 original_name contains 普通-香港, should be excluded; n1 included; n3 excluded
    names = sorted([n.name for n in out])
    assert names == ["PRE-香港-A"]


def test_rename_processor_prefix_suffix_and_replace():
    n = make_node("node-123")
    out = rename_nodes(
        [n],
        RenameConfig(
            add_prefix="[P] ",
            suffix=" [S]",
            replace=(RenameRule("123", "X"),),
        ),
    )
    assert out[0].name == "[P] node-X [S]"
    assert out[0].original_name == "node-123"


def test_rename_processor_updates_dialer_proxy_references():
    base = make_node("base")
    chained = make_node("chained")
    chained.dialer_proxy = "base"

    rename_nodes([base, chained], RenameConfig(add_prefix="P-"))

    assert base.name == "P-base"
    assert chained.dialer_proxy == "P-base"
