from subio_v2.model.nodes import ShadowsocksNode, Protocol, get_nodes_for_user, clone_node_for_user


def make_node(name, users=None):
    return ShadowsocksNode(name=name, type=Protocol.SHADOWSOCKS, server="s", port=1, password="p", users=users)


def test_clone_node_for_user_applies_overrides_and_clears_users():
    n = make_node("A", users={"alice": {"password": "pa", "server": "sa"}})
    cloned = clone_node_for_user(n, "alice")
    assert cloned is not None
    assert cloned.password == "pa"
    assert cloned.server == "sa"
    assert cloned.users is None


def test_get_nodes_for_user_mixes_shared_and_user_specific():
    shared = make_node("S")
    multi = make_node("M", users={"bob": {"password": "pb"}})
    out = get_nodes_for_user([shared, multi], "bob")
    # shared included, multi cloned
    names = [n.name for n in out]
    assert names == ["S", "M"]
    # cloned carries override
    assert out[1].password == "pb"
