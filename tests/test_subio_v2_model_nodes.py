from dataclasses import fields

import pytest

from subio_v2.model.nodes import (
    BaseNode,
    Node,
    Protocol,
    ShadowsocksNode,
    SourcePassthroughNode,
    SSHNode,
)
from subio_v2.model.records import NodeRecord
from subio_v2.protocols.user_overrides import (
    clone_node_for_user,
    get_nodes_for_user,
)


def make_node(name, users=None):
    return ShadowsocksNode(
        name=name,
        type=Protocol.SHADOWSOCKS,
        server="s",
        port=1,
        password="p",
        users=users,
    )


def test_general_node_annotation_has_no_concrete_protocol_list():
    assert Node is BaseNode


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


def test_clone_node_for_user_rejects_structural_overrides():
    node = make_node("A", users={"alice": {"type": "vmess"}})

    with pytest.raises(ValueError, match="cannot override"):
        clone_node_for_user(node, "alice")

    assert node.type == Protocol.SHADOWSOCKS


def test_clone_node_for_user_normalizes_hyphenated_credentials():
    node = SSHNode(
        name="ssh",
        type=Protocol.SSH,
        server="example.com",
        port=22,
        username="default",
        users={"alice": {"private-key": "secret", "username": "alice"}},
    )

    cloned = clone_node_for_user(node, "alice")
    assert cloned is not None
    assert cloned.private_key == "secret"
    assert cloned.username == "alice"


def test_source_passthrough_user_override_keeps_common_endpoint_behavior():
    node = SourcePassthroughNode(
        name="opaque",
        record=NodeRecord(opaque_type="future", opaque_raw={}),
        server="old.example",
        port=443,
        users={"alice": {"server": "new.example", "port": 8443}},
    )

    cloned = clone_node_for_user(node, "alice")

    assert cloned is not None
    assert cloned.server == "new.example"
    assert cloned.port == 8443


def test_lifecycle_metadata_is_owned_by_node_record_and_hidden_from_repr():
    semantic_fields = {item.name for item in fields(BaseNode)}
    assert "record" in semantic_fields
    assert {
        "original_name",
        "extra",
        "source_extensions",
        "source_provider",
        "source_context",
    }.isdisjoint(semantic_fields)

    node = make_node("record")
    node.record = NodeRecord(
        original_name="before",
        source_provider="provider",
        source_extensions={"surge": {"private-key": "secret"}},
    )

    assert node.original_name == "before"
    assert node.source_provider == "provider"
    assert "secret" not in repr(node)


def test_opaque_payload_is_owned_by_node_record_and_hidden_from_repr():
    semantic_fields = {item.name for item in fields(SourcePassthroughNode)}
    assert {"original_type", "raw"}.isdisjoint(semantic_fields)

    node = SourcePassthroughNode(
        name="opaque",
        record=NodeRecord(
            opaque_type="future",
            opaque_raw={"private-key": "secret"},
        ),
    )

    assert node.original_type == "future"
    assert node.raw == {"private-key": "secret"}
    assert "secret" not in repr(node)
