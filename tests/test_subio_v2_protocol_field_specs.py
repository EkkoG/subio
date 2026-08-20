from dataclasses import dataclass, fields

import pytest

import subio_v2.protocols as registry
from subio_v2.adapters.clash_family.emitter import ClashEmitter
from subio_v2.core.nodes import BaseNode, Protocol, ShadowsocksNode
from subio_v2.adapters.clash_family.parser import ClashParser
from subio_v2.protocols._base import StructuredClashProtocolCodec
from subio_v2.protocols._fields import EmitPolicy, scalar_field


@dataclass
class SpecNode(BaseNode):
    canonical: str = ""
    always: str = ""
    truthy: str | None = None
    not_none: int | None = None


class SpecCodec(StructuredClashProtocolCodec):
    protocol = Protocol.HTTP
    clash_type = "spec"
    node_class = SpecNode
    fields = (
        scalar_field("canonical", aliases=("legacy",), emit_policy=EmitPolicy.ALWAYS),
        scalar_field("always", emit_policy=EmitPolicy.ALWAYS),
        scalar_field("truthy", emit_policy=EmitPolicy.TRUTHY),
        scalar_field("not-none", "not_none", emit_policy=EmitPolicy.NOT_NONE),
    )


def test_field_spec_derives_alias_handling_extra_and_emit_policies():
    codec = SpecCodec()
    node = codec.parse_clash(
        {
            "name": "spec",
            "type": "spec",
            "server": "example.com",
            "port": 443,
            "legacy": "from-alias",
            "always": "",
            "truthy": "",
            "not-none": 0,
            "future-field": False,
        }
    )

    assert node.canonical == "from-alias"
    assert node.extra == {"future-field": False}

    emitted = codec.emit_clash(node)
    assert emitted["canonical"] == "from-alias"
    assert "legacy" not in emitted
    assert emitted["always"] == ""
    assert "truthy" not in emitted
    assert emitted["not-none"] == 0
    assert emitted["future-field"] is False


def test_migrated_codecs_roundtrip_fields_and_unknown_extensions():
    nodes = ClashParser().parse_result(
        """
proxies:
  - name: http-fields
    type: http
    server: example.com
    port: 443
    username: user
    password: pass
    headers: {User-Agent: UA}
    tls: true
    sni: tls.example.com
    future-field: false
  - name: socks-fields
    type: socks5
    server: example.com
    port: 1080
    tls: true
    sni: socks.example.com
  - name: ssh-fields
    type: ssh
    server: example.com
    port: 22
    username: root
    private-key: key
    private-key-passphrase: passphrase
    host-key: [host-key]
    host-key-algorithms: [ssh-ed25519]
"""
    ).nodes

    emitted = {proxy["name"]: proxy for proxy in ClashEmitter().emit_result(nodes).content["proxies"]}
    assert emitted["http-fields"]["headers"] == {"User-Agent": "UA"}
    assert emitted["http-fields"]["sni"] == "tls.example.com"
    assert emitted["http-fields"]["future-field"] is False
    assert emitted["socks-fields"]["sni"] == "socks.example.com"
    assert emitted["ssh-fields"]["private-key-passphrase"] == "passphrase"
    assert emitted["ssh-fields"]["host-key"] == ["host-key"]
    assert emitted["ssh-fields"]["host-key-algorithms"] == ["ssh-ed25519"]


def test_structured_codec_specs_reference_real_unique_node_fields():
    for codec in registry.all():
        if not isinstance(codec, StructuredClashProtocolCodec):
            continue
        node_fields = {item.name for item in fields(codec.node_class)}
        consumed: set[str] = set()
        for field_spec in codec.fields:
            assert field_spec.node_attrs <= node_fields
            assert field_spec.required_attrs <= field_spec.node_attrs
            assert not consumed.intersection(field_spec.consumed_keys)
            consumed.update(field_spec.consumed_keys)
        assert codec.consumed_keys == frozenset(consumed)


def test_stash_codecs_own_their_output_field_contracts():
    stash_codecs = [
        codec for codec in registry.all() if codec.supports_dialect("stash")
    ]

    assert len(stash_codecs) == 20
    assert all(codec.fields_for_dialect("stash") for codec in stash_codecs)
    assert all(
        not codec.fields_for_dialect("stash")
        for codec in registry.all()
        if not codec.supports_dialect("stash")
    )


def test_structured_codec_rejects_wrong_node_type():
    node = ShadowsocksNode(
        name="ss",
        type=Protocol.SHADOWSOCKS,
        server="example.com",
        port=443,
    )
    with pytest.raises(TypeError, match="Expected SpecNode"):
        SpecCodec().emit_clash(node)
