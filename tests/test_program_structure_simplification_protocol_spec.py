from __future__ import annotations

from dataclasses import fields
from pathlib import Path

import subio_v2.protocols as registry
from subio_v2.core.nodes import Protocol, ShadowsocksNode, VlessNode, VmessNode
from subio_v2.protocols.shadowsocks import SPEC as SHADOWSOCKS_SPEC
from subio_v2.protocols.vless import SPEC as VLESS_SPEC
from subio_v2.protocols.vmess import SPEC as VMESS_SPEC


def test_representative_protocol_specs_are_local_and_authoritative():
    expected = {
        Protocol.SHADOWSOCKS: (SHADOWSOCKS_SPEC, ShadowsocksNode),
        Protocol.VLESS: (VLESS_SPEC, VlessNode),
        Protocol.VMESS: (VMESS_SPEC, VmessNode),
    }
    for protocol, (spec, node_class) in expected.items():
        codec = registry.get(protocol)
        assert codec is not None
        assert codec.spec is spec
        assert registry.get_definition(protocol) is spec
        assert spec.node_class is node_class
        assert spec.terminal_native_fields
        assert spec.terminal_native_user_override_fields <= {
            field.name for field in fields(spec.node_class)
        }


def test_all_protocol_codecs_have_local_specs():
    codecs = tuple(registry.all())
    assert len(codecs) == 27
    assert all(codec.spec is not None for codec in codecs)
    assert len(registry.all_definitions()) == 27


def test_concrete_nodes_have_protocol_defaults_without_type_argument():
    assert ShadowsocksNode(name="ss").type is Protocol.SHADOWSOCKS
    assert VlessNode(name="vless").type is Protocol.VLESS
    assert VmessNode(name="vmess").type is Protocol.VMESS
    source = (Path(__file__).parents[1] / "src/subio_v2/core/nodes.py").read_text()
    assert "self.type != Protocol." not in source


def test_protocols_are_removed_from_central_definition_tables():
    definitions = (Path(__file__).parents[1] / "src/subio_v2/protocols/definitions.py").read_text()
    assert "Protocol." not in definitions


def test_native_and_override_consumers_use_protocol_registry_for_specs():
    root = Path(__file__).parents[1] / "src/subio_v2"
    overrides = (root / "protocols/user_overrides.py").read_text()
    schema = (root / "adapters/subio/schema.py").read_text()
    assert "protocol_registry.get_definition" in overrides
    assert "protocol_registry.get_definition" in schema
    assert "from subio_v2.protocols.definitions import get_definition" not in overrides


def test_stash_protocol_specific_transforms_live_on_protocol_codecs():
    stash = (
        Path(__file__).parents[1] / "src/subio_v2/adapters/clash_family/stash.py"
    ).read_text()
    assert "\n_INPUT_ALIASES =" not in stash
    for protocol in ("TUIC", "MIERU", "HYSTERIA", "HYSTERIA2", "SHADOWSOCKS"):
        assert f"node.type == Protocol.{protocol}" not in stash


def test_native_contract_uses_v2_wording_without_legacy_decoder_paths():
    root = Path(__file__).parents[1]
    codec = (root / "src/subio_v2/adapters/subio/codec.py").read_text()
    schema = (root / "src/subio_v2/adapters/subio/schema.py").read_text()
    docs = (root / "docs/subio_node_format.md").read_text()
    assert "SubIO v1" not in codec
    assert "node v1 schema" not in schema
    assert "version = 2" in docs
