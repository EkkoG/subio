from dataclasses import replace

import pytest

from subio_v2.adapters.catalog import get_emitter, get_target
from subio_v2.adapters.clash_family.codecs.vless import VlessCodec
from subio_v2.adapters.target import TargetValidationService
from subio_v2.core.nodes import Protocol, TLSSettings, TransportSettings, VlessNode
from tests.test_subio_v2_capability_invariants import _base_node_factories


def vless(**kwargs):
    return VlessNode(
        name="node", server="example.test", port=443, uuid="synthetic", **kwargs
    )


@pytest.mark.parametrize("target", ["mihomo", "surge", "dae", "v2rayn"])
def test_registered_vless_contract_is_the_actual_emitter_path(target, monkeypatch):
    emitter = get_emitter(target)
    codec = emitter._conversion.target.codecs[Protocol.VLESS]
    calls = []
    original = codec.encode

    def encode(node, context):
        calls.append(node)
        return original(node, context)

    emitter._conversion.target.codecs[Protocol.VLESS] = replace(codec, encode=encode)
    node = vless()
    result = emitter.emit_result([node])
    assert not result.errors and result.supported_nodes == [node]
    assert calls == [node]


@pytest.mark.parametrize("target", ["surge", "dae", "v2rayn"])
def test_vless_foreign_targets_do_not_borrow_clash_validation(target, monkeypatch):
    monkeypatch.setattr(
        VlessCodec, "check", lambda *_: pytest.fail("Clash target checker called")
    )
    result = get_emitter(target).emit_result([vless()])
    assert not result.errors and len(result.supported_nodes) == 1


def test_checked_contract_cannot_be_replaced_by_an_encoder_or_permissive_check():
    service = TargetValidationService("mihomo")
    with pytest.raises(TypeError):
        service.encode_node(vless(), lambda _: "unvalidated payload")
    result = service.encode_node(vless())
    assert result.content[0]["type"] == "vless"
    rejected = service.encode_node(vless(tls=TLSSettings(sni_disabled=True)))
    assert rejected.supported_node is None
    assert any(issue.field == "tls.sni_disabled" for issue in rejected.issues)


@pytest.mark.parametrize("target", ["mihomo", "surge", "dae", "v2rayn"])
def test_target_factories_are_fresh_and_retain_contract_provenance(target):
    first, second = get_target(target), get_target(target)
    assert first is not second and first.codecs is not second.codecs
    assert first.context.dialect == target
    assert first.reference


@pytest.mark.parametrize("target", ["dae", "v2rayn"])
@pytest.mark.parametrize(
    "field", ["certificate_sha256", "verify_name", "private_key", "sni_disabled"]
)
def test_vless_link_contract_rejects_identity_loss(target, field):
    node = vless(tls=TLSSettings(enabled=True))
    setattr(node.tls, field, True if field == "sni_disabled" else "synthetic")
    result = get_emitter(target).emit_result([node])
    assert not result.supported_nodes
    assert any(issue.field == f"tls.{field}" for issue in result.errors)


@pytest.mark.parametrize("target", ["mihomo", "surge", "dae", "v2rayn"])
def test_vless_contract_rejects_grpc_fields_on_other_transports(target):
    result = get_emitter(target).emit_result(
        [
            vless(transport=TransportSettings(grpc_authority="authority.test")),
        ]
    )
    assert not result.supported_nodes
    assert any(issue.field == "transport.grpc_authority" for issue in result.errors)


@pytest.mark.parametrize("target", ["surge", "dae", "v2rayn"])
def test_foreign_protocol_bindings_do_not_call_clash_checkers(target, monkeypatch):
    import subio_v2.adapters.clash_family.codecs as clash_registry

    for codec in clash_registry.all():
        monkeypatch.setattr(
            codec, "check", lambda *_: pytest.fail("Clash checker called")
        )
    emitter = get_emitter(target)
    for protocol, factory in _base_node_factories().items():
        if protocol not in emitter._conversion.target.codecs:
            continue
        node = factory()
        result = emitter.emit_result([node])
        assert result.supported_nodes == [node], (target, protocol, result.issues)


@pytest.mark.parametrize(
    "target", ["mihomo", "clash", "stash", "surge", "dae", "v2rayn", "sing-box"]
)
def test_all_emitters_use_the_selected_binding_for_check_and_encode(target):
    from subio_v2.core.results import IssueDraft, IssueSeverity

    emitter = get_emitter(target)
    node = _base_node_factories()[Protocol.SHADOWSOCKS]()
    node.source_provider = "provider"
    codec = emitter._conversion.target.codecs[node.type]
    calls = []
    original = codec.encode

    def encode(item, context):
        calls.append(item)
        return original(item, context)

    emitter._conversion.target.codecs[node.type] = replace(codec, encode=encode)
    assert emitter.emit_result([node]).supported_nodes == [node]
    assert calls == [node]
    emitter._conversion.target.codecs[node.type] = replace(
        codec,
        check_protocol=lambda _: [
            IssueDraft(IssueSeverity.ERROR, "rejected by binding", "password")
        ],
        encode=lambda *_: pytest.fail("rejected node was encoded"),
    )
    rejected = emitter.emit_result([node])
    assert not rejected.supported_nodes
    assert any(
        issue.field == "password"
        and issue.source == "provider"
        and issue.target == target
        for issue in rejected.errors
    )


@pytest.mark.parametrize(
    "target", ["mihomo", "clash", "stash", "surge", "dae", "v2rayn", "sing-box"]
)
def test_binding_check_includes_its_common_and_input_checks(target):
    from subio_v2.core.results import IssueSeverity

    emitter = get_emitter(target)
    node = _base_node_factories()[Protocol.SHADOWSOCKS]()
    node.name = "REJECT"
    node.udp_port = 1234
    binding = emitter._conversion.target.codecs[node.type]
    direct = binding.check(node)
    checked = emitter.check_node(node)
    assert direct == checked.warnings
    emitted = emitter.emit_result([node])
    assert bool(emitted.supported_nodes) == (
        not any(issue.severity == IssueSeverity.ERROR for issue in direct)
    )
