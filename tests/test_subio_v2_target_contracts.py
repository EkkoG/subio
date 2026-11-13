from dataclasses import replace

import pytest

from subio_v2.adapters.catalog import get_emitter, get_target
from subio_v2.adapters.target import TargetValidationService
from subio_v2.core.nodes import Protocol, TLSSettings, TransportSettings, VlessNode
from subio_v2.core.results import TargetCheckResult
from subio_v2.protocols.vless import VlessCodec


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
    result = service.encode_node(vless(), lambda _: "unvalidated payload")
    assert result.content[0]["type"] == "vless"
    rejected = service.encode_node(
        vless(tls=TLSSettings(sni_disabled=True)),
        lambda _: "unsafe payload",
        lambda _: TargetCheckResult(supported=True),
    )
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
