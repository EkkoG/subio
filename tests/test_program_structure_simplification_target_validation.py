from __future__ import annotations

from pathlib import Path

import subio_v2.protocols as protocol_registry
from subio_v2.adapters.target import TargetValidationService
from subio_v2.core.nodes import Protocol, ShadowsocksNode
from subio_v2.links import all_codecs
from subio_v2.surge.codecs import SURGE_PROTOCOL_CODECS


def test_target_validation_protocols_derive_from_actual_target_codecs():
    surge = TargetValidationService("surge")
    dae = TargetValidationService("dae")
    assert set(surge.protocol_codecs) == set(SURGE_PROTOCOL_CODECS)
    assert set(dae.protocol_codecs) == {
        codec.protocol for codec in all_codecs() if "dae" in codec.targets
    }
    assert Protocol.VLESS not in surge.protocol_codecs
    assert Protocol.VLESS in dae.protocol_codecs
    mihomo = TargetValidationService("mihomo")
    assert set(mihomo.protocol_codecs) == {
        codec.protocol
        for codec in protocol_registry.all()
        if codec.supports_dialect("mihomo")
    }


def test_target_validation_no_longer_constructs_capability_snapshots():
    root = Path(__file__).parents[1]
    source = (root / "src/subio_v2/adapters/target.py").read_text()
    emitter = (Path(__file__).parents[1] / "src/subio_v2/adapters/base.py").read_text()
    assert "get_platform_capabilities" not in source
    assert "self.capabilities" not in source
    assert "TargetValidationService" in emitter
    assert "NodeConversionService" not in emitter
    assert "emit_with_check" not in emitter
    assert not list((root / "src/subio_v2/capabilities").glob("*.py"))
    assert not (root / "src/subio_v2/target_registry.py").exists()
    assert not (root / "src/subio_v2/conversion_service.py").exists()
    assert "NodeConversionService" not in source
    clash_emitter = (
        Path(__file__).parents[1] / "src/subio_v2/emitter/clash.py"
    ).read_text()
    assert "protocol_registry.target_codec" in clash_emitter


def test_clash_target_validation_can_return_one_checked_encode_result():
    node = ShadowsocksNode(
        name="ss",
        server="example.test",
        port=8388,
        cipher="aes-256-gcm",
        password="password",
    )
    result = TargetValidationService("mihomo").encode_node(
        node, lambda item: {"name": item.name}
    )
    assert result.supported_node is node
    assert result.content == {"name": "ss"}
    assert result.issues == []
