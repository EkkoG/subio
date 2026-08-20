from __future__ import annotations

from pathlib import Path

import subio_v2.protocols as protocol_registry
from subio_v2.core.nodes import Protocol
from subio_v2.surge.codecs import SURGE_CODEC_SPECS, SURGE_PROTOCOL_CODECS


def test_surge_executable_codec_registry_owns_parser_and_emitter_paths():
    node_specs = [item for item in SURGE_CODEC_SPECS if item.protocol is not None]
    assert all(item.emitter is not None for item in node_specs)
    assert {protocol for protocol in SURGE_PROTOCOL_CODECS} == {
        item.protocol for item in node_specs
    }
    assert Protocol.VLESS not in SURGE_PROTOCOL_CODECS


def test_surge_document_adapters_have_no_parallel_protocol_maps():
    root = Path(__file__).parents[1] / "src/subio_v2/surge"
    parser_source = (root / "parsers.py").read_text()
    emitter_source = (root / "emitters.py").read_text()
    codec_source = (root / "codecs.py").read_text()
    parser_adapter = (Path(__file__).parents[1] / "src/subio_v2/parser/surge.py").read_text()
    emitter_adapter = (Path(__file__).parents[1] / "src/subio_v2/emitter/surge.py").read_text()

    assert "SURGE_PROTOCOL_PARSERS" not in parser_source
    assert "SURGE_PROTOCOL_EMITTERS" not in emitter_source
    assert "_SURGE_PARSERS" not in codec_source
    assert "_SURGE_EMITTERS" not in codec_source
    assert "get_surge_protocol_codec" in emitter_adapter
    assert ".parser" in parser_adapter


def test_clash_protocol_codecs_do_not_declare_surge_target_constraints():
    assert all("surge" not in codec.target_constraints for codec in protocol_registry.all())
