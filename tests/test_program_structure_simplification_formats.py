from __future__ import annotations

from pathlib import Path

from subio_v2.adapters.catalog import (
    all_formats,
    get_emitter,
    get_format,
    get_parser,
    normalize_format,
)


def test_format_catalog_owns_names_aliases_and_directions():
    formats = {spec.name: spec for spec in all_formats()}
    assert set(formats) == {
        "mihomo",
        "clash",
        "stash",
        "surge",
        "dae",
        "v2rayn",
        "subio",
    }
    assert get_format("clash-meta") is formats["mihomo"]
    assert normalize_format("clash-meta") == "mihomo"
    assert formats["clash"].deprecated is True
    assert formats["clash"].replacement == "mihomo"
    assert formats["subio"].parser_factory is not None
    assert formats["subio"].emitter_factory is None
    assert formats["dae"].parser_factory is None
    assert formats["dae"].emitter_factory is not None
    assert get_parser("dae") is None
    assert get_emitter("subio") is None


def test_format_catalog_returns_fresh_stateful_adapters():
    assert get_parser("surge") is not get_parser("surge")
    assert get_emitter("mihomo") is not get_emitter("mihomo")


def test_old_format_registry_paths_are_removed_and_consumers_use_catalog():
    root = Path(__file__).parents[1]
    assert not (root / "src/subio_v2/platforms.py").exists()
    assert not (root / "src/subio_v2/parser/registry.py").exists()
    assert not (root / "src/subio_v2/emitter/registry.py").exists()

    providers = (root / "src/subio_v2/workflow/providers.py").read_text()
    artifacts = (root / "src/subio_v2/workflow/artifacts.py").read_text()
    assert "from subio_v2.adapters.catalog import get_parser" in providers
    assert "from subio_v2.adapters.catalog import get_emitter" in artifacts
    assert "parser.registry" not in providers
    assert "emitter.registry" not in artifacts
