from __future__ import annotations

from pathlib import Path


def test_provider_transforms_are_pure_functions_without_processor_abc():
    root = Path(__file__).parents[1]
    assert not (root / "src/subio_v2/processor/base.py").exists()
    assert not (root / "src/subio_v2/processor/common.py").exists()
    providers = (root / "src/subio_v2/workflow/providers.py").read_text()
    artifacts = (root / "src/subio_v2/workflow/artifacts.py").read_text()
    transforms = (root / "src/subio_v2/workflow/transforms.py").read_text()
    assert "workflow.transforms" in providers
    assert "workflow.transforms" in artifacts
    assert "class Processor" not in transforms
    assert "def filter_nodes" in transforms
    assert "def rename_nodes" in transforms
    assert "def set_dialer_proxy" in transforms
