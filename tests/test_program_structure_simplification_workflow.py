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


def test_artifact_builder_delays_upload_queue_until_after_generation_loop():
    source = (
        Path(__file__).parents[1] / "src/subio_v2/workflow/artifacts.py"
    ).read_text()
    generate_body = source.split("    def generate", 1)[1].split(
        "    def _generate_one", 1
    )[0]
    stage_body = source.split("    def _stage", 1)[1]
    assert generate_body.index("for content, artifact_config") < generate_body.index(
        "upload("
    )
    assert "upload(" not in stage_body


def test_workflow_uses_typed_artifact_drafts():
    root = Path(__file__).parents[1] / "src/subio_v2/workflow"
    artifacts = (root / "artifacts.py").read_text()
    engine = (root / "engine.py").read_text()
    publication = (root / "publication.py").read_text()
    assert "class ArtifactDraft" in artifacts
    assert "drafts: tuple[ArtifactDraft" in artifacts
    assert "artifact_result.drafts" in engine
    assert "ArtifactDraft" in publication
    assert "staged_artifacts: dict" not in artifacts
