from pathlib import Path

import pytest

from subio_v2.adapters.base import BaseEmitter
from subio_v2.core.errors import ArtifactGenerationError
from subio_v2.core.nodes import DirectNode, Node, Protocol, ShadowsocksNode
from subio_v2.core.results import EmissionResult
from subio_v2.workflow.artifacts import ArtifactGenerationService
from subio_v2.workflow.engine import WorkflowEngine


def _node(name: str, protocol: Protocol = Protocol.DIRECT) -> Node:
    if protocol == Protocol.DIRECT:
        return DirectNode(name=name, type=protocol, udp=False)
    return ShadowsocksNode(
        name=name,
        type=protocol,
        server="example.com",
        port=443,
        password="secret",
    )


def _service(tmp_path: Path, monkeypatch, artifact_type: str = "custom"):
    (tmp_path / "config.toml").write_text(
        f"""
[selectors.streaming]
name_regex = ["HK"]

[[provider]]
name = "source"
type = "custom"
file = "source.txt"

[[artifact]]
name = "out.txt"
type = "{artifact_type}"
providers = ["source"]
selector = "streaming"
template = "out.j2"
""".strip()
    )
    (tmp_path / "source.txt").write_text("unused")
    (tmp_path / "out.j2").write_text(
        "{{ nodes.names(\"streaming\") | join(',') }}|"
        "{{ nodes.names() | join(',') }}"
    )
    engine = WorkflowEngine(str(tmp_path / "config.toml"), dry_run=True)

    class Emitter(BaseEmitter):
        platform = "mihomo"

        def emit_result(self, nodes: list[Node]) -> EmissionResult[str]:
            return EmissionResult(content="payload", supported_nodes=nodes)

    monkeypatch.setattr(
        "subio_v2.workflow.artifacts.get_emitter", lambda _type: Emitter()
    )
    return engine, ArtifactGenerationService(
        engine.config,
        {},
        {},
        engine.renderer,
        engine._local_rulesets,
        engine.global_age_public_key,
    )


def test_artifact_selector_and_template_selector_share_one_result(tmp_path, monkeypatch):
    engine, service = _service(tmp_path, monkeypatch)
    monkeypatch.chdir(tmp_path)
    service.providers = {
        "source": [_node("HK-1"), _node("US-1")],
    }

    result = service.generate()
    engine.publisher.commit(result.drafts)

    assert (tmp_path / "dist/out.txt").read_text() == "HK-1|HK-1"


def test_artifact_selector_rejects_missing_dialer_target(tmp_path, monkeypatch):
    _engine, service = _service(tmp_path, monkeypatch, artifact_type="mihomo")
    monkeypatch.chdir(tmp_path)
    chained = _node("HK-1", Protocol.TROJAN)
    chained.dialer_proxy = "missing"
    service.providers = {"source": [chained]}

    with pytest.raises(ArtifactGenerationError) as exc_info:
        service.generate()

    assert [issue.code for issue in exc_info.value.issues] == [
        "conversion.missing-dialer-proxy"
    ]


def test_artifact_selector_rejects_duplicate_names_by_default(tmp_path, monkeypatch):
    _engine, service = _service(tmp_path, monkeypatch)
    monkeypatch.chdir(tmp_path)
    service.providers = {
        "source": [_node("HK-1"), _node("HK-1", Protocol.TROJAN)],
    }

    with pytest.raises(ArtifactGenerationError) as exc_info:
        service.generate()

    assert [issue.code for issue in exc_info.value.issues] == [
        "conversion.duplicate-node-name"
    ]
