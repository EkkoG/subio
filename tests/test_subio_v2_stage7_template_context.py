from pathlib import Path

from subio_v2.conversion import EmissionResult
from subio_v2.emitter.base import BaseEmitter
from subio_v2.emitter.clash import ClashEmitter
from subio_v2.emitter.dae import DaeEmitter
from subio_v2.emitter.registry import EmitterRegistry
from subio_v2.emitter.surge import SurgeEmitter
from subio_v2.emitter.v2rayn import V2RayNEmitter
from subio_v2.model.nodes import DirectNode, Node, Protocol, ShadowsocksNode
from subio_v2.workflow.artifacts import ArtifactGenerationService
from subio_v2.workflow.engine import WorkflowEngine


def _ss() -> ShadowsocksNode:
    return ShadowsocksNode(
        name="proxy",
        type=Protocol.SHADOWSOCKS,
        server="example.com",
        port=8388,
        cipher="aes-256-gcm",
        password="secret",
    )


def test_builtin_emitters_provide_complete_template_context():
    node = _ss()

    clash = ClashEmitter().emit_result([node])
    assert clash.extras["template_context"] == {"proxies_names": ["proxy"]}

    surge = SurgeEmitter().emit_result([node])
    assert surge.extras["template_context"] == {
        "proxies_names": "PROXY = select, proxy"
    }
    assert not hasattr(surge, "emitted_policy_names")

    dae = DaeEmitter().emit_result([node])
    assert dae.extras["template_context"] == {
        "proxies_names": "'proxy'",
        "subscription": dae.extras["subscription"],
    }

    v2rayn = V2RayNEmitter().emit_result([node])
    assert v2rayn.extras["template_context"] == {"proxies_names": ["proxy"]}
    assert "list" in v2rayn.extras
    assert "list" not in v2rayn.extras["template_context"]


def test_workflow_accepts_new_emitter_template_context_without_platform_branch(
    tmp_path: Path, monkeypatch
):
    (tmp_path / "custom.j2").write_text(
        "{{ proxies_names }}|{{ custom_value }}|{{ private is undefined }}"
    )
    (tmp_path / "source.txt").write_text("unused")
    config = tmp_path / "config.toml"
    config.write_text(
        """
[[provider]]
name = "source"
type = "custom"
file = "source.txt"

[[artifact]]
name = "out.txt"
type = "custom"
providers = ["source"]
template = "custom.j2"
""".strip()
    )

    class CustomEmitter(BaseEmitter):
        platform = "clash-meta"

        def emit_content(self, nodes: list[Node]) -> str:
            return self.emit_result(nodes).content

        def emit_result(self, nodes: list[Node]) -> EmissionResult[str]:
            return EmissionResult(
                content="payload",
                supported_nodes=nodes,
                extras={
                    "private": "must-not-leak",
                    "template_context": {
                        "proxies_names": "CUSTOM",
                        "custom_value": "context",
                    },
                },
            )

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        EmitterRegistry, "get_emitter", lambda _emitter_type: CustomEmitter()
    )
    engine = WorkflowEngine(str(config), dry_run=True)
    engine.providers["source"] = [
        DirectNode(name="direct", type=Protocol.DIRECT, udp=False)
    ]

    result = ArtifactGenerationService(
        engine.config,
        engine.providers,
        engine.provider_issues,
        engine.renderer,
        engine.rulesets,
        engine.batch_uploader,
        engine.global_age_public_key,
    ).generate()
    engine.publisher.commit(result.staged_artifacts)

    assert (tmp_path / "dist/out.txt").read_text() == "CUSTOM|context|True"
