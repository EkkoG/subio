from pathlib import Path

from subio_v2.adapters.base import BaseEmitter
from subio_v2.adapters.clash_family.emitter import ClashEmitter
from subio_v2.adapters.links.dae import DaeEmitter
from subio_v2.adapters.links.v2rayn import V2RayNEmitter
from subio_v2.adapters.surge.emitter import SurgeEmitter
from subio_v2.core.nodes import DirectNode, Node, Protocol, ShadowsocksNode
from subio_v2.core.results import EmissionResult
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


def test_builtin_emitters_provide_bounded_template_fragments():
    node = _ss()

    clash = ClashEmitter().emit_result([node])
    assert clash.fragments.subscription is None
    assert clash.fragments.plain_list is None

    surge = SurgeEmitter().emit_result([node])
    assert not hasattr(surge, "emitted_policy_names")

    dae = DaeEmitter().emit_result([node])
    assert dae.fragments.subscription.startswith("ss://")

    v2rayn = V2RayNEmitter().emit_result([node])
    assert v2rayn.fragments.plain_list


def test_template_node_api_is_consistent_and_secret_safe(tmp_path):
    (tmp_path / "nodes.j2").write_text(
        "{{ nodes.names() | join(',') }}|{{ nodes.count() }}|"
        "{{ nodes.exists() }}|{{ nodes.summaries is undefined }}"
    )
    # Use the public renderer without constructing a workflow or loading inputs.
    from subio_v2.workflow.template import TemplateRenderer
    from subio_v2.workflow.template_context import build_template_context

    node = _ss()
    fragments = ClashEmitter().emit_result([node]).fragments
    context = build_template_context(
        platform="mihomo",
        rendered="- name: proxy",
        nodes=[node],
        fragments=fragments,
    )
    output = TemplateRenderer(str(tmp_path)).render("nodes.j2", context)
    assert output == "proxy|1|True|True"
    assert "secret" not in output


def test_workflow_uses_bounded_template_context_without_platform_branch(
    tmp_path: Path, monkeypatch
):
    (tmp_path / "custom.j2").write_text(
        "{{ nodes.names() | join(',') }}|{{ custom_value is undefined }}|"
        "{{ private is undefined }}"
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

        def emit_result(self, nodes: list[Node]) -> EmissionResult[str]:
            return EmissionResult(
                content="payload",
                supported_nodes=nodes,
            )

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        "subio_v2.workflow.artifacts.get_emitter",
        lambda _emitter_type: CustomEmitter(),
    )
    engine = WorkflowEngine(str(config), dry_run=True)
    providers = {
        "source": [DirectNode(name="direct", type=Protocol.DIRECT, udp=False)]
    }

    result = ArtifactGenerationService(
        engine.config,
        providers,
        {},
        engine.renderer,
        engine._local_rulesets,
        engine.global_age_public_key,
    ).generate()
    engine.publisher.commit(result.drafts)

    assert (tmp_path / "dist/out.txt").read_text() == "direct|True|True"
