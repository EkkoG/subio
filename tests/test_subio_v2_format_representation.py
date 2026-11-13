from dataclasses import replace

import pytest

from subio_v2.adapters import catalog
from subio_v2.core.nodes import ShadowsocksNode
from subio_v2.core.results import EmissionFragments
from subio_v2.workflow.selectors import SelectorEngine
from subio_v2.workflow.template_context import build_template_context


def context(platform, rendered="rendered"):
    return build_template_context(
        platform=platform,
        rendered=rendered,
        nodes=[ShadowsocksNode(name="node")],
        fragments=EmissionFragments(),
        selector_engine=SelectorEngine({}),
    )


@pytest.mark.parametrize(
    ("source", "rendered", "legacy"),
    [
        ("surge", "rendered", "PROXY = select, node"),
        ("dae", "rendered", "'node'"),
        ("sing-box", '{"outbounds": [], "endpoints": []}', ["node"]),
    ],
)
def test_template_format_behavior_follows_registered_owner(
    source, rendered, legacy, monkeypatch
):
    spec = replace(catalog.get_format(source), name="renamed-format")
    monkeypatch.setitem(catalog._FORMAT_BY_REQUESTED, spec.name, spec)
    assert spec.representation_factory is not None
    values = context(spec.name, rendered)
    assert values["proxies_names"] == legacy
    assert values["nodes"].names() == ["node"]
    if source == "sing-box":
        assert values["nodes"].outbounds() == "[]"
        assert values["nodes"].endpoints() == "[]"
    else:
        with pytest.raises(ValueError, match="only available for sing-box"):
            values["nodes"].outbounds()


def test_template_alias_uses_canonical_representation():
    assert context("clash-meta")["proxies_names"] == ["node"]
    with pytest.raises(ValueError, match="nodes.endpoints"):
        context("clash-meta")["nodes"].endpoints()


def test_artifact_uses_registered_serialization_and_template_validation(
    tmp_path, monkeypatch
):
    from subio_v2.workflow.engine import WorkflowEngine

    spec = catalog.get_format("sing-box")
    presentation = spec.representation_factory()
    calls = []

    def serialize(content, template):
        calls.append(("serialize", template))
        return presentation.serialize(content, template)

    def validate(content, path):
        calls.append(("validate", path))
        presentation.validate_template(content, path)

    monkeypatch.setitem(
        catalog._FORMAT_BY_REQUESTED,
        spec.name,
        replace(
            spec,
            representation_factory=lambda: replace(
                presentation,
                serialize=serialize,
                validate_template=validate,
            ),
        ),
    )
    (tmp_path / "nodes.yaml").write_text("""
proxies:
  - name: ss
    type: ss
    server: example.test
    port: 443
    cipher: aes-256-gcm
    password: synthetic
""")
    (tmp_path / "client.j2").write_text('{"outbounds": {{ nodes.outbounds() }}}')
    config = tmp_path / "config.toml"
    config.write_text("""
[[provider]]
name = "source"
type = "mihomo"
file = "nodes.yaml"
[[artifact]]
name = "client.json"
type = "sing-box"
providers = ["source"]
template = "client.j2"
""")
    monkeypatch.chdir(tmp_path)
    assert not WorkflowEngine(str(config), dry_run=True).run().errors
    assert calls == [("serialize", True), ("validate", "client.j2")]
