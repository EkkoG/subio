import json

import pytest

from subio_v2.adapters.catalog import get_emitter
from subio_v2.adapters.surge.parser import SurgeParser
from subio_v2.core.errors import ArtifactGenerationError
from subio_v2.core.nodes import ShadowsocksNode
from subio_v2.workflow.config import ConfigLoader
from subio_v2.workflow.engine import WorkflowEngine
from subio_v2.workflow.rendering import prepare_resources


def ss(name, dialer=None, password="synthetic"):
    return ShadowsocksNode(
        name=name, server="example.test", port=8388,
        cipher="aes-256-gcm", password=password, dialer_proxy=dialer,
    )


@pytest.mark.parametrize("selection", ["provider", "global", "selector", "user"])
@pytest.mark.parametrize("prepared", [False, True])
@pytest.mark.parametrize("parameterized", [False, True])
def test_selection_rejects_removed_known_dialer(tmp_path, selection, prepared, parameterized):
    nodes = [
        {"name": name, "type": "ss", "server": "example.test", "port": 8388,
         "cipher": "aes-256-gcm", "password": "synthetic"}
        for name in ("upstream", "leaf")
    ]
    nodes[1]["dialer-proxy"] = "upstream"
    provider = {"name": "source", "type": "mihomo", "file": "nodes.json"}
    provider["parameterized"] = parameterized
    artifact = {"name": "out.yaml", "type": "mihomo", "providers": ["source"]}
    config = {"provider": [provider], "artifact": [artifact]}
    if selection == "provider":
        provider["filters"] = {"exclude": "^upstream$"}
        provider["rename"] = {"add_prefix": "prefix-"}
    elif selection == "global":
        config["filters"] = {"exclude": "^upstream$"}
    elif selection == "selector":
        config["selectors"] = {"leaf": {"name_regex": "^leaf$"}}
        artifact["selector"] = "leaf"
    else:
        nodes[0]["users"] = {"alice": {"password": "alice-synthetic"}}
        artifact["user"] = "bob"
    (tmp_path / "nodes.json").write_text(json.dumps({"proxies": nodes}))
    path = tmp_path / "config.json"
    path.write_text(json.dumps(config))

    with pytest.raises(ArtifactGenerationError) as exc:
        if prepared:
            candidate = prepare_resources(str(path), ConfigLoader.load(str(path)))
            candidate.candidates["out.yaml"].render("out.yaml", {})
        else:
            WorkflowEngine(str(path), parameter_pairs=() if parameterized else None).prepare()

    assert any(issue.code == "conversion.missing-dialer-proxy" for issue in exc.value.issues)
    assert not (tmp_path / "dist").exists()


@pytest.mark.parametrize("allow_errors,allow_empty,success", [
    (False, False, False), (True, False, False), (True, True, True),
])
@pytest.mark.parametrize("prepared", [False, True])
def test_conversion_pruning_respects_artifact_gates(
    tmp_path, allow_errors, allow_empty, success, prepared,
):
    (tmp_path / "nodes.yaml").write_text(
        "proxies:\n"
        "  - {name: upstream, type: dns}\n"
        "  - {name: leaf, type: ss, server: example.test, port: 8388, "
        "cipher: aes-256-gcm, password: synthetic, dialer-proxy: upstream}\n"
    )
    path = tmp_path / "config.json"
    path.write_text(json.dumps({
        "provider": [{"name": "source", "type": "mihomo", "file": "nodes.yaml"}],
        "artifact": [{"name": "out.conf", "type": "surge", "providers": ["source"],
                      "allow_conversion_errors": allow_errors, "allow_empty": allow_empty}],
    }))

    def generate():
        if prepared:
            resources = prepare_resources(str(path), ConfigLoader.load(str(path)))
            return resources.candidates["out.conf"].render("out.conf", {}).artifact_result
        return WorkflowEngine(str(path)).prepare().artifact_result

    if success:
        result = generate()
        assert "leaf" not in result.drafts[0].content
        assert any(issue.code == "conversion.missing-dialer-proxy" for issue in result.issues)
    else:
        with pytest.raises(ArtifactGenerationError):
            generate()


@pytest.mark.parametrize("target", ["mihomo", "stash", "surge", "sing-box"])
def test_emitter_drops_transitive_dependents_of_rejected_node(target):
    nodes = [ss("leaf", "middle"), ss("middle", "bad"), ss("bad", password=""), ss("safe")]

    result = get_emitter(target).emit_result(nodes)

    assert [node.name for node in result.supported_nodes] == ["safe"]
    assert {issue.node for issue in result.errors if issue.field == "dialer_proxy"} == {"leaf", "middle"}


@pytest.mark.parametrize("target", ["mihomo", "stash", "surge", "sing-box"])
def test_emitter_keeps_external_names_and_surviving_same_name_target(target):
    result = get_emitter(target).emit_result([
        ss("bad", password=""), ss("leaf", "bad"), ss("external", "TemplateGroup"), ss("bad"),
    ])
    assert {node.name for node in result.supported_nodes} == {"bad", "leaf", "external"}
    assert not any(issue.field == "dialer_proxy" for issue in result.issues)


@pytest.mark.parametrize("target", ["clash", "v2rayn"])
def test_targets_without_dialer_support_do_not_reject_dependents(target):
    result = get_emitter(target).emit_result([ss("bad", password=""), ss("leaf", "bad")])
    assert [node.name for node in result.supported_nodes] == ["leaf"]


def test_surge_pruned_node_does_not_leave_its_attachment():
    parsed = SurgeParser(source_kind="local").parse_result("""
[Proxy]
leaf = https, example.test, 443, client-cert=client, underlying-proxy=bad
safe = ss, example.test, 8388, encrypt-method=aes-256-gcm, password=synthetic
[Keystore]
client = type=p12, base64=Q0VSVA==
""")
    assert not parsed.issues
    result = get_emitter("surge").emit_result([*parsed.nodes, ss("bad", password="")])
    assert [node.name for node in result.supported_nodes] == ["safe"]
    assert "[Keystore]" not in result.content
    assert "client-cert" not in result.content


def test_surge_selector_accepts_static_template_group(tmp_path):
    (tmp_path / "nodes.conf").write_text(
        "[Proxy]\nleaf = ss, example.test, 8388, encrypt-method=aes-256-gcm, "
        "password=synthetic, underlying-proxy=StaticGroup\n"
    )
    (tmp_path / "client.conf").write_text(
        "[Proxy]\n{{ nodes.render() }}\n[Proxy Group]\nStaticGroup = select, DIRECT\n"
    )
    path = tmp_path / "config.json"
    path.write_text(json.dumps({
        "provider": [{"name": "source", "type": "surge", "file": "nodes.conf"}],
        "selectors": {"all": {}},
        "artifact": [{"name": "out.conf", "type": "surge", "providers": ["source"],
                      "template": "client.conf", "selector": "all"}],
    }))
    result = WorkflowEngine(str(path)).prepare().artifact_result
    assert not result.issues
    assert "underlying-proxy=StaticGroup" in result.drafts[0].content
