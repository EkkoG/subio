import hashlib
import json
from collections import Counter

import pytest
import yaml

from subio_v2.adapters.clash_family.parser import ClashParser
from subio_v2.core.errors import ArtifactGenerationError, ConfigError
from subio_v2.core.parameters import MissingParameterError
from subio_v2.infrastructure import age
from subio_v2.workflow.artifacts import ArtifactGenerationService
from subio_v2.workflow.engine import WorkflowEngine
from subio_v2.workflow.manifest import MANIFEST_NAME, build_manifest
from subio_v2.workflow.providers import PreparedProvider, ProviderLoaderService
from subio_v2.workflow.template import TemplateRenderer


def _fixture(tmp_path):
    document = {"proxies": [
        {
            "name": "{{ params.label }}", "type": "socks5",
            "server": "example.test", "port": "{{ params.port }}",
            "password": "{{ params.credential }}",
        },
        {"name": "keep-static", "type": "socks5", "server": "example.test", "port": 1080},
    ]}
    (tmp_path / "nodes.yaml").write_text(yaml.safe_dump(document))
    (tmp_path / "ordinary.yaml").write_text("proxies: [{name: ordinary, type: direct}]\n")
    (tmp_path / "client.j2").write_text(
        "proxies:\n{{ nodes.render() | indent(2, true) }}\nvalues: {{ params | tojson }}\n"
    )
    data = {
        "provider": [
            {"name": "source", "type": "mihomo", "file": "nodes.yaml",
             "parameterized": True, "filters": {"include": "^keep-"}},
            {"name": "ordinary", "type": "mihomo", "file": "ordinary.yaml"},
        ],
        "artifact": [
            {
                "name": name, "type": "mihomo", "providers": ["source", "ordinary"],
                "template": "client.j2",
                "params": {
                    "label": {"default": label},
                    "port": {"type": port_type, "default": port},
                    "credential": {"default": "synthetic-default"},
                },
            }
            for name, label, port_type, port in (
                ("first.yaml", "keep-first", "integer", 1081),
                ("second.yaml", "drop-second", "string", "1082"),
            )
        ],
    }
    return tmp_path / "config.json", data


def _save(path, data):
    path.write_text(json.dumps(data))


@pytest.mark.parametrize("override", [False, True])
def test_artifacts_bind_independent_typed_defaults_once_prepared_with_safe_provenance(
    tmp_path, monkeypatch, override
):
    path, data = _fixture(tmp_path)
    _save(path, data)
    calls = Counter()
    fetch = ProviderLoaderService._fetch_content
    decode = ProviderLoaderService._decode_content
    decode_source = ClashParser.decode_source
    bind = PreparedProvider.bind
    render = TemplateRenderer.render_result
    bound_parameters = []
    template_parameters = []

    def counted_fetch(service, config, loader):
        calls[("fetch", config.name)] += 1
        return fetch(service, config, loader)

    def counted_decode(service, content, config):
        calls[("decode", config.name)] += 1
        return decode(service, content, config)

    def counted_source(content):
        calls[("source", "parameterized" if "params." in content else "ordinary")] += 1
        return decode_source(content)

    def capture_bind(prepared, parameters):
        bound_parameters.append(parameters)
        with pytest.raises(TypeError):
            parameters["credential"] = "changed"
        return bind(prepared, parameters)

    def capture_render(renderer, template, context, *args):
        template_parameters.append(context["params"])
        return render(renderer, template, context, *args)

    monkeypatch.setattr(ProviderLoaderService, "_fetch_content", counted_fetch)
    monkeypatch.setattr(ProviderLoaderService, "_decode_content", counted_decode)
    monkeypatch.setattr(ClashParser, "decode_source", staticmethod(counted_source))
    monkeypatch.setattr(PreparedProvider, "bind", capture_bind)
    monkeypatch.setattr(TemplateRenderer, "render_result", capture_render)
    credential = "literal {{ 7 * 7 }} & + = PRIVATE-PARAMETER-CANARY"
    pairs = (("port", "1083"), ("credential", credential)) if override else ()
    result = WorkflowEngine(str(path), parameter_pairs=pairs).prepare()

    assert calls == Counter({
        ("fetch", "source"): 1, ("fetch", "ordinary"): 1,
        ("decode", "source"): 1, ("decode", "ordinary"): 1,
        ("source", "parameterized"): 1, ("source", "ordinary"): 1,
    })
    assert len(bound_parameters) == 2
    assert all(bound is template for bound, template in zip(bound_parameters, template_parameters))
    assert bound_parameters[0] is not bound_parameters[1]
    outputs = [yaml.safe_load(draft.content) for draft in result.artifact_result.drafts]
    first, second = outputs
    assert [node["name"] for node in first["proxies"]] == ["keep-first", "keep-static", "ordinary"]
    assert [node["name"] for node in second["proxies"]] == ["keep-static", "ordinary"]
    assert first["values"]["port"] == (1083 if override else 1081)
    assert second["values"]["port"] == ("1083" if override else "1082")
    assert first["proxies"][0]["port"] == first["values"]["port"]
    assert first["proxies"][0]["password"] == (
        credential if override else "synthetic-default"
    )
    assert set(result.provider_result.providers) == {"ordinary"}
    assert set(result.provider_result.summaries) == {"ordinary"}
    assert result.provider_result.summaries["ordinary"].parsed_nodes == 1
    summaries = result.artifact_result.summaries
    assert [summary.input_nodes for summary in summaries] == [3, 2]
    assert [summary.parameterized_providers[0].selected_nodes for summary in summaries] == [2, 1]
    manifest = build_manifest(str(path), summaries, result.provider_result.summaries)
    digest = hashlib.sha256((tmp_path / "nodes.yaml").read_bytes()).hexdigest()
    for name, selected in (("first.yaml", 2), ("second.yaml", 1)):
        assert manifest["artifacts"][name]["parameterized_providers"] == {
            "source": {"content_sha256": digest, "parsed_nodes": 2, "selected_nodes": selected}
        }
    assert set(manifest["providers"]) == {"ordinary"}
    serialized = json.dumps(manifest)
    for private in (credential, "synthetic-default", "keep-first", "drop-second", "params", "password"):
        assert private not in serialized
    assert not (tmp_path / "dist").exists()


def test_late_missing_binding_prevents_all_publication_and_cleanup(tmp_path, monkeypatch):
    path, data = _fixture(tmp_path)
    data["artifact"][1]["params"].pop("credential")
    data["uploader"] = [{"name": "gist", "type": "gist", "id": "unused"}]
    for artifact in data["artifact"]:
        artifact["upload"] = [{"to": "gist"}]
    _save(path, data)
    monkeypatch.chdir(tmp_path)
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "old.yaml").write_text("previous artifact")
    manifest = '{"version": 1, "artifacts": {"old.yaml": {}}}'
    (dist / MANIFEST_NAME).write_text(manifest)
    staged = []
    stage = ArtifactGenerationService._stage

    def capture_stage(service, filename, *args):
        staged.append(filename)
        return stage(service, filename, *args)

    def denied(*args, **kwargs):
        pytest.fail("Late binding failure reached publication")

    monkeypatch.setattr(ArtifactGenerationService, "_stage", capture_stage)
    for target in ("queue_upload_requests", "apply_manifest"):
        monkeypatch.setattr("subio_v2.workflow.engine." + target, denied)
    monkeypatch.setattr("subio_v2.workflow.publication.ArtifactPublisher.commit", denied)
    monkeypatch.setattr("subio_v2.workflow.uploader.GistBatchUploader.flush", denied)
    engine = WorkflowEngine(str(path), clean_dist=True, parameter_pairs=())
    with pytest.raises(MissingParameterError, match="Missing rendering parameter"):
        engine.run()
    assert staged == ["first.yaml"]
    assert engine.batch_uploader.pending_uploads() == []
    assert (dist / "old.yaml").read_text() == "previous artifact"
    assert (dist / MANIFEST_NAME).read_text() == manifest
    assert {item.name for item in dist.iterdir()} == {"old.yaml", MANIFEST_NAME}


@pytest.mark.parametrize("dry_run", [False, True])
def test_success_publishes_all_drafts_manifest_and_only_configured_uploads(
    tmp_path, monkeypatch, dry_run
):
    path, data = _fixture(tmp_path)
    data["uploader"] = [
        {"name": "gist", "type": "gist", "id": "synthetic", "token": "synthetic"}
    ]
    for artifact in data["artifact"]:
        artifact["upload"] = [{"to": "gist"}]
    _save(path, data)
    monkeypatch.chdir(tmp_path)
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "old.yaml").write_text("old")
    (dist / "manual.txt").write_text("manual")
    (dist / MANIFEST_NAME).write_text('{"version": 1, "artifacts": {"old.yaml": {}}}')
    engine = WorkflowEngine(str(path), dry_run=dry_run, clean_dist=True, parameter_pairs=())
    staged = []
    uploaded = []
    stage = ArtifactGenerationService._stage
    add = engine.batch_uploader.add

    def capture_stage(service, filename, *args):
        staged.append(filename)
        return stage(service, filename, *args)

    def capture_add(*args):
        assert staged == ["first.yaml", "second.yaml"]
        return add(*args)

    monkeypatch.setattr(ArtifactGenerationService, "_stage", capture_stage)
    monkeypatch.setattr(engine.batch_uploader, "add", capture_add)
    monkeypatch.setattr(
        engine.batch_uploader, "_upload_batch",
        lambda gist, token, files, clean: uploaded.append(dict(files)),
    )
    result = engine.run()
    assert result.generated == ["first.yaml", "second.yaml"]
    assert result.uploaded == ([] if dry_run else ["synthetic:first.yaml", "synthetic:second.yaml"])
    assert len(uploaded) == (0 if dry_run else 1)
    manifest = json.loads((dist / MANIFEST_NAME).read_text())
    for filename, selected in (("first.yaml", 2), ("second.yaml", 1)):
        content = (dist / filename).read_text()
        assert yaml.safe_load(content)["values"]["credential"] == "synthetic-default"
        assert manifest["artifacts"][filename]["parameterized_providers"]["source"]["selected_nodes"] == selected
        if not dry_run:
            assert uploaded[0][filename] == content
    assert not (dist / "old.yaml").exists()
    assert (dist / "manual.txt").read_text() == "manual"
    assert engine.batch_uploader.pending_uploads() == []


def test_explicit_context_preserves_ordinary_outputs_and_manifest_shape(tmp_path):
    path, data = _fixture(tmp_path)
    data["provider"] = data["provider"][1:]
    data["artifact"] = [data["artifact"][0]]
    data["artifact"][0]["providers"] = ["ordinary"]
    _save(path, data)
    ordinary = WorkflowEngine(str(path)).prepare()
    contextual = WorkflowEngine(str(path), parameter_pairs=()).prepare()
    assert ordinary == contextual
    manifest = build_manifest(str(path), contextual.artifact_result.summaries)
    assert "parameterized_providers" not in manifest["artifacts"]["first.yaml"]


def test_unscoped_engine_rejects_parameterized_sources_before_input_io(tmp_path, monkeypatch):
    path, data = _fixture(tmp_path)
    _save(path, data)
    (tmp_path / "snippet").mkdir()

    def denied(*args, **kwargs):
        pytest.fail("Unscoped diagnostics reached input I/O")

    for target in ("load_snippets", "load_rulesets", "RunRemoteLoader"):
        monkeypatch.setattr("subio_v2.workflow.engine." + target, denied)
    monkeypatch.setattr(ProviderLoaderService, "_fetch_content", denied)
    with pytest.raises(ConfigError, match="scoped rendering"):
        WorkflowEngine(str(path))


def test_native_bindings_keep_batch_users_selector_and_age_path(tmp_path):
    path, data = _fixture(tmp_path)
    node = {
        "name": "keep-user", "type": "socks5", "server": "example.test", "port": 1080,
        "users": {
            "alice": {"password": "alice-{{ params.credential }}"},
            "bob": {"password": "bob-{{ params.credential }}"},
        },
    }
    (tmp_path / "nodes.yaml").write_text(yaml.safe_dump({"version": 2, "nodes": [node]}))
    data["provider"][0].update(type="subio")
    secret, public = age.generate_x25519_keypair()
    data["artifact"] = [data["artifact"][0]]
    data["artifact"][0].update(
        name="{user}.yaml", users=["alice", "bob"], selector="selected", age_public_key=public
    )
    data["selectors"] = {"selected": {"name_regex": "^keep-"}}
    _save(path, data)
    result = WorkflowEngine(str(path), parameter_pairs=(("credential", "bound-value"),)).prepare()
    for user, draft, summary in zip(("alice", "bob"), result.artifact_result.drafts, result.artifact_result.summaries):
        assert draft.filename == f"{user}.yaml"
        assert age.is_age_encrypted(draft.content)
        output = yaml.safe_load(age.decrypt_bytes(draft.content.encode(), secret))
        assert len(output["proxies"]) == 1
        assert output["proxies"][0]["password"] == f"{user}-bound-value"
        assert output["values"]["credential"] == "bound-value"
        assert summary.user == user
        assert summary.parameterized_providers[0].selected_nodes == 1


@pytest.mark.parametrize("allow_errors", [False, True])
def test_bound_provider_parse_errors_keep_conversion_gate_and_actual_counts(
    tmp_path, allow_errors
):
    path, data = _fixture(tmp_path)
    data["artifact"] = [data["artifact"][1]]
    data["artifact"][0]["allow_conversion_errors"] = allow_errors
    _save(path, data)
    engine = WorkflowEngine(str(path), parameter_pairs=(("port", "invalid"),))
    if not allow_errors:
        with pytest.raises(ArtifactGenerationError, match="conversion error"):
            engine.prepare()
    else:
        result = engine.prepare().artifact_result
        assert result.summaries[0].parameterized_providers[0].parsed_nodes == 1
        assert result.summaries[0].parameterized_providers[0].selected_nodes == 1
        assert "parse.node" in result.summaries[0].issue_codes
        assert all(issue.artifact == "second.yaml" for issue in result.issues)
