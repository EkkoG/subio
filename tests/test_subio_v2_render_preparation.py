import json
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from types import MappingProxyType

import pytest
import yaml

from subio_v2.core.errors import (
    ArtifactGenerationError,
    ConfigError,
    TemplateRenderError,
)
from subio_v2.core.parameters import MissingParameterError
from subio_v2.adapters.catalog import get_parser
from subio_v2.infrastructure import age
from subio_v2.infrastructure.remote import RunRemoteLoader
from subio_v2.main import main
from subio_v2.rules.runtime import RuleSetStore
from subio_v2.workflow.config import ConfigLoader
from subio_v2.workflow.engine import WorkflowEngine
from subio_v2.workflow.parameters import normalize_parameters
from subio_v2.workflow.template import TemplateRenderer
from subio_v2.workflow.rendering import prepare_resources


def _fixture(tmp_path, *, native=False, parameterized=True):
    node = {
        "name": "{{ params.name }}",
        "type": "socks5",
        "server": "{{ params.host }}",
        "port": "{{ params.port }}",
        "password": "{{ params.credential }}",
    }
    if not parameterized:
        node = {
            "name": "static",
            "type": "socks5",
            "server": "example.test",
            "port": 1080,
        }
    document = {"version": 2, "nodes": [node]} if native else {"proxies": [node]}
    (tmp_path / "nodes.yaml").write_text(yaml.safe_dump(document))
    (tmp_path / "client.j2").write_text(
        "proxies:\n{{ nodes.render() | indent(2, true) }}\nvalues: {{ params | tojson }}\n"
    )
    params = {
        "name": {"type": "string", "default": "route-a"},
        "host": {"type": "string", "default": "example.test"},
        "port": {"type": "integer", "default": 80, "min": 1, "max": 100},
        "credential": {"type": "string", "default": "synthetic"},
    }
    data = {
        "provider": [
            {
                "name": "source",
                "type": "subio" if native else "mihomo",
                "file": "nodes.yaml",
                "parameterized": parameterized,
            }
        ],
        "artifact": [
            {
                "name": "out.yaml",
                "type": "mihomo",
                "providers": ["source"],
                "template": "client.j2",
                "params": params,
            }
        ],
    }
    path = tmp_path / "config.json"
    return path, data


def _snapshot(path, data):
    path.write_text(json.dumps(data))
    return ConfigLoader.load(str(path))


def _render(path, config, file_name="out.yaml", pairs=()):
    artifact = next(
        item for item in config.artifacts
        if any(name == file_name for name, _ in item.output_names())
    )
    parameters = normalize_parameters(artifact.params, pairs)
    return prepare_resources(str(path), config).candidates[file_name].render(file_name, parameters)


@pytest.mark.parametrize("native", [False, True])
def test_selected_render_uses_snapshot_and_only_referenced_providers(
    tmp_path, monkeypatch, native
):
    path, data = _fixture(tmp_path, native=native)
    data["provider"].append(
        {"name": "unrelated", "type": "mihomo", "file": "missing.yaml"}
    )
    data["artifact"].append(
        {
            "name": "unrelated.yaml",
            "type": "mihomo",
            "providers": ["unrelated"],
            "template": "missing.j2",
        }
    )
    data["filters"] = {"include": "route-a"}
    data["selectors"] = {"chosen": {"name_regex": "route-a", "limit": 1}}
    data["artifact"][0]["selector"] = "chosen"
    config = _snapshot(path, data)
    path.write_text("invalid new config is not the startup snapshot")
    monkeypatch.setattr(
        ConfigLoader, "load", lambda *_: pytest.fail("Snapshot was reread")
    )
    result = _render(
        path, config, pairs=[("credential", "literal {{ 7 * 7 }} & + = #")]
    )
    assert list(result.provider_result.providers) == ["source"]
    assert len(result.artifact_result.drafts) == 1
    output = yaml.safe_load(result.artifact_result.drafts[0].content)
    assert output["proxies"][0]["port"] == 80
    assert output["proxies"][0]["password"] == "literal {{ 7 * 7 }} & + = #"
    assert output["values"]["credential"] == output["proxies"][0]["password"]
    assert len(config.providers) == len(config.artifacts) == 2


def test_selected_render_preserves_shared_rulesets_as_dependencies(
    tmp_path, monkeypatch
):
    path, data = _fixture(tmp_path)
    data["ruleset"] = [{"name": "shared", "url": "https://unused.test/rules"}]
    config = _snapshot(path, data)
    calls = []

    def fetch(loader, url, *, headers=None):
        calls.append(url)
        return b"DOMAIN,example.test"

    monkeypatch.setattr(RunRemoteLoader, "fetch", fetch)
    assert _render(path, config).artifact_result.drafts
    assert calls == ["https://unused.test/rules"]
    monkeypatch.setattr(RunRemoteLoader, "fetch", lambda *args, **kwargs: b"")
    assert prepare_resources(str(path), config).failures["out.yaml"].phase == "ruleset"


@pytest.mark.parametrize(
    "arguments",
    [["convert"], ["check"], ["inspect", "providers"], ["inspect", "artifacts"]],
)
def test_static_cli_rejects_parameterized_sources_before_any_input_io(
    tmp_path, monkeypatch, capsys, arguments
):
    path, data = _fixture(tmp_path)
    _snapshot(path, data)
    (tmp_path / "snippet").mkdir()
    (tmp_path / "snippet" / "bad").write_text("would fail if loaded")

    def denied(*args, **kwargs):
        pytest.fail("Input I/O occurred before static rejection")

    for target in ("load_snippets", "load_rulesets", "RunRemoteLoader"):
        monkeypatch.setattr("subio_v2.workflow.engine." + target, denied)
    monkeypatch.setattr(
        "subio_v2.workflow.providers.ProviderLoaderService._fetch_content", denied
    )
    monkeypatch.setattr(sys, "argv", ["subio", *arguments, str(path)])
    assert main() == 1
    assert "scoped rendering" in capsys.readouterr().out


def test_static_template_defaults_work_and_missing_values_block_publication(
    tmp_path, monkeypatch
):
    path, data = _fixture(tmp_path, parameterized=False)
    config = _snapshot(path, data)
    output = WorkflowEngine(str(path)).prepare().artifact_result.drafts[0].content
    assert yaml.safe_load(output)["values"]["port"] == 80
    assert config.artifacts[0].params["port"].default == 80
    data["artifact"][0]["params"].pop("credential")
    _snapshot(path, data)
    (tmp_path / "client.j2").write_text('credential: {{ params.credential | tojson }}')
    monkeypatch.setattr(
        "subio_v2.workflow.publication.ArtifactPublisher.commit",
        lambda *_: pytest.fail("Published"),
    )
    monkeypatch.setattr(
        "subio_v2.workflow.engine.queue_upload_requests",
        lambda *_: pytest.fail("Queued uploads"),
    )
    with pytest.raises(TemplateRenderError, match="Missing rendering parameter"):
        WorkflowEngine(str(path)).run()
    assert not (tmp_path / "dist").exists()


def test_params_namespace_is_nested_immutable_and_always_present(
    tmp_path, monkeypatch
):
    path, data = _fixture(tmp_path, parameterized=False)
    data["artifact"][0]["params"].update(
        {
            "self": {"type": "string", "default": "self-value"},
            "items": {"type": "string", "default": "items-value"},
        }
    )
    (tmp_path / "client.j2").write_text(
        '{{ params["self"] }}|{{ params["items"] }}|{{ credential is undefined }}'
    )
    config = _snapshot(path, data)
    runtime = dict(normalize_parameters(config.artifacts[0].params, ()))
    prepared = prepare_resources(str(path), config).candidates["out.yaml"]
    render_result = TemplateRenderer.render_result
    contexts = []

    def capture(renderer, template, context, *args):
        contexts.append(context)
        with pytest.raises(TypeError):
            context["params"]["credential"] = "changed"
        runtime["self"] = "changed after render started"
        return render_result(renderer, template, context, *args)

    monkeypatch.setattr(TemplateRenderer, "render_result", capture)
    assert prepared.render("out.yaml", runtime).artifact_result.drafts[0].content == "self-value|items-value|True"
    assert "self" not in contexts[0] and "credential" not in contexts[0]
    monkeypatch.setattr(TemplateRenderer, "render_result", render_result)
    data["artifact"][0].pop("params")
    _snapshot(path, data)
    (tmp_path / "client.j2").write_text("{{ params is undefined }}")
    assert (
        WorkflowEngine(str(path)).prepare().artifact_result.drafts[0].content == "False"
    )


def test_scoped_singbox_json_uses_params_serialization_and_normal_node_fragments(
    tmp_path,
):
    path, data = _fixture(tmp_path)
    data["artifact"][0].update({"name": "out.json", "type": "sing-box"})
    (tmp_path / "client.j2").write_text(
        '{"outbounds":{{ nodes.outbounds() }},"params":{{ params | tojson }}}'
    )
    config = _snapshot(path, data)
    output = (
        _render(path, config, "out.json", pairs=[("credential", 'literal " & {{ 7 * 7 }}')])
        .artifact_result.drafts[0]
        .content
    )
    decoded = json.loads(output)
    assert decoded["outbounds"][0]["server_port"] == 80
    assert decoded["params"]["credential"] == 'literal " & {{ 7 * 7 }}'


def test_immutable_params_use_yaml_and_builtin_json_serialization_policies(tmp_path):
    (tmp_path / "json.j2").write_text("{{ params | tojson(indent=2) }}")
    (tmp_path / "yaml.j2").write_text("{{ params | to_yaml }}")
    renderer = TemplateRenderer(str(tmp_path))
    parameters = MappingProxyType(
        {"text": "\"'&<> {{ 7 * 7 }}", "port": 1080, "tls": True}
    )
    calls = []

    def dumps(value, **kwargs):
        calls.append((value, kwargs))
        return json.dumps(value, **kwargs)

    renderer.env.policies["json.dumps_function"] = dumps
    renderer.env.policies["json.dumps_kwargs"] = {"sort_keys": False}
    output = renderer.render("json.j2", {"params": parameters})
    assert json.loads(output) == dict(parameters)
    assert "\\u003c" in output and "\\u0026" in output
    assert calls == [(dict(parameters), {"sort_keys": False, "indent": 2})]
    assert yaml.safe_load(renderer.render("yaml.j2", {"params": parameters})) == dict(
        parameters
    )


@pytest.mark.parametrize("expression", [
    "params.missing", 'params["missing"]', 'params["items"]',
    'params.missing | tojson', 'params.missing | default("fallback")',
    "params.missing is defined", "params.token",
])
def test_missing_params_fail_on_direct_template_access_before_filters(tmp_path, expression):
    (tmp_path / "client.j2").write_text("{{ " + expression + " }}")
    renderer = TemplateRenderer(str(tmp_path))
    with pytest.raises(TemplateRenderError) as error:
        renderer.render("client.j2", {"params": {}})
    assert isinstance(error.value.__cause__, MissingParameterError)


def test_ruleset_callable_params_collision_fails_without_shadowing(tmp_path):
    path, data = _fixture(tmp_path, parameterized=False)
    (tmp_path / "snippet").mkdir()
    (tmp_path / "snippet" / "params").write_text("policy\nDOMAIN,example.test")
    config = _snapshot(path, data)
    with pytest.raises(TemplateRenderError, match="conflicts.*params"):
        _render(path, config)


def test_fixed_user_and_age_reuse_normal_gates_without_publication(
    tmp_path, monkeypatch
):
    path, data = _fixture(tmp_path)
    document = yaml.safe_load((tmp_path / "nodes.yaml").read_text())
    document["proxies"][0]["users"] = {
        "alice": {"password": "alice-{{ params.credential }}"},
        "bob": {"password": "bob-static"},
    }
    (tmp_path / "nodes.yaml").write_text(yaml.safe_dump(document))
    secret, public = age.generate_x25519_keypair()
    data["artifact"][0].update(
        {"user": "alice", "age_public_key": public, "upload": [{"to": "gist"}]}
    )
    data["uploader"] = [{"name": "gist", "type": "gist", "id": "unused"}]
    config = _snapshot(path, data)

    def denied(*args, **kwargs):
        pytest.fail("Scoped rendering reached publishing or upload")

    for target in ("queue_upload_requests", "apply_manifest"):
        monkeypatch.setattr("subio_v2.workflow.engine." + target, denied)
    for target in ("begin", "add", "flush"):
        monkeypatch.setattr(
            "subio_v2.workflow.uploader.GistBatchUploader." + target, denied
        )
    monkeypatch.setattr(
        "subio_v2.workflow.publication.ArtifactPublisher.commit", denied
    )
    result = _render(path, config, pairs=[("credential", "request-value")])
    draft = result.artifact_result.drafts[0]
    assert age.is_age_encrypted(draft.content)
    output = yaml.safe_load(age.decrypt_bytes(draft.content.encode(), secret))
    assert output["proxies"][0]["password"] == "alice-request-value"
    assert result.artifact_result.summaries[0].user == "alice"
    assert result.artifact_result.upload_requests == ()
    assert not (tmp_path / "dist").exists()


@pytest.mark.parametrize("failure", ["parse", "emit", "ruleset"])
def test_scoped_errors_use_strict_existing_gate_despite_static_opt_out(
    tmp_path, monkeypatch, failure
):
    path, data = _fixture(tmp_path, parameterized=False)
    data["allow_conversion_errors"] = True
    data["artifact"][0]["allow_conversion_errors"] = True
    document = yaml.safe_load((tmp_path / "nodes.yaml").read_text())
    if failure == "parse":
        document["proxies"].append("invalid entry")
    elif failure == "emit":
        data["artifact"][0]["type"] = "v2rayn"
        document["proxies"].append(
            {
                "name": "unsupported",
                "type": "hysteria2",
                "server": "example.test",
                "port": 443,
                "password": "synthetic",
            }
        )
        (tmp_path / "client.j2").write_text("{{ nodes.render() }}")
    else:
        data["ruleset"] = [
            {"name": "bad", "url": "https://unused.test/rules", "type": "surge"}
        ]
        monkeypatch.setattr(
            RunRemoteLoader, "fetch", lambda *args, **kwargs: b"USER-AGENT,*Safari*"
        )
        (tmp_path / "client.j2").write_text('{{ remote_bad("DIRECT") }}')
    (tmp_path / "nodes.yaml").write_text(yaml.safe_dump(document))
    config = _snapshot(path, data)
    static_result = WorkflowEngine(str(path)).prepare().artifact_result
    assert static_result.drafts and any(
        issue.severity == "error" for issue in static_result.issues
    )
    monkeypatch.setattr(
        "subio_v2.workflow.artifacts.ArtifactGenerationService._stage",
        lambda *args: pytest.fail("Staged partial output"),
    )
    with pytest.raises(ArtifactGenerationError) as error:
        _render(path, config)
    assert any(issue.severity == "error" for issue in error.value.issues)
    assert (
        config.allow_conversion_errors and config.artifacts[0].allow_conversion_errors
    )


@pytest.mark.parametrize(
    "target, field, parameter, value",
    [
        ("dae", "name", "name", "x': 'malformed"),
        ("dae", "server", "host", "good.example#fragment"),
        ("v2rayn", "server", "host", "good.example#fragment"),
    ],
)
def test_scoped_parameterized_encoding_errors_block_despite_static_opt_out(
    tmp_path, monkeypatch, target, field, parameter, value
):
    path, data = _fixture(tmp_path, parameterized=False)
    data["allow_conversion_errors"] = True
    data["artifact"][0].update({"type": target, "allow_conversion_errors": True})
    (tmp_path / "client.j2").write_text("{{ nodes.render() }}")
    document = yaml.safe_load((tmp_path / "nodes.yaml").read_text())
    document["proxies"].append(
        {"name": "safe", "type": "socks5", "server": "example.test", "port": 1080}
    )
    document["proxies"][0][field] = value
    (tmp_path / "nodes.yaml").write_text(yaml.safe_dump(document))
    _snapshot(path, data)
    static_result = WorkflowEngine(str(path)).prepare().artifact_result
    assert static_result.drafts
    assert any(
        issue.field == field and issue.code == "conversion.invalid-value"
        for issue in static_result.issues
    )

    data["provider"][0]["parameterized"] = True
    document["proxies"][0][field] = "{{ params." + parameter + " }}"
    (tmp_path / "nodes.yaml").write_text(yaml.safe_dump(document))
    config = _snapshot(path, data)
    monkeypatch.setattr(
        "subio_v2.workflow.artifacts.ArtifactGenerationService._stage",
        lambda *args: pytest.fail("Staged malformed target output"),
    )
    with pytest.raises(ArtifactGenerationError) as error:
        _render(path, config, pairs=[(parameter, value)])
    assert any(
        issue.field == field
        and issue.code == "conversion.invalid-value"
        and issue.stage == "emit"
        and issue.severity == "error"
        for issue in error.value.issues
    )
    assert not (tmp_path / "dist").exists()


@pytest.mark.parametrize("native", [False, True])
@pytest.mark.parametrize("field, value, protocol", [
    ("name", "#hidden", "socks5"),
    ("name", "//hidden", "socks5"),
    ("name", " #hidden", "socks5"),
    ("name", " //hidden", "socks5"),
    ("name", " ", "socks5"),
    ("name", " leading", "socks5"),
    ("name", "trailing ", "socks5"),
    ("name", " both ", "socks5"),
    ("server", "host=value", "socks5"),
    ("server", "host=value", "http"),
    ("server", "host=value", "ss"),
    ("server", "host=value", "trojan"),
])
def test_scoped_surge_parameter_errors_block_before_staging_despite_static_opt_out(
    tmp_path, monkeypatch, native, field, value, protocol
):
    path, data = _fixture(tmp_path, native=native, parameterized=False)
    data["allow_conversion_errors"] = True
    data["artifact"][0].update({"type": "surge", "allow_conversion_errors": True})
    (tmp_path / "client.j2").write_text("{{ nodes.render() }}")
    document = yaml.safe_load((tmp_path / "nodes.yaml").read_text())
    key = "nodes" if native else "proxies"
    node = document[key][0]
    node.update({
        "type": "shadowsocks" if native and protocol == "ss" else protocol,
        "password": "synthetic",
    })
    if protocol == "ss":
        node["cipher"] = "aes-256-gcm"
    document[key].append({**node, "name": "safe", "server": "example.test"})
    node[field] = value
    (tmp_path / "nodes.yaml").write_text(yaml.safe_dump(document))
    _snapshot(path, data)
    static = WorkflowEngine(str(path)).prepare().artifact_result
    assert static.drafts
    assert any(
        issue.field == field and issue.code == "conversion.invalid-value"
        for issue in static.issues
    )

    parameter = "name" if field == "name" else "host"
    data["provider"][0]["parameterized"] = True
    node[field] = "{{ params." + parameter + " }}"
    (tmp_path / "nodes.yaml").write_text(yaml.safe_dump(document))
    config = _snapshot(path, data)
    monkeypatch.setattr(
        "subio_v2.workflow.artifacts.ArtifactGenerationService._stage",
        lambda *args: pytest.fail("Staged malformed Surge output"),
    )
    with pytest.raises(ArtifactGenerationError) as error:
        _render(path, config, pairs=[(parameter, value)])
    assert any(
        issue.field == field and issue.code == "conversion.invalid-value"
        and issue.severity == "error"
        for issue in error.value.issues
    )
    assert config.allow_conversion_errors and config.artifacts[0].allow_conversion_errors
    assert not (tmp_path / "dist").exists()


@pytest.mark.parametrize("native", [False, True])
@pytest.mark.parametrize("parameter, value", [
    ("name", "plain"), ("name", "foo#bar"), ("name", "foo//bar"),
    ("name", "internal space"), ("host", "example.test"),
    ("host", "comma,host"), ("host", 'quoted"host'),
])
def test_scoped_surge_parameter_neighbors_round_trip_exactly(tmp_path, native, parameter, value):
    path, data = _fixture(tmp_path, native=native)
    data["artifact"][0]["type"] = "surge"
    (tmp_path / "client.j2").write_text("{{ nodes.render() }}")
    config = _snapshot(path, data)
    result = _render(path, config, pairs=[
        (parameter, value), ("credential", 'pass=word, with "quotes"'),
    ])
    assert not result.artifact_result.issues
    output = result.artifact_result.drafts[0].content
    parsed = get_parser("surge").parse_result(output)
    assert parsed.issues == [] and len(parsed.nodes) == 1
    node = parsed.nodes[0]
    assert (node.name if parameter == "name" else node.server) == value
    assert node.password == 'pass=word, with "quotes"'


@pytest.mark.parametrize("native", [False, True])
@pytest.mark.parametrize("tag", ["!!pairs", "!!omap"])
@pytest.mark.parametrize("position", ["field", "outside", "cycle"])
def test_scoped_tuple_tags_fail_before_staging_despite_static_opt_out(
    tmp_path, monkeypatch, native, tag, position
):
    path, data = _fixture(tmp_path, native=native)
    data["allow_conversion_errors"] = True
    data["artifact"][0]["allow_conversion_errors"] = True
    key = "nodes" if native else "proxies"
    tagged = tag + ' [{static: "{{ params.name }}"}]'
    source = {
        "field": f"{key}: [{{password: {tagged}}}]",
        "outside": f"{key}: []\nother: {tagged}",
        "cycle": f"{key}: &cycle {tag} [{{again: *cycle}}]",
    }[position]
    if native:
        source = "version: 2\n" + source
    (tmp_path / "nodes.yaml").write_text(source)
    config = _snapshot(path, data)
    monkeypatch.setattr(
        "subio_v2.workflow.artifacts.ArtifactGenerationService._stage",
        lambda *args: pytest.fail("Staged an unsupported tuple document"),
    )
    with pytest.raises(ValueError, match="Unsupported tuple"):
        _render(path, config)
    assert not (tmp_path / "dist").exists()


def test_two_routes_get_fresh_concurrent_state_and_independent_defaults(
    tmp_path, monkeypatch
):
    path, data = _fixture(tmp_path)
    second = json.loads(json.dumps(data["artifact"][0]))
    second.update(
        {
            "name": "b.yaml",
            "params": {
                **second["params"],
                "name": {"type": "string", "default": "route-b"},
                "port": {"type": "integer", "default": 443, "min": 101, "max": 500},
            },
        }
    )
    data["artifact"].append(second)
    data["options"] = {"nested": {"values": []}}
    data["artifact"][0]["options"] = {"local": {"values": []}}
    config = _snapshot(path, data)
    (tmp_path / "snippet").mkdir()
    (tmp_path / "snippet" / "shared").write_text("policy\nDOMAIN,example.test")
    prepared = prepare_resources(str(path), config)
    candidates = [prepared.candidates[name] for name in ("out.yaml", "b.yaml")]
    barrier = threading.Barrier(2)
    from subio_v2.adapters.catalog import get_emitter
    from subio_v2.workflow.providers import PreparedProvider

    emitters, collectors = [], []
    get_callables = RuleSetStore.get_callables
    bind = PreparedProvider.bind

    def collect_callables(store, platform, collector=None):
        collectors.append(collector)
        return get_callables(store, platform, collector)

    def emitter_factory(platform):
        emitter = get_emitter(platform)
        emitters.append(emitter)
        return emitter

    def parallel_bind(provider, parameters):
        barrier.wait(timeout=5)
        return bind(provider, parameters)

    monkeypatch.setattr(PreparedProvider, "bind", parallel_bind)
    monkeypatch.setattr("subio_v2.workflow.artifacts.get_emitter", emitter_factory)
    monkeypatch.setattr(RuleSetStore, "get_callables", collect_callables)
    with ThreadPoolExecutor(max_workers=2) as pool:
        jobs = [pool.submit(candidate.render, name, normalize_parameters(
            artifact.params, [("credential", credential)]
        )) for candidate, name, artifact, credential in zip(
            candidates, ("out.yaml", "b.yaml"), config.artifacts, ("a", "b")
        )]
        results = [job.result(timeout=10) for job in jobs]
    outputs = [yaml.safe_load(result.artifact_result.drafts[0].content) for result in results]
    assert [(out["proxies"][0]["name"], out["proxies"][0]["port"],
             out["proxies"][0]["password"]) for out in outputs] == [
        ("route-a", 80, "a"), ("route-b", 443, "b")
    ]
    assert emitters[0] is not emitters[1] and collectors[0] is not collectors[1]
    nodes = [result.provider_result.providers["source"][0] for result in results]
    assert nodes[0] is not nodes[1] and nodes[0].tls is not nodes[1].tls
    nodes[0].password = "changed"
    assert nodes[1].password == "b"
    assert config.options["nested"]["values"] == []
    assert config.artifacts[0].options["local"]["values"] == []
    monkeypatch.setattr(PreparedProvider, "bind", bind)
    assert yaml.safe_load(_render(path, config).artifact_result.drafts[0].content)["proxies"][0]["password"] == "synthetic"


def test_unknown_filename_is_rejected_by_prepared_artifact(tmp_path):
    path, data = _fixture(tmp_path)
    config = _snapshot(path, data)
    candidate = prepare_resources(str(path), config).candidates["out.yaml"]
    with pytest.raises(ConfigError, match="Unknown subscription filename"):
        candidate.render("unconfigured", {})
