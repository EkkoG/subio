import json
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from types import MappingProxyType

import pytest
import yaml

from subio_v2.core.errors import (
    ArtifactGenerationError,
    ConfigError,
    ProviderLoadError,
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


def _engine(path, config, file_name="out.yaml", pairs=()):
    artifact = next(
        item
        for item in config.artifacts
        if any(name == file_name for name, _ in item.output_names())
    )
    parameters = normalize_parameters(artifact.params, pairs)
    return WorkflowEngine.for_render(str(path), config, file_name, parameters)


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
    engine = _engine(
        path, config, pairs=[("credential", "literal {{ 7 * 7 }} & + = #")]
    )
    assert [item.name for item in engine.config.providers] == ["source"]
    result = engine.prepare()
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
    assert _engine(path, config).prepare().artifact_result.drafts
    assert calls == ["https://unused.test/rules"]
    monkeypatch.setattr(RunRemoteLoader, "fetch", lambda *args, **kwargs: b"")
    with pytest.raises(ConfigError, match="empty"):
        _engine(path, config).prepare()


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


def test_static_template_defaults_work_and_required_values_block_publication(
    tmp_path, monkeypatch
):
    path, data = _fixture(tmp_path, parameterized=False)
    config = _snapshot(path, data)
    output = WorkflowEngine(str(path)).prepare().artifact_result.drafts[0].content
    assert yaml.safe_load(output)["values"]["port"] == 80
    assert config.artifacts[0].params["port"].default == 80
    data["artifact"][0]["params"]["credential"] = {
        "type": "string",
        "required": True,
    }
    _snapshot(path, data)
    monkeypatch.setattr(
        "subio_v2.workflow.publication.ArtifactPublisher.commit",
        lambda *_: pytest.fail("Published"),
    )
    monkeypatch.setattr(
        "subio_v2.workflow.engine.queue_upload_requests",
        lambda *_: pytest.fail("Queued uploads"),
    )
    with pytest.raises(ArtifactGenerationError, match="requires runtime parameter"):
        WorkflowEngine(str(path)).run()
    assert not (tmp_path / "dist").exists()


def test_params_namespace_is_nested_immutable_and_static_defaults_are_opted_in(
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
    engine = WorkflowEngine.for_render(str(path), config, "out.yaml", runtime)
    runtime["self"] = "changed after engine construction"
    render_result = engine.renderer.render_result
    contexts = []

    def capture(template, context, *args):
        contexts.append(context)
        with pytest.raises(TypeError):
            context["params"]["credential"] = "changed"
        return render_result(template, context, *args)

    monkeypatch.setattr(engine.renderer, "render_result", capture)
    assert (
        engine.prepare().artifact_result.drafts[0].content
        == "self-value|items-value|True"
    )
    assert "self" not in contexts[0] and "credential" not in contexts[0]
    data["artifact"][0].pop("params")
    _snapshot(path, data)
    (tmp_path / "client.j2").write_text("{{ params is undefined }}")
    assert (
        WorkflowEngine(str(path)).prepare().artifact_result.drafts[0].content == "True"
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
        _engine(path, config, "out.json", pairs=[("credential", 'literal " & {{ 7 * 7 }}')])
        .prepare()
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
        _engine(path, config).prepare()


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
    engine = _engine(path, config, pairs=[("credential", "request-value")])
    with pytest.raises(ConfigError, match="only support preparation"):
        engine.run()
    result = engine.prepare()
    draft = result.artifact_result.drafts[0]
    assert age.is_age_encrypted(draft.content)
    output = yaml.safe_load(age.decrypt_bytes(draft.content.encode(), secret))
    assert output["proxies"][0]["password"] == "alice-request-value"
    assert result.artifact_result.summaries[0].user == "alice"
    assert result.artifact_result.upload_requests == ()
    assert engine.config.uploaders == ()
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
    engine = _engine(path, config)
    assert not engine.config.allow_conversion_errors
    assert not engine.config.artifacts[0].allow_conversion_errors
    monkeypatch.setattr(
        "subio_v2.workflow.artifacts.ArtifactGenerationService._stage",
        lambda *args: pytest.fail("Staged partial output"),
    )
    with pytest.raises(ArtifactGenerationError) as error:
        engine.prepare()
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
    engine = _engine(path, config, pairs=[(parameter, value)])
    monkeypatch.setattr(
        "subio_v2.workflow.artifacts.ArtifactGenerationService._stage",
        lambda *args: pytest.fail("Staged malformed target output"),
    )
    with pytest.raises(ArtifactGenerationError) as error:
        engine.prepare()
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
    engine = _engine(path, config, pairs=[(parameter, value)])
    assert not engine.config.allow_conversion_errors
    assert not engine.config.artifacts[0].allow_conversion_errors
    monkeypatch.setattr(
        "subio_v2.workflow.artifacts.ArtifactGenerationService._stage",
        lambda *args: pytest.fail("Staged malformed Surge output"),
    )
    with pytest.raises(ArtifactGenerationError) as error:
        engine.prepare()
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
    result = _engine(path, config, pairs=[
        (parameter, value), ("credential", 'pass=word, with "quotes"'),
    ]).prepare()
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
    with pytest.raises(ProviderLoadError, match="Unsupported tuple"):
        _engine(path, config).prepare()
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
    engines = [
        _engine(path, config, file_name, [("credential", value)])
        for file_name, value in (("out.yaml", "a"), ("b.yaml", "b"))
    ]
    assert engines[0].renderer is not engines[1].renderer
    assert engines[0]._local_rulesets is not engines[1]._local_rulesets
    engines[0].config.options["nested"]["values"].append("a")
    engines[0].config.artifacts[0].options["local"]["values"].append("a")
    assert engines[1].config.options["nested"]["values"] == []
    assert config.options["nested"]["values"] == []
    assert config.artifacts[0].options["local"]["values"] == []
    barrier = threading.Barrier(2)
    from subio_v2.adapters.catalog import get_parser
    from subio_v2.adapters.catalog import get_emitter

    parsers, loaders, emitters, collectors = [], [], [], []
    get_callables = RuleSetStore.get_callables

    def collect_callables(store, platform, collector=None):
        collectors.append(collector)
        return get_callables(store, platform, collector)

    def emitter_factory(platform):
        emitter = get_emitter(platform)
        emitters.append(emitter)
        return emitter

    def parser_factory(*args, **kwargs):
        parser = get_parser(*args, **kwargs)
        parsers.append(parser)
        parse_result = parser.parse_result

        def parse(content):
            barrier.wait(timeout=5)
            return parse_result(content)

        parser.parse_result = parse
        return parser

    def loader_factory(engine):
        loader = RunRemoteLoader()
        loaders.append(loader)
        return loader

    monkeypatch.setattr("subio_v2.workflow.providers.get_parser", parser_factory)
    monkeypatch.setattr("subio_v2.workflow.artifacts.get_emitter", emitter_factory)
    monkeypatch.setattr(RuleSetStore, "get_callables", collect_callables)
    monkeypatch.setattr(WorkflowEngine, "_remote_loader", loader_factory)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda engine: engine.prepare(), engines))
    outputs = [
        yaml.safe_load(result.artifact_result.drafts[0].content) for result in results
    ]
    assert [
        (
            out["proxies"][0]["name"],
            out["proxies"][0]["port"],
            out["proxies"][0]["password"],
        )
        for out in outputs
    ] == [("route-a", 80, "a"), ("route-b", 443, "b")]
    assert parsers[0] is not parsers[1] and loaders[0] is not loaders[1]
    assert emitters[0] is not emitters[1]
    assert collectors[0] is not collectors[1]
    assert all(loader._session is None for loader in loaders)
    nodes = [result.provider_result.providers["source"][0] for result in results]
    assert nodes[0] is not nodes[1] and nodes[0].tls is not nodes[1].tls
    nodes[0].password = "changed"
    assert nodes[1].password == "b"
    monkeypatch.setattr("subio_v2.workflow.providers.get_parser", get_parser)
    assert (
        yaml.safe_load(
            _engine(path, config).prepare().artifact_result.drafts[0].content
        )["proxies"][0]["password"]
        == "synthetic"
    )


def test_failed_request_closes_loader_and_next_request_has_fresh_nodes(
    tmp_path, monkeypatch
):
    path, data = _fixture(tmp_path)
    config = _snapshot(path, data)
    loaders = []

    def loader_factory(engine):
        loader = RunRemoteLoader()
        loaders.append(loader)
        return loader

    monkeypatch.setattr(WorkflowEngine, "_remote_loader", loader_factory)
    failing = _engine(path, config)
    failing.config = replace(
        failing.config,
        artifacts=(replace(failing.config.artifacts[0], template="missing.j2"),),
    )
    with pytest.raises(TemplateRenderError):
        failing.prepare()
    result = _engine(path, config, pairs=[("credential", "after-failure")]).prepare()
    assert result.provider_result.providers["source"][0].password == "after-failure"
    assert loaders[0] is not loaders[1]
    assert all(loader._session is None for loader in loaders)


def test_unknown_filename_is_rejected_before_snippet_io(tmp_path, monkeypatch):
    path, data = _fixture(tmp_path)
    config = _snapshot(path, data)
    monkeypatch.setattr(
        "subio_v2.workflow.engine.load_snippets",
        lambda *_: pytest.fail("Loaded snippets"),
    )
    with pytest.raises(ConfigError, match="Unknown subscription filename"):
        WorkflowEngine.for_render(str(path), config, "unconfigured", {})
