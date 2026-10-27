import builtins
import copy
import json
import pickle
import threading
from concurrent.futures import ThreadPoolExecutor

import jinja2
import json5
import pytest
import toml
import yaml

from subio_v2.adapters.clash_family.parser import ClashParser
from subio_v2.adapters.subio.parser import SubioParser
from subio_v2.core.errors import (
    ArtifactGenerationError,
    ConfigError,
    TemplateRenderError,
)
from subio_v2.core.parameters import MissingParameterError
from subio_v2.infrastructure import age
from subio_v2.infrastructure.remote import RunRemoteLoader
from subio_v2.rules.runtime import RuleSetStore
from subio_v2.server import _failure_status
from subio_v2.workflow.config import ConfigLoader
from subio_v2.workflow.parameters import normalize_parameters
from subio_v2.workflow.providers import ProviderLoaderService
from subio_v2.workflow.rendering import prepare_resources
from subio_v2.workflow.template import PreparedTemplates


def _fixture(tmp_path, *, fmt="mihomo", parameterized=True, encode=yaml.safe_dump):
    node = {
        "name": "{{ params.name }}",
        "type": "socks5",
        "server": "example.test",
        "port": 1080,
        "password": "{{ params.credential }}",
    }
    if not parameterized:
        node.update(name="static", password="static-secret")
    document = (
        {"version": 2, "nodes": [node]} if fmt == "subio" else {"proxies": [node]}
    )
    (tmp_path / "nodes.source").write_text(encode(document))
    (tmp_path / "client.j2").write_text(
        "proxies:\n{{ nodes.render() | indent(2, true) }}\nparams: {{ params | tojson }}\n"
    )
    data = {
        "provider": [
            {
                "name": "source",
                "type": fmt,
                "file": "nodes.source",
                "parameterized": parameterized,
            }
        ],
        "artifact": [
            {
                "name": "out.yaml",
                "type": "mihomo",
                "providers": ["source"],
                "template": "client.j2",
                "params": {
                    "name": {"default": "default-name"},
                    "credential": {"default": "default-secret"},
                },
            }
        ],
    }
    return data


def _config(tmp_path, data):
    path = tmp_path / "config.json"
    path.write_text(json.dumps(data))
    return str(path), ConfigLoader.load(str(path))


def _render(candidate, file_name="out.yaml", pairs=()):
    params = normalize_parameters(candidate._config.artifacts[0].params, pairs)
    return candidate.render(file_name, params)


def _denied(*args, **kwargs):
    pytest.fail("Warm rendering reached source I/O, source decoding or publication")


@pytest.mark.parametrize(
    "fmt,encode,serialization",
    [
        ("mihomo", yaml.safe_dump, "yaml"),
        ("clash", yaml.safe_dump, "yaml"),
        ("clash-meta", yaml.safe_dump, "yaml"),
        ("subio", toml.dumps, "toml"),
        ("subio", json.dumps, "json"),
        ("subio", lambda value: "// native\n" + json5.dumps(value), "json5"),
        ("subio", yaml.safe_dump, "yaml"),
    ],
)
def test_decoded_once_then_real_warm_render_has_no_source_or_publication_work(
    tmp_path, monkeypatch, fmt, encode, serialization
):
    data = _fixture(tmp_path, fmt=fmt, encode=encode)
    data["provider"].append({"name": "unused", "type": "mihomo", "file": "absent"})
    data["ruleset"] = [{"name": "shared", "url": "https://synthetic.test/rules"}]
    data["remote"] = {"cache": {"enabled": True, "stale_if_error": True}}
    (tmp_path / "snippet").mkdir()
    (tmp_path / "snippet" / "local").write_text("policy\nDOMAIN,local.test")
    (tmp_path / "client.j2").write_text(
        "proxies:\n{{ nodes.render() | indent(2, true) }}\n"
        "remote: {{ remote_shared(params.credential) | tojson }}\n"
        "local: {{ local(params.credential) | tojson }}\n"
    )
    path, config = _config(tmp_path, data)
    parser_type = SubioParser if fmt == "subio" else ClashParser
    decode = parser_type.decode_source
    decodes, fetches, loaders = [], [], []

    def decode_once(content):
        decodes.append(content)
        return decode(content)

    def fetch(loader, url, **kwargs):
        fetches.append(url)
        loaders.append(loader)
        assert not loader.cache_enabled and not loader.stale_if_error
        return b"DOMAIN,remote.test"

    monkeypatch.setattr(parser_type, "decode_source", staticmethod(decode_once))
    monkeypatch.setattr(RunRemoteLoader, "fetch", fetch)
    prepared = prepare_resources(path, config)
    assert not prepared.failures and list(prepared.candidates) == ["out.yaml"]
    assert len(decodes) == 1 and fetches == ["https://synthetic.test/rules"]
    assert all(loader._session is None for loader in loaders)
    candidate = prepared.candidates["out.yaml"]
    private_document = pickle.dumps(candidate._providers[0]._document)
    with monkeypatch.context() as warm:
        warm.setattr(builtins, "open", _denied)
        warm.setattr(ProviderLoaderService, "_fetch_content", _denied)
        warm.setattr(parser_type, "decode_source", staticmethod(_denied))
        warm.setattr(RunRemoteLoader, "__init__", _denied)
        warm.setattr("subio_v2.workflow.engine.WorkflowEngine.__init__", _denied)
        warm.setattr(
            "subio_v2.workflow.publication.ArtifactPublisher.__init__", _denied
        )
        warm.setattr("subio_v2.workflow.uploader.GistBatchUploader.__init__", _denied)
        warm.setattr("subio_v2.workflow.rendering.load_snippets", _denied)
        warm.setattr("subio_v2.workflow.rendering.load_rulesets", _denied)
        results = [
            _render(candidate, pairs=[("credential", value)])
            for value in ("first {{ params.name }}", "", "third")
        ]
    for result, value in zip(results, ("first {{ params.name }}", "", "third")):
        output = yaml.safe_load(result.artifact_result.drafts[0].content)
        assert output["proxies"][0].get("password", "") == value
        assert result.provider_result.providers["source"][0].password == value
        assert yaml.safe_load(output["remote"]) == ["DOMAIN,remote.test," + value]
        assert yaml.safe_load(output["local"]) == ["DOMAIN,local.test," + value]
        assert (
            result.provider_result.providers["source"][0].source_context.format
            == serialization
        )
        assert not result.artifact_result.upload_requests
    assert pickle.dumps(candidate._providers[0]._document) == private_document
    assert not (tmp_path / "dist").exists()


@pytest.mark.parametrize("native", [False, True])
def test_concurrent_secrets_defaults_users_and_nested_state_are_request_owned(
    tmp_path, monkeypatch, native
):
    data = _fixture(tmp_path, fmt="subio" if native else "mihomo")
    key = "nodes" if native else "proxies"
    document = yaml.safe_load((tmp_path / "nodes.source").read_text())
    node = document[key][0]
    node["users"] = {
        "alice": {"password": "alice-{{ params.credential }}"},
        "bob": {"password": "bob-{{ params.credential }}"},
    }
    if native:
        node["tls"] = {"enabled": True, "alpn": ["h2", "{{ params.credential }}"]}
    else:
        node.update(tls=True, alpn=["h2", "{{ params.credential }}"])
        node["future"] = node["future_alias"] = {"values": ["{{ params.credential }}"]}
    document[key].append(
        node
    )  # Real YAML aliases are copied independently by the binder.
    (tmp_path / "nodes.source").write_text(yaml.safe_dump(document))
    data["artifact"][0].update(
        name="out-{user}.yaml",
        users=["alice", "bob"],
        on_duplicate_name="keep_first",
        options={"local": {"values": []}},
    )
    second = copy.deepcopy(data["artifact"][0])
    second.update(name="second.yaml", users=[], user="alice")
    second["params"]["name"]["default"] = "second-default"
    data["artifact"].append(second)
    data["options"] = {"global": {"values": []}}
    (tmp_path / "helper.j2").write_text(
        "{% set history = [] %}{% macro mark(value) %}"
        "{% set _ = history.append(value) %}{{ history | tojson }}{% endmacro %}"
    )
    (tmp_path / "client.j2").write_text(
        "{% import 'helper.j2' as helper %}"
        "{% set _ = options.global['values'].append(params.credential) %}"
        "{% set _ = options.local['values'].append(params.credential) %}"
        "proxies:\n{{ nodes.render() | indent(2, true) }}\n"
        "history: {{ helper.mark(params.credential) }}\n"
        "options: {{ options | tojson }}\n"
        "rules: {{ local(params.credential) | tojson }}\n"
    )
    (tmp_path / "snippet").mkdir()
    (tmp_path / "snippet" / "local").write_text("policy\nDOMAIN,local.test")
    path, config = _config(tmp_path, data)
    round_ = prepare_resources(path, config)
    a = round_.candidates["out-alice.yaml"]
    b = round_.candidates["second.yaml"]
    assert round_.candidates["out-bob.yaml"] is a
    assert a._providers[0] is b._providers[0]
    before = pickle.dumps(a._providers[0]._document)
    collectors = []
    barrier = threading.Barrier(2)
    callables = RuleSetStore.get_callables

    def collect(store, platform, collector=None):
        collectors.append(collector)
        barrier.wait(timeout=5)
        return callables(store, platform, collector)

    with monkeypatch.context() as concurrent:
        concurrent.setattr(RuleSetStore, "get_callables", collect)
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [
                pool.submit(_render, a, "out-bob.yaml", [("credential", "secret-b")]),
                pool.submit(_render, b, "second.yaml", [("credential", "secret-a")]),
            ]
            results = [future.result(timeout=10) for future in futures]
    assert collectors[0] is not collectors[1]
    for result, user, secret, name in zip(
        results,
        ("bob", "alice"),
        ("secret-b", "secret-a"),
        ("default-name", "second-default"),
    ):
        output = yaml.safe_load(result.artifact_result.drafts[0].content)
        assert output["history"] == [secret]
        assert output["options"] == {
            "global": {"values": [secret]},
            "local": {"values": [secret]},
        }
        assert output["proxies"][0]["password"] == user + "-" + secret
        assert output["proxies"][0]["name"] == name
        nodes = result.provider_result.providers["source"]
        assert nodes[0] is not nodes[1] and nodes[0].tls is not nodes[1].tls
        if not native:
            assert nodes[0].extra["future"] is not nodes[0].extra["future_alias"]
            nodes[0].extra["future"]["values"].append("changed")
    assert pickle.dumps(a._providers[0]._document) == before
    assert config.options["global"]["values"] == []
    assert config.artifacts[0].options["local"]["values"] == []
    assert yaml.safe_load(
        _render(a, "out-alice.yaml").artifact_result.drafts[0].content
    )["history"] == ["default-secret"]


def test_static_nodes_are_parsed_and_transformed_once_then_deeply_cloned(
    tmp_path, monkeypatch
):
    data = _fixture(tmp_path, parameterized=False)
    document = yaml.safe_load((tmp_path / "nodes.source").read_text())
    document["proxies"][0].update(
        tls=True,
        alpn=["h2"],
        future={"values": ["original"]},
        users={"alice": {"password": "alice-secret"}},
    )
    (tmp_path / "nodes.source").write_text(yaml.safe_dump(document))
    data["provider"][0].update(
        rename={"add_prefix": "renamed-"}, filters={"include": "static"}
    )
    data["provider"].append({**data["provider"][0], "name": "shared-source"})
    data["artifact"].append(
        {"name": "second.yaml", "type": "mihomo", "providers": ["shared-source"]}
    )
    path, config = _config(tmp_path, data)
    fetch = ProviderLoaderService._fetch_content
    parse = ClashParser.parse_result
    process = ProviderLoaderService._process_nodes
    reads, parses, transforms = [], [], []

    def counted(*args):
        reads.append(args[1].file)
        return fetch(*args)

    def counted_parse(parser, content):
        parses.append(parser)
        return parse(parser, content)

    def counted_process(nodes, config):
        transforms.append(config.name)
        return process(nodes, config)

    monkeypatch.setattr(ProviderLoaderService, "_fetch_content", counted)
    monkeypatch.setattr(ClashParser, "parse_result", counted_parse)
    monkeypatch.setattr(
        ProviderLoaderService, "_process_nodes", staticmethod(counted_process)
    )
    prepared = prepare_resources(path, config)
    assert reads == ["nodes.source"]
    assert len(parses) == 2 and parses[0] is not parses[1]
    assert transforms == ["source", "shared-source"]
    candidate = prepared.candidates["out.yaml"]
    with monkeypatch.context() as warm:
        warm.setattr(ClashParser, "parse_result", _denied)
        warm.setattr(ClashParser, "parse_document", _denied)
        warm.setattr(ProviderLoaderService, "_process_nodes", _denied)
        warm.setattr(builtins, "open", _denied)
        first = _render(candidate)
        node = first.provider_result.providers["source"][0]
        node.tls.alpn.append("changed")
        node.extra["future"]["values"].append("changed")
        node.users["alice"]["password"] = "changed"
        second = _render(candidate)
    node = second.provider_result.providers["source"][0]
    assert node.name == "renamed-static" and node.tls.alpn == ["h2"]
    assert node.extra["future"] == {"values": ["original"]}
    assert node.users["alice"]["password"] == "alice-secret"


@pytest.mark.parametrize("fatal", [False, True])
@pytest.mark.parametrize("allow_errors,allow_empty", [(False, False), (True, False), (True, True)])
def test_returned_parse_errors_complete_preparation_and_follow_artifact_policy(
    tmp_path, fatal, allow_errors, allow_empty
):
    data = _fixture(tmp_path, fmt="subio" if fatal else "mihomo", parameterized=False)
    source = (
        {"version": 1, "nodes": []}
        if fatal
        else {
            "proxies": [
                {
                    "name": "valid",
                    "type": "socks5",
                    "server": "example.test",
                    "port": 1080,
                },
                "invalid",
            ]
        }
    )
    (tmp_path / "nodes.source").write_text(yaml.safe_dump(source))
    data["artifact"][0].update(allow_conversion_errors=allow_errors, allow_empty=allow_empty)
    path, config = _config(tmp_path, data)
    prepared = prepare_resources(path, config)
    assert not prepared.failures
    candidate = prepared.candidates["out.yaml"]
    static = candidate._providers[0]._static
    assert len(static.providers["source"]) == (0 if fatal else 1)
    assert any(issue.severity == "error" for issue in static.issues["source"])
    if allow_errors and (not fatal or allow_empty):
        result = _render(candidate).artifact_result
        proxies = yaml.safe_load(result.drafts[0].content)["proxies"]
        assert [node["name"] for node in proxies] == ([] if fatal else ["valid"])
        assert any(issue.severity == "error" for issue in result.issues)
    else:
        with pytest.raises(ArtifactGenerationError) as error:
            _render(candidate)
        assert _failure_status(error.value) == 422
        assert any(issue.severity == "error" for issue in error.value.issues)
    assert config.artifacts[0].allow_conversion_errors == allow_errors


def test_partial_preparation_scope_failures_and_loader_cleanup_are_sanitized(
    tmp_path, monkeypatch
):
    data = _fixture(tmp_path)
    data["provider"].append(
        {"name": "broken", "type": "mihomo", "file": "sensitive-absent"}
    )
    data["artifact"].append(
        {"name": "broken.yaml", "type": "mihomo", "providers": ["broken"]}
    )
    data["artifact"].append(
        {
            "name": "bad-root.yaml",
            "type": "mihomo",
            "providers": ["source"],
            "template": "broken.j2",
        }
    )
    (tmp_path / "broken.j2").write_text("{% invalid %}")
    path, config = _config(tmp_path, data)
    closed = []
    close = RunRemoteLoader.close

    def closing(loader):
        close(loader)
        closed.append(loader)

    monkeypatch.setattr(RunRemoteLoader, "close", closing)
    result = prepare_resources(path, config)
    assert list(result.candidates) == ["out.yaml"]
    assert {name: failure.phase for name, failure in result.failures.items()} == {
        "broken.yaml": "provider",
        "bad-root.yaml": "template",
    }
    assert "sensitive" not in repr(result.failures) and "invalid" not in repr(
        result.failures
    )
    assert len(closed) == 1 and closed[0]._session is None
    with pytest.raises(ConfigError):
        _render(result.candidates["out.yaml"], "unknown")
    monkeypatch.setattr(
        "subio_v2.workflow.rendering.load_rulesets",
        lambda *a, **kw: (_ for _ in ()).throw(ValueError("secret")),
    )
    result = prepare_resources(path, config)
    assert not result.candidates and all(
        f.phase == "ruleset" for f in result.failures.values()
    )
    assert "secret" not in repr(result.failures) and len(closed) == 2


def test_age_fixed_user_and_no_publication_requests(tmp_path, monkeypatch):
    data = _fixture(tmp_path)
    document = yaml.safe_load((tmp_path / "nodes.source").read_text())
    document["proxies"][0]["users"] = {
        "alice": {"password": "alice-{{ params.credential }}"}
    }
    (tmp_path / "nodes.source").write_text(yaml.safe_dump(document))
    secret, public = age.generate_x25519_keypair()
    source = tmp_path / "nodes.source"
    source.write_bytes(age.encrypt_bytes(source.read_bytes(), public))
    data["provider"][0]["age_secret_key"] = secret
    data["artifact"][0].update(
        user="alice", age_public_key=public, upload=[{"to": "gist"}]
    )
    data["uploader"] = [{"name": "gist", "type": "gist", "id": "unused"}]
    path, config = _config(tmp_path, data)
    candidate = prepare_resources(path, config).candidates["out.yaml"]
    assert secret not in repr(candidate._providers[0])
    with monkeypatch.context() as warm:
        warm.setattr(age, "decrypt_bytes", _denied)
        result = _render(candidate)
    output = yaml.safe_load(
        age.decrypt_bytes(result.artifact_result.drafts[0].content.encode(), secret)
    )
    assert output["proxies"][0]["password"] == "alice-default-secret"
    assert result.artifact_result.upload_requests == ()
    assert not (tmp_path / "dist").exists()


@pytest.mark.parametrize("failure", ["empty", "utf8", "serialization", "decrypt"])
def test_acquisition_and_serialization_failures_do_not_produce_candidates(
    tmp_path, failure
):
    data = _fixture(tmp_path, parameterized=False)
    if failure == "decrypt":
        data["provider"][0]["age_secret_key"] = age.generate_x25519_keypair()[0]
    content = {
        "empty": b"",
        "utf8": b"\xff\xfe",
        "serialization": b"proxies: [",
        "decrypt": b"-----BEGIN AGE ENCRYPTED FILE-----invalid",
    }[failure]
    (tmp_path / "nodes.source").write_bytes(content)
    path, config = _config(tmp_path, data)
    result = prepare_resources(path, config)
    assert not result.candidates
    assert result.failures["out.yaml"].phase == "provider"
    assert result.failures["out.yaml"].category == "unavailable"


@pytest.mark.parametrize("native", [False, True])
@pytest.mark.parametrize(
    "source,message",
    [
        ("{key}: &loop [*loop]", "Cyclic"),
        ("{key}: []\nother: !!pairs [{{x: y}}]", "Unsupported tuple"),
        ('{key}: [{{password: "{{{{ params.x | upper }}}}"}}]', "Malformed"),
        ('{key}: []\nother: "{{{{ params.x }}}}"', "only allowed"),
    ],
)
def test_prepared_documents_keep_existing_binding_safety(
    tmp_path, native, source, message
):
    data = _fixture(tmp_path, fmt="subio" if native else "mihomo")
    text = source.format(key="nodes" if native else "proxies")
    (tmp_path / "nodes.source").write_text(("version: 2\n" if native else "") + text)
    path, config = _config(tmp_path, data)
    candidate = prepare_resources(path, config).candidates["out.yaml"]
    with pytest.raises(ValueError, match=message):
        _render(candidate, pairs=[("x", "literal")])


def test_memory_templates_inheritance_imports_filters_and_fallback_root_isolation(
    tmp_path, monkeypatch
):
    data = _fixture(tmp_path)
    (tmp_path / "unused.bin").write_bytes(b"\xff\xfe\x00")
    (tmp_path / "unreadable.j2").write_text("secret text")
    (tmp_path / "bad-root.j2").write_text("{% syntax error %}")
    (tmp_path / "base.j2").write_text("{% block content %}{% endblock %}")
    (tmp_path / "macros.j2").write_text(
        "{% macro value(value) %}{{ value | tojson }}{% endmacro %}"
    )
    (tmp_path / "include.j2").write_text("{{ params.credential | to_yaml }}")
    (tmp_path / "client.j2").write_text(
        "{% extends 'base.j2' %}{% import 'macros.j2' as macros %}"
        "{% block content %}{{ macros.value(params.credential) }}|"
        "{% include 'include.j2' %}{% endblock %}"
    )
    data["artifact"].extend(
        [
            {**data["artifact"][0], "name": "bad.yaml", "template": "bad-root.j2"},
            {
                **data["artifact"][0],
                "name": "unreadable.yaml",
                "template": "unreadable.j2",
            },
        ]
    )
    path, config = _config(tmp_path, data)
    original_open = builtins.open

    def read_failure(file, *args, **kwargs):
        if str(file).endswith("unreadable.j2"):
            raise PermissionError("sensitive filename and body")
        return original_open(file, *args, **kwargs)

    with monkeypatch.context() as capture:
        capture.setattr(builtins, "open", read_failure)
        prepared = prepare_resources(path, config)
    assert list(prepared.candidates) == ["out.yaml"]
    assert {failure.phase for failure in prepared.failures.values()} == {"template"}
    (tmp_path / "client.j2").unlink()
    (tmp_path / "include.j2").unlink()
    compile_template = jinja2.Environment.compile

    def compile_helper(environment, source, name=None, *args, **kwargs):
        assert name != "client.j2", "Root template was not precompiled"
        return compile_template(environment, source, name, *args, **kwargs)

    with monkeypatch.context() as warm:
        warm.setattr(builtins, "open", _denied)
        warm.setattr(jinja2.FileSystemLoader, "get_source", _denied)
        warm.setattr(jinja2.Environment, "compile", compile_helper)
        value = 'literal " & {{ params.name }}'
        content = (
            _render(prepared.candidates["out.yaml"], pairs=[("credential", value)])
            .artifact_result.drafts[0]
            .content
        )
    json_value, yaml_value = content.split("|", 1)
    assert json.loads(json_value) == yaml.safe_load(yaml_value) == value


@pytest.mark.parametrize(
    "expression",
    [
        "{% include params.helper ignore missing %}",
        "{% include [params.helper, 'fallback.j2'] %}",
    ],
)
@pytest.mark.parametrize("broken", ["binary", "unreadable", "syntax", "lookup"])
@pytest.mark.parametrize("prefix", ["", "./", "//", "dir//", "dir/./"])
def test_memory_helpers_distinguish_absent_from_broken_under_jinja_fallbacks(
    tmp_path, monkeypatch, expression, broken, prefix
):
    data = _fixture(tmp_path)
    (tmp_path / "client.j2").write_text(expression)
    (tmp_path / "fallback.j2").write_text("fallback")
    helper_dir = tmp_path / "dir" if prefix.startswith("dir/") else tmp_path
    helper_dir.mkdir(exist_ok=True)
    helper = helper_dir / "broken.j2"
    (helper_dir / "healthy.j2").write_text("healthy")
    if broken == "binary":
        helper.write_bytes(b"\xff\xfe")
    else:
        helper.write_text(
            "{% invalid %}" if broken == "syntax" else "unreadable secret"
        )
    path, config = _config(tmp_path, data)
    original_open = builtins.open
    get_source = jinja2.FileSystemLoader.get_source

    def read_failure(file, *args, **kwargs):
        if broken == "unreadable" and str(file).endswith("broken.j2"):
            raise PermissionError("secret body")
        return original_open(file, *args, **kwargs)

    def lookup_failure(loader, environment, name):
        if broken == "lookup" and name.endswith("broken.j2"):
            raise jinja2.TemplateNotFound(name)
        return get_source(loader, environment, name)

    with monkeypatch.context() as capture:
        capture.setattr(builtins, "open", read_failure)
        capture.setattr(jinja2.FileSystemLoader, "get_source", lookup_failure)
        prepared = prepare_resources(path, config)
    assert not prepared.failures
    candidate = prepared.candidates["out.yaml"]
    healthy = _render(candidate, pairs=[("helper", prefix + "healthy.j2")])
    assert healthy.artifact_result.drafts[0].content == "healthy"
    absent = (
        _render(candidate, pairs=[("helper", prefix + "absent.j2")])
        .artifact_result.drafts[0]
        .content
    )
    assert absent == ("" if "ignore missing" in expression else "fallback")
    with pytest.raises(TemplateRenderError) as error:
        _render(candidate, pairs=[("helper", prefix + "broken.j2")])
    assert _failure_status(error.value) == 500
    assert not isinstance(error.value.__cause__, jinja2.TemplateNotFound)
    assert "secret" not in str(error.value)


def test_template_helper_removal_keeps_previous_bundle_and_new_runtime_missing_error(
    tmp_path,
):
    data = _fixture(tmp_path)
    (tmp_path / "client.j2").write_text("{% include 'helper.j2' %}")
    helper = tmp_path / "helper.j2"
    helper.write_text("old helper")
    path, config = _config(tmp_path, data)
    previous = prepare_resources(path, config).candidates["out.yaml"]
    helper.unlink()
    current = prepare_resources(path, config).candidates["out.yaml"]
    assert _render(previous).artifact_result.drafts[0].content == "old helper"
    with pytest.raises(TemplateRenderError) as error:
        _render(current)
    assert isinstance(error.value.__cause__, jinja2.TemplateNotFound)


def test_directory_symlink_helpers_require_explicit_configured_root_names(tmp_path):
    data = _fixture(tmp_path)
    template = tmp_path / "template"
    template.mkdir()
    (tmp_path / "helpers").mkdir()
    (tmp_path / "helpers" / "linked.j2").write_text("linked helper")
    (template / "linked").symlink_to(tmp_path / "helpers", target_is_directory=True)
    (template / "client.j2").write_text("{% include 'linked/linked.j2' %}")
    path, config = _config(tmp_path, data)
    candidate = prepare_resources(path, config).candidates["out.yaml"]
    with pytest.raises(TemplateRenderError) as error:
        _render(candidate)
    assert isinstance(error.value.__cause__, jinja2.TemplateNotFound)
    data["artifact"].append(
        {
            "name": "explicit.yaml",
            "type": "mihomo",
            "providers": ["source"],
            "template": "linked/linked.j2",
        }
    )
    path, config = _config(tmp_path, data)
    prepared = prepare_resources(path, config)
    assert not prepared.failures
    assert (
        _render(prepared.candidates["out.yaml"]).artifact_result.drafts[0].content
        == "linked helper"
    )


@pytest.mark.parametrize(
    "expression",
    [
        "params.missing | default('fallback')",
        "params.missing | tojson",
        "params.missing is defined",
    ],
)
def test_memory_templates_keep_strict_missing_parameters_at_request_gate(
    tmp_path, expression
):
    data = _fixture(tmp_path)
    data["artifact"][0]["allow_conversion_errors"] = True
    (tmp_path / "client.j2").write_text("{{ " + expression + " }}")
    path, config = _config(tmp_path, data)
    prepared = prepare_resources(path, config)
    assert not prepared.failures
    with pytest.raises(TemplateRenderError) as error:
        _render(prepared.candidates["out.yaml"])
    assert isinstance(error.value.__cause__, MissingParameterError)
    assert _failure_status(error.value) == 400


def test_prepared_singbox_template_and_parameter_dependent_target_encoding(tmp_path):
    data = _fixture(tmp_path)
    data["artifact"][0].update(name="client.json", type="sing-box")
    (tmp_path / "client.j2").write_text(
        '{"outbounds":{{ nodes.outbounds() }},"values":{{ params | tojson }}}'
    )
    path, config = _config(tmp_path, data)
    candidate = prepare_resources(path, config).candidates["client.json"]
    output = json.loads(
        _render(candidate, "client.json").artifact_result.drafts[0].content
    )
    assert output["outbounds"][0]["password"] == "default-secret"
    data["artifact"][0].update(name="links.txt", type="v2rayn")
    (tmp_path / "nodes.source").write_text(
        yaml.safe_dump(
            {
                "proxies": [
                    {
                        "name": "dynamic",
                        "type": "socks5",
                        "server": "{{ params.host }}",
                        "port": 1080,
                    }
                ]
            }
        )
    )
    (tmp_path / "client.j2").write_text("{{ nodes.render() }}")
    path, config = _config(tmp_path, data)
    candidate = prepare_resources(path, config).candidates["links.txt"]
    with pytest.raises(ArtifactGenerationError) as error:
        _render(candidate, "links.txt", [("host", "example.test#fragment")])
    assert _failure_status(error.value) == 422
    assert any(issue.code == "conversion.invalid-value" for issue in error.value.issues)


@pytest.mark.parametrize(
    "selections",
    [
        ({"users": ["alice", "anna"]}, {"users": ["bob", "bill"]}),
        ({"user": "alice"}, {"user": "bob"}),
        ({"users": ["alice", "anna"]}, {"user": "bob"}),
    ],
)
@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("failure", [None, "provider", "template", "ruleset"])
def test_concrete_output_identity_preserves_disjoint_patterns_and_dependency_failures(
    tmp_path, monkeypatch, selections, reverse, failure
):
    data = _fixture(tmp_path)
    document = yaml.safe_load((tmp_path / "nodes.source").read_text())
    document["proxies"][0]["users"] = {
        user: {"password": user + "-first"} for user in ("alice", "anna", "bob", "bill")
    }
    (tmp_path / "nodes.source").write_text(yaml.safe_dump(document))
    second_document = copy.deepcopy(document)
    for user, override in second_document["proxies"][0]["users"].items():
        override["password"] = user + "-second"
    (tmp_path / "second.source").write_text(yaml.safe_dump(second_document))
    data["provider"].append(
        {
            **data["provider"][0],
            "name": "second",
            "file": "second.source",
        }
    )
    first = {**data["artifact"][0], "name": "out-{user}.yaml", **selections[0]}
    second = {
        **data["artifact"][0],
        "name": "out-{user}.yaml",
        "providers": ["second"],
        **selections[1],
    }
    if failure == "provider":
        data["provider"][1]["file"] = "absent.source"
    elif failure == "template":
        second["template"] = "absent.j2"
    elif failure == "ruleset":

        def fail_rulesets(*args, **kwargs):
            raise ConfigError("Unavailable shared ruleset")

        monkeypatch.setattr("subio_v2.workflow.rendering.load_rulesets", fail_rulesets)
    data["artifact"] = [second, first] if reverse else [first, second]
    path, config = _config(tmp_path, data)
    prepared = prepare_resources(path, config)
    expected_ready, expected_failed = set(), set()
    artifact_candidates = []
    for artifact in config.artifacts:
        outputs = artifact.output_names()
        if failure == "ruleset" or (failure and artifact.providers == ("second",)):
            for name, _ in outputs:
                expected_failed.add(name)
                assert prepared.failures[name].phase == failure
        else:
            candidate = prepared.candidates[outputs[0][0]]
            artifact_candidates.append(candidate)
            for name, user in outputs:
                expected_ready.add(name)
                assert prepared.candidates[name] is candidate
                result = _render(candidate, name)
                output = yaml.safe_load(result.artifact_result.drafts[0].content)
                label = "second" if artifact.providers == ("second",) else "first"
                assert output["proxies"][0]["password"] == user + "-" + label
                assert result.artifact_result.drafts[0].filename == name
    assert set(prepared.candidates) == expected_ready
    assert set(prepared.failures) == expected_failed
    if len(artifact_candidates) == 2:
        assert artifact_candidates[0] is not artifact_candidates[1]


@pytest.mark.parametrize(
    "selections",
    [
        ({"users": ["alice", "bob"]}, {"users": ["bob", "carol"]}),
        ({"user": "alice"}, {"user": "alice"}),
        ({"users": ["alice", "bob"]}, {"user": "bob"}),
    ],
)
@pytest.mark.parametrize("reverse", [False, True])
def test_overlapping_concrete_outputs_keep_existing_config_rejection(
    tmp_path, selections, reverse
):
    data = _fixture(tmp_path)
    artifacts = [
        {**data["artifact"][0], "name": "out-{user}.yaml", **selection}
        for selection in selections
    ]
    data["artifact"] = artifacts[::-1] if reverse else artifacts
    with pytest.raises(ConfigError, match="Duplicate artifact output name"):
        _config(tmp_path, data)


def test_node_only_artifacts_do_not_capture_unused_template_sources(
    tmp_path, monkeypatch
):
    data = _fixture(tmp_path)
    data["artifact"][0].pop("template")
    path, config = _config(tmp_path, data)
    monkeypatch.setattr(PreparedTemplates, "capture", _denied)
    monkeypatch.setattr(jinja2.FileSystemLoader, "list_templates", _denied)
    candidate = prepare_resources(path, config).candidates["out.yaml"]
    assert not candidate._templates._sources
    output = yaml.safe_load(_render(candidate).artifact_result.drafts[0].content)
    assert output["proxies"][0]["password"] == "default-secret"


def test_root_aliases_capture_and_compile_once_then_reuse_precompiled_code(
    tmp_path, monkeypatch
):
    data = _fixture(tmp_path)
    (tmp_path / "dir").mkdir()
    (tmp_path / "dir" / "root.j2").write_text("{{ params.credential }}")
    aliases = ["dir/root.j2", "./dir/root.j2", "dir//root.j2", "dir/./root.j2"]
    data["artifact"] = [
        {**data["artifact"][0], "name": f"out-{index}.yaml", "template": alias}
        for index, alias in enumerate(aliases)
    ]
    path, config = _config(tmp_path, data)
    get_source = jinja2.FileSystemLoader.get_source
    compile_template = jinja2.Environment.compile
    captures, compilations = [], []

    def capture_source(loader, environment, name):
        captures.append(name)
        return get_source(loader, environment, name)

    def compile_root(environment, source, name=None, *args, **kwargs):
        compilations.append(name)
        return compile_template(environment, source, name, *args, **kwargs)

    with monkeypatch.context() as preparation:
        preparation.setattr(jinja2.FileSystemLoader, "get_source", capture_source)
        preparation.setattr(jinja2.Environment, "compile", compile_root)
        prepared = prepare_resources(path, config)
    assert not prepared.failures
    assert captures.count("dir/root.j2") == 1
    assert compilations == ["dir/root.j2"]
    with monkeypatch.context() as warm:
        warm.setattr(jinja2.Environment, "compile", _denied)
        warm.setattr(builtins, "open", _denied)
        for name, candidate in prepared.candidates.items():
            assert (
                _render(candidate, name).artifact_result.drafts[0].content
                == "default-secret"
            )


@pytest.mark.parametrize(
    "name", ["../helper.j2", "./../helper.j2", "dir/../helper.j2", "dir//../helper.j2"]
)
def test_normalization_rejects_traversal_for_roots_and_memory_helpers(
    tmp_path, monkeypatch, name
):
    data = _fixture(tmp_path)
    (tmp_path / "helper.j2").write_text("healthy")
    (tmp_path / "client.j2").write_text("{% include params.helper %}")
    data["artifact"].append(
        {**data["artifact"][0], "name": "unsafe.yaml", "template": name}
    )
    path, config = _config(tmp_path, data)
    prepared = prepare_resources(path, config)
    assert list(prepared.candidates) == ["out.yaml"]
    assert prepared.failures["unsafe.yaml"].phase == "template"
    with monkeypatch.context() as warm:
        warm.setattr(builtins, "open", _denied)
        with pytest.raises(TemplateRenderError) as error:
            _render(prepared.candidates["out.yaml"], pairs=[("helper", name)])
        assert isinstance(error.value.__cause__, jinja2.TemplateNotFound)
        assert (
            _render(prepared.candidates["out.yaml"], pairs=[("helper", "./helper.j2")])
            .artifact_result.drafts[0]
            .content
            == "healthy"
        )


@pytest.mark.parametrize("content", [b"\xff\xfe", b"{% invalid %}"])
def test_broken_root_aliases_fail_only_their_concrete_outputs(tmp_path, content):
    data = _fixture(tmp_path)
    (tmp_path / "dir").mkdir()
    (tmp_path / "dir" / "broken.j2").write_bytes(content)
    aliases = ["./dir/broken.j2", "dir//broken.j2", "dir/./broken.j2"]
    data["artifact"].extend(
        {**data["artifact"][0], "name": f"broken-{index}.yaml", "template": alias}
        for index, alias in enumerate(aliases)
    )
    path, config = _config(tmp_path, data)
    prepared = prepare_resources(path, config)
    assert list(prepared.candidates) == ["out.yaml"]
    assert set(prepared.failures) == {
        f"broken-{index}.yaml" for index in range(len(aliases))
    }
    assert all(failure.phase == "template" for failure in prepared.failures.values())
