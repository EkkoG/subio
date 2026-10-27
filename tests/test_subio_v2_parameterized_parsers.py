import copy
import json

import json5
import pytest
import toml
import yaml

from subio_v2.adapters.catalog import get_emitter, get_parser
from subio_v2.core.errors import ProviderLoadError
from subio_v2.core.nodes import SourcePassthroughNode
from subio_v2.core.parameters import bind_document_parameters
from subio_v2.workflow.config import RunConfig
from subio_v2.workflow.parameters import RenderConfig, normalize_parameters
from subio_v2.workflow.providers import ProviderLoaderService


PAYLOAD = "literal \"' &:[]=+#% {{ params.host }} {{ 7 * 7 }} {% include 'x' %}"


def _values():
    render = RenderConfig.from_mapping({"route": "demo", "params": {
        "host": {"type": "string", "required": True},
        "port": {"type": "integer", "required": True},
        "tls": {"type": "boolean", "required": True},
        "credential": {"type": "string", "required": True},
        "node_token": {"type": "string", "required": True},
    }})
    return normalize_parameters(render.params, [
        ("host", "proxy.example.test"), ("port", "1080"), ("tls", "true"),
        ("credential", PAYLOAD), ("node_token", "synthetic-token"),
    ])


def _parser(fmt, values=None):
    return get_parser(fmt, source_kind="local", parameterized=True, parameters=_values() if values is None else values)


def _node(native):
    node = {
        "name": "proxy-{{ params.host }}", "type": "socks5",
        "server": "{{ params.host }}", "port": "{{ params.port }}",
        "username": "{{ params.credential }}", "password": "prefix-{{params.credential}}",
        "users": {"alice": {"password": "{{ params.credential }}", "port": "{{ params.port }}"}},
    }
    if native:
        node["tls"] = {"enabled": "{{ params.tls }}", "server_name": "{{ params.host }}", "alpn": ["h2", "{{ params.credential }}"]}
    else:
        node.update({"tls": "{{ params.tls }}", "sni": "{{ params.host }}", "alpn": ["h2", "{{ params.credential }}"]})
    return node


@pytest.mark.parametrize("fmt", ["mihomo", "clash", "clash-meta"])
def test_yaml_binding_reaches_existing_codec_with_typed_nested_and_user_values(fmt):
    source = {"proxies": [_node(False)], "dns": {"enable": True}}
    result = _parser(fmt).parse_result(yaml.safe_dump(source))
    assert result.issues == []
    node = result.nodes[0]
    assert node.name == "proxy-proxy.example.test"
    assert node.server == "proxy.example.test"
    assert node.port == 1080 and type(node.port) is int
    assert node.tls.enabled is True
    assert node.tls.server_name == "proxy.example.test"
    assert node.tls.alpn == ["h2", PAYLOAD]
    assert node.username == PAYLOAD and node.password == "prefix-" + PAYLOAD
    assert node.users["alice"] == {"password": PAYLOAD, "port": 1080}
    assert source["proxies"][0]["port"] == "{{ params.port }}"


@pytest.mark.parametrize(("serialization", "encode"), [
    ("toml", toml.dumps), ("json", json.dumps),
    ("json5", lambda value: "// native fixture\n" + json5.dumps(value)),
    ("yaml", yaml.safe_dump),
])
def test_native_all_serializations_bind_before_strict_codec(serialization, encode):
    source = {"version": 2, "nodes": [_node(True)]}
    result = _parser("subio").parse_result(encode(source))
    assert result.issues == []
    node = result.nodes[0]
    assert node.source_context.format == serialization
    assert node.name == "proxy-proxy.example.test"
    assert node.port == 1080 and type(node.port) is int
    assert node.tls.enabled is True
    assert node.tls.server_name == "proxy.example.test"
    assert node.tls.alpn == ["h2", PAYLOAD]
    assert node.username == PAYLOAD and node.password == "prefix-" + PAYLOAD
    assert node.users["alice"] == {"password": PAYLOAD, "port": 1080}


def test_shared_binder_expands_acyclic_aliases_per_path_without_mutating_source():
    source = yaml.safe_load("""
proxies:
  - &node
    name: "{{ params.host }}"
    options: &options
      values: ["{{ params.credential }}", "{{ params.port }}", "{{ params.tls }}"]
    copy: *options
  - *node
""")
    before = copy.deepcopy(source)
    bound = bind_document_parameters(source, "proxies", _values())
    assert source == before
    assert bound["proxies"][0] == bound["proxies"][1]
    assert bound["proxies"][0] is not bound["proxies"][1]
    assert bound["proxies"][0]["options"] is not bound["proxies"][0]["copy"]
    assert bound["proxies"][0]["options"]["values"] == [PAYLOAD, 1080, True]


@pytest.mark.parametrize("fmt", ["mihomo", "subio"])
def test_actual_yaml_parser_handles_aliases_once_per_visible_path_and_rejects_cycles(fmt):
    native = fmt == "subio"
    key = "nodes" if native else "proxies"
    header = "version: 2\n" if native else ""
    source = header + key + """:
  - &node
    name: example
    type: socks5
    server: "{{ params.host }}"
    port: "{{ params.port }}"
    password: "{{ params.credential }}"
  - *node
"""
    nodes = _parser(fmt).parse_result(source).nodes
    assert len(nodes) == 2
    assert [node.password for node in nodes] == [PAYLOAD, PAYLOAD]
    assert nodes[0] is not nodes[1]
    for cycle in (header + key + ": &cycle [*cycle]", header + key + ": [{name: x, extra: &cycle {again: *cycle}}]"):
        with pytest.raises(ValueError, match="Cyclic"):
            _parser(fmt).parse_result(cycle)


@pytest.mark.parametrize("value", ["{{ params.missing }}", "{{ params.host | upper }}", "{{ params['host'] }}", "{{ params.host", "{{ params. }}", "{{ params }}", "prefix-{{ params.port }}", "prefix-{{ params.tls }}"])
@pytest.mark.parametrize("fmt", ["mihomo", "subio"])
def test_unknown_malformed_or_embedded_nonstring_bindings_fail_closed(fmt, value):
    native = fmt == "subio"
    source = {"nodes" if native else "proxies": [{**_node(native), "password": value}]}
    if native:
        source["version"] = 2
    with pytest.raises(ValueError):
        _parser(fmt).parse_result(yaml.safe_dump(source))


@pytest.mark.parametrize("source", [
    {"proxies": [], "dns": {"server": "{{ params.host }}"}},
    {"{{ params.host }}": [], "proxies": []},
    {"proxies": [{"{{ params.host }}": "x"}]},
    {"proxies": [{"users": {"{{ params.host }}": {"password": "x"}}}]},
    {"proxies": "{{ params.host }}"},
])
def test_yaml_placeholders_cannot_change_keys_envelope_or_unrelated_sections(source):
    with pytest.raises(ValueError):
        _parser("mihomo").parse_result(yaml.safe_dump(source))


@pytest.mark.parametrize("source", [
    {"version": "{{ params.port }}", "nodes": []},
    {"version": 2, "nodes": [], "other": "{{ params.host }}"},
    {"version": 2, "nodes": [{"users": {"{{ params.host }}": {}}}]},
    {"version": 2, "nodes": "{{ params.host }}"},
])
def test_native_envelope_version_keys_and_structure_stay_static(source):
    with pytest.raises(ValueError):
        _parser("subio").parse_result(json.dumps(source))


def test_safe_unknown_yaml_scalars_keep_existing_same_dialect_semantics():
    source = {"proxies": [{**_node(False), "future-options": {"token": "{{ params.node_token }}", "nested": ["{{ params.credential }}"], "static": [None, 1.5, False]}}]}
    node = _parser("mihomo").parse_result(yaml.safe_dump(source)).nodes[0]
    assert node.extra["future-options"] == {"token": "synthetic-token", "nested": [PAYLOAD], "static": [None, 1.5, False]}
    emitted = get_emitter("mihomo").emit_result([node])
    assert emitted.content["proxies"][0]["future-options"] == node.extra["future-options"]
    unknown = _parser("mihomo").parse_result(yaml.safe_dump({"proxies": [{"type": "future-type", "name": "x", "token": "{{ params.node_token }}"}]})).nodes[0]
    assert isinstance(unknown, SourcePassthroughNode)
    assert unknown.raw["token"] == "synthetic-token"


def test_yaml_set_members_are_static_keys_and_alias_copies_are_independent():
    for source in (
        'proxies: []\nother: !!set {"{{ params.host }}": null}',
        'proxies: [{options: !!set {"{{ params.host }}": null}}]',
    ):
        with pytest.raises(ValueError):
            _parser("mihomo").parse_result(source)
    source = yaml.safe_load("proxies: [{options: &options !!set {static: null}}, {options: *options}]")
    bound = bind_document_parameters(source, "proxies", _values())
    assert bound["proxies"][0]["options"] == {"static"}
    assert bound["proxies"][0]["options"] is not bound["proxies"][1]["options"]


@pytest.mark.parametrize("fmt", ["mihomo", "subio"])
def test_generic_type_and_known_token_fields_can_bind_without_field_allowlists(fmt):
    native = fmt == "subio"
    source = {"nodes" if native else "proxies": [{
        "name": "tuic", "type": "{{ params.protocol }}", "server": "{{ params.host }}",
        "port": "{{ params.port }}", "token": "{{ params.node_token }}",
    }]}
    if native:
        source["version"] = 2
    values = {**_values(), "protocol": "tuic"}
    result = _parser(fmt, values).parse_result(yaml.safe_dump(source))
    assert result.issues == []
    assert result.nodes[0].token == "synthetic-token"


def test_native_unknown_fields_and_bound_types_still_use_existing_validation():
    source = {"version": 2, "nodes": [{**_node(True), "future": "{{ params.host }}"}]}
    result = _parser("subio").parse_result(json.dumps(source))
    assert not result.nodes
    assert any(issue.code == "parse.subio.unknown-field" for issue in result.issues)
    source["nodes"][0].pop("future")
    result = _parser("subio", {**_values(), "port": "1080"}).parse_result(json.dumps(source))
    assert not result.nodes
    assert any(issue.field == "nodes[0].port" for issue in result.issues)


@pytest.mark.parametrize("fmt", ["stash", "surge", "sing-box", "v2rayn", "unknown"])
def test_catalog_rejects_unsupported_parameterization(fmt):
    with pytest.raises(ValueError):
        _parser(fmt)


@pytest.mark.parametrize("source_kind", ["remote", "unknown"])
def test_catalog_rejects_remote_or_unknown_source_authority(source_kind):
    with pytest.raises(ValueError):
        get_parser("mihomo", source_kind=source_kind, parameterized=True, parameters=_values())


def test_catalog_requires_explicit_opt_in_and_runtime_bindings():
    with pytest.raises(ValueError):
        get_parser("mihomo", source_kind="local", parameters=_values())
    with pytest.raises(ValueError):
        get_parser("mihomo", source_kind="local", parameterized=True)


@pytest.mark.parametrize("fmt", ["mihomo", "subio"])
def test_ordinary_parsers_keep_literals_and_new_parsers_do_not_share_bindings(fmt):
    native = fmt == "subio"
    source = {"nodes" if native else "proxies": [{"name": "x", "type": "socks5", "server": "s", "port": 1080, "password": "{{ params.host }}"}]}
    if native:
        source["version"] = 2
    content = yaml.safe_dump(source)
    assert get_parser(fmt).parse_result(content).nodes[0].password == "{{ params.host }}"
    values = dict(_values())
    parser = _parser(fmt, values)
    values["host"] = "changed"
    assert parser.parse_result(content).nodes[0].password == "proxy.example.test"
    other = _parser(fmt, {**values, "host": "other"})
    assert other is not parser
    assert other.parse_result(content).nodes[0].password == "other"
    assert parser.parse_result(content).nodes[0].password == "proxy.example.test"


def test_provider_loader_requires_bindings_before_any_provider_io(tmp_path, monkeypatch):
    config = RunConfig.from_mapping({"provider": [
        {"name": "static", "type": "mihomo", "file": "static.yaml"},
        {"name": "dynamic", "type": "mihomo", "file": "p.yaml", "parameterized": True},
    ]})
    service = ProviderLoaderService(str(tmp_path / "config.toml"))
    monkeypatch.setattr(service, "_fetch_content", lambda *args: pytest.fail("Provider I/O occurred"))
    with pytest.raises(ProviderLoadError, match="runtime bindings"):
        service.load(config, object())


@pytest.mark.parametrize("fmt", ["mihomo", "subio"])
def test_provider_loader_passes_explicit_bindings_through_catalog(tmp_path, fmt):
    native = fmt == "subio"
    document = {"nodes" if native else "proxies": [_node(native)]}
    if native:
        document["version"] = 2
    (tmp_path / "p.yaml").write_text(yaml.safe_dump(document))
    config = RunConfig.from_mapping({"provider": [{"name": "p", "type": fmt, "file": "p.yaml", "parameterized": True}]})
    result = ProviderLoaderService(str(tmp_path / "config.toml")).load(config, object(), parameters=_values())
    assert result.issues["p"] == []
    assert result.providers["p"][0].username == PAYLOAD
    assert result.providers["p"][0].source_provider == "p"
