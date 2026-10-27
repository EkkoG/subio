import json

import pytest

from subio_v2.core.errors import ConfigError
from subio_v2.workflow.config import ArtifactConfig, ConfigLoader
from subio_v2.workflow.config_validation import ConfigValidator
from subio_v2.workflow.parameters import (
    ParameterError,
    ParameterLimitError,
    ParameterSpec,
    normalize_parameters,
    parse_parameter_specs,
)


def test_artifact_params_load_typed_declarations(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({
        "provider": [{"name": "p", "type": "clash-meta", "file": "p.yaml", "parameterized": True}],
        "artifact": [{
            "name": "a.yaml", "type": "mihomo", "providers": ["p"], "user": "alice",
            "params": {
                "host": {"type": "string", "default": "example.test"},
                "port": {"type": "integer", "default": 1080, "min": 1, "max": 65535},
                "tls": {"type": "boolean", "default": False},
                "node_token": {"type": "string", "required": True},
            },
        }],
    }))
    config = ConfigLoader.load(str(path))
    assert config.providers[0].parameterized is True
    params = config.artifacts[0].params
    assert params["port"].default == 1080
    assert params["node_token"].required is True
    with pytest.raises(TypeError):
        params["added"] = params["host"]


@pytest.mark.parametrize("declaration", [
    None, [], {"type": "object", "required": True},
    {"type": "string"}, {"type": "string", "required": "true"},
    {"type": "string", "required": True, "default": "CANARY"},
    {"type": "integer", "default": "CANARY"},
    {"type": "integer", "default": True},
    {"type": "boolean", "default": 1},
    {"type": "string", "default": None},
    {"type": "string", "default": []},
    {"type": "string", "default": {}},
    {"type": "string", "default": ""},
    {"type": "string", "default": "CANARY\n"},
    {"type": "string", "default": "CANARY" * 200},
    {"type": "string", "required": True, "choices": [1]},
    {"type": "string", "default": "CANARY", "choices": ["other"]},
    {"type": "string", "required": True, "choices": []},
    {"type": "string", "required": True, "choices": "CANARY"},
    {"type": "string", "required": True, "min": 1},
    {"type": "integer", "default": 1, "min": True},
    {"type": "integer", "default": 1, "min": 2},
    {"type": "integer", "default": 1, "max": 0},
    {"type": "integer", "required": True, "min": 2, "max": 1},
    {"type": "integer", "required": True, "allow_empty": False},
    {"type": "string", "default": "CANARY", "unknown": True},
])
def test_invalid_parameter_declarations_fail_without_values(declaration):
    with pytest.raises(ConfigError) as error:
        ParameterSpec.from_mapping(declaration)
    assert "CANARY" not in str(error.value)


@pytest.mark.parametrize("params", [
    None, [],
    {"token": {"type": "string", "required": True}},
    {"bad-name": {"type": "string", "required": True}},
    {"x" * 65: {"type": "string", "required": True}},
    {"\u540d": {"type": "string", "required": True}},
    {f"p{i}": {"type": "string", "required": True} for i in range(33)},
])
def test_parameter_declaration_shape_and_names_are_validated(params):
    with pytest.raises(ConfigError):
        ConfigValidator.validate({"artifact": [{"name": "a", "type": "mihomo", "params": params}]})


@pytest.mark.parametrize("render", [None, {}, {"route": "demo"}])
def test_legacy_render_declaration_has_migration_error(render):
    with pytest.raises(ConfigError, match=r"move render.params to artifact.params"):
        ConfigValidator.validate({"artifact": [{"name": "a", "type": "mihomo", "render": render}]})


def test_parameters_share_existing_output_filename_collision_validation():
    artifact = {"name": "{user}.yaml", "type": "mihomo", "users": ["alice", "bob"], "params": {}}
    ConfigValidator.validate({"artifact": [artifact]})
    with pytest.raises(ConfigError, match="Duplicate artifact output name"):
        ConfigValidator.validate({"artifact": [artifact, {"name": "alice.yaml", "type": "mihomo"}]})


@pytest.mark.parametrize("provider", [
    {"type": "mihomo", "file": "p.yaml", "parameterized": "true"},
    {"type": "mihomo", "url": "https://unused.test/p", "parameterized": True},
    {"type": "mihomo", "file": None, "parameterized": True},
    *({"type": fmt, "file": "p", "parameterized": True} for fmt in ("stash", "surge", "sing-box", "v2rayn", "unknown")),
])
def test_parameterized_provider_requires_supported_local_opt_in(provider):
    with pytest.raises(ConfigError):
        ConfigValidator.validate({"provider": [{"name": "p", **provider}]})


def test_normalization_preserves_types_unicode_spaces_and_defaults():
    params = parse_parameter_specs({
        "name": {"type": "string", "required": True},
        "port": {"type": "integer", "required": True, "min": -10, "max": 100},
        "tls": {"type": "boolean", "default": True, "choices": [True, False]},
        "self": {"type": "string", "default": "" , "allow_empty": True},
    })
    values = normalize_parameters(params, [("name", " \u540d+&=%# "), ("port", "+0010"), ("tls", "false")])
    assert dict(values) == {"name": " \u540d+&=%# ", "port": 10, "tls": False, "self": ""}
    assert type(values["port"]) is int
    assert type(values["tls"]) is bool
    with pytest.raises(TypeError):
        values["name"] = "other"


@pytest.mark.parametrize(("declaration", "raw"), [
    ({"type": "integer", "required": True}, value)
    for value in ("1.0", "1e2", " 1", "1 ", "0x10", "\uff11", "--1", "", "true")
] + [
    ({"type": "boolean", "required": True}, value)
    for value in ("True", "FALSE", "1", "0", " true", "")
] + [
    ({"type": "string", "required": True}, value)
    for value in ("", "CANARY\n", "CANARY\x00", "CANARY\x7f", "CANARY\x85", "CANARY\u2028", "CANARY\u2029", "CANARY\ud800")
] + [
    ({"type": "integer", "required": True, "min": 1, "max": 10}, "11"),
    ({"type": "integer", "required": True, "min": 1, "max": 10}, "0"),
    ({"type": "string", "required": True, "choices": ["allowed"]}, "CANARY"),
])
def test_invalid_runtime_values_fail_without_echoing_input(declaration, raw):
    with pytest.raises(ParameterError) as error:
        normalize_parameters({"value": ParameterSpec.from_mapping(declaration)}, [("value", raw)])
    assert "CANARY" not in str(error.value)


def test_normalization_rejects_missing_duplicate_unknown_and_size_limits():
    declaration = ParameterSpec.from_mapping({"type": "string", "required": True})
    for pairs in ([], [("value", "x"), ("value", "y")], [("unknown", "x")], [("token", "CANARY")], [("value", [])]):
        with pytest.raises(ParameterError):
            normalize_parameters({"value": declaration}, pairs)
    assert normalize_parameters({"value": declaration}, [("value", "\u540d" * 341)])["value"] == "\u540d" * 341
    with pytest.raises(ParameterLimitError):
        normalize_parameters({"value": declaration}, [("value", "\u540d" * 342)])
    declarations = {f"p{i}": declaration for i in range(33)}
    with pytest.raises(ParameterLimitError):
        normalize_parameters(declarations, [(name, "x") for name in declarations])


def test_artifact_parameters_have_independent_defaults_and_constraints():
    a = parse_parameter_specs({"port": {"type": "integer", "default": 80, "max": 100}})
    b = parse_parameter_specs({"port": {"type": "integer", "default": 443, "min": 101}})
    assert normalize_parameters(a, [])["port"] == 80
    assert normalize_parameters(b, [])["port"] == 443
    with pytest.raises(ParameterError):
        normalize_parameters(a, [("port", "443")])
    assert normalize_parameters(b, [("port", "443")])["port"] == 443


def test_config_reprs_do_not_include_parameter_defaults_or_choices():
    artifact = {"name": "a", "type": "mihomo", "params": {
        "credential": {"type": "string", "default": "CANARY", "choices": ["CANARY"]},
    }}
    config = ArtifactConfig.from_mapping(artifact)
    assert "CANARY" not in repr(config)
    assert "CANARY" not in repr(config.params["credential"])
