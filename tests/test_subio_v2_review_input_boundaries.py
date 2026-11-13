import pytest
import yaml

from subio_v2.adapters.catalog import get_emitter, get_parser
from subio_v2.core.errors import ConfigError
from subio_v2.core.nodes import HttpNode, MieruNode, ShadowQUICNode, SudokuNode
from subio_v2.core.validation import validate_node
from subio_v2.protocols import get_definition
from subio_v2.protocols.user_overrides import clone_node_for_user
from subio_v2.workflow.config_validation import ConfigValidator
from subio_v2.workflow.providers import ProviderLoaderService
from subio_v2.workflow.config import ProviderConfig
from subio_v2.workflow.selectors import SelectorEngine, SelectorSpec


def ss(**values):
    return {"name": "safe", "type": "ss", "server": "example.test", "port": 443,
            "cipher": "aes-128-gcm", "password": "p", **values}


@pytest.mark.parametrize("port", [True, False, 443.9, 443.0])
def test_clash_invalid_port_type_preserves_a_valid_sibling(port):
    parsed = get_parser("mihomo").parse_result({"proxies": [ss(name="bad", port=port), ss()]})
    result = get_emitter("mihomo").emit_result(parsed.nodes)
    assert [node.name for node in result.supported_nodes] == ["safe"]
    assert parsed.issues or result.errors


@pytest.mark.parametrize("port", [443, "443", " 443 "])
def test_clash_integer_port_text_remains_supported(port):
    parsed = get_parser("mihomo").parse_result({"proxies": [ss(port=port)]})
    assert not parsed.issues and parsed.nodes[0].port == 443


@pytest.mark.parametrize("name", [[], {}, 1, True, "", " "])
def test_invalid_opaque_name_is_rejected_before_provider_aggregation(name):
    parsed = get_parser("mihomo").parse_result({"proxies": [{"name": name, "type": "easytier"}, ss()]})
    result = ProviderLoaderService._finish_parse(parsed, ProviderConfig.from_mapping({"name": "source", "type": "mihomo", "file": "unused"}), "digest", None)
    assert [node.name for node in result.providers["source"]] == ["safe"]
    assert result.issues["source"]


@pytest.mark.parametrize("location", ["root", "node", "tls"])
def test_native_mixed_mapping_keys_use_structured_errors(location):
    document = {"version": 2, "nodes": [{"name": "bad", "type": "http", "server": "example.test", "port": 443}, {"name": "safe", "type": "http", "server": "example.test", "port": 443}]}
    target = document if location == "root" else document["nodes"][0]
    if location == "tls":
        target["tls"] = {"enabled": True}
        target = target["tls"]
    target.update({1: "bad", "invalid": "bad"})
    parsed = get_parser("subio").parse_result(yaml.safe_dump(document, sort_keys=False))
    assert parsed.issues and all(issue.severity.value == "error" for issue in parsed.issues)
    assert [node.name for node in parsed.nodes] == ([] if location == "root" else ["safe"])


@pytest.mark.parametrize("node,field", [
    (HttpNode(name=[], server="example.test", port=443), "name"),
    (HttpNode(name="bad", server="example.test", port=443, ip_version=[]), "ip_version"),
    (ShadowQUICNode(name="bad", server="example.test", port=443, congestion_controller=[]), "congestion_controller"),
    (ShadowQUICNode(name="bad", server="example.test", port=443, bbr_profile={}), "bbr_profile"),
    (SudokuNode(name="bad", server="example.test", port=443, key="p", aead_method=[]), "aead_method"),
])
def test_container_enum_values_are_validation_errors(node, field):
    errors = validate_node(node, definition=get_definition(node.type))
    assert any(error.field == field for error in errors)
    result = get_emitter("mihomo").emit_result([node, HttpNode(name="safe", server="example.test", port=8080)])
    assert [item.name for item in result.supported_nodes] == ["safe"]


@pytest.mark.parametrize("port_range", ["\u00b2-3", "\uff12-3", [], {}, "9" * 5000 + "-9"], ids=["superscript", "fullwidth", "list", "mapping", "long"])
def test_mieru_invalid_port_range_returns_field_errors(port_range):
    node = MieruNode(name="bad", server="example.test", username="u", password="p", port_range=port_range)
    assert any(error.field == "port_range" for error in validate_node(node, definition=get_definition(node.type)))


def test_opaque_ip_version_container_does_not_abort_sibling_emission():
    parsed = get_parser("mihomo").parse_result({"proxies": [
        {"name": "bad", "type": "easytier", "ip-version": []}, ss(),
    ]})
    result = get_emitter("mihomo").emit_result(parsed.nodes)
    assert [node.name for node in result.supported_nodes] == ["safe"]
    assert any(issue.field == "ip_version" for issue in result.errors)


def test_user_override_values_are_independent_between_clones_and_source():
    node = HttpNode(name="test", server="example.test", port=443, users={"alice": {"server": ["a.test", "b.test"]}})
    first = clone_node_for_user(node, "alice")
    second = clone_node_for_user(node, "alice")
    first.server.append("changed")
    assert node.users["alice"]["server"] == ["a.test", "b.test"]
    assert second.server == ["a.test", "b.test"]


@pytest.mark.parametrize("key", [1, None, ("server",)])
def test_non_string_override_keys_raise_the_existing_value_error(key):
    node = HttpNode(name="test", server="example.test", port=443, users={"alice": {key: "bad"}})
    with pytest.raises(ValueError):
        clone_node_for_user(node, "alice")


@pytest.mark.parametrize("kind", ["filter", "config-selector", "engine-selector", "inline"])
def test_regex_repeat_overflow_is_a_config_error(kind):
    pattern = "a{999999999999999999999}"
    with pytest.raises(ConfigError):
        if kind == "filter":
            ConfigValidator.validate({"filters": {"include": pattern}})
        elif kind == "config-selector":
            ConfigValidator.validate({"selectors": {"bad": {"name_regex": pattern}}})
        elif kind == "engine-selector":
            SelectorEngine({"bad": SelectorSpec(name_regex=(pattern,))})
        else:
            SelectorEngine().select([HttpNode(name="test")], include=pattern)
