import pytest
import yaml

from subio_v2.core import parameters


def bind(document, values=None):
    return parameters.bind_document_parameters(document, "nodes", values or {})


def test_container_depth_accepts_64_and_rejects_65_without_recursion_error():
    value = 0
    for _ in range(64):
        value = [value]
    assert bind(value) == value
    with pytest.raises(ValueError, match="depth limit"):
        bind([value])


def test_expanded_visits_accept_100000_and_reject_100001():
    assert len(bind([None] * 99999)) == 99999
    with pytest.raises(ValueError, match="visit limit"):
        bind([None] * 100000)


def test_small_yaml_alias_graph_cannot_expand_past_the_visit_limit(monkeypatch):
    monkeypatch.setattr(parameters, "MAX_DOCUMENT_VISITS", 40, raising=False)
    document = yaml.safe_load("a: &a [x, x]\nb: &b [*a, *a]\nnodes: [*b, *b, *b, *b, *b]\n")
    with pytest.raises(ValueError, match="visit limit"):
        bind(document)
    assert document["nodes"][0] is document["b"]


def test_normal_aliases_expand_into_independent_copies():
    document = yaml.safe_load("a: &a {password: '{{ params.secret }}'}\nnodes: [*a, *a]\n")
    # Placeholders outside the node subtree remain forbidden.
    with pytest.raises(ValueError, match="only allowed"):
        bind(document, {"secret": "value"})
    document.pop("a")
    result = bind(document, {"secret": "value"})
    result["nodes"][0]["password"] = "changed"
    assert result["nodes"][1]["password"] == "value"
    assert document["nodes"][0]["password"] == "{{ params.secret }}"


def test_string_budget_is_utf8_bytes_and_covers_keys_and_non_node_values(monkeypatch):
    monkeypatch.setattr(parameters, "MAX_DOCUMENT_STRING_BYTES", 6, raising=False)
    assert bind({"meta": "\u00e9"}) == {"meta": "\u00e9"}
    with pytest.raises(ValueError, match="string byte limit"):
        bind({"meta": "\u00e9x"})


@pytest.mark.parametrize("value", ["{{ params.value }}", "{{ params.value }}{{ params.value }}"])
def test_replaced_strings_are_charged_before_output_is_built(monkeypatch, value):
    monkeypatch.setattr(parameters, "MAX_DOCUMENT_STRING_BYTES", 12, raising=False)
    document = {"nodes": [{"name": value}]}
    with pytest.raises(ValueError, match="string byte limit"):
        bind(document, {"value": "\u00e9\u00e9"})
    assert document["nodes"][0]["name"] == value


def test_aliases_charge_each_visible_string_copy(monkeypatch):
    monkeypatch.setattr(parameters, "MAX_DOCUMENT_STRING_BYTES", 12, raising=False)
    node = {"name": "x"}
    assert bind({"nodes": [node]}) == {"nodes": [node]}
    with pytest.raises(ValueError, match="string byte limit"):
        bind({"nodes": [node, node]})


def test_tuple_and_cycle_rejection_are_preserved():
    cycle = []
    cycle.append(cycle)
    with pytest.raises(ValueError, match="Cyclic"):
        bind(cycle)
    with pytest.raises(ValueError, match="tuple"):
        bind({"nodes": [("a", "b")]})
