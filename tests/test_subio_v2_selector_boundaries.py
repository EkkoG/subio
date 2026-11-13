from types import SimpleNamespace

import pytest

from subio_v2.core.errors import ConfigError
from subio_v2.workflow.config_validation import ConfigValidator
from subio_v2.workflow.selectors import SelectorEngine, SelectorSpec


@pytest.mark.parametrize("owner", ["config", "engine"])
def test_selector_reference_chain_does_not_use_the_python_call_stack(owner):
    selectors = {f"s{i}": [f"s{i + 1}"] if i < 1099 else [] for i in range(1100)}
    if owner == "config":
        ConfigValidator.validate({"selectors": {name: {"all_of": refs} for name, refs in selectors.items()}})
    else:
        SelectorEngine({name: SelectorSpec(all_of=tuple(refs)) for name, refs in selectors.items()})


@pytest.mark.parametrize("count", [12, 24, 48])
@pytest.mark.parametrize("owner", ["config", "engine"])
def test_shared_selector_dag_visits_a_bounded_number_of_edges(owner, count):
    visits = 0

    class References(list):
        def __iter__(self):
            nonlocal visits
            for value in super().__iter__():
                visits += 1
                assert visits <= count * 20
                yield value

    selectors = {f"s{i}": References(f"s{j}" for j in (i + 1, i + 2) if j < count) for i in range(count)}
    if owner == "config":
        ConfigValidator.validate({"selectors": {name: {"all_of": refs} for name, refs in selectors.items()}})
    else:
        SelectorEngine({name: SelectorSpec(all_of=refs) for name, refs in selectors.items()})


@pytest.mark.parametrize("owner", ["config", "engine"])
def test_back_edges_and_unknown_references_still_fail(owner):
    for selectors in ({"a": ["b"], "b": ["a"]}, {"a": ["missing"]}):
        with pytest.raises(ConfigError):
            if owner == "config":
                ConfigValidator.validate({"selectors": {name: {"all_of": refs} for name, refs in selectors.items()}})
            else:
                SelectorEngine({name: SelectorSpec(all_of=tuple(refs)) for name, refs in selectors.items()})


@pytest.mark.parametrize("field", ["include", "exclude"])
@pytest.mark.parametrize("pattern", ["[", "a{999999999999999999999}"])
def test_empty_selection_validates_inline_regex(field, pattern):
    with pytest.raises(ConfigError, match="invalid regex"):
        SelectorEngine().select([], **{field: pattern})


@pytest.mark.parametrize("keys,expected", [
    (("source_order", "name"), ["Z", "A"]),
    (("name", "source_order"), ["A", "Z"]),
    (("source_order",), ["Z", "A"]),
])
def test_source_order_is_a_real_sort_key(keys, expected):
    engine = SelectorEngine({"test": SelectorSpec(sort_by=keys)})
    selected = engine.select([SimpleNamespace(name="Z"), SimpleNamespace(name="A")], "test")
    assert [item.name for item in selected] == expected
