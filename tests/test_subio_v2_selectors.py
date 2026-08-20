import pytest

from subio_v2.core.errors import ConfigError
from subio_v2.core.nodes import Protocol, ShadowsocksNode
from subio_v2.workflow.config_validation import ConfigValidator
from subio_v2.workflow.selectors import (
    SelectorEngine,
    SelectorSpec,
    resolve_duplicate_names,
)


def node(name: str, protocol: Protocol, provider: str) -> ShadowsocksNode:
    result = ShadowsocksNode(
        name=name,
        type=protocol,
        server="example.com",
        port=8388,
        password="secret",
    )
    result.source_provider = provider
    return result


def test_selector_composes_fields_and_preserves_source_order():
    nodes = [
        node("HK streaming", Protocol.SHADOWSOCKS, "backup"),
        node("US streaming", Protocol.TROJAN, "primary"),
        node("HK ordinary", Protocol.TROJAN, "primary"),
    ]
    engine = SelectorEngine(
        {
            "hk": SelectorSpec(name_regex=("HK",)),
            "streaming": SelectorSpec(name_regex=("streaming",)),
            "target": SelectorSpec(
                protocols=("trojan",),
                all_of=("streaming",),
                not_of=("hk",),
                sort_by=("name",),
                limit=1,
            ),
        }
    )

    selected = engine.select(nodes, "target")

    assert [item.name for item in selected] == ["US streaming"]


def test_selector_inline_query_and_template_safe_summary_fields():
    nodes = [
        node("HK-1", Protocol.SHADOWSOCKS, "primary"),
        node("JP-1", Protocol.TROJAN, "backup"),
    ]
    engine = SelectorEngine()

    selected = engine.select(
        nodes,
        include="HK|JP",
        protocols=["trojan"],
        providers=["backup"],
    )

    assert [item.name for item in selected] == ["JP-1"]


def test_selector_rejects_unknown_and_cyclic_references():
    with pytest.raises(ConfigError, match="unknown selector"):
        SelectorEngine({"a": SelectorSpec(all_of=("missing",))})

    with pytest.raises(ConfigError, match="cycle"):
        SelectorEngine(
            {
                "a": SelectorSpec(all_of=("b",)),
                "b": SelectorSpec(not_of=("a",)),
            }
        )

    with pytest.raises(ConfigError, match="missing selector"):
        ConfigValidator.validate(
            {
                "artifact": [
                    {
                        "name": "out",
                        "type": "mihomo",
                        "selector": "missing",
                    }
                ]
            }
        )


def test_duplicate_policy_keeps_first_or_reports_all_duplicate_names():
    nodes = [
        node("same", Protocol.SHADOWSOCKS, "one"),
        node("same", Protocol.TROJAN, "two"),
        node("other", Protocol.TROJAN, "three"),
    ]

    kept, duplicates = resolve_duplicate_names(nodes, "keep_first")

    assert [item.name for item in kept] == ["same", "other"]
    assert duplicates == ("same",)
