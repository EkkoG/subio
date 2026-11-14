import json

import pytest

from subio_v2.core.errors import ConfigError
from subio_v2.core.nodes import ShadowsocksNode
from subio_v2.workflow.config import ConfigLoader, RenameConfig, RenameRule
from subio_v2.workflow.transforms import rename_nodes


def test_regex_rename_keeps_rule_order_original_names_and_dialer():
    nodes = [
        ShadowsocksNode(name="HK-001-fast", server="entry.test", port=8388),
        ShadowsocksNode(name="HK-002-fast", server="exit.test", port=8388,
                        dialer_proxy="HK-001-fast"),
    ]
    rename_nodes(nodes, RenameConfig(
        add_prefix="via-", suffix="-new",
        replace=(
            RenameRule(r"^HK-0*(\d+)-.*$", r"HK-\1", regex=True),
            RenameRule("HK", "HongKong"),
            RenameRule("", "ignored"),
        ),
    ))
    assert [node.name for node in nodes] == ["via-HongKong-1-new", "via-HongKong-2-new"]
    assert nodes[0].original_name == "HK-001-fast"
    assert nodes[1].dialer_proxy == nodes[0].name


def test_regex_named_capture_and_deletion_keep_literal_rules_literal():
    node = ShadowsocksNode(name="[HK] 01 temporary", server="example.test", port=8388)
    rename_nodes([node], RenameConfig(replace=(
        RenameRule(r"\[(?P<region>\w+)\]", r"\g<region>", regex=True),
        RenameRule(" temporary", "", regex=True),
        RenameRule(".", "literal"),
    )))
    assert node.name == "HK 01"


def test_config_loads_regex_and_defaults_to_literal(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"provider": [{
        "name": "source", "type": "subio", "file": "missing.toml",
        "rename": {"replace": [
            {"old": "(HK)", "new": r"\1", "regex": True},
            {"old": ".", "new": "-"},
        ]},
    }]}))
    rules = ConfigLoader.load(str(path)).providers[0].rename.replace
    assert rules[0].regex is True
    assert rules[1].regex is False


@pytest.mark.parametrize("rule", [
    {"old": "[", "new": "", "regex": True},
    {"old": "(HK)", "new": r"\2", "regex": True},
    {"old": "(HK)", "new": r"\g<missing>", "regex": True},
    {"old": "(HK)", "new": r"\q", "regex": True},
    {"old": "HK", "new": "", "regex": 1},
    {"old": "HK", "new": "", "regex": "true"},
])
def test_invalid_regex_is_rejected_without_reading_the_provider(tmp_path, rule):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"provider": [{
        "name": "source", "type": "subio", "file": "missing.toml",
        "rename": {"replace": [rule]},
    }]}))
    with pytest.raises(ConfigError, match="rename"):
        ConfigLoader.load(str(path))
