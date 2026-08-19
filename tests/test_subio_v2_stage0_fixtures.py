import hashlib
import json
from pathlib import Path

import pytest
import yaml

from subio_v2.dialect import DialectContext
from subio_v2.model.rules import (
    BoundRule,
    DefaultParameter,
    ParameterizedRuleSet,
    Predicate,
)
from subio_v2.rules.runtime import RuleSet

FIXTURES = Path(__file__).parent / "fixtures"
RULESET_FIXTURES = FIXTURES / "rulesets"


def test_mihomo_schema_snapshot_is_offline_and_complete():
    snapshot = json.loads(
        (FIXTURES / "mihomo/schema/proxies-88d5239.json").read_text()
    )

    assert snapshot["commit"] == "88d5239f9b5db8340bcdda3c963fe7fc5f6f5dbb"
    assert len(snapshot["proxy_types"]) == 26
    assert len(set(snapshot["proxy_types"])) == 26
    assert {
        "anytls",
        "gost-relay",
        "masque",
        "mieru",
        "reject",
        "rematch",
        "shadowquic",
        "tailscale",
        "trusttunnel",
    } <= set(snapshot["proxy_types"])
    assert snapshot["key_fields"]["tls"] == {
        "fingerprint": "server certificate SHA-256 fingerprint",
        "client-fingerprint": "TLS client fingerprint",
        "name-cert-verify": "certificate DNSName verification target",
    }
    assert "disable-reuse" in snapshot["key_fields"]["anytls"]
    assert "uri" in snapshot["key_fields"]["masque"]


def test_stash_proxy_snapshot_records_official_field_boundaries():
    snapshot = yaml.safe_load(
        (FIXTURES / "stash/official/proxy-types.yaml").read_text()
    )

    assert str(snapshot["last_updated"]) == "2026-06-25"
    assert snapshot["protocols"]["ssh"]["required"][-1] == "user"
    assert snapshot["protocols"]["masque"]["network_values"] == ["h3", "h2"]
    assert snapshot["protocols"]["tailscale"]["exit_node_fallback"] == (
        "automatic-selection"
    )
    assert snapshot["protocols"]["mieru"]["one_of"] == ["port", "port-range"]


@pytest.mark.parametrize("dialect", ["mihomo", "stash"])
@pytest.mark.parametrize("behavior", ["domain", "ipcidr", "classical"])
@pytest.mark.parametrize("format_name", ["yaml", "text"])
def test_ruleset_behavior_format_fixtures_are_nonempty(
    dialect, behavior, format_name
):
    suffix = "yaml" if format_name == "yaml" else "list"
    fixture = RULESET_FIXTURES / dialect / f"{behavior}-{format_name}.{suffix}"

    assert fixture.is_file()
    content = fixture.read_text()
    assert content.strip()
    if format_name == "yaml":
        payload = yaml.safe_load(content)["payload"]
        assert isinstance(payload, list)
        assert payload


def test_ruleset_fixtures_cover_advanced_and_rejected_syntax():
    mihomo = (RULESET_FIXTURES / "mihomo/classical-text.list").read_text()
    stash = (RULESET_FIXTURES / "stash/classical-text.list").read_text()
    surge = (RULESET_FIXTURES / "surge/rule-set.list").read_text()
    surge_invalid = (RULESET_FIXTURES / "surge/invalid-rule-set.list").read_text()

    assert ",src,no-resolve" in mihomo
    assert "AND,((" in mihomo and "OR,((" in mihomo and "NOT,((" in mihomo
    assert "no-track" in stash
    assert "SCRIPT,quic" in stash
    assert "URL-REGEX" in surge and "extended-matching" in surge
    assert "SCRIPT,ssid-rule,requires-resolve" in surge
    assert "FINAL" in surge_invalid
    assert "pre-matching" in surge_invalid


def test_parameterized_snippet_fixtures_cover_binding_modes():
    snippets = RULESET_FIXTURES / "snippets"

    assert (snippets / "default_rule").read_text().startswith("rule\n")
    assert (snippets / "named_rules").read_text().startswith(
        "default_rule, api_rule\n"
    )
    assert ",DIRECT" in (snippets / "literal_policy").read_text()
    assert "AND,((" in (snippets / "outer_logic").read_text()
    assert "{{ missing }}" in (snippets / "undeclared_reference").read_text()
    assert "not a Mihomo classical rule" in (
        snippets / "arbitrary_invalid_text"
    ).read_text()


def test_existing_ruleset_callable_and_renderer_golden():
    golden = json.loads((RULESET_FIXTURES / "golden/render.json").read_text())
    ruleset = RuleSet(
        ParameterizedRuleSet(
            name=golden["name"],
            parameters=tuple(
                value.strip() for value in golden["arguments"].split(",")
            ),
            entries=tuple(
                BoundRule(
                    Predicate(
                        rule["rule_type"],
                        rule.get("matcher", ""),
                        tuple(rule.get("options", [])),
                    ),
                    DefaultParameter(),
                )
                for rule in golden["rules"]
            ),
            source_context=DialectContext("mihomo", "text"),
        )
    )

    for call in golden["calls"]:
        renderer = ruleset.as_callable(call["platform"])
        actual = renderer(*call.get("args", []), **call.get("kwargs", {}))
        assert actual == call["expected"]


@pytest.mark.parametrize(
    ("filename", "expected_hash"),
    [
        (
            "domain.mrs",
            "3e419a319d8005d602a00291af9cbd1741867a8ee8f7f0388054a48dd49e4f0a",
        ),
        (
            "ipcidr.mrs",
            "2e2d3681c35d0fc747cc73a67b0ba90d2a2d116e5f9759410229b7b140881164",
        ),
    ],
)
def test_mrs_fixtures_match_official_generation_hashes(filename, expected_hash):
    content = (RULESET_FIXTURES / "mrs" / filename).read_bytes()

    assert content.startswith(b"\x28\xb5\x2f\xfd")
    assert hashlib.sha256(content).hexdigest() == expected_hash
