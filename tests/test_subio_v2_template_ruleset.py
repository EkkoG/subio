import io
import os

import pytest

from subio_v2.dialect import DialectContext
from subio_v2.model.rules import (
    BoundRule,
    DefaultParameter,
    ParameterizedRuleSet,
    Predicate,
    RuleComment,
)
from subio_v2.workflow.template import TemplateRenderer
from subio_v2.workflow.errors import TemplateRenderError
from subio_v2.workflow.ruleset import RuleSet, RuleSetStore


def make_ruleset(name, entries):
    return RuleSet(
        ParameterizedRuleSet(
            name=name,
            parameters=("rule",),
            entries=tuple(entries),
            source_context=DialectContext("mihomo", "text"),
        )
    )


def bound(rule_type, matcher="", options=()):
    return BoundRule(
        Predicate(rule_type, matcher, tuple(options)),
        DefaultParameter(),
    )


def test_template_renderer_renders_with_macros(tmp_path):
    # Create a template file
    tpl_dir = tmp_path / "tpl"
    tpl_dir.mkdir()
    (tpl_dir / "base.j2").write_text(
        "Name: {{ options.name }}\nProxies:\n{{ proxies }}\nRules:\n{% for n in proxies_names %}- {{ n }}\n{% endfor %}"
    )

    # Prepare ruleset store with a simple ruleset
    ruleset = make_ruleset(
        "rs1",
        [RuleComment("# comment"), bound("DOMAIN", "google.com"), bound("MATCH")],
    )
    store = RuleSetStore()
    store.register("rs1", ruleset)

    renderer = TemplateRenderer(str(tpl_dir))

    context = {
        "proxies": "- name: A\n- name: B",
        "options": {"name": "test"},
        "user": None,
        "proxies_names": ["A", "B"],
    }
    out = renderer.render(
        "base.j2", context, artifact_type="clash-meta", rulesets=store
    )
    assert "Name: test" in out
    assert "- name: A" in out and "- name: B" in out
    rendered_rules = store.get_callables("clash-meta")["rs1"]("DIRECT")
    assert "# comment" in rendered_rules
    assert "- DOMAIN,google.com,DIRECT" in rendered_rules


def test_template_missing_file_fails(tmp_path):
    renderer = TemplateRenderer(str(tmp_path))
    with pytest.raises(TemplateRenderError, match="missing.j2"):
        renderer.render("missing.j2", {}, artifact_type="clash")


def test_template_missing_variable_fails(tmp_path):
    (tmp_path / "strict.j2").write_text("{{ missing_value }}")
    renderer = TemplateRenderer(str(tmp_path))

    with pytest.raises(TemplateRenderError, match="missing_value"):
        renderer.render("strict.j2", {}, artifact_type="clash")


def test_ruleset_ssti_payload_is_plain_data(tmp_path, monkeypatch):
    (tmp_path / "safe.j2").write_text("{{ remote_evil('DIRECT') }}")
    payload = "{{ cycler.__init__.__globals__.os.popen('id').read() }}"
    ruleset = make_ruleset("remote_evil", [bound("DOMAIN", payload)])
    store = RuleSetStore()
    store.register("remote_evil", ruleset)

    calls = []

    def fake_popen(command):
        calls.append(command)
        return io.StringIO("EXECUTED")

    monkeypatch.setattr(os, "popen", fake_popen)
    renderer = TemplateRenderer(str(tmp_path))
    output = renderer.render("safe.j2", {}, artifact_type="clash", rulesets=store)

    assert payload in output
    assert calls == []


def test_ruleset_callable_context_conflict_fails(tmp_path):
    (tmp_path / "conflict.j2").write_text("{{ rules('DIRECT') }}")
    store = RuleSetStore()
    store.register("rules", make_ruleset("rules", []))
    renderer = TemplateRenderer(str(tmp_path))

    with pytest.raises(TemplateRenderError, match="conflicts"):
        renderer.render(
            "conflict.j2",
            {"rules": "context value"},
            artifact_type="clash",
            rulesets=store,
        )


def test_ruleset_render_surge_transformations():
    rs = make_ruleset(
        "r",
        [
            bound("MATCH"),
            bound("DST-PORT", "80"),
            bound("IP-CIDR", "1.1.1.0/24", ("no-resolve",)),
        ],
    )
    surge_rules = rs.render("surge", "DIRECT")
    # MATCH -> FINAL, DST-PORT -> DEST-PORT, keep no-resolve for IP-CIDR
    assert "FINAL,DIRECT" in surge_rules
    assert "DEST-PORT,80,DIRECT" in surge_rules
    assert "IP-CIDR,1.1.1.0/24,DIRECT,no-resolve" in surge_rules


def test_template_render_result_collects_ruleset_issues(tmp_path):
    (tmp_path / "rules.j2").write_text("{{ rs1('Proxy') }}")
    store = RuleSetStore()
    store.register("rs1", make_ruleset("rs1", [bound("USER-AGENT", "*Safari*")]))

    result = TemplateRenderer(str(tmp_path)).render_result(
        "rules.j2",
        {},
        artifact_type="clash-meta",
        rulesets=store,
    )

    assert result.content == ""
    assert [issue.code for issue in result.issues] == [
        "ruleset.unsupported-target-rule"
    ]
