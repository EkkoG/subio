import os
from pathlib import Path
import pytest

from subio_v2.workflow.template import TemplateRenderer
from subio_v2.workflow.ruleset import RuleSet, RuleSetStore, RuleEntry, CommentEntry


def test_template_renderer_renders_with_macros(tmp_path):
    # Create a template file
    tpl_dir = tmp_path / "tpl"
    tpl_dir.mkdir()
    (tpl_dir / "base.j2").write_text("Name: {{ options.name }}\nProxies:\n{{ proxies }}\nRules:\n{% for n in proxies_names %}- {{ n }}\n{% endfor %}")

    # Prepare ruleset store with a simple ruleset
    ruleset = RuleSet(name="rs1", args="rule", rules=[
        CommentEntry("# comment"),
        RuleEntry(rule_type="DOMAIN", matcher="google.com", policy="{{ rule }}"),
        RuleEntry(rule_type="MATCH", matcher="", policy="{{ rule }}"),
    ])
    store = RuleSetStore()
    store.register("rs1", ruleset)

    renderer = TemplateRenderer(str(tpl_dir))

    context = {
        "proxies": "- name: A\n- name: B",
        "options": {"name": "test"},
        "user": None,
        "proxies_names": ["A", "B"],
    }
    out = renderer.render("base.j2", context, artifact_type="clash-meta", rulesets=store)
    assert "Name: test" in out
    assert "- name: A" in out and "- name: B" in out
    # Macros are prepended but not directly rendered unless invoked; ensure macros include comment
    macros = store.generate_macros("clash-meta")
    assert "# comment" in macros


def test_template_missing_file_exits(tmp_path):
    renderer = TemplateRenderer(str(tmp_path))
    with pytest.raises(SystemExit):
        renderer.render("missing.j2", {}, artifact_type="clash")


def test_ruleset_render_surge_transformations():
    rs = RuleSet(name="r", args="rule", rules=[
        RuleEntry(rule_type="MATCH", matcher="", policy=""),
        RuleEntry(rule_type="DST-PORT", matcher="80", policy="Proxy"),
        RuleEntry(rule_type="IP-CIDR", matcher="1.1.1.0/24", policy="Proxy", options=["no-resolve"]),
    ])
    surge_macro = rs.to_macro(platform="surge")
    # MATCH -> FINAL, DST-PORT -> DEST-PORT, keep no-resolve for IP-CIDR
    assert "FINAL,{{ rule }}" in surge_macro
    assert "DEST-PORT,80,Proxy" in surge_macro
    assert "IP-CIDR,1.1.1.0/24,Proxy,no-resolve" in surge_macro
