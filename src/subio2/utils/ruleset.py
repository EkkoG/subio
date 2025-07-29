"""Ruleset loading utility for templates."""

import logging
from typing import Dict

logger = logging.getLogger("SubIO2.RulesetLoader")


def wrap_ruleset_as_macro(content: str, name: str) -> str:
    """Wrap ruleset content as a Jinja2 macro.

    Args:
        content: Ruleset content
        name: Ruleset name

    Returns:
        Jinja2 macro definition
    """

    # Process each rule to append {{ rule }} parameter
    def append_rule(rule: str) -> str:
        rule = rule.strip()
        if not rule or rule.startswith("#"):
            return rule
        # Handle special case for no-resolve
        if ",no-resolve" in rule:
            return rule.replace(",no-resolve", ",{{ rule }},no-resolve")
        return rule + ",{{ rule }}"

    processed_content = "\n".join(map(append_rule, content.split("\n")))

    return "{{% macro remote_{}(rule) -%}}\n{}\n{{%- endmacro -%}}".format(
        name, processed_content
    )


def convert_rulesets_to_macros(rulesets: Dict[str, str]) -> str:
    """Convert rulesets to Jinja2 macros.

    Args:
        rulesets: Dictionary of ruleset name to content

    Returns:
        String containing all rulesets as Jinja2 macros
    """
    macro_text = ""
    for name, content in rulesets.items():
        if content:
            macro_text += wrap_ruleset_as_macro(content, name) + "\n"
            logger.debug(f"Created macro for ruleset: remote_{name}")

    return macro_text
