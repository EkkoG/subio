"""Ruleset rendering utilities."""

import logging

logger = logging.getLogger("SubIO2.RulesetRender")


def render_ruleset_in_clash(text: str) -> str:
    """Render ruleset for Clash format.

    Args:
        text: Raw ruleset text

    Returns:
        Formatted ruleset for Clash
    """
    lines = text.split("\n")

    def filter_rules(rule):
        if "USER-AGENT" in rule:
            logger.warning(f"Found USER-AGENT rule, auto ignored: {rule}")
            return False
        if "IP-ASN" in rule:
            logger.warning(f"Found IP-ASN rule, auto ignored: {rule}")
            return False
        return True

    lines = list(filter(filter_rules, lines))

    def trans(line):
        line = line.strip()
        if len(line) == 0 or line[0] == "#":
            return line
        if ",no-resolve" in line:
            return f"- {line}".replace(",no-resolve", "")
        return f"- {line}"

    return "\n".join(map(trans, lines))


def render_ruleset_in_surge(text: str) -> str:
    """Render ruleset for Surge format.

    Args:
        text: Raw ruleset text

    Returns:
        Formatted ruleset for Surge
    """
    lines = text.split("\n")

    def trans(line):
        line = line.strip()
        if len(line) == 0 or line[0] == "#":
            return line
        return line

    return "\n".join(map(trans, lines))


def render_ruleset_in_dae(text: str) -> str:
    """Render ruleset for DAE format.

    Args:
        text: Raw ruleset text

    Returns:
        Formatted ruleset for DAE
    """

    def trans(line):
        line = line.strip()
        if line.startswith("#") or line == "" or line == "\n" or line == "//":
            return line
        parts = line.split(",")
        if len(parts) < 3:
            return line
        type = parts[0]
        content = parts[1]
        policy = parts[2]
        if type == "DOMAIN":
            return f"domain(full: {content}) -> {policy}"
        elif type == "DOMAIN-SUFFIX":
            return f"domain(suffix: {content}) -> {policy}"
        elif type == "DOMAIN-KEYWORD":
            return f"domain(keyword: {content}) -> {policy}"
        elif type == "IP-CIDR" or type == "IP-CIDR6":
            return f"dip({content}) -> {policy}"
        else:
            logger.error(f"Unsupported rule type: {type}")
            return ""

    lines = text.split("\n")
    new_lines = "\n".join(map(trans, lines))
    return new_lines
