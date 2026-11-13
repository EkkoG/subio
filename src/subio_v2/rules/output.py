"""Immutable output dialects for shareable rule sets."""

from __future__ import annotations

import ipaddress
import re
import yaml
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from types import MappingProxyType
from typing import TypeAlias

from subio_v2.adapters.catalog import normalize_format
from subio_v2.core.dialect import DialectContext, dialect_context_for_platform
from subio_v2.core.results import ConversionIssue, IssueSeverity
from subio_v2.core.rule_model import (
    BoundRule, LogicalExpression, ParameterizedRuleSet, Predicate,
    RuleComment, RuleExpression, RuleRenderResult,
)
from subio_v2.rules.singbox import SINGBOX_ROUTE_RULE_SERIALIZER
from subio_v2.rules.parser import (
    MIHOMO_PREDICATES,
    STASH_PREDICATES,
    SURGE_PREDICATES,
)

LowerExpression: TypeAlias = Callable[
    [RuleExpression, DialectContext], tuple[str, str, tuple[str, ...]]
]
SerializeExpression: TypeAlias = Callable[
    [RuleExpression, str, str, tuple[str, ...], str | None, tuple[str, ...]], str
]


@dataclass(frozen=True)
class RuleOutputDialect:
    """Executable output contract for one rule target dialect."""

    name: str
    context: DialectContext
    rule_types: frozenset[str]
    option_names: frozenset[str]
    lower_expression: LowerExpression
    serialize_expression: SerializeExpression
    option_prefixes: tuple[str, ...] = ()
    line_prefix: str = ""
    validate_values: Callable[[str, str, str | None], str | None] | None = None

    def render_ruleset(
        self,
        ruleset: ParameterizedRuleSet,
        resolve_policy: Callable[[BoundRule], str],
    ) -> RuleRenderResult:
        issues = [replace(issue, target=self.name) for issue in ruleset.issues]
        lines: list[str] = []
        for entry in ruleset.entries:
            if isinstance(entry, RuleComment):
                lines.append(entry.content)
                continue
            rendered, expression_issues = self.render(
                source=ruleset.name,
                expression=entry.expression,
                source_context=ruleset.source_context,
                policy=resolve_policy(entry),
            )
            issues.extend(expression_issues)
            if rendered is not None:
                lines.append(rendered)
        return RuleRenderResult(content="\n".join(lines), issues=tuple(issues))

    def supports_rule(self, rule_type: str) -> bool:
        return rule_type in self.rule_types

    def supports_option(self, option: str) -> bool:
        return option in self.option_names or option.startswith(self.option_prefixes)

    def render(
        self,
        *,
        source: str,
        expression: RuleExpression,
        source_context: DialectContext,
        policy: str | None,
        nested: bool = False,
    ) -> tuple[str | None, tuple[ConversionIssue, ...]]:
        rule_type, matcher, options = self.lower_expression(
            expression, source_context
        )
        if not self.supports_rule(rule_type):
            return None, (
                _issue(
                    source,
                    expression,
                    self.name,
                    "ruleset.unsupported-target-rule",
                    f"Rule type {rule_type} cannot be rendered for {self.name}",
                ),
            )

        for option in options:
            if not self.supports_option(option) and option:
                return None, (
                    _issue(
                        source,
                        expression,
                        self.name,
                        "ruleset.unsupported-target-option",
                        f"Rule option {option!r} cannot be rendered for {self.name}",
                    ),
                )

        if self.validate_values is not None:
            error = self.validate_values(rule_type, matcher, policy)
            if error is not None:
                return None, (_issue(
                    source, expression, self.name, "ruleset.invalid-target-value",
                    error,
                ),)

        if isinstance(expression, LogicalExpression):
            operands: list[str] = []
            issues: list[ConversionIssue] = []
            for operand in expression.operands:
                rendered, operand_issues = self.render(
                    source=source,
                    expression=operand,
                    source_context=source_context,
                    policy=None,
                    nested=True,
                )
                issues.extend(operand_issues)
                if rendered is None:
                    return None, tuple(issues)
                operands.append(f"({rendered})")
        else:
            operands = []

        content = self.serialize_expression(
            expression,
            rule_type,
            matcher,
            options,
            policy,
            tuple(operands),
        )
        if not nested:
            if self.line_prefix == "- " and (
                re.search(r":(?:\s|$)|\s#", content)
                or any(not char.isprintable() for char in content)
                or content != content.rstrip()
            ):
                content = yaml.safe_dump(
                    content, default_style='"', allow_unicode=True, width=2**31 - 1,
                ).rstrip("\n")
            content = f"{self.line_prefix}{content}"
        return content, ()


def _canonical_source_form(
    expression: RuleExpression,
    source_context: DialectContext,
) -> tuple[str, str]:
    rule_type = (
        expression.operator
        if isinstance(expression, LogicalExpression)
        else expression.rule_type
    )
    matcher = expression.matcher if isinstance(expression, Predicate) else ""

    if rule_type == "FINAL":
        rule_type = "MATCH"
    elif rule_type == "DEST-PORT":
        rule_type = "DST-PORT"

    if not isinstance(expression, Predicate):
        return rule_type, matcher

    if source_context.dialect in {"stash", "surge"}:
        if rule_type == "SRC-IP":
            try:
                network = ipaddress.ip_network(matcher, strict=False)
            except ValueError:
                pass
            else:
                rule_type = "SRC-IP-CIDR"
                if "/" not in matcher:
                    matcher = f"{matcher}/{network.max_prefixlen}"
        elif rule_type == "PROTOCOL" and matcher.lower() in {"tcp", "udp"}:
            rule_type = "NETWORK"
        elif rule_type == "PROCESS-NAME":
            rule_type, matcher = _canonical_process_matcher(matcher)
    return rule_type, matcher


def _canonical_process_matcher(matcher: str) -> tuple[str, str]:
    has_wildcard = "*" in matcher or "?" in matcher
    if matcher.startswith("/"):
        if matcher.endswith("/"):
            return "PROCESS-PATH-WILDCARD", f"{matcher}*"
        if has_wildcard:
            return "PROCESS-PATH-WILDCARD", matcher
        return "PROCESS-PATH", matcher
    if has_wildcard:
        return "PROCESS-NAME-WILDCARD", matcher
    return "PROCESS-NAME", matcher


def _lower_mihomo(
    expression: RuleExpression,
    source_context: DialectContext,
) -> tuple[str, str, tuple[str, ...]]:
    rule_type, matcher = _canonical_source_form(expression, source_context)
    options = expression.options
    if isinstance(expression, Predicate) and rule_type == "SRC-IP":
        try:
            network = ipaddress.ip_network(matcher, strict=False)
        except ValueError:
            pass
        else:
            rule_type = "SRC-IP-CIDR"
            if "/" not in matcher:
                matcher = f"{matcher}/{network.max_prefixlen}"
    if isinstance(expression, Predicate) and rule_type == "PROTOCOL":
        if matcher.lower() in {"tcp", "udp"}:
            rule_type = "NETWORK"
    return rule_type, matcher, options


def _lower_clash(
    expression: RuleExpression,
    source_context: DialectContext,
) -> tuple[str, str, tuple[str, ...]]:
    rule_type, matcher = _canonical_source_form(expression, source_context)
    options = expression.options
    if isinstance(expression, Predicate) and rule_type == "PROTOCOL":
        if matcher.lower() in {"tcp", "udp"}:
            rule_type = "NETWORK"
    return rule_type, matcher, options


def _lower_stash(
    expression: RuleExpression,
    source_context: DialectContext,
) -> tuple[str, str, tuple[str, ...]]:
    rule_type, matcher = _canonical_source_form(expression, source_context)
    options = expression.options
    if (
        isinstance(expression, Predicate)
        and rule_type in {"IP-CIDR", "IP-CIDR6"}
        and "src" in options
    ):
        rule_type = "SRC-IP"
        options = tuple(
            option for option in options if option not in {"src", "no-resolve"}
        )
    if rule_type == "SRC-IP-CIDR":
        rule_type = "SRC-IP"
    elif rule_type in {"PROCESS-NAME-WILDCARD", "PROCESS-PATH-WILDCARD"}:
        rule_type = "PROCESS-NAME"
    return rule_type, matcher, options


def _lower_surge(
    expression: RuleExpression,
    source_context: DialectContext,
) -> tuple[str, str, tuple[str, ...]]:
    rule_type, matcher = _canonical_source_form(expression, source_context)
    options = expression.options
    if (
        isinstance(expression, Predicate)
        and rule_type in {"IP-CIDR", "IP-CIDR6"}
        and "src" in options
    ):
        rule_type = "SRC-IP"
        options = tuple(
            option for option in options if option not in {"src", "no-resolve"}
        )
    if rule_type == "MATCH":
        rule_type = "FINAL"
    elif rule_type == "DST-PORT":
        rule_type = "DEST-PORT"
    elif rule_type == "NETWORK":
        rule_type = "PROTOCOL"
    elif rule_type == "SRC-IP-CIDR":
        rule_type = "SRC-IP"
    elif rule_type in {
        "PROCESS-NAME-WILDCARD",
        "PROCESS-PATH",
        "PROCESS-PATH-WILDCARD",
    }:
        rule_type = "PROCESS-NAME"
    return rule_type, matcher, options


def _lower_dae(
    expression: RuleExpression,
    source_context: DialectContext,
) -> tuple[str, str, tuple[str, ...]]:
    return (*_canonical_source_form(expression, source_context), expression.options)


def _validate_dae_values(rule_type: str, matcher: str, policy: str | None) -> str | None:
    safe_policy = policy is not None and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]*", policy)
    safe_matcher = re.fullmatch(r"[A-Za-z0-9_.-]+", matcher)
    if rule_type in {"IP-CIDR", "IP-CIDR6"}:
        try:
            ipaddress.ip_network(matcher, strict=False)
            safe_matcher = re.fullmatch(r"[0-9A-Fa-f:./]+", matcher)
        except ValueError:
            safe_matcher = False
    if not safe_policy or (rule_type != "MATCH" and not safe_matcher):
        return "Rule matcher or policy cannot be represented safely in dae"
    return None


def _serialize_expression(
    expression: RuleExpression,
    rule_type: str,
    matcher: str,
    options: tuple[str, ...],
    policy: str | None,
    operands: tuple[str, ...],
) -> str:
    if isinstance(expression, LogicalExpression):
        fields = [rule_type, f"({','.join(operands)})"]
    else:
        fields = [rule_type]
        if matcher:
            fields.append(_serialize_matcher(rule_type, matcher))
    if policy is not None:
        fields.append(_serialize_token(policy))
    fields.extend(_serialize_option(option) for option in options)
    return ",".join(fields)


def _serialize_dae(
    expression: RuleExpression,
    _rule_type: str,
    _matcher: str,
    _options: tuple[str, ...],
    policy: str | None,
    _operands: tuple[str, ...],
) -> str:
    assert isinstance(expression, Predicate)
    assert policy is not None
    if expression.rule_type in {"MATCH", "FINAL"}:
        return f"fallback: {policy}"
    if expression.rule_type == "DOMAIN":
        return f"domain(full: {expression.matcher}) -> {policy}"
    if expression.rule_type == "DOMAIN-SUFFIX":
        return f"domain(suffix: {expression.matcher}) -> {policy}"
    if expression.rule_type == "DOMAIN-KEYWORD":
        return f"domain(keyword: {expression.matcher}) -> {policy}"
    return f"dip({expression.matcher}) -> {policy}"


def _serialize_token(value: str) -> str:
    if not any(char in value for char in (",", '"', "\n", "\r")):
        return value
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _serialize_matcher(rule_type: str, matcher: str) -> str:
    if rule_type in {"DST-PORT", "SRC-PORT", "DEST-PORT", "IN-PORT"}:
        fragments = matcher.split(",")
        if fragments and all(
            fragment.isdigit()
            or (
                "-" in fragment
                and all(part.isdigit() for part in fragment.split("-", 1))
            )
            for fragment in fragments
        ):
            return matcher
    return _serialize_token(matcher)


def _serialize_option(option: str) -> str:
    if "=" not in option:
        return option
    name, value = option.split("=", 1)
    return f"{name}={_serialize_token(value)}"


def _issue(
    source: str,
    expression: RuleExpression,
    target: str,
    code: str,
    message: str,
) -> ConversionIssue:
    return ConversionIssue(
        severity=IssueSeverity.ERROR,
        node=None,
        protocol=None,
        source=source,
        target=target,
        field=(
            f"line {expression.source_line}"
            if expression.source_line is not None
            else None
        ),
        message=message,
        stage="render",
        code=code,
    )


_CLASH_RULE_TYPES = frozenset(
    {
        "DOMAIN",
        "DOMAIN-SUFFIX",
        "DOMAIN-KEYWORD",
        "IP-CIDR",
        "IP-CIDR6",
        "GEOIP",
        "DST-PORT",
        "SRC-PORT",
        "PROCESS-NAME",
        "MATCH",
    }
)
_DAE_RULE_TYPES = frozenset(
    {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "IP-CIDR", "IP-CIDR6", "MATCH"}
)


RULE_OUTPUT_DIALECTS: Mapping[str, RuleOutputDialect] = MappingProxyType(
    {
        "mihomo": RuleOutputDialect(
            name="mihomo",
            context=dialect_context_for_platform("mihomo"),
            rule_types=MIHOMO_PREDICATES | {"MATCH", "AND", "OR", "NOT"},
            option_names=frozenset({"src", "no-resolve"}),
            line_prefix="- ",
            lower_expression=_lower_mihomo,
            serialize_expression=_serialize_expression,
        ),
        "clash": RuleOutputDialect(
            name="clash",
            context=dialect_context_for_platform("clash"),
            rule_types=_CLASH_RULE_TYPES,
            option_names=frozenset({"no-resolve"}),
            line_prefix="- ",
            lower_expression=_lower_clash,
            serialize_expression=_serialize_expression,
        ),
        "stash": RuleOutputDialect(
            name="stash",
            context=dialect_context_for_platform("stash"),
            rule_types=(STASH_PREDICATES - {"SCRIPT"}) | {"MATCH", "AND", "OR", "NOT"},
            option_names=frozenset({"no-resolve", "no-track"}),
            line_prefix="- ",
            lower_expression=_lower_stash,
            serialize_expression=_serialize_expression,
        ),
        "surge": RuleOutputDialect(
            name="surge",
            context=dialect_context_for_platform("surge"),
            rule_types=(SURGE_PREDICATES - {"SCRIPT"}) | {"FINAL", "AND", "OR", "NOT"},
            option_names=frozenset({"no-resolve", "extended-matching", "requires-resolve"}),
            option_prefixes=(
                "notification-text=",
                "notification-interval=",
                "always-capture=",
            ),
            lower_expression=_lower_surge,
            serialize_expression=_serialize_expression,
        ),
        "dae": RuleOutputDialect(
            name="dae",
            context=dialect_context_for_platform("dae"),
            rule_types=_DAE_RULE_TYPES,
            option_names=frozenset({"no-resolve"}),
            lower_expression=_lower_dae,
            serialize_expression=_serialize_dae,
            validate_values=_validate_dae_values,
        ),
    }
)


def get_rule_output_dialect(platform: str) -> RuleOutputDialect | None:
    """Return the immutable output dialect for a public target name."""
    return RULE_OUTPUT_DIALECTS.get(normalize_format(platform))


RULE_OUTPUT_TARGETS = MappingProxyType({
    **RULE_OUTPUT_DIALECTS,
    "sing-box": SINGBOX_ROUTE_RULE_SERIALIZER,
})


def get_rule_output_target(platform: str):
    return RULE_OUTPUT_TARGETS.get(normalize_format(platform))
