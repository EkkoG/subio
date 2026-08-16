"""Load shareable rulesets and expose data-only template callables."""

from __future__ import annotations

import hashlib
import ipaddress
import os
from dataclasses import dataclass, field, replace
from typing import Any, Callable, Mapping

import requests

from subio_v2.conversion import ConversionIssue, IssueSeverity
from subio_v2.dialect import DialectContext, dialect_context_for_platform
from subio_v2.model.rules import (
    BoundRule,
    DefaultParameter,
    HeadlessRuleSet,
    LiteralPolicy,
    LogicalExpression,
    ParameterReference,
    ParameterizedRuleSet,
    Predicate,
    RuleComment,
    RuleExpression,
    RuleRenderResult,
)
from subio_v2.platforms import normalize_platform
from subio_v2.utils.logger import logger
from subio_v2.workflow.errors import ConfigError
from subio_v2.workflow.rule_parser import (
    MIHOMO_CLASSICAL_PARSER,
    parse_argument_names,
    validate_identifier,
)
from subio_v2.workflow.ruleset_codec import (
    DEFAULT_RULESET_CODEC_REGISTRY,
    RuleSetInputCodecRegistry,
    RuleSetInputSelection,
)


CLASH_PLATFORMS = frozenset({"clash", "mihomo", "stash"})
LOGICAL_RULES = frozenset({"AND", "OR", "NOT"})

PLATFORM_RULES: dict[str, frozenset[str]] = {
    "mihomo": frozenset(
        {
            "DOMAIN",
            "DOMAIN-SUFFIX",
            "DOMAIN-KEYWORD",
            "DOMAIN-WILDCARD",
            "DOMAIN-REGEX",
            "GEOSITE",
            "IP-CIDR",
            "IP-CIDR6",
            "IP-SUFFIX",
            "IP-ASN",
            "GEOIP",
            "SRC-GEOIP",
            "SRC-IP-ASN",
            "SRC-IP-CIDR",
            "SRC-IP-SUFFIX",
            "DST-PORT",
            "SRC-PORT",
            "IN-PORT",
            "IN-TYPE",
            "IN-USER",
            "IN-NAME",
            "REMATCH-NAME",
            "PROCESS-PATH",
            "PROCESS-PATH-WILDCARD",
            "PROCESS-PATH-REGEX",
            "PROCESS-NAME",
            "PROCESS-NAME-WILDCARD",
            "PROCESS-NAME-REGEX",
            "UID",
            "NETWORK",
            "DSCP",
            "MATCH",
            *LOGICAL_RULES,
        }
    ),
    "clash": frozenset(
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
    ),
    "stash": frozenset(
        {
            "DOMAIN",
            "DOMAIN-SUFFIX",
            "DOMAIN-KEYWORD",
            "DOMAIN-WILDCARD",
            "DOMAIN-REGEX",
            "GEOSITE",
            "IP-CIDR",
            "IP-CIDR6",
            "IP-ASN",
            "GEOIP",
            "SRC-IP",
            "DST-PORT",
            "PROCESS-NAME",
            "PROCESS-PATH",
            "USER-AGENT",
            "URL-REGEX",
            "NETWORK",
            "PROTOCOL",
            "MATCH",
            *LOGICAL_RULES,
        }
    ),
    "surge": frozenset(
        {
            "DOMAIN",
            "DOMAIN-SUFFIX",
            "DOMAIN-KEYWORD",
            "DOMAIN-WILDCARD",
            "IP-CIDR",
            "IP-CIDR6",
            "IP-ASN",
            "GEOIP",
            "SRC-IP",
            "DEST-PORT",
            "SRC-PORT",
            "IN-PORT",
            "PROCESS-NAME",
            "USER-AGENT",
            "URL-REGEX",
            "PROTOCOL",
            "DEVICE-NAME",
            "MAC-ADDRESS",
            "HOSTNAME-TYPE",
            "SUBNET",
            "CELLULAR-RADIO",
            "CELLULAR-CARRIER",
            "FINAL",
            *LOGICAL_RULES,
        }
    ),
    "dae": frozenset(
        {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "IP-CIDR", "IP-CIDR6", "MATCH"}
    ),
}


@dataclass
class RuleIssueCollector:
    issues: list[ConversionIssue] = field(default_factory=list)
    _seen: set[ConversionIssue] = field(default_factory=set, init=False, repr=False)

    def add(self, issue: ConversionIssue) -> None:
        if issue not in self._seen:
            self._seen.add(issue)
            self.issues.append(issue)

    def extend(self, issues: tuple[ConversionIssue, ...] | list[ConversionIssue]) -> None:
        for issue in issues:
            self.add(issue)


class RuleSetRenderer:
    def render(
        self,
        ruleset: ParameterizedRuleSet,
        platform: str,
        arguments: Mapping[str, Any],
    ) -> RuleRenderResult:
        platform = normalize_platform(platform)
        if platform not in PLATFORM_RULES:
            raise ValueError(f"Unknown ruleset target platform: {platform}")
        target_context = dialect_context_for_platform(platform)
        issues = [replace(issue, target=platform) for issue in ruleset.issues]
        lines: list[str] = []

        for entry in ruleset.entries:
            if isinstance(entry, RuleComment):
                lines.append(entry.content)
                continue

            policy = self._resolve_policy(entry, ruleset, arguments)
            rendered, expression_issues = self._render_expression(
                ruleset.name,
                entry.expression,
                platform,
                target_context,
                policy,
                nested=False,
            )
            issues.extend(expression_issues)
            if rendered is not None:
                if platform in CLASH_PLATFORMS:
                    rendered = f"- {rendered}"
                lines.append(rendered)

        return RuleRenderResult(content="\n".join(lines), issues=tuple(issues))

    def _resolve_policy(
        self,
        entry: BoundRule,
        ruleset: ParameterizedRuleSet,
        arguments: Mapping[str, Any],
    ) -> str:
        binding = entry.policy_binding
        if isinstance(binding, DefaultParameter):
            return str(arguments[ruleset.parameters[0]])
        if isinstance(binding, ParameterReference):
            return str(arguments[binding.name])
        if isinstance(binding, LiteralPolicy):
            return binding.value
        raise TypeError(f"Unsupported policy binding: {type(binding).__name__}")

    def _render_expression(
        self,
        source: str,
        expression: RuleExpression,
        platform: str,
        target_context: DialectContext,
        policy: str | None,
        *,
        nested: bool,
    ) -> tuple[str | None, list[ConversionIssue]]:
        rule_type = self._target_rule_type(expression, platform, target_context)
        matcher = expression.matcher if isinstance(expression, Predicate) else ""
        if (
            platform == "mihomo"
            and isinstance(expression, Predicate)
            and expression.rule_type == "SRC-IP"
        ):
            try:
                address = ipaddress.ip_address(expression.matcher)
            except ValueError:
                pass
            else:
                rule_type = "SRC-IP-CIDR"
                matcher = f"{address}/{32 if address.version == 4 else 128}"
        if not self._is_supported(rule_type, platform):
            return None, [
                self._issue(
                    source,
                    expression,
                    platform,
                    "ruleset.unsupported-target-rule",
                    f"Rule type {rule_type} cannot be rendered for {platform}",
                )
            ]

        option_issue = self._unsupported_option(source, expression, platform)
        if option_issue is not None:
            return None, [option_issue]

        if platform == "dae":
            assert isinstance(expression, Predicate)
            return self._render_dae(expression, policy), []

        if isinstance(expression, LogicalExpression):
            operands: list[str] = []
            issues: list[ConversionIssue] = []
            for operand in expression.operands:
                rendered, operand_issues = self._render_expression(
                    source,
                    operand,
                    platform,
                    target_context,
                    None,
                    nested=True,
                )
                issues.extend(operand_issues)
                if rendered is None:
                    return None, issues
                operands.append(f"({rendered})")
            fields = [rule_type, f"({','.join(operands)})"]
        else:
            fields = [rule_type]
            if matcher:
                fields.append(self._serialize_matcher(rule_type, matcher))

        if policy is not None:
            fields.append(self._serialize_token(policy))
        fields.extend(self._serialize_option(option) for option in expression.options)
        return ",".join(fields), []

    def _target_rule_type(
        self,
        expression: RuleExpression,
        platform: str,
        target_context: DialectContext,
    ) -> str:
        rule_type = (
            expression.operator
            if isinstance(expression, LogicalExpression)
            else expression.rule_type
        )
        if target_context.dialect == "surge":
            if rule_type == "MATCH":
                return "FINAL"
            if rule_type == "DST-PORT":
                return "DEST-PORT"
            if rule_type == "NETWORK":
                return "PROTOCOL"
        elif target_context.dialect in {"mihomo", "clash", "stash"}:
            if rule_type == "FINAL":
                return "MATCH"
            if rule_type == "DEST-PORT":
                return "DST-PORT"
            if platform == "mihomo" and rule_type == "PROTOCOL":
                assert isinstance(expression, Predicate)
                if expression.matcher.lower() in {"tcp", "udp"}:
                    return "NETWORK"
        return rule_type

    def _is_supported(self, rule_type: str, platform: str) -> bool:
        return rule_type in PLATFORM_RULES[platform]

    def _unsupported_option(
        self,
        source: str,
        expression: RuleExpression,
        platform: str,
    ) -> ConversionIssue | None:
        for option in expression.options:
            if option == "src" and platform != "mihomo":
                return self._issue(
                    source,
                    expression,
                    platform,
                    "ruleset.unsupported-target-option",
                    f"Rule option {option!r} cannot be rendered for {platform}",
                )
            if (
                option in {"extended-matching", "requires-resolve"}
                or option.startswith(
                    ("notification-text=", "notification-interval=", "always-capture=")
                )
            ) and platform != "surge":
                return self._issue(
                    source,
                    expression,
                    platform,
                    "ruleset.unsupported-target-option",
                    f"Rule option {option!r} cannot be rendered for {platform}",
                )
        return None

    @staticmethod
    def _serialize_token(value: str) -> str:
        if not any(char in value for char in (",", '"', "\n", "\r")):
            return value
        escaped = value.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'

    def _serialize_matcher(self, rule_type: str, matcher: str) -> str:
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
        return self._serialize_token(matcher)

    def _serialize_option(self, option: str) -> str:
        if "=" not in option:
            return option
        name, value = option.split("=", 1)
        return f"{name}={self._serialize_token(value)}"

    @staticmethod
    def _render_dae(expression: Predicate, policy: str | None) -> str:
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

    @staticmethod
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


RULESET_RENDERER = RuleSetRenderer()


class RuleSet:
    """Runtime facade for a parameterized, data-only ruleset."""

    def __init__(self, model: ParameterizedRuleSet):
        validate_identifier(model.name, "name")
        if not model.parameters:
            raise ValueError("Ruleset must declare at least one argument")
        for name in model.parameters:
            validate_identifier(name, "argument")
        self.model = model

    @property
    def name(self) -> str:
        return self.model.name

    @property
    def argument_names(self) -> tuple[str, ...]:
        return self.model.parameters

    def _bind_arguments(
        self, values: tuple[Any, ...], kwargs: dict[str, Any]
    ) -> dict[str, Any]:
        names = self.argument_names
        if len(values) > len(names):
            raise TypeError(
                f"Ruleset {self.name!r} expected at most {len(names)} argument(s), "
                f"got {len(values)}"
            )

        bound = dict(zip(names, values))
        for name, value in kwargs.items():
            if name not in names:
                raise TypeError(
                    f"Ruleset {self.name!r} got an unexpected argument {name!r}"
                )
            if name in bound:
                raise TypeError(
                    f"Ruleset {self.name!r} got multiple values for argument {name!r}"
                )
            bound[name] = value

        missing = [name for name in names if name not in bound]
        if missing:
            raise TypeError(
                f"Ruleset {self.name!r} missing required argument(s): "
                f"{', '.join(missing)}"
            )
        return bound

    def render_result(
        self, platform: str, *values: Any, **kwargs: Any
    ) -> RuleRenderResult:
        arguments = self._bind_arguments(values, kwargs)
        return RULESET_RENDERER.render(self.model, platform, arguments)

    def render(self, platform: str, *values: Any, **kwargs: Any) -> str:
        return self.render_result(platform, *values, **kwargs).content

    def as_callable(
        self, platform: str, collector: RuleIssueCollector | None = None
    ) -> Callable[..., str]:
        def render_ruleset(*values: Any, **kwargs: Any) -> str:
            result = self.render_result(platform, *values, **kwargs)
            if collector is not None:
                collector.extend(result.issues)
            return result.content

        render_ruleset.__name__ = self.name
        return render_ruleset


class RuleSetStore:
    def __init__(self) -> None:
        self._items: dict[str, RuleSet] = {}

    def register(self, name: str, item: RuleSet) -> None:
        validate_identifier(name, "name")
        if name != item.name:
            raise ValueError(
                f"Ruleset registration name {name!r} does not match item name "
                f"{item.name!r}"
            )
        if name in self._items:
            raise ValueError(f"Duplicate ruleset name: {name}")
        self._items[name] = item

    def get(self, name: str) -> RuleSet | None:
        return self._items.get(name)

    def __contains__(self, name: str) -> bool:
        return name in self._items

    @property
    def names(self) -> list[str]:
        return list(self._items)

    def get_callables(
        self, platform: str, collector: RuleIssueCollector | None = None
    ) -> dict[str, Callable[..., str]]:
        return {
            name: item.as_callable(platform, collector)
            for name, item in self._items.items()
        }


def load_remote_resource(
    url: str, user_agent: str | None = None, debug: bool = False
) -> bytes:
    """Load remote ruleset bytes without text decoding or content sniffing."""

    headers = {"User-Agent": user_agent} if user_agent else {}
    cache_file: str | None = None
    if debug or os.getenv("DEBUG"):
        os.makedirs("cache", exist_ok=True)
        cache_file = f"cache/{hashlib.md5(url.encode('utf-8')).hexdigest()}"
        if os.path.exists(cache_file):
            with open(cache_file, "rb") as file:
                return file.read()

    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        content = response.content
    except Exception as exc:
        raise ConfigError(
            f"Failed to fetch remote ruleset: {type(exc).__name__}"
        ) from exc

    if cache_file is not None:
        with open(cache_file, "wb") as file:
            file.write(content)
    return content


def load_rulesets(
    ruleset_configs: list[dict[str, Any]],
    registry: RuleSetInputCodecRegistry = DEFAULT_RULESET_CODEC_REGISTRY,
) -> RuleSetStore:
    store = RuleSetStore()
    if not isinstance(ruleset_configs, list):
        raise ConfigError("Config section 'ruleset' must be a list")

    for config in ruleset_configs:
        if not isinstance(config, dict):
            raise ConfigError("Entries in 'ruleset' must be objects")
        name = config.get("name")
        url = config.get("url")
        if not isinstance(name, str) or not name:
            raise ConfigError("Every remote ruleset must define a name")
        if not isinstance(url, str) or not url:
            raise ConfigError(f"Ruleset {name!r} must define a URL")
        user_agent = config.get("user_agent")
        if user_agent is not None and not isinstance(user_agent, str):
            raise ConfigError(f"Ruleset {name!r} user_agent must be a string")

        callable_name = f"remote_{name}"
        try:
            validate_identifier(callable_name, "name")
        except ValueError as exc:
            raise ConfigError(str(exc)) from exc

        selection = RuleSetInputSelection.from_config(config)
        codec = registry.get(selection)
        logger.info(f"Loading ruleset: [cyan]{name}[/cyan]")
        content = load_remote_resource(url, user_agent)
        if not content:
            raise ConfigError(f"Ruleset {name!r} is empty")

        context = DialectContext(
            dialect=selection.dialect,
            format=selection.format,
        )
        parsed = codec.parse(name=callable_name, content=content, context=context)
        model = _parameterize_headless(parsed.ruleset, parsed.issues)
        store.register(callable_name, RuleSet(model))

    return store


def load_snippets(snippet_dir: str) -> RuleSetStore:
    store = RuleSetStore()
    if not os.path.exists(snippet_dir):
        return store

    for snippet_file in sorted(os.listdir(snippet_dir)):
        if snippet_file.startswith("."):
            continue
        snippet_path = os.path.join(snippet_dir, snippet_file)
        if not os.path.isfile(snippet_path):
            continue

        try:
            validate_identifier(snippet_file, "name")
            with open(snippet_path, "r", encoding="utf-8") as file:
                text = file.read()
            lines = text.splitlines()
            if not lines:
                raise ValueError("file is empty")
            parameters = parse_argument_names(lines[0].strip())
            parsed = MIHOMO_CLASSICAL_PARSER.parse_snippet(
                name=snippet_file,
                parameter_names=parameters,
                content="\n".join(lines[1:]),
                source_context=DialectContext("mihomo", "text"),
            )
            model = ParameterizedRuleSet(
                name=snippet_file,
                parameters=parameters,
                entries=parsed.entries,
                source_context=DialectContext("mihomo", "text"),
                issues=parsed.issues,
            )
            store.register(snippet_file, RuleSet(model))
        except ConfigError:
            raise
        except (OSError, UnicodeError, ValueError) as exc:
            raise ConfigError(f"Invalid snippet {snippet_file!r}: {exc}") from exc

    return store


def _parameterize_headless(
    ruleset: HeadlessRuleSet,
    issues: tuple[ConversionIssue, ...],
) -> ParameterizedRuleSet:
    entries = tuple(
        entry
        if isinstance(entry, RuleComment)
        else BoundRule(entry, DefaultParameter())
        for entry in ruleset.entries
    )
    return ParameterizedRuleSet(
        name=ruleset.name,
        parameters=("rule",),
        entries=entries,
        source_context=ruleset.source_context,
        issues=issues,
    )


def merge_stores(*stores: RuleSetStore) -> RuleSetStore:
    merged = RuleSetStore()
    for store in stores:
        for name in store.names:
            item = store.get(name)
            if item is not None:
                merged.register(name, item)
    return merged
