from __future__ import annotations

import re
from dataclasses import dataclass, field

from subio_v2.core.dialect import DialectContext
from subio_v2.core.errors import ConfigError
from subio_v2.core.results import ConversionIssue, IssueSeverity
from subio_v2.core.rule_model import (
    BoundRule,
    DefaultParameter,
    HeadlessRuleSet,
    LiteralPolicy,
    LogicalExpression,
    ParameterizedEntry,
    ParameterReference,
    Predicate,
    RuleComment,
    RuleExpression,
    RuleSetEntry,
    RuleSetParseResult,
)

IDENTIFIER_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")
POLICY_PLACEHOLDER_RE = re.compile(r"^\{\{\s*([A-Za-z][A-Za-z0-9_]*)\s*\}\}$")
RULE_TYPE_RE = re.compile(r"^[A-Z][A-Z0-9-]*$")
LOGICAL_RULES = frozenset({"AND", "OR", "NOT"})

MIHOMO_PREDICATES = frozenset(
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
    }
)

STASH_PREDICATES = frozenset(
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
        "SCRIPT",
    }
)

SURGE_PREDICATES = frozenset(
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
        "SRC-PORT",
        "DEST-PORT",
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
        "SCRIPT",
    }
)


@dataclass(frozen=True)
class ClassicalDialectSpec:
    dialect: str
    predicates: frozenset[str]
    allowed_options: dict[str, frozenset[str]] = field(default_factory=dict)
    non_shareable_rules: frozenset[str] = frozenset()
    external_dependency_rules: frozenset[str] = frozenset()
    external_ruleset_rules: frozenset[str] = frozenset()
    catch_all_rules: frozenset[str] = frozenset()
    global_options: frozenset[str] = frozenset()
    option_prefixes: tuple[str, ...] = ()
    comment_prefixes: tuple[str, ...] = ("#", "//")
    max_logic_depth: int | None = None


_MIHOMO_IP_OPTIONS = frozenset({"no-resolve", "src"})
MIHOMO_CLASSICAL_SPEC = ClassicalDialectSpec(
    dialect="mihomo",
    predicates=MIHOMO_PREDICATES,
    allowed_options={
        rule_type: _MIHOMO_IP_OPTIONS
        for rule_type in {"GEOIP", "IP-ASN", "IP-CIDR", "IP-CIDR6", "IP-SUFFIX"}
    },
    non_shareable_rules=frozenset({"RULE-SET", "SUB-RULE"}),
    catch_all_rules=frozenset({"MATCH"}),
)

STASH_CLASSICAL_SPEC = ClassicalDialectSpec(
    dialect="stash",
    predicates=STASH_PREDICATES,
    allowed_options={
        rule_type: frozenset({"no-resolve"})
        for rule_type in {"GEOIP", "IP-ASN", "IP-CIDR", "IP-CIDR6"}
    },
    non_shareable_rules=frozenset({"FINAL"}),
    external_dependency_rules=frozenset({"SCRIPT"}),
    external_ruleset_rules=frozenset({"RULE-SET"}),
    catch_all_rules=frozenset({"MATCH"}),
    global_options=frozenset({"no-track"}),
)

SURGE_CLASSICAL_SPEC = ClassicalDialectSpec(
    dialect="surge",
    predicates=SURGE_PREDICATES,
    allowed_options={
        "DOMAIN": frozenset({"extended-matching"}),
        "DOMAIN-SUFFIX": frozenset({"extended-matching"}),
        "DOMAIN-KEYWORD": frozenset({"extended-matching"}),
        "DOMAIN-WILDCARD": frozenset({"extended-matching"}),
        "URL-REGEX": frozenset({"extended-matching"}),
        "IP-CIDR": frozenset({"no-resolve"}),
        "IP-CIDR6": frozenset({"no-resolve"}),
        "GEOIP": frozenset({"no-resolve"}),
        "IP-ASN": frozenset({"no-resolve"}),
        "SCRIPT": frozenset({"requires-resolve"}),
    },
    non_shareable_rules=frozenset({"MATCH", "FINAL"}),
    external_dependency_rules=frozenset({"SCRIPT"}),
    external_ruleset_rules=frozenset({"RULE-SET", "DOMAIN-SET"}),
    option_prefixes=(
        "notification-text=",
        "notification-interval=",
        "always-capture=",
    ),
    comment_prefixes=("#", "//", ";"),
    max_logic_depth=10,
)


@dataclass(frozen=True)
class SnippetParseResult:
    entries: tuple[ParameterizedEntry, ...]
    issues: tuple[ConversionIssue, ...] = ()


def validate_identifier(value: str, kind: str) -> str:
    if not isinstance(value, str) or not IDENTIFIER_RE.fullmatch(value):
        raise ValueError(
            f"Invalid ruleset {kind} {value!r}: expected an ASCII identifier "
            "starting with a letter"
        )
    return value


def parse_argument_names(args: str) -> tuple[str, ...]:
    if not isinstance(args, str):
        raise ValueError("Invalid ruleset arguments: expected a comma-separated string")

    parts = tuple(part.strip() for part in args.split(","))
    if not parts or any(not part for part in parts):
        raise ValueError("Invalid ruleset arguments: argument names cannot be empty")

    seen: set[str] = set()
    for name in parts:
        validate_identifier(name, "argument")
        if name in seen:
            raise ValueError(f"Duplicate ruleset argument: {name}")
        seen.add(name)
    return parts


def split_rule_tokens(value: str) -> tuple[str, ...]:
    """Split on top-level commas without truncating logical expressions."""

    tokens: list[str] = []
    current: list[str] = []
    depth = 0
    quote: str | None = None
    escaped = False

    for char in value:
        if quote is not None:
            current.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue

        if char in {'"', "'"}:
            quote = char
            current.append(char)
        elif char == "(":
            depth += 1
            current.append(char)
        elif char == ")":
            depth -= 1
            if depth < 0:
                raise ValueError("unbalanced closing parenthesis")
            current.append(char)
        elif char == "," and depth == 0:
            tokens.append(_decode_token("".join(current).strip()))
            current = []
        else:
            current.append(char)

    if quote is not None:
        raise ValueError("unterminated quoted value")
    if depth != 0:
        raise ValueError("unbalanced parentheses")

    tokens.append(_decode_token("".join(current).strip()))
    return tuple(tokens)


def _decode_token(token: str) -> str:
    if len(token) < 2 or token[0] not in {'"', "'"} or token[-1] != token[0]:
        return token

    result: list[str] = []
    escaped = False
    quote = token[0]
    for char in token[1:-1]:
        if escaped:
            if char in {quote, "\\"}:
                result.append(char)
            else:
                result.extend(("\\", char))
            escaped = False
        elif char == "\\":
            escaped = True
        else:
            result.append(char)
    if escaped:
        result.append("\\")
    return "".join(result)


class ClassicalRuleParser:
    def __init__(self, spec: ClassicalDialectSpec):
        self.spec = spec

    def parse_headless(
        self,
        *,
        name: str,
        lines: list[tuple[int, str]],
        source_context: DialectContext,
    ) -> RuleSetParseResult:
        entries: list[RuleSetEntry] = []
        issues: list[ConversionIssue] = []

        for line_number, raw_line in lines:
            parsed = self._parse_line(
                raw_line,
                source=name,
                line_number=line_number,
                parameter_names=(),
                parameterized=False,
                subrule=False,
                logic_depth=0,
                issues=issues,
            )
            if parsed is not None:
                assert not isinstance(parsed, BoundRule)
                entries.append(parsed)

        if not entries and not issues:
            raise ConfigError(f"Ruleset {name!r} contains no rules or comments")

        return RuleSetParseResult(
            ruleset=HeadlessRuleSet(
                name=name,
                source_context=source_context,
                behavior="classical",
                entries=tuple(entries),
            ),
            issues=tuple(issues),
        )

    def parse_snippet(
        self,
        *,
        name: str,
        parameter_names: tuple[str, ...],
        content: str,
        source_context: DialectContext,
    ) -> SnippetParseResult:
        del source_context
        entries: list[ParameterizedEntry] = []
        issues: list[ConversionIssue] = []

        for line_number, raw_line in enumerate(content.splitlines(), start=2):
            parsed = self._parse_line(
                raw_line,
                source=name,
                line_number=line_number,
                parameter_names=parameter_names,
                parameterized=True,
                subrule=False,
                logic_depth=0,
                issues=issues,
            )
            if parsed is not None:
                entries.append(parsed)

        if not any(isinstance(entry, BoundRule) for entry in entries):
            raise ConfigError(f"Snippet {name!r} contains no Mihomo classical rules")

        return SnippetParseResult(entries=tuple(entries), issues=tuple(issues))

    def _parse_line(
        self,
        raw_line: str,
        *,
        source: str,
        line_number: int,
        parameter_names: tuple[str, ...],
        parameterized: bool,
        subrule: bool,
        logic_depth: int,
        issues: list[ConversionIssue],
    ) -> RuleSetEntry | BoundRule | None:
        line = raw_line.strip()
        if not line:
            return None
        for prefix in self.spec.comment_prefixes:
            if line.startswith(prefix):
                content = line[len(prefix) :].strip()
                return RuleComment(content=f"# {content}".rstrip(), source_line=line_number)
        line = self._strip_inline_comment(line)
        if not line:
            return None
        if line.startswith("- "):
            self._fail(source, line_number, "YAML list syntax is not valid text format")

        try:
            tokens = split_rule_tokens(line)
        except ValueError as exc:
            self._fail(source, line_number, str(exc))

        expression, binding = self._parse_tokens(
            tokens,
            source=source,
            line_number=line_number,
            parameter_names=parameter_names,
            parameterized=parameterized,
            subrule=subrule,
            logic_depth=logic_depth,
            issues=issues,
        )
        if expression is None:
            return None
        if parameterized:
            assert binding is not None
            return BoundRule(expression=expression, policy_binding=binding)
        return expression

    def _parse_tokens(
        self,
        tokens: tuple[str, ...],
        *,
        source: str,
        line_number: int,
        parameter_names: tuple[str, ...],
        parameterized: bool,
        subrule: bool,
        logic_depth: int,
        issues: list[ConversionIssue],
    ) -> tuple[RuleExpression | None, object | None]:
        if not tokens or not tokens[0]:
            self._fail(source, line_number, "missing rule type")

        rule_type = tokens[0].upper()
        if not RULE_TYPE_RE.fullmatch(rule_type):
            self._fail(source, line_number, f"invalid rule type {tokens[0]!r}")

        if rule_type in self.spec.external_dependency_rules:
            if parameterized:
                self._fail(source, line_number, f"{rule_type} is not self-contained")
            issues.append(
                self._issue(
                    source,
                    line_number,
                    "ruleset.external-script-dependency",
                    f"{rule_type} depends on a script defined outside the shareable ruleset",
                )
            )
            return None, None

        if rule_type in self.spec.external_ruleset_rules:
            if parameterized:
                self._fail(source, line_number, f"{rule_type} is not self-contained")
            issues.append(
                self._issue(
                    source,
                    line_number,
                    "ruleset.external-ruleset-dependency",
                    f"{rule_type} depends on another resource outside this ruleset",
                )
            )
            return None, None

        if rule_type in self.spec.non_shareable_rules:
            if parameterized:
                self._fail(
                    source,
                    line_number,
                    f"{rule_type} is not allowed in a Mihomo classical snippet",
                )
            issues.append(
                self._issue(
                    source,
                    line_number,
                    "ruleset.non-shareable-rule",
                    f"{rule_type} is not valid in a shareable {self.spec.dialect} ruleset",
                )
            )
            return None, None

        if rule_type in LOGICAL_RULES:
            return self._parse_logical(
                rule_type,
                tokens,
                source=source,
                line_number=line_number,
                parameter_names=parameter_names,
                parameterized=parameterized,
                subrule=subrule,
                logic_depth=logic_depth,
                issues=issues,
            )

        if rule_type in self.spec.catch_all_rules:
            binding, options = self._binding_and_options(
                rule_type,
                tokens[1:],
                source=source,
                line_number=line_number,
                parameter_names=parameter_names,
                parameterized=parameterized and not subrule,
            )
            if subrule:
                self._fail(source, line_number, f"{rule_type} cannot be a logical sub-rule")
            self._validate_options(rule_type, options, source, line_number)
            return (
                Predicate(rule_type=rule_type, source_line=line_number),
                binding,
            )

        if rule_type not in self.spec.predicates:
            if parameterized:
                self._fail(source, line_number, f"unknown Mihomo rule type {rule_type}")
            issues.append(
                self._issue(
                    source,
                    line_number,
                    "ruleset.unknown-rule",
                    f"Unknown {self.spec.dialect} ruleset rule type: {rule_type}",
                )
            )
            return None, None

        matcher, suffix = self._matcher_and_suffix(
            rule_type,
            tokens[1:],
            parameterized=parameterized and not subrule,
        )
        if not matcher:
            self._fail(source, line_number, f"{rule_type} requires a matcher")

        binding, options = self._binding_and_options(
            rule_type,
            suffix,
            source=source,
            line_number=line_number,
            parameter_names=parameter_names,
            parameterized=parameterized and not subrule,
        )
        self._validate_options(rule_type, options, source, line_number)
        return (
            Predicate(
                rule_type=rule_type,
                matcher=matcher,
                options=options,
                source_line=line_number,
            ),
            binding,
        )

    def _parse_logical(
        self,
        rule_type: str,
        tokens: tuple[str, ...],
        *,
        source: str,
        line_number: int,
        parameter_names: tuple[str, ...],
        parameterized: bool,
        subrule: bool,
        logic_depth: int,
        issues: list[ConversionIssue],
    ) -> tuple[LogicalExpression | None, object | None]:
        next_depth = logic_depth + 1
        if self.spec.max_logic_depth is not None and next_depth > self.spec.max_logic_depth:
            self._fail(
                source,
                line_number,
                f"logical nesting exceeds {self.spec.max_logic_depth} levels",
            )
        if len(tokens) < 2:
            self._fail(source, line_number, f"{rule_type} requires sub-rules")

        child_values = self._logical_children(tokens[1], source, line_number)
        if rule_type == "NOT" and len(child_values) != 1:
            self._fail(source, line_number, "NOT requires exactly one sub-rule")
        if rule_type in {"AND", "OR"} and len(child_values) < 2:
            self._fail(source, line_number, f"{rule_type} requires at least two sub-rules")

        operands: list[RuleExpression] = []
        for child in child_values:
            try:
                child_tokens = split_rule_tokens(child)
            except ValueError as exc:
                self._fail(source, line_number, str(exc))
            expression, binding = self._parse_tokens(
                child_tokens,
                source=source,
                line_number=line_number,
                parameter_names=parameter_names,
                parameterized=False,
                subrule=True,
                logic_depth=next_depth,
                issues=issues,
            )
            if binding is not None:
                self._fail(source, line_number, "logical sub-rules cannot bind a policy")
            if expression is None:
                return None, None
            operands.append(expression)

        binding, options = self._binding_and_options(
            rule_type,
            tokens[2:],
            source=source,
            line_number=line_number,
            parameter_names=parameter_names,
            parameterized=parameterized and not subrule,
        )
        self._validate_options(rule_type, options, source, line_number)
        return (
            LogicalExpression(
                operator=rule_type,
                operands=tuple(operands),
                options=options,
                source_line=line_number,
            ),
            binding,
        )

    def _matcher_and_suffix(
        self,
        rule_type: str,
        values: tuple[str, ...],
        *,
        parameterized: bool,
    ) -> tuple[str, tuple[str, ...]]:
        if not values:
            return "", ()

        remaining = list(values)
        if rule_type in {"DST-PORT", "SRC-PORT", "DEST-PORT", "IN-PORT"}:
            matcher_parts: list[str] = []
            while remaining and self._looks_like_matcher_fragment(
                rule_type, remaining[0]
            ):
                matcher_parts.append(remaining.pop(0))
            return ",".join(matcher_parts).strip(), tuple(remaining)

        matcher = remaining.pop(0).strip()
        return matcher, tuple(remaining)

    @staticmethod
    def _looks_like_matcher_fragment(rule_type: str, value: str) -> bool:
        if rule_type in {"DST-PORT", "SRC-PORT", "DEST-PORT", "IN-PORT"}:
            return bool(re.fullmatch(r"\d+(?:-\d+)?", value))
        return False

    def _logical_children(
        self, value: str, source: str, line_number: int
    ) -> tuple[str, ...]:
        outer = self._strip_wrapping_parentheses(value, source, line_number)
        try:
            parts = split_rule_tokens(outer)
        except ValueError as exc:
            self._fail(source, line_number, str(exc))
        return tuple(
            self._strip_wrapping_parentheses(part, source, line_number)
            for part in parts
        )

    def _strip_wrapping_parentheses(
        self, value: str, source: str, line_number: int
    ) -> str:
        if len(value) < 2 or value[0] != "(" or value[-1] != ")":
            self._fail(source, line_number, "logical sub-rules must be parenthesized")

        depth = 0
        quote: str | None = None
        escaped = False
        for index, char in enumerate(value):
            if quote is not None:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote:
                    quote = None
                continue
            if char in {'"', "'"}:
                quote = char
            elif char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0 and index != len(value) - 1:
                    self._fail(
                        source,
                        line_number,
                        "logical parentheses do not wrap the entire value",
                    )
        if depth != 0 or quote is not None:
            self._fail(source, line_number, "unbalanced logical expression")
        return value[1:-1].strip()

    def _binding_and_options(
        self,
        rule_type: str,
        suffix: tuple[str, ...],
        *,
        source: str,
        line_number: int,
        parameter_names: tuple[str, ...],
        parameterized: bool,
    ) -> tuple[object | None, tuple[str, ...]]:
        if not parameterized:
            return None, tuple(self._normalize_option(value) for value in suffix)

        if not suffix or self._is_option(rule_type, suffix[0].lower()):
            binding: object = DefaultParameter()
            options = suffix
        else:
            policy = suffix[0]
            options = suffix[1:]
            placeholder = POLICY_PLACEHOLDER_RE.fullmatch(policy)
            if placeholder:
                name = placeholder.group(1)
                if name not in parameter_names:
                    self._fail(
                        source,
                        line_number,
                        f"references undeclared argument {name!r}",
                    )
                binding = ParameterReference(name)
            elif "{{" in policy or "}}" in policy:
                self._fail(source, line_number, "invalid policy parameter reference")
            elif not policy:
                self._fail(source, line_number, "policy cannot be empty")
            else:
                binding = LiteralPolicy(policy)

        return binding, tuple(self._normalize_option(value) for value in options)

    @staticmethod
    def _normalize_option(value: str) -> str:
        if "=" not in value:
            return value.lower()
        name, option_value = value.split("=", 1)
        return f"{name.lower()}={_decode_token(option_value.strip())}"

    def _validate_options(
        self,
        rule_type: str,
        options: tuple[str, ...],
        source: str,
        line_number: int,
    ) -> None:
        for option in options:
            if option == "pre-matching" and self.spec.dialect == "surge":
                self._fail(
                    source,
                    line_number,
                    "pre-matching is not valid inside a Surge Rule Set",
                )
            if not self._is_option(rule_type, option):
                self._fail(
                    source,
                    line_number,
                    f"unsupported {self.spec.dialect} option {option!r} for {rule_type}",
                )

    def _is_option(self, rule_type: str, value: str) -> bool:
        allowed = self.spec.allowed_options.get(rule_type, frozenset())
        return value in allowed or value in self.spec.global_options or any(
            value.startswith(prefix) for prefix in self.spec.option_prefixes
        )

    def _strip_inline_comment(self, value: str) -> str:
        quote: str | None = None
        escaped = False
        depth = 0
        for index, char in enumerate(value):
            if quote is not None:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote:
                    quote = None
                continue
            if char in {'"', "'"}:
                quote = char
                continue
            if char == "(":
                depth += 1
                continue
            if char == ")":
                depth -= 1
                continue
            if depth or (index and not value[index - 1].isspace()):
                continue
            if char in {"#", ";"} and char in self.spec.comment_prefixes:
                return value[:index].rstrip()
            if value.startswith("//", index) and "//" in self.spec.comment_prefixes:
                return value[:index].rstrip()
        return value

    def _issue(
        self, source: str, line_number: int, code: str, message: str
    ) -> ConversionIssue:
        return ConversionIssue(
            severity=IssueSeverity.ERROR,
            node=None,
            protocol=None,
            source=source,
            target=None,
            field=f"line {line_number}",
            message=message,
            stage="parse",
            code=code,
        )

    @staticmethod
    def _fail(source: str, line_number: int, message: str) -> None:
        raise ConfigError(f"Invalid ruleset {source!r} at line {line_number}: {message}")


MIHOMO_CLASSICAL_PARSER = ClassicalRuleParser(MIHOMO_CLASSICAL_SPEC)
STASH_CLASSICAL_PARSER = ClassicalRuleParser(STASH_CLASSICAL_SPEC)
SURGE_CLASSICAL_PARSER = ClassicalRuleParser(SURGE_CLASSICAL_SPEC)
