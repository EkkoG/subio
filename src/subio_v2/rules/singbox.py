from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, replace
from typing import Any, Callable

from subio_v2.core.dialect import DialectContext
from subio_v2.core.errors import ConfigError
from subio_v2.core.results import ConversionIssue, IssueSeverity
from subio_v2.core.rule_model import (
    BoundRule,
    HeadlessRuleSet,
    LogicalExpression,
    ParameterizedRuleSet,
    Predicate,
    RuleComment,
    RuleExpression,
    RuleRenderResult,
    RuleSetParseResult,
)

_DEFAULT_FIELDS = frozenset(
    {
        "type",
        "query_type",
        "network",
        "domain",
        "domain_suffix",
        "domain_keyword",
        "domain_regex",
        "source_ip_cidr",
        "ip_cidr",
        "source_port",
        "source_port_range",
        "port",
        "port_range",
        "process_name",
        "process_path",
        "process_path_regex",
        "package_name",
        "package_name_regex",
        "network_type",
        "network_is_expensive",
        "network_is_constrained",
        "wifi_ssid",
        "wifi_bssid",
        "network_interface_address",
        "default_interface_address",
        "invert",
    }
)
_LOGICAL_FIELDS = frozenset({"type", "mode", "rules", "invert"})
_UNREPRESENTABLE_FIELDS = frozenset(
    {
        "query_type",
        "package_name",
        "package_name_regex",
        "network_type",
        "network_is_expensive",
        "network_is_constrained",
        "wifi_ssid",
        "wifi_bssid",
        "network_interface_address",
        "default_interface_address",
    }
)
_PORT_RANGE_RE = re.compile(r"^(\d*):(\d*)$")
_COUNTED_REPETITION_RE = re.compile(r"\{([0-9]+)(?:,([0-9]*))?\}")
_RE2_ALPHA_ESCAPES = frozenset("AdDsSwWafnrtvx")
_RE2_ESCAPED_PUNCTUATION = frozenset(r"\\.*+?()[]{}|^$-")


class _DuplicateJsonKey(ValueError):
    pass


@dataclass(frozen=True)
class _UnsupportedRule(Exception):
    field: str
    message: str


@dataclass(frozen=True)
class _UnsupportedTargetRule(Exception):
    code: str
    message: str


class SingBoxRouteRuleSerializer:
    """Render bound rule IR as sing-box client route-rule JSON fragments."""

    def render(
        self,
        ruleset: ParameterizedRuleSet,
        resolve_policy: Callable[[BoundRule], str],
    ) -> RuleRenderResult:
        issues = [replace(issue, target="sing-box") for issue in ruleset.issues]
        rules: list[dict[str, Any]] = []

        for entry in ruleset.entries:
            if isinstance(entry, RuleComment):
                continue
            try:
                if (
                    isinstance(entry.expression, Predicate)
                    and entry.expression.rule_type.upper() in {"MATCH", "FINAL"}
                ):
                    encoded: dict[str, Any] = {}
                else:
                    encoded = _encode_source_rule(
                        entry.expression, ruleset.source_context
                    )
                encoded["action"] = "route"
                encoded["outbound"] = resolve_policy(entry)
                rules.append(encoded)
            except _UnsupportedTargetRule as exc:
                expression = entry.expression
                issues.append(
                    ConversionIssue(
                        severity=IssueSeverity.ERROR,
                        node=None,
                        protocol=None,
                        source=ruleset.name,
                        target="sing-box",
                        field=(
                            f"line {expression.source_line}"
                            if expression.source_line is not None
                            else None
                        ),
                        message=exc.message,
                        stage="render",
                        code=exc.code,
                    )
                )

        return RuleRenderResult(
            content=json.dumps(rules, ensure_ascii=False, indent=2),
            issues=tuple(issues),
        )


SINGBOX_ROUTE_RULE_SERIALIZER = SingBoxRouteRuleSerializer()


class SingBoxSourceCodec:
    """Decode official sing-box Source JSON without broadening rule matches."""

    def parse(
        self,
        *,
        name: str,
        content: bytes,
        context: DialectContext,
    ) -> RuleSetParseResult:
        document = _load_source_document(content, name)
        entries: list[RuleExpression] = []
        issues: list[ConversionIssue] = []

        for index, rule in enumerate(document["rules"], start=1):
            path = f"rule {index}"
            if not isinstance(rule, dict):
                raise ConfigError(f"Ruleset {name!r} {path} must be a JSON object")
            try:
                entries.append(_with_source_line(_parse_rule(rule, path), index))
            except _UnsupportedRule as exc:
                issues.append(
                    ConversionIssue(
                        severity=IssueSeverity.ERROR,
                        node=None,
                        protocol=None,
                        source=name,
                        target=None,
                        field=exc.field,
                        message=exc.message,
                        stage="parse",
                        code="ruleset.unsupported-source-rule",
                    )
                )

        return RuleSetParseResult(
            ruleset=HeadlessRuleSet(
                name=name,
                source_context=context,
                behavior="classical",
                entries=tuple(entries),
            ),
            issues=tuple(issues),
        )


def _load_source_document(content: bytes, name: str) -> dict[str, Any]:
    if not isinstance(content, bytes):
        raise ConfigError(f"Ruleset {name!r} loader must return bytes")
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ConfigError(f"Ruleset {name!r} is not valid UTF-8") from exc

    try:
        document = json.loads(
            text,
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
    except _DuplicateJsonKey as exc:
        raise ConfigError(f"Ruleset {name!r} contains a duplicate JSON key") from exc
    except (json.JSONDecodeError, ValueError) as exc:
        raise ConfigError(f"Ruleset {name!r} is not valid JSON") from exc

    if not isinstance(document, dict):
        raise ConfigError(f"Ruleset {name!r} Source root must be a JSON object")
    if set(document) != {"version", "rules"}:
        raise ConfigError(
            f"Ruleset {name!r} Source root must contain exactly 'version' and 'rules'"
        )
    version = document["version"]
    if type(version) is not int or version not in range(1, 6):
        raise ConfigError(
            f"Ruleset {name!r} Source version must be an integer from 1 to 5"
        )
    if not isinstance(document["rules"], list):
        raise ConfigError(f"Ruleset {name!r} Source rules must be a JSON array")
    return document


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJsonKey(key)
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"invalid JSON constant {value}")


def _parse_rule(rule: dict[str, Any], path: str) -> RuleExpression:
    rule_type = rule.get("type", "default")
    if not isinstance(rule_type, str):
        raise ConfigError(f"Sing-box Source {path}.type must be a string")
    if rule_type == "logical":
        return _parse_logical_rule(rule, path)
    if rule_type not in {"", "default"}:
        raise _UnsupportedRule(
            f"{path}.type",
            f"Sing-box Source {path} uses unsupported rule type {rule_type!r}",
        )
    return _parse_default_rule(rule, path)


def _parse_logical_rule(rule: dict[str, Any], path: str) -> RuleExpression:
    _reject_unknown_fields(rule, _LOGICAL_FIELDS, path)
    if "mode" not in rule or "rules" not in rule:
        raise ConfigError(
            f"Sing-box Source {path} logical rule requires 'mode' and 'rules'"
        )
    mode = rule["mode"]
    if not isinstance(mode, str) or mode not in {"and", "or"}:
        raise ConfigError(f"Sing-box Source {path}.mode must be 'and' or 'or'")
    invert = _read_invert(rule, path)
    children = rule["rules"]
    if not isinstance(children, list):
        raise ConfigError(f"Sing-box Source {path}.rules must be a JSON array")
    if not children:
        raise _UnsupportedRule(
            f"{path}.rules",
            f"Sing-box Source {path} logical rule has no conditions",
        )

    operands: list[RuleExpression] = []
    for index, child in enumerate(children, start=1):
        child_path = f"{path}.rules[{index}]"
        if not isinstance(child, dict):
            raise ConfigError(f"Sing-box Source {child_path} must be a JSON object")
        operands.append(_parse_rule(child, child_path))

    if len(operands) == 1:
        expression = operands[0]
    else:
        expression = LogicalExpression(mode.upper(), tuple(operands))
    return _apply_invert(expression, invert)


def _parse_default_rule(rule: dict[str, Any], path: str) -> RuleExpression:
    _reject_unknown_fields(rule, _DEFAULT_FIELDS, path)
    for field in sorted(_UNREPRESENTABLE_FIELDS):
        if field in rule:
            raise _UnsupportedRule(
                f"{path}.{field}",
                f"Sing-box Source field {field!r} cannot be represented by the rule IR",
            )
    invert = _read_invert(rule, path)

    groups: list[RuleExpression] = []

    destination = []
    destination.extend(_string_predicates(rule, "domain", "DOMAIN", path))
    destination.extend(_domain_suffix_predicates(rule, path))
    destination.extend(
        _string_predicates(rule, "domain_keyword", "DOMAIN-KEYWORD", path)
    )
    destination.extend(_regex_predicates(rule, "domain_regex", "DOMAIN-REGEX", path))
    destination.extend(_ip_predicates(rule, "ip_cidr", False, path))
    _append_group(groups, destination, "OR")

    _append_group(
        groups,
        _port_predicates(rule, "port", "port_range", "DST-PORT", path),
        "OR",
    )
    _append_group(
        groups,
        _port_predicates(rule, "source_port", "source_port_range", "SRC-PORT", path),
        "OR",
    )
    _append_group(
        groups,
        _network_predicates(rule, path),
        "OR",
    )
    _append_group(
        groups,
        _ip_predicates(rule, "source_ip_cidr", True, path),
        "OR",
    )
    for field, rule_type in (
        ("process_name", "PROCESS-NAME"),
        ("process_path", "PROCESS-PATH"),
    ):
        _append_group(groups, _string_predicates(rule, field, rule_type, path), "OR")
    _append_group(
        groups,
        _regex_predicates(rule, "process_path_regex", "PROCESS-PATH-REGEX", path),
        "OR",
    )

    if not groups:
        raise _UnsupportedRule(
            path,
            f"Sing-box Source {path} has no supported match conditions",
        )
    if len(groups) == 1:
        expression = groups[0]
    else:
        expression = LogicalExpression("AND", tuple(groups))
    return _apply_invert(expression, invert)


def _reject_unknown_fields(
    rule: dict[str, Any], allowed: frozenset[str], path: str
) -> None:
    unknown = sorted(set(rule) - allowed)
    if unknown:
        field = unknown[0]
        raise _UnsupportedRule(
            f"{path}.{field}",
            f"Sing-box Source {path} contains unknown field {field!r}",
        )


def _read_invert(rule: dict[str, Any], path: str) -> bool:
    value = rule.get("invert", False)
    if not isinstance(value, bool):
        raise ConfigError(f"Sing-box Source {path}.invert must be a boolean")
    return value


def _string_predicates(
    rule: dict[str, Any], field: str, rule_type: str, path: str
) -> list[Predicate]:
    return [Predicate(rule_type, value) for value in _string_values(rule, field, path)]


def _string_values(rule: dict[str, Any], field: str, path: str) -> tuple[str, ...]:
    if field not in rule:
        return ()
    value = rule[field]
    if isinstance(value, list) and not value:
        raise _UnsupportedRule(
            f"{path}.{field}",
            f"Sing-box Source {path}.{field} must not be an empty array",
        )
    values = value if isinstance(value, list) else [value]
    if any(not isinstance(item, str) or not item for item in values):
        raise ConfigError(
            f"Sing-box Source {path}.{field} must be a string or an array of non-empty strings"
        )
    return tuple(values)


def _domain_suffix_predicates(rule: dict[str, Any], path: str) -> list[RuleExpression]:
    predicates: list[RuleExpression] = []
    for value in _string_values(rule, "domain_suffix", path):
        if value.startswith("..") or value == ".":
            raise _UnsupportedRule(
                f"{path}.domain_suffix",
                "Sing-box Source leading-dot domain suffix must name a domain",
            )
        if value.startswith("."):
            suffix = value[1:]
            predicates.append(
                LogicalExpression(
                    "AND",
                    (
                        Predicate("DOMAIN-SUFFIX", suffix),
                        LogicalExpression("NOT", (Predicate("DOMAIN", suffix),)),
                    ),
                )
            )
        else:
            predicates.append(Predicate("DOMAIN-SUFFIX", value))
    return predicates


def _regex_predicates(
    rule: dict[str, Any], field: str, rule_type: str, path: str
) -> list[Predicate]:
    predicates: list[Predicate] = []
    for index, value in enumerate(_string_values(rule, field, path), start=1):
        value_path = f"{path}.{field}"
        if isinstance(rule[field], list):
            value_path = f"{value_path}[{index}]"
        _validate_re2_subset(value, value_path)
        predicates.append(Predicate(rule_type, value))
    return predicates


def _validate_re2_subset(pattern: str, path: str) -> None:
    # Keep only syntax with the same structural meaning in Python and Go RE2.
    _reject_ambiguous_re2_syntax(pattern, path)
    try:
        re.compile(pattern)
    except (re.error, RecursionError, MemoryError, OverflowError) as exc:
        raise _UnsupportedRule(
            path,
            f"Sing-box Source {path} contains an invalid regular expression",
        ) from exc

    in_class = False
    index = 0
    while index < len(pattern):
        character = pattern[index]
        if character == "\\":
            if index + 1 >= len(pattern):
                raise _UnsupportedRule(
                    path,
                    f"Sing-box Source {path} contains an invalid regular expression",
                )
            escaped = pattern[index + 1]
            if escaped.isdigit() or escaped == "Z":
                _raise_unsupported_regex(path)
            if escaped.isalpha() and escaped not in _RE2_ALPHA_ESCAPES:
                _raise_unsupported_regex(path)
            if not escaped.isalnum() and escaped not in _RE2_ESCAPED_PUNCTUATION:
                _raise_unsupported_regex(path)
            index += 2
            continue
        if character == "[" and not in_class:
            in_class = True
            index += 1
            continue
        if character == "]" and in_class:
            in_class = False
            index += 1
            continue
        if in_class:
            index += 1
            continue
        if pattern.startswith("(?", index):
            _raise_unsupported_regex(path)
        if character in "*+?" and pattern[index + 1 : index + 2] == "+":
            _raise_unsupported_regex(path)
        if character == "{":
            repetition = _COUNTED_REPETITION_RE.match(pattern, index)
            if repetition is None:
                _raise_unsupported_regex(path)
            bounds = [
                int(bound) for bound in repetition.groups() if bound not in {None, ""}
            ]
            if any(bound > 1000 for bound in bounds):
                _raise_unsupported_regex(path)
            if pattern[repetition.end() : repetition.end() + 1] == "+":
                _raise_unsupported_regex(path)
            index = repetition.end()
            continue
        if character == "}":
            _raise_unsupported_regex(path)
        index += 1

    _validate_repeat_expansion(pattern, path)


def _reject_ambiguous_re2_syntax(pattern: str, path: str) -> None:
    index = 0
    while index < len(pattern):
        character = pattern[index]
        if character == "\\":
            index += 2
            continue
        if character == "[":
            class_end = _character_class_end(pattern, index)
            if "[:" in pattern[index + 1 : class_end]:
                _raise_unsupported_regex(path)
            index = class_end
            continue
        if character == "{":
            closing = pattern.find("}", index + 1)
            if closing != -1 and any(
                digit.isdecimal() and not digit.isascii()
                for digit in pattern[index + 1 : closing]
            ):
                _raise_unsupported_regex(path)
            repetition = _COUNTED_REPETITION_RE.match(pattern, index)
            if repetition is not None and any(
                _has_leading_zero(bound)
                for bound in repetition.groups()
                if bound not in {None, ""}
            ):
                _raise_unsupported_regex(path)
            if repetition is not None:
                index = repetition.end()
                continue
        index += 1


def _has_leading_zero(value: str) -> bool:
    return len(value) > 1 and value.startswith("0")


def _validate_repeat_expansion(pattern: str, path: str) -> None:
    group_products = [1]
    pending_product: int | None = None
    can_repeat = False
    index = 0

    while index < len(pattern):
        character = pattern[index]
        if character == "\\":
            if pending_product is not None:
                group_products[-1] = max(group_products[-1], pending_product)
            pending_product = 1
            can_repeat = True
            index += 2
            continue
        if character == "[":
            if pending_product is not None:
                group_products[-1] = max(group_products[-1], pending_product)
            pending_product = 1
            can_repeat = True
            index = _character_class_end(pattern, index)
            continue
        if character == "(":
            if pending_product is not None:
                group_products[-1] = max(group_products[-1], pending_product)
            pending_product = None
            can_repeat = False
            group_products.append(1)
            index += 1
            continue
        if character == ")":
            if pending_product is not None:
                group_products[-1] = max(group_products[-1], pending_product)
            pending_product = group_products.pop()
            can_repeat = True
            index += 1
            continue
        if character == "|":
            if pending_product is not None:
                group_products[-1] = max(group_products[-1], pending_product)
            pending_product = None
            can_repeat = False
            index += 1
            continue
        if character in "*+?":
            if pending_product is None or not can_repeat:
                _raise_unsupported_regex(path)
            can_repeat = False
            index += 1
            if pattern[index : index + 1] == "?":
                index += 1
            continue
        if character == "{":
            repetition = _COUNTED_REPETITION_RE.match(pattern, index)
            if repetition is None or pending_product is None or not can_repeat:
                _raise_unsupported_regex(path)
            minimum_text, maximum_text = repetition.groups()
            multiplier = (
                int(minimum_text) if maximum_text in {None, ""} else int(maximum_text)
            )
            if pending_product * multiplier > 1000:
                _raise_unsupported_regex(path)
            pending_product *= multiplier
            can_repeat = False
            index = repetition.end()
            if pattern[index : index + 1] == "?":
                index += 1
            continue

        if pending_product is not None:
            group_products[-1] = max(group_products[-1], pending_product)
        pending_product = 1
        can_repeat = True
        index += 1


def _character_class_end(pattern: str, start: int) -> int:
    index = start + 1
    if pattern[index : index + 1] == "^":
        index += 1
    if pattern[index : index + 1] == "]":
        index += 1
    while index < len(pattern):
        if pattern[index] == "\\":
            index += 2
            continue
        if pattern[index] == "]":
            return index + 1
        index += 1
    return index


def _raise_unsupported_regex(path: str) -> None:
    raise _UnsupportedRule(
        path,
        f"Sing-box Source {path} uses regular-expression syntax outside the "
        "supported Go RE2-compatible subset",
    )


def _ip_predicates(
    rule: dict[str, Any], field: str, source: bool, path: str
) -> list[Predicate]:
    predicates: list[Predicate] = []
    for value in _string_values(rule, field, path):
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            raise ConfigError(
                f"Sing-box Source {path}.{field} contains an invalid IP CIDR"
            ) from exc
        rule_type = (
            "SRC-IP-CIDR"
            if source
            else ("IP-CIDR" if network.version == 4 else "IP-CIDR6")
        )
        predicates.append(Predicate(rule_type, str(network)))
    return predicates


def _port_predicates(
    rule: dict[str, Any],
    value_field: str,
    range_field: str,
    rule_type: str,
    path: str,
) -> list[Predicate]:
    predicates = [
        Predicate(rule_type, str(value))
        for value in _port_values(rule, value_field, path)
    ]
    predicates.extend(
        Predicate(rule_type, _normalize_port_range(value, path, range_field))
        for value in _string_values(rule, range_field, path)
    )
    return predicates


def _port_values(rule: dict[str, Any], field: str, path: str) -> tuple[int, ...]:
    if field not in rule:
        return ()
    value = rule[field]
    if isinstance(value, list) and not value:
        raise _UnsupportedRule(
            f"{path}.{field}",
            f"Sing-box Source {path}.{field} must not be an empty array",
        )
    values = value if isinstance(value, list) else [value]
    if any(type(item) is not int or not 0 <= item <= 65535 for item in values):
        raise ConfigError(
            f"Sing-box Source {path}.{field} must be a port or an array of ports"
        )
    return tuple(values)


def _normalize_port_range(value: str, path: str, field: str) -> str:
    match = _PORT_RANGE_RE.fullmatch(value)
    if match is None or not any(match.groups()):
        raise ConfigError(
            f"Sing-box Source {path}.{field} contains an invalid port range"
        )
    start_text, end_text = match.groups()
    start = int(start_text) if start_text else 0
    end = int(end_text) if end_text else 65535
    if start > end or not 0 <= start <= 65535 or not 0 <= end <= 65535:
        raise ConfigError(
            f"Sing-box Source {path}.{field} contains an invalid port range"
        )
    return f"{start}-{end}"


def _network_predicates(rule: dict[str, Any], path: str) -> list[Predicate]:
    predicates: list[Predicate] = []
    for value in _string_values(rule, "network", path):
        if value not in {"tcp", "udp", "icmp"}:
            raise ConfigError(
                f"Sing-box Source {path}.network contains an invalid network"
            )
        if value == "icmp":
            raise _UnsupportedRule(
                f"{path}.network",
                "Sing-box Source network 'icmp' cannot be represented by the rule IR",
            )
        predicates.append(Predicate("NETWORK", value))
    return predicates


def _append_group(
    groups: list[RuleExpression], operands: list[RuleExpression], operator: str
) -> None:
    if not operands:
        return
    if len(operands) == 1:
        groups.append(operands[0])
    else:
        groups.append(LogicalExpression(operator, tuple(operands)))


def _apply_invert(expression: RuleExpression, invert: bool) -> RuleExpression:
    if not invert:
        return expression
    return LogicalExpression("NOT", (expression,))


def _with_source_line(expression: RuleExpression, source_line: int) -> RuleExpression:
    if isinstance(expression, Predicate):
        return Predicate(
            expression.rule_type,
            expression.matcher,
            expression.options,
            source_line,
        )
    return LogicalExpression(
        expression.operator,
        tuple(
            _with_source_line(operand, source_line) for operand in expression.operands
        ),
        expression.options,
        source_line,
    )


def _encode_source_rule(
    expression: RuleExpression, source_context: DialectContext
) -> dict[str, Any]:
    if isinstance(expression, Predicate):
        return _encode_source_predicate(expression, source_context)
    if expression.options:
        option = expression.options[0]
        raise _UnsupportedTargetRule(
            "ruleset.unsupported-target-option",
            f"Rule option {option!r} cannot be rendered for sing-box",
        )

    operator = expression.operator.upper()
    if operator == "NOT":
        if len(expression.operands) != 1:
            raise _UnsupportedTargetRule(
                "ruleset.unsupported-target-rule",
                "Logical NOT requires exactly one operand for sing-box",
            )
        encoded = _encode_source_rule(expression.operands[0], source_context)
        if encoded.get("invert") is True:
            encoded.pop("invert")
        else:
            encoded["invert"] = True
        return encoded
    if operator not in {"AND", "OR"}:
        raise _UnsupportedTargetRule(
            "ruleset.unsupported-target-rule",
            f"Logical rule type {expression.operator} cannot be rendered for sing-box",
        )
    if not expression.operands:
        raise _UnsupportedTargetRule(
            "ruleset.unsupported-target-rule",
            f"Logical {operator} has no operands",
        )

    leading_dot = _leading_dot_domain_suffix(expression)
    if leading_dot is not None:
        return {"domain_suffix": f".{leading_dot}"}

    rules = [
        _encode_source_rule(operand, source_context) for operand in expression.operands
    ]
    if len(rules) == 1:
        return rules[0]
    return {"type": "logical", "mode": operator.lower(), "rules": rules}


def _encode_source_predicate(
    predicate: Predicate, source_context: DialectContext
) -> dict[str, Any]:
    rule_type = predicate.rule_type.upper()
    matcher = predicate.matcher
    options = predicate.options
    if source_context.dialect in {"surge", "stash"} and rule_type == "DEST-PORT":
        rule_type = "DST-PORT"
    if source_context.dialect in {"surge", "stash"}:
        if rule_type == "SRC-IP":
            rule_type = "SRC-IP-CIDR"
        elif rule_type == "PROTOCOL" and matcher.lower() in {"tcp", "udp"}:
            rule_type = "NETWORK"
            matcher = matcher.lower()
        elif rule_type == "PROCESS-NAME":
            rule_type, matcher = _canonical_process_matcher(matcher)
    if (
        source_context.dialect == "mihomo"
        and rule_type in {"IP-CIDR", "IP-CIDR6"}
        and "src" in options
    ):
        co_options = tuple(option for option in options if option != "src")
        if co_options:
            option = co_options[0]
            raise _UnsupportedTargetRule(
                "ruleset.unsupported-target-option",
                f"Rule option {option!r} cannot be rendered for sing-box",
            )
        rule_type = "SRC-IP-CIDR"
        options = ()
    if options:
        option = options[0]
        raise _UnsupportedTargetRule(
            "ruleset.unsupported-target-option",
            f"Rule option {option!r} cannot be rendered for sing-box",
        )

    field_by_type = {
        "DOMAIN": "domain",
        "DOMAIN-SUFFIX": "domain_suffix",
        "DOMAIN-KEYWORD": "domain_keyword",
        "DOMAIN-REGEX": "domain_regex",
        "IP-CIDR": "ip_cidr",
        "IP-CIDR6": "ip_cidr",
        "SRC-IP-CIDR": "source_ip_cidr",
        "NETWORK": "network",
        "PROCESS-NAME": "process_name",
        "PROCESS-PATH": "process_path",
        "PROCESS-PATH-REGEX": "process_path_regex",
    }
    if rule_type in {"DST-PORT", "SRC-PORT"}:
        return _encode_source_port(predicate.matcher, source=rule_type == "SRC-PORT")
    field = field_by_type.get(rule_type)
    if field is None:
        raise _UnsupportedTargetRule(
            "ruleset.unsupported-target-rule",
            f"Rule type {rule_type} cannot be rendered for sing-box",
        )
    if not matcher:
        raise _UnsupportedTargetRule(
            "ruleset.unsupported-target-rule",
            f"Rule type {predicate.rule_type} has an empty matcher",
        )
    if rule_type in {"IP-CIDR", "IP-CIDR6", "SRC-IP-CIDR"}:
        try:
            matcher = str(ipaddress.ip_network(matcher, strict=False))
        except ValueError as exc:
            raise _UnsupportedTargetRule(
                "ruleset.unsupported-target-rule",
                f"Rule type {predicate.rule_type} has an invalid IP CIDR",
            ) from exc
    elif rule_type == "NETWORK" and matcher not in {"tcp", "udp"}:
        raise _UnsupportedTargetRule(
            "ruleset.unsupported-target-rule",
            f"Network {matcher!r} cannot be rendered for sing-box",
        )
    elif rule_type in {"DOMAIN-REGEX", "PROCESS-PATH-REGEX"}:
        try:
            _validate_re2_subset(matcher, predicate.rule_type)
        except _UnsupportedRule as exc:
            raise _UnsupportedTargetRule(
                "ruleset.unsupported-target-rule", exc.message
            ) from exc
    return {field: matcher}


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


def _encode_source_port(matcher: str, *, source: bool) -> dict[str, Any]:
    parts = [part.strip() for part in matcher.split(",")]
    if not parts or any(not part for part in parts):
        raise _UnsupportedTargetRule(
            "ruleset.unsupported-target-rule",
            f"Port matcher {matcher!r} cannot be rendered for sing-box",
        )
    rules = [_encode_source_port_part(part, source=source) for part in parts]
    if len(rules) == 1:
        return rules[0]
    return {"type": "logical", "mode": "or", "rules": rules}


def _encode_source_port_part(value: str, *, source: bool) -> dict[str, Any]:
    value_field = "source_port" if source else "port"
    range_field = "source_port_range" if source else "port_range"
    if value.isdigit():
        port = int(value)
        if 0 <= port <= 65535:
            return {value_field: port}
    match = re.fullmatch(r"(\d+)-(\d+)", value)
    if match is not None:
        start, end = (int(part) for part in match.groups())
        if 0 <= start <= end <= 65535:
            start_text = "" if start == 0 else str(start)
            end_text = "" if end == 65535 else str(end)
            if not start_text and not end_text:
                start_text, end_text = "0", "65535"
            return {range_field: f"{start_text}:{end_text}"}
    raise _UnsupportedTargetRule(
        "ruleset.unsupported-target-rule",
        f"Port matcher {value!r} cannot be rendered for sing-box",
    )


def _leading_dot_domain_suffix(expression: LogicalExpression) -> str | None:
    if expression.operator.upper() != "AND" or len(expression.operands) != 2:
        return None
    suffix, negated = expression.operands
    if not isinstance(suffix, Predicate) or suffix.rule_type != "DOMAIN-SUFFIX":
        return None
    if suffix.options or not isinstance(negated, LogicalExpression):
        return None
    if negated.operator.upper() != "NOT" or len(negated.operands) != 1:
        return None
    domain = negated.operands[0]
    if not isinstance(domain, Predicate) or domain.rule_type != "DOMAIN":
        return None
    if domain.options or domain.matcher != suffix.matcher or not suffix.matcher:
        return None
    return suffix.matcher
