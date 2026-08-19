from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Protocol

import yaml

from subio_v2.dialect import DialectContext
from subio_v2.errors import ConfigError
from subio_v2.model.rules import (
    HeadlessRuleSet,
    LogicalExpression,
    Predicate,
    RuleComment,
    RuleExpression,
    RuleSetEntry,
    RuleSetParseResult,
)
from subio_v2.rules.mrs import decode_mrs
from subio_v2.rules.parser import (
    MIHOMO_CLASSICAL_PARSER,
    STASH_CLASSICAL_PARSER,
    SURGE_CLASSICAL_PARSER,
    ClassicalRuleParser,
)

SUPPORTED_RULESET_DIALECTS = frozenset({"mihomo", "stash", "surge"})


class _UniqueKeySafeLoader(yaml.SafeLoader):
    pass


def _construct_unique_mapping(loader, node, deep=False):
    mapping = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"found duplicate key {key!r}",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeySafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


@dataclass(frozen=True)
class RuleSetInputSelection:
    dialect: str
    behavior: str
    format: str

    @classmethod
    def from_config(cls, config: dict[str, object]) -> RuleSetInputSelection:
        dialect = config.get("type", "mihomo")
        behavior = config.get("behavior", "classical")
        format_name = config.get("format", "text")

        for field_name, value in (
            ("type", dialect),
            ("behavior", behavior),
            ("format", format_name),
        ):
            if not isinstance(value, str) or not value:
                raise ConfigError(f"Ruleset {field_name!r} must be a non-empty string")

        if dialect not in SUPPORTED_RULESET_DIALECTS:
            raise ConfigError(f"Unsupported ruleset input type: {dialect!r}")
        return cls(dialect=dialect, behavior=behavior, format=format_name)


class RuleSetInputCodec(Protocol):
    def parse(
        self,
        *,
        name: str,
        content: bytes,
        context: DialectContext,
    ) -> RuleSetParseResult: ...


class RuleSetInputCodecRegistry:
    def __init__(self) -> None:
        self._codecs: dict[tuple[str, str, str], RuleSetInputCodec] = {}

    def register(
        self,
        dialect: str,
        behavior: str,
        format_name: str,
        codec: RuleSetInputCodec,
    ) -> None:
        key = (dialect, behavior, format_name)
        if key in self._codecs:
            raise ValueError(f"Duplicate ruleset input codec: {key!r}")
        self._codecs[key] = codec

    def get(self, selection: RuleSetInputSelection) -> RuleSetInputCodec:
        key = (selection.dialect, selection.behavior, selection.format)
        codec = self._codecs.get(key)
        if codec is None:
            raise ConfigError(
                "Unsupported ruleset input combination: "
                f"type={selection.dialect!r}, behavior={selection.behavior!r}, "
                f"format={selection.format!r}"
            )
        return codec

    @property
    def combinations(self) -> tuple[tuple[str, str, str], ...]:
        return tuple(sorted(self._codecs))


class ClassicalTextCodec:
    def __init__(self, parser: ClassicalRuleParser):
        self.parser = parser

    def parse(
        self,
        *,
        name: str,
        content: bytes,
        context: DialectContext,
    ) -> RuleSetParseResult:
        text = _decode_utf8(content, name)
        lines = list(enumerate(text.splitlines(), start=1))
        return self.parser.parse_headless(
            name=name,
            lines=lines,
            source_context=context,
        )


class ClassicalYamlCodec:
    def __init__(self, parser: ClassicalRuleParser):
        self.parser = parser

    def parse(
        self,
        *,
        name: str,
        content: bytes,
        context: DialectContext,
    ) -> RuleSetParseResult:
        payload = _load_yaml_payload(content, name)
        lines = [(index, value) for index, value in enumerate(payload, start=1)]
        return self.parser.parse_headless(
            name=name,
            lines=lines,
            source_context=context,
        )


class ScalarRuleSetCodec:
    def __init__(self, behavior: str, format_name: str):
        self.behavior = behavior
        self.format_name = format_name

    def parse(
        self,
        *,
        name: str,
        content: bytes,
        context: DialectContext,
    ) -> RuleSetParseResult:
        if self.format_name == "yaml":
            values = [
                (index, value)
                for index, value in enumerate(
                    _load_yaml_payload(content, name), start=1
                )
            ]
        else:
            text = _decode_utf8(content, name)
            values = list(enumerate(text.splitlines(), start=1))

        return _parse_scalar_values(
            name=name,
            values=values,
            context=context,
            behavior=self.behavior,
        )


class MrsRuleSetCodec:
    def __init__(self, behavior: str):
        self.behavior = behavior

    def parse(
        self,
        *,
        name: str,
        content: bytes,
        context: DialectContext,
    ) -> RuleSetParseResult:
        values = list(enumerate(decode_mrs(content, self.behavior), start=1))
        return _parse_scalar_values(
            name=name,
            values=values,
            context=context,
            behavior=self.behavior,
        )


def _parse_scalar_values(
    *,
    name: str,
    values: list[tuple[int, str]],
    context: DialectContext,
    behavior: str,
) -> RuleSetParseResult:
    entries: list[RuleSetEntry] = []
    for line_number, raw_value in values:
        value = raw_value.strip()
        if not value:
            continue
        if value.startswith("#") or value.startswith("//"):
            entries.append(RuleComment(value, line_number))
            continue
        if behavior == "domain":
            entries.append(_parse_domain(value, context.dialect, name, line_number))
        else:
            entries.append(_parse_ipcidr(value, name, line_number))

    if not entries:
        raise ConfigError(f"Ruleset {name!r} contains no rules or comments")
    return RuleSetParseResult(
        ruleset=HeadlessRuleSet(
            name=name,
            source_context=context,
            behavior=behavior,
            entries=tuple(entries),
        )
    )


def _decode_utf8(content: bytes, name: str) -> str:
    if not isinstance(content, bytes):
        raise ConfigError(f"Ruleset {name!r} loader must return bytes")
    try:
        return content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ConfigError(f"Ruleset {name!r} is not valid UTF-8") from exc


def _load_yaml_payload(content: bytes, name: str) -> list[str]:
    text = _decode_utf8(content, name)
    try:
        document = yaml.load(text, Loader=_UniqueKeySafeLoader)
    except yaml.YAMLError as exc:
        raise ConfigError(f"Ruleset {name!r} is not valid YAML") from exc

    if not isinstance(document, dict) or set(document) != {"payload"}:
        raise ConfigError(
            f"Ruleset {name!r} YAML must contain exactly one 'payload' field"
        )
    payload = document["payload"]
    if not isinstance(payload, list) or not payload:
        raise ConfigError(f"Ruleset {name!r} YAML payload must be a non-empty list")
    if any(not isinstance(value, str) for value in payload):
        raise ConfigError(f"Ruleset {name!r} YAML payload items must be strings")
    return payload


def _parse_domain(
    value: str, dialect: str, source: str, line_number: int
) -> RuleExpression:
    if "," in value or any(char.isspace() for char in value):
        raise ConfigError(
            f"Invalid ruleset {source!r} at line {line_number}: invalid domain entry"
        )
    if value.startswith("+."):
        rule_type, matcher = "DOMAIN-SUFFIX", value[2:]
    elif value.startswith("."):
        matcher = value[1:]
        if dialect in {"mihomo", "stash"}:
            return LogicalExpression(
                operator="AND",
                operands=(
                    Predicate("DOMAIN-SUFFIX", matcher, source_line=line_number),
                    LogicalExpression(
                        operator="NOT",
                        operands=(
                            Predicate("DOMAIN", matcher, source_line=line_number),
                        ),
                        source_line=line_number,
                    ),
                ),
                source_line=line_number,
            )
        rule_type = "DOMAIN-SUFFIX"
    elif "*" in value:
        matcher = _domain_label_pattern_to_regex(value)
        rule_type = "DOMAIN-REGEX"
    else:
        rule_type, matcher = "DOMAIN", value
    if not matcher:
        raise ConfigError(
            f"Invalid ruleset {source!r} at line {line_number}: empty domain entry"
        )
    return Predicate(rule_type=rule_type, matcher=matcher, source_line=line_number)


def _domain_label_pattern_to_regex(value: str) -> str:
    labels = []
    for label in value.split("."):
        escaped = re.escape(label).replace(r"\*", "[^.]*")
        labels.append(escaped)
    return "^" + r"\.".join(labels) + "$"


def _parse_ipcidr(value: str, source: str, line_number: int) -> Predicate:
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise ConfigError(
            f"Invalid ruleset {source!r} at line {line_number}: invalid IP CIDR"
        ) from exc
    rule_type = "IP-CIDR" if network.version == 4 else "IP-CIDR6"
    return Predicate(rule_type=rule_type, matcher=value, source_line=line_number)


def create_default_ruleset_codec_registry() -> RuleSetInputCodecRegistry:
    registry = RuleSetInputCodecRegistry()
    for dialect, parser in (
        ("mihomo", MIHOMO_CLASSICAL_PARSER),
        ("stash", STASH_CLASSICAL_PARSER),
    ):
        registry.register(dialect, "classical", "text", ClassicalTextCodec(parser))
        registry.register(dialect, "classical", "yaml", ClassicalYamlCodec(parser))
        for behavior in ("domain", "ipcidr"):
            registry.register(
                dialect,
                behavior,
                "text",
                ScalarRuleSetCodec(behavior, "text"),
            )
            registry.register(
                dialect,
                behavior,
                "yaml",
                ScalarRuleSetCodec(behavior, "yaml"),
            )
            registry.register(
                dialect,
                behavior,
                "mrs",
                MrsRuleSetCodec(behavior),
            )

    registry.register(
        "surge",
        "classical",
        "text",
        ClassicalTextCodec(SURGE_CLASSICAL_PARSER),
    )
    registry.register(
        "surge", "domain", "text", ScalarRuleSetCodec("domain", "text")
    )
    return registry


DEFAULT_RULESET_CODEC_REGISTRY = create_default_ruleset_codec_registry()
