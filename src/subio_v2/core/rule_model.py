from __future__ import annotations

from dataclasses import dataclass
from typing import TypeAlias

from subio_v2.core.dialect import DialectContext
from subio_v2.core.results import ConversionIssue


@dataclass(frozen=True)
class Predicate:
    rule_type: str
    matcher: str = ""
    options: tuple[str, ...] = ()
    source_line: int | None = None


@dataclass(frozen=True)
class LogicalExpression:
    operator: str
    operands: tuple[RuleExpression, ...]
    options: tuple[str, ...] = ()
    source_line: int | None = None


RuleExpression: TypeAlias = Predicate | LogicalExpression


@dataclass(frozen=True)
class RuleComment:
    content: str
    source_line: int | None = None


RuleSetEntry: TypeAlias = RuleExpression | RuleComment


@dataclass(frozen=True)
class HeadlessRuleSet:
    name: str
    source_context: DialectContext
    behavior: str
    entries: tuple[RuleSetEntry, ...]


@dataclass(frozen=True)
class DefaultParameter:
    pass


@dataclass(frozen=True)
class ParameterReference:
    name: str


@dataclass(frozen=True)
class LiteralPolicy:
    value: str


PolicyBinding: TypeAlias = DefaultParameter | ParameterReference | LiteralPolicy


@dataclass(frozen=True)
class BoundRule:
    expression: RuleExpression
    policy_binding: PolicyBinding


ParameterizedEntry: TypeAlias = BoundRule | RuleComment


@dataclass(frozen=True)
class ParameterizedRuleSet:
    name: str
    parameters: tuple[str, ...]
    entries: tuple[ParameterizedEntry, ...]
    source_context: DialectContext
    issues: tuple[ConversionIssue, ...] = ()


@dataclass(frozen=True)
class RuleSetParseResult:
    ruleset: HeadlessRuleSet
    issues: tuple[ConversionIssue, ...] = ()


@dataclass(frozen=True)
class RuleRenderResult:
    content: str
    issues: tuple[ConversionIssue, ...] = ()
