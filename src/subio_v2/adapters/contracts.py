"""Executable node contracts selected by a format's target factory."""

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from subio_v2.core.dialect import DialectContext
from subio_v2.core.nodes import Node, Protocol
from subio_v2.core.results import IssueDraft, IssueSeverity


@dataclass(frozen=True)
class NodeTargetCodec:
    protocol: Protocol
    check_protocol: Callable[[Node], list[IssueDraft]]
    encode: Callable[[Node, Any], Any]
    target_constraints: Mapping[str, Any] = field(default_factory=dict)
    section: str | None = None
    precheck: Callable[[Node], list[IssueDraft]] = lambda node: []
    check_common: Callable[[Node], list[IssueDraft]] = lambda node: []

    def check(self, node: Node) -> list[IssueDraft]:
        issues = self.precheck(node)
        if any(issue.severity == IssueSeverity.ERROR for issue in issues):
            return issues
        return issues + self.check_protocol(node) + self.check_common(node)


@dataclass
class TargetAdapter:
    context: DialectContext
    codecs: dict[Protocol, NodeTargetCodec]
    reference: str
    source_passthrough: NodeTargetCodec | None = None
    precheck: Callable[[Node], list[IssueDraft]] = lambda node: []
