"""Executable node contracts selected by a format's target factory."""

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from subio_v2.core.dialect import DialectContext
from subio_v2.core.nodes import Node, Protocol
from subio_v2.core.results import IssueDraft


@dataclass(frozen=True)
class NodeTargetCodec:
    protocol: Protocol
    check: Callable[[Node], list[IssueDraft]]
    encode: Callable[[Node, Any], Any]
    target_constraints: Mapping[str, Any] = field(default_factory=dict)


@dataclass
class TargetAdapter:
    context: DialectContext
    codecs: dict[Protocol, NodeTargetCodec]
    check_common: Callable[[Node], list[IssueDraft]]
    reference: str
