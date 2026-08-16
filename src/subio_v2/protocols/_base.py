from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict

from subio_v2.clash.helpers import (
    assign_extra,
    emit_base,
    merge_extra,
    parse_base_fields,
)
from subio_v2.conversion import IssueDraft
from subio_v2.model.nodes import Node, Protocol
from subio_v2.dialect import DialectContext
from subio_v2.protocols._fields import ClashFieldSpec


@dataclass(frozen=True)
class NodeValidationError:
    field: str
    message: str


class ProtocolDescriptor(ABC):
    """
    Descriptor for one protocol's Clash parse/emit/check behavior.
    """

    protocol: Protocol
    clash_type: str
    node_class: type[Node]
    dynamic_clash_type: bool = False
    requires_endpoint: bool = True
    clash_dialects: frozenset[str] = frozenset({"mihomo", "clash", "stash"})

    def supports_dialect(self, dialect: str) -> bool:
        return dialect in self.clash_dialects

    @abstractmethod
    def parse_clash(
        self, data: Dict[str, Any], context: DialectContext | None = None
    ) -> Node:
        raise NotImplementedError

    @abstractmethod
    def emit_clash(
        self, node: Node, context: DialectContext | None = None
    ) -> Dict[str, Any]:
        raise NotImplementedError

    def check(
        self, node: Node, proto_caps: dict, platform: str
    ) -> list[IssueDraft]:
        return []

    def validate(self, node: Node) -> list[NodeValidationError]:
        return []


class StructuredProtocolDescriptor(ProtocolDescriptor):
    """Descriptor whose handled, parse, and emit behavior share one field spec."""

    fields: tuple[ClashFieldSpec, ...] = ()

    @property
    def consumed_keys(self) -> frozenset[str]:
        return frozenset(key for field in self.fields for key in field.consumed_keys)

    def validate(self, node: Node) -> list[NodeValidationError]:
        errors: list[NodeValidationError] = []
        for field in self.fields:
            for attr in field.required_attrs:
                value = getattr(node, attr)
                if value is None or value == "":
                    errors.append(
                        NodeValidationError(
                            field=attr,
                            message=f"Required field '{attr}' is missing",
                        )
                    )
        return errors

    def prepare_parse_kwargs(
        self, data: Dict[str, Any], kwargs: Dict[str, Any]
    ) -> Dict[str, Any]:
        return kwargs

    def after_parse(self, node: Node, data: Dict[str, Any]) -> Node:
        return node

    def after_emit(self, out: Dict[str, Any], node: Node) -> None:
        return None

    def parse_clash(
        self, data: Dict[str, Any], context: DialectContext | None = None
    ) -> Node:
        context = context or DialectContext("mihomo", "yaml")
        kwargs: Dict[str, Any] = {
            "type": self.protocol,
            **parse_base_fields(data),
        }
        for field in self.fields:
            parsed = field.parse_kwargs(data)
            duplicate = kwargs.keys() & parsed.keys()
            if duplicate:
                names = ", ".join(sorted(duplicate))
                raise ValueError(
                    f"Duplicate parsed attribute(s) for {self.protocol.value}: {names}"
                )
            kwargs.update(parsed)
        kwargs = self.prepare_parse_kwargs(data, kwargs)
        node = self.node_class(**kwargs)
        node.source_context = context
        assign_extra(node, data, set(self.consumed_keys))
        return self.after_parse(node, data)

    def emit_clash(
        self, node: Node, context: DialectContext | None = None
    ) -> Dict[str, Any]:
        context = context or DialectContext("mihomo", "yaml")
        if not isinstance(node, self.node_class):
            raise TypeError(f"Expected {self.node_class.__name__}, got {type(node)}")
        out = emit_base(node)
        for field in self.fields:
            field.emit_into(out, node)
        self.after_emit(out, node)
        return merge_extra(out, node, context)
