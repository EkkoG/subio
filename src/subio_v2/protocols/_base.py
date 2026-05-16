from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict

from subio_v2.model.nodes import Node, Protocol


class ProtocolDescriptor(ABC):
    """
    Descriptor for one protocol's Clash parse/emit/check behavior.
    """

    protocol: Protocol
    clash_type: str
    node_class: type[Node]
    passthrough: bool = False

    @abstractmethod
    def parse_clash(self, data: Dict[str, Any]) -> Node:
        raise NotImplementedError

    @abstractmethod
    def emit_clash(self, node: Node) -> Dict[str, Any]:
        raise NotImplementedError

    def check(self, node: Node, proto_caps: dict, platform: str) -> list[Any]:
        return []
