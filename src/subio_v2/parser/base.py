from abc import ABC, abstractmethod
from typing import Any
from subio_v2.conversion import ParseResult
from subio_v2.model.nodes import Node


class BaseParser(ABC):
    def parse(self, content: Any) -> list[Node]:
        """Compatibility API returning only successfully parsed nodes."""
        return self.parse_result(content).nodes

    @abstractmethod
    def parse_result(self, content: Any) -> ParseResult:
        """Return parsed nodes and structured issues."""
