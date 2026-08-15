from abc import ABC, abstractmethod
from typing import List, Any
from subio_v2.conversion import ParseResult
from subio_v2.model.nodes import Node


class BaseParser(ABC):
    @abstractmethod
    def parse(self, content: Any) -> List[Node]:
        """
        Parse content into a list of Nodes.
        content can be a string (raw text) or dict (parsed yaml/json).
        """
        pass

    def parse_result(self, content: Any) -> ParseResult:
        """Structured parse API; parsers can override to report partial failures."""
        return ParseResult(nodes=self.parse(content))
