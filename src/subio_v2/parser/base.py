from abc import ABC, abstractmethod
from typing import Any

from subio_v2.conversion import ParseResult


class BaseParser(ABC):
    @abstractmethod
    def parse_result(self, content: Any) -> ParseResult:
        """Return parsed nodes and structured issues."""
