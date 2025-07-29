"""Base parser class for new parser structure."""

from abc import ABC, abstractmethod
from typing import List
from ..models import Node


class BaseParser(ABC):
    """Base class for all protocol parsers."""

    @abstractmethod
    def parse(self, content: str) -> List[Node]:
        """Parse content and return list of nodes."""
        pass
