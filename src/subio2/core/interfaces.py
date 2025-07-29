"""Core interfaces for SubIO2 plugins."""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from ..models import Node


class Parser(ABC):
    """Base interface for all parsers."""

    @abstractmethod
    def parse(self, content: str) -> List[Node]:
        """Parse content and return a list of nodes."""
        pass

    @abstractmethod
    def supports_format(self, format_type: str) -> bool:
        """Check if this parser supports the given format."""
        pass


class Renderer(ABC):
    """Base interface for all renderers."""

    @abstractmethod
    def render(self, nodes: List[Node], template: str, context: Dict[str, Any]) -> str:
        """Render nodes using the template and context."""
        pass

    @abstractmethod
    def supports_format(self, format_type: str) -> bool:
        """Check if this renderer supports the given format."""
        pass


class Filter(ABC):
    """Base interface for all filters."""

    @abstractmethod
    def filter(self, nodes: List[Node]) -> List[Node]:
        """Filter nodes based on implementation logic."""
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the name of this filter."""
        pass


class Uploader(ABC):
    """Base interface for all uploaders."""

    @abstractmethod
    def upload(
        self, content: str, filename: str, config: Dict[str, Any]
    ) -> Optional[str]:
        """Upload content and return the URL if successful."""
        pass

    @abstractmethod
    def supports_type(self, upload_type: str) -> bool:
        """Check if this uploader supports the given type."""
        pass
