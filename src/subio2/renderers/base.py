"""Base renderer class for new renderer structure."""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from ..models import Node
from ..utils.snippet import load_snippets
from ..utils.ruleset import convert_rulesets_to_macros


class BaseRenderer(ABC):
    """Base class for all renderers."""

    def __init__(
        self, template_dir: Optional[str] = None, snippet_dir: Optional[str] = None
    ):
        """Initialize renderer with optional template directories."""
        self.template_dir = template_dir
        self.snippet_dir = snippet_dir
        self._snippet_text = load_snippets(snippet_dir) if snippet_dir else ""
        self._ruleset_text = ""  # Will be set by main.py

    @abstractmethod
    def render(
        self, nodes: List[Node], template: Optional[str], context: Dict[str, Any]
    ) -> str:
        """Render nodes to target format."""
        pass

    def set_rulesets(self, rulesets: Dict[str, str]):
        """Set rulesets for template rendering."""
        self._ruleset_text = convert_rulesets_to_macros(rulesets)
