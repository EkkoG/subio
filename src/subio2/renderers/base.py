"""Base renderer class for new renderer structure."""
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from ..models import Node


class BaseRenderer(ABC):
    """Base class for all renderers."""
    
    def __init__(self, template_dir: Optional[str] = None, snippet_dir: Optional[str] = None):
        """Initialize renderer with optional template directories."""
        self.template_dir = template_dir
        self.snippet_dir = snippet_dir
    
    @abstractmethod
    def render(self, nodes: List[Node], template: Optional[str], context: Dict[str, Any]) -> str:
        """Render nodes to target format."""
        pass