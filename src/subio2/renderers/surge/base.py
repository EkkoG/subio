"""Surge renderer implementation."""
from typing import List, Optional, Dict, Any
from ...models.node_composite import CompositeNode
from ..base import BaseRenderer
import os
from pathlib import Path
from jinja2 import Environment, FileSystemLoader, select_autoescape
from ...core.registry import renderer_registry
from .protocols.registry import surge_protocol_registry


@renderer_registry.decorator('surge')
class SurgeRenderer(BaseRenderer):
    """Renderer for Surge format."""
    
    def __init__(self, template_dir: Optional[str] = None, snippet_dir: Optional[str] = None):
        super().__init__(template_dir, snippet_dir)
        # Trigger protocol registration
        from . import protocols  # noqa
        
        # Setup Jinja2 environment if template directories exist
        if self.template_dir and os.path.exists(self.template_dir):
            self.env = Environment(
                loader=FileSystemLoader([self.template_dir, self.snippet_dir] if self.snippet_dir else [self.template_dir]),
                autoescape=select_autoescape(),
                trim_blocks=True,
                lstrip_blocks=True
            )
            self._register_filters()
        else:
            self.env = None
    
    def render(self, nodes: List[CompositeNode], template: Optional[str] = None, context: Dict[str, Any] = None) -> str:
        """Render nodes to Surge format."""
        # If template is provided, use template rendering
        if template:
            # For template rendering, convert nodes to Surge format
            surge_lines = []
            for node in nodes:
                line = self._render_node(node)
                if line:
                    surge_lines.append(line)
            
            # Add rendered nodes to context
            if context is None:
                context = {}
            context['proxies'] = '\n'.join(surge_lines)
            context['proxies_names'] = [node.name for node in nodes]
            
            # Use Jinja2 template rendering
            if self.env:
                jinja_template = self.env.get_template(template)
                return jinja_template.render(context)
            else:
                return '\n'.join(surge_lines)
        
        # Otherwise, just render proxy lines
        lines = []
        for node in nodes:
            line = self._render_node(node)
            if line:
                lines.append(line)
        
        return '\n'.join(lines)
    
    def _render_node(self, node: CompositeNode) -> Optional[str]:
        """Render a single node to Surge proxy line."""
        protocol_type = node.protocol.get_type().value
        renderer = surge_protocol_registry.get_renderer(protocol_type)
        
        if renderer:
            return renderer(node)
        else:
            return None
    
    def _register_filters(self):
        """Register custom Jinja2 filters."""
        if not self.env:
            return
            
        self.env.filters['to_yaml'] = self._to_yaml_filter
        self.env.filters['render'] = self._render_filter
        
        # Import and register all node filters globally
        from ...filters import all_filters
        self.env.globals['filter'] = all_filters
    
    @staticmethod
    def _to_yaml_filter(value):
        """Convert value to YAML."""
        import yaml
        return yaml.dump(value, default_flow_style=False, allow_unicode=True)
    
    def _render_filter(self, value):
        """Render a value (list or string) in appropriate format."""
        if isinstance(value, list):
            # For Surge, render as comma-separated list
            return ', '.join(str(v) for v in value)
        elif isinstance(value, str):
            return value
        else:
            return str(value)