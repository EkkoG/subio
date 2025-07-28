"""Clash renderer base class."""
import yaml
from typing import List, Dict, Any, Optional
from pathlib import Path
from jinja2 import Environment, FileSystemLoader, select_autoescape
from ...core.registry import renderer_registry
from ...models import Node
from ...models.node import Proxy
from ..base import BaseRenderer


@renderer_registry.decorator('clash')
@renderer_registry.decorator('clash-meta')
class ClashRenderer(BaseRenderer):
    """Renderer for Clash YAML format."""
    
    def __init__(self, template_dir: Optional[str] = None, snippet_dir: Optional[str] = None):
        super().__init__(template_dir, snippet_dir)
        self._setup_jinja_env()
        self._register_protocols()
    
    def _setup_jinja_env(self):
        """Setup Jinja2 environment."""
        if self.template_dir:
            self.env = Environment(
                loader=FileSystemLoader(self.template_dir),
                autoescape=select_autoescape(),
                trim_blocks=True,
                lstrip_blocks=True
            )
            self._register_filters()
        else:
            self.env = None
    
    def _register_filters(self):
        """Register custom Jinja2 filters."""
        if self.env:
            self.env.filters['to_yaml'] = self._to_yaml_filter
            self.env.filters['to_json'] = self._to_json_filter
            self.env.filters['quote'] = self._quote_filter
            self.env.filters['render'] = self._render_filter
            
            # Import and register all node filters globally
            from ...filters import all_filters
            self.env.globals['filter'] = all_filters
    
    def _register_protocols(self):
        """Register protocol-specific renderers by importing modules."""
        try:
            # Import all protocol modules to trigger auto-registration
            from .protocols import shadowsocks, vmess, trojan, vless, hysteria, http, socks5
            from .protocols.registry import clash_renderer_registry
            
            # Store reference to registry
            self.protocol_registry = clash_renderer_registry
            
        except ImportError as e:
            print(f"Warning: Failed to import protocol renderers: {e}")
            self.protocol_registry = None
    
    def render(self, nodes: List[Node], template: Optional[str], context: Dict[str, Any]) -> str:
        """Render nodes to Clash format."""
        if template and self.env:
            # Use template rendering
            return self._render_with_template(nodes, template, context)
        else:
            # Direct rendering
            return self._render_direct(nodes)
    
    def _render_with_template(self, nodes: List[Node], template: str, context: Dict[str, Any]) -> str:
        """Render using Jinja2 template."""
        try:
            # Load template with snippet and ruleset prepended
            template_source = self.env.loader.get_source(self.env, template)[0]
            prepend_text = ""
            if self._ruleset_text:
                prepend_text += self._ruleset_text + '\n'
            if self._snippet_text:
                prepend_text += self._snippet_text + '\n'
            if prepend_text:
                template_source = prepend_text + template_source
            tmpl = self.env.from_string(template_source)
            
            # Prepare context
            full_context = context.copy()
            # Render nodes to YAML-compatible dicts
            proxies_list = []
            for node in nodes:
                if isinstance(node, Proxy):
                    proxy_dict = self._render_node(node)
                    if proxy_dict:
                        proxies_list.append(proxy_dict)
            full_context['proxies'] = yaml.dump(proxies_list, allow_unicode=True, sort_keys=False)
            full_context['proxies_names'] = [node.name for node in nodes]
            
            return tmpl.render(**full_context)
        except Exception as e:
            print(f"Template rendering failed: {e}")
            return self._render_direct(nodes)
    
    def _render_direct(self, nodes: List[Node]) -> str:
        """Direct rendering without template."""
        proxies = []
        
        for node in nodes:
            if isinstance(node, Proxy):
                proxy_dict = self._render_node(node)
                if proxy_dict:
                    proxies.append(proxy_dict)
        
        result = {'proxies': proxies}
        return yaml.dump(result, allow_unicode=True, sort_keys=False)
    
    def _render_node(self, node: Proxy) -> Optional[Dict[str, Any]]:
        """Render a single node using protocol-specific renderer."""
        try:
            protocol_type = node.protocol.get_type().value
            
            if self.protocol_registry:
                renderer_func = self.protocol_registry.get_renderer(protocol_type)
                if renderer_func:
                    return renderer_func(node)
            
            # Fallback to generic rendering
            return node.to_dict()
            
        except Exception as e:
            print(f"Failed to render node {node.name}: {e}")
            return None
    
    # Jinja2 filters
    def _to_yaml_filter(self, data):
        """Convert data to YAML format."""
        return yaml.dump(data, allow_unicode=True, sort_keys=False)
    
    def _to_json_filter(self, data):
        """Convert data to JSON format."""
        import json
        return json.dumps(data, ensure_ascii=False, indent=2)
    
    def _quote_filter(self, text):
        """Quote text for YAML."""
        return f'"{text}"'
    
    def _render_filter(self, items):
        """Render items based on context - arrays or rulesets."""
        if isinstance(items, str):
            # This is likely ruleset text from a macro
            from ...utils.ruleset_render import render_ruleset_in_clash
            return render_ruleset_in_clash(items)
        elif isinstance(items, list):
            # This is a list of proxy names
            if not items:
                return '[]'
            # Return YAML inline list format with unicode support
            return yaml.dump(items, default_flow_style=True, allow_unicode=True).strip()
        else:
            # Fallback - convert to string
            return str(items)