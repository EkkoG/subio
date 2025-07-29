"""DAE renderer implementation."""

from typing import List, Optional, Dict, Any
from ...models.node import Proxy
from ..base import BaseRenderer
from ...core.registry import renderer_registry
from .protocols.registry import dae_protocol_registry
import os
from jinja2 import Environment, FileSystemLoader, select_autoescape


@renderer_registry.decorator("dae")
class DAERenderer(BaseRenderer):
    """Renderer for DAE format."""

    def __init__(
        self, template_dir: Optional[str] = None, snippet_dir: Optional[str] = None
    ):
        super().__init__(template_dir, snippet_dir)
        # Trigger protocol registration
        from . import protocols  # noqa

        # Setup Jinja2 environment if template directories exist
        if self.template_dir and os.path.exists(self.template_dir):
            self.env = Environment(
                loader=FileSystemLoader(
                    [self.template_dir, self.snippet_dir]
                    if self.snippet_dir
                    else [self.template_dir]
                ),
                autoescape=select_autoescape(),
                trim_blocks=True,
                lstrip_blocks=True,
            )
            self._register_filters()
        else:
            self.env = None

    def render(
        self,
        nodes: List[Proxy],
        template: Optional[str] = None,
        context: Dict[str, Any] = None,
    ) -> str:
        """Render nodes to DAE format."""
        # If template is provided, use template rendering
        if template:
            # For template rendering, convert nodes to DAE format
            dae_urls = []
            for node in nodes:
                url = self._render_node(node)
                if url:
                    dae_urls.append(url)

            # Add rendered nodes to context
            if context is None:
                context = {}

            # Check template type
            if "subscription" in template:
                # For subscription template, just join URLs with newlines
                context["subscription"] = "\n".join(dae_urls)
            else:
                # For DAE config template, format URLs with indentation
                if dae_urls:
                    formatted_urls = "\n    ".join(dae_urls)
                    context["proxies"] = formatted_urls
                else:
                    context["proxies"] = ""
                context["proxies_str"] = "\\n".join(dae_urls)

            # Add pt function for DAE template compatibility
            context["pt"] = self._pt

            # Use Jinja2 template rendering
            if self.env:
                # Load template with snippet and ruleset prepended
                template_source = self.env.loader.get_source(self.env, template)[0]
                prepend_text = ""
                if self._ruleset_text:
                    prepend_text += self._ruleset_text + "\n"
                if self._snippet_text:
                    prepend_text += self._snippet_text + "\n"
                if prepend_text:
                    template_source = prepend_text + template_source
                jinja_template = self.env.from_string(template_source)
                return jinja_template.render(context)
            else:
                return "\\n".join(dae_urls)

        # Otherwise, just render URLs
        urls = []
        for node in nodes:
            url = self._render_node(node)
            if url:
                urls.append(url)

        return "\\n".join(urls)

    def _render_node(self, node: Proxy) -> Optional[str]:
        """Render a single node to DAE URL."""
        protocol_type = node.protocol.get_type().value
        renderer = dae_protocol_registry.get_renderer(protocol_type)

        if renderer:
            return renderer(node)
        else:
            return None

    @staticmethod
    def _pt(proxies: List[str]) -> str:
        """Format proxies for DAE subscription format."""
        if not proxies:
            return ""
        return "\\n        ".join(proxies)

    def _register_filters(self):
        """Register custom Jinja2 filters."""
        if not self.env:
            return

        self.env.filters["to_yaml"] = self._to_yaml_filter
        self.env.filters["render"] = self._render_filter

        # Import and register all node filters globally
        from ...filters import all_filters

        self.env.globals["filter"] = all_filters

    @staticmethod
    def _to_yaml_filter(value):
        """Convert value to YAML."""
        import yaml

        return yaml.dump(value, default_flow_style=False, allow_unicode=True)

    def _render_filter(self, value):
        """Render a value (list or string) in appropriate format."""
        if isinstance(value, str) and ("DOMAIN" in value or "IP-CIDR" in value):
            # This is likely ruleset text from a macro
            from ...utils.ruleset_render import render_ruleset_in_dae

            return render_ruleset_in_dae(value)
        elif isinstance(value, list):
            return "\\n".join(str(v) for v in value)
        elif isinstance(value, str):
            return value
        else:
            return str(value)
