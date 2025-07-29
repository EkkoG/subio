"""V2rayN renderer implementation."""

from typing import List, Optional, Dict, Any
from ...models.node import Proxy
from ..base import BaseRenderer
from ...core.registry import renderer_registry
from .protocols.registry import v2rayn_protocol_registry


@renderer_registry.decorator("v2rayn")
class V2rayNRenderer(BaseRenderer):
    """Renderer for V2rayN format."""

    def __init__(
        self, template_dir: Optional[str] = None, snippet_dir: Optional[str] = None
    ):
        super().__init__(template_dir, snippet_dir)
        # Trigger protocol registration
        from . import protocols  # noqa

    def render(
        self,
        nodes: List[Proxy],
        template: Optional[str] = None,
        context: Dict[str, Any] = None,
    ) -> str:
        """Render nodes to V2rayN format."""
        urls = []

        for node in nodes:
            protocol_type = node.protocol.get_type().value
            renderer = v2rayn_protocol_registry.get_renderer(protocol_type)

            if renderer:
                url = renderer(node)
                if url:
                    urls.append(url)

        # Return URLs separated by newlines
        return "\n".join(urls)
