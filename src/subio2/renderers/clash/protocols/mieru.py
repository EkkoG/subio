"""Mieru protocol renderer for Clash."""

from typing import Dict, Any
from ....models.node import Proxy, MieruProtocol
from .registry import register_clash_renderer


@register_clash_renderer("mieru")
def render_mieru(node: Proxy) -> Dict[str, Any]:
    """Render Mieru proxy configuration."""
    protocol = node.protocol
    if not isinstance(protocol, MieruProtocol):
        return {}

    # Use the generic to_dict method which handles all fields properly
    result = node.to_dict()

    # Mieru specific adjustments
    # Ensure type is correctly set
    result["type"] = "mieru"

    return result
