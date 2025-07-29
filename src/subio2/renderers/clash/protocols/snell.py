"""Snell protocol renderer for Clash."""

from typing import Dict, Any
from ....models.node import Proxy, SnellProtocol
from .registry import register_clash_renderer


@register_clash_renderer("snell")
def render_snell(node: Proxy) -> Dict[str, Any]:
    """Render Snell proxy configuration."""
    protocol = node.protocol
    if not isinstance(protocol, SnellProtocol):
        return {}

    # Use the generic to_dict method which handles all fields properly
    result = node.to_dict()

    # Snell specific adjustments
    # Ensure type is correctly set
    result["type"] = "snell"

    return result
