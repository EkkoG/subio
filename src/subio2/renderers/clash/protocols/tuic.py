"""TUIC protocol renderer for Clash."""
from typing import Dict, Any
from ....models.node import Proxy, TuicProtocol
from .registry import register_clash_renderer


@register_clash_renderer('tuic')
def render_tuic(node: Proxy) -> Dict[str, Any]:
    """Render TUIC proxy configuration."""
    protocol = node.protocol
    if not isinstance(protocol, TuicProtocol):
        return {}
    
    # Use the generic to_dict method which handles all fields properly
    result = node.to_dict()
    
    # TUIC specific adjustments
    # Ensure type is correctly set
    result['type'] = 'tuic'
    
    return result