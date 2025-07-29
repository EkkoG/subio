"""AnyTLS protocol renderer for Clash."""
from typing import Dict, Any
from ....models.node import Proxy, AnyTLSProtocol
from .registry import register_clash_renderer


@register_clash_renderer('anytls')
def render_anytls(node: Proxy) -> Dict[str, Any]:
    """Render AnyTLS proxy configuration."""
    protocol = node.protocol
    if not isinstance(protocol, AnyTLSProtocol):
        return {}
    
    # Use the generic to_dict method which handles all fields properly
    result = node.to_dict()
    
    # AnyTLS specific adjustments
    # Ensure type is correctly set
    result['type'] = 'anytls'
    
    return result