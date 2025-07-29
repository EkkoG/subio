"""WireGuard protocol renderer for Clash."""
from typing import Dict, Any
from ....models.node import Proxy, WireGuardProtocol
from .registry import register_clash_renderer


@register_clash_renderer('wireguard')
def render_wireguard(node: Proxy) -> Dict[str, Any]:
    """Render WireGuard proxy configuration."""
    protocol = node.protocol
    if not isinstance(protocol, WireGuardProtocol):
        return {}
    
    # Use the generic to_dict method which handles all fields properly
    result = node.to_dict()
    
    # WireGuard specific adjustments
    # Ensure type is correctly set
    result['type'] = 'wireguard'
    
    return result