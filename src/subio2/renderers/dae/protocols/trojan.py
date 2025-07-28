"""Trojan renderer for DAE format."""
from urllib.parse import quote
from ....models.node import CompositeNode, TrojanProtocol
from .registry import dae_protocol_registry


@dae_protocol_registry.register('trojan')
def render(node: CompositeNode) -> str:
    """Render Trojan node to DAE URL format."""
    protocol = node.protocol
    if not isinstance(protocol, TrojanProtocol):
        return ""
    
    # Build trojan URL: trojan://password@server:port#name
    url = f"trojan://{quote(protocol.password)}@{node.server}:{node.port}"
    
    # Add name as fragment
    if node.name:
        url += f"#{quote(node.name)}"
    
    return url