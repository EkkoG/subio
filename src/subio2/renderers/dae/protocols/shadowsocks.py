"""Shadowsocks renderer for DAE format."""
import base64
from urllib.parse import quote
from ....models.node_composite import CompositeNode, ShadowsocksProtocol
from .registry import dae_protocol_registry


@dae_protocol_registry.register('ss', 'shadowsocks')
def render(node: CompositeNode) -> str:
    """Render Shadowsocks node to DAE URL format (same as V2rayN)."""
    protocol = node.protocol
    if not isinstance(protocol, ShadowsocksProtocol):
        return ""
    
    # Build ss URL: ss://base64(method:password)@server:port#name
    auth = f"{protocol.method}:{protocol.password}"
    encoded_auth = base64.b64encode(auth.encode()).decode().rstrip('=')
    
    # Build URL
    url = f"ss://{encoded_auth}@{node.server}:{node.port}"
    
    # Add name as fragment
    if node.name:
        url += f"#{quote(node.name)}"
    
    return url