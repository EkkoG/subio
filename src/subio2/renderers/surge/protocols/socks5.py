"""SOCKS5 proxy renderer for Surge format."""
from ....models.node_composite import CompositeNode, Socks5Protocol
from .registry import surge_protocol_registry


@surge_protocol_registry.register('socks5')
def render(node: CompositeNode) -> str:
    """Render SOCKS5 proxy node to Surge format."""
    protocol = node.protocol
    if not isinstance(protocol, Socks5Protocol):
        return ""
    
    # Determine protocol type
    proto = 'socks5-tls' if protocol.tls else 'socks5'
    
    # Basic format: ProxyName = socks5/socks5-tls, server, port, username, password
    parts = [
        node.name,
        proto,
        node.server,
        str(node.port)
    ]
    
    # Add authentication if present
    if node.auth:
        parts.extend([
            node.auth.username or '',
            node.auth.password or ''
        ])
    
    return f"{parts[0]} = {', '.join(parts[1:])}"