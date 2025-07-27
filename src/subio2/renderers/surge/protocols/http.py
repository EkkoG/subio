"""HTTP proxy renderer for Surge format."""
from ....models.node_composite import CompositeNode, HttpProtocol
from .registry import surge_protocol_registry


@surge_protocol_registry.register('http')
def render(node: CompositeNode) -> str:
    """Render HTTP proxy node to Surge format."""
    protocol = node.protocol
    if not isinstance(protocol, HttpProtocol):
        return ""
    
    # Determine protocol type
    proto = 'https' if protocol.tls else 'http'
    
    # Basic format: ProxyName = http/https, server, port, username, password
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