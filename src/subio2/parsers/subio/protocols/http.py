"""HTTP protocol parser for SubIO format."""
from typing import Dict, Any, Optional
from ....models.node import CompositeNode, HttpProtocol, BasicAuth, TLSConfig
from .common import parse_transport, add_common_fields
from . import register_parser


@register_parser('http')
def parse_http(node_data: Dict[str, Any]) -> Optional[CompositeNode]:
    """Parse HTTP proxy node."""
    # Get basic info
    name = node_data.get('name', 'Unnamed')
    server = node_data.get('server', node_data.get('address'))
    port = node_data.get('port', 443)
    
    if not server:
        return None
    
    # Create protocol
    protocol = HttpProtocol(
        tls=node_data.get('tls', False)
    )
    
    # Create composite node
    node = CompositeNode(
        name=name,
        server=server,
        port=port,
        protocol=protocol
    )
    
    # Add common fields
    add_common_fields(node, node_data)
    
    return node