"""Shadowsocks protocol parser for SubIO format."""
from typing import Dict, Any, Optional
from ....models.node import CompositeNode, ShadowsocksProtocol
from . import register_parser


@register_parser('shadowsocks')
@register_parser('ss')
def parse_shadowsocks(node_data: Dict[str, Any]) -> Optional[CompositeNode]:
    """Parse Shadowsocks node."""
    # Get basic info
    name = node_data.get('name', 'Unnamed')
    server = node_data.get('server', node_data.get('address'))
    port = node_data.get('port', 443)
    
    if not server:
        return None
    
    # Create protocol
    protocol = ShadowsocksProtocol(
        method=node_data.get('method', node_data.get('cipher', 'aes-256-gcm')),
        password=node_data.get('password', '')
    )
    
    # Create composite node
    node = CompositeNode(
        name=name,
        server=server,
        port=port,
        protocol=protocol
    )
    
    # Add extra metadata
    if node_data.get('udp'):
        node.extra['udp'] = True
    
    return node