"""Trojan protocol parser for SubIO format."""
from typing import Dict, Any, Optional
from ....models.node import CompositeNode, TrojanProtocol, TLSConfig
from .common import parse_transport
from . import register_parser


@register_parser('trojan')
def parse_trojan(node_data: Dict[str, Any]) -> Optional[CompositeNode]:
    """Parse Trojan node."""
    # Get basic info
    name = node_data.get('name', 'Unnamed')
    server = node_data.get('server', node_data.get('address'))
    port = node_data.get('port', 443)
    
    if not server:
        return None
    
    # Create protocol
    protocol = TrojanProtocol(
        password=node_data.get('password', '')
    )
    
    # Create composite node
    node = CompositeNode(
        name=name,
        server=server,
        port=port,
        protocol=protocol
    )
    
    # Add transport if specified
    transport_type = node_data.get('transport', node_data.get('network'))
    if transport_type:
        transport = parse_transport(transport_type, node_data)
        if transport:
            node.transport = transport
    
    # Add TLS config (Trojan usually requires TLS)
    if node_data.get('tls', True):  # Default to True for Trojan
        node.tls = TLSConfig(
            enabled=True,
            skip_cert_verify=node_data.get('skip_cert_verify', node_data.get('skip-cert-verify', False)),
            sni=node_data.get('sni', node_data.get('servername'))
        )
    
    # Add extra metadata
    if node_data.get('udp'):
        node.extra['udp'] = True
    
    return node