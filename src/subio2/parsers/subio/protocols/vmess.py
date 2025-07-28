"""VMess protocol parser for SubIO format."""
from typing import Dict, Any, Optional
from ....models.node import Proxy, VmessProtocol, TLSConfig
from .common import parse_transport
from . import register_parser


@register_parser('vmess')
def parse_vmess(node_data: Dict[str, Any]) -> Optional[Proxy]:
    """Parse VMess node."""
    # Get basic info
    name = node_data.get('name', 'Unnamed')
    server = node_data.get('server', node_data.get('address'))
    port = node_data.get('port', 443)
    
    if not server:
        return None
    
    # Create protocol
    protocol = VmessProtocol(
        uuid=node_data.get('uuid', ''),
        security=node_data.get('security', node_data.get('cipher', 'auto')),
        alter_id=node_data.get('alter_id', node_data.get('alterId', 0))
    )
    
    # Create composite node
    node = Proxy(
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
    
    # Add TLS config
    if node_data.get('tls'):
        node.tls = TLSConfig(
            enabled=True,
            skip_cert_verify=node_data.get('skip_cert_verify', node_data.get('skip-cert-verify', False)),
            sni=node_data.get('sni', node_data.get('servername'))
        )
    
    # Add extra metadata
    if node_data.get('udp'):
        node.extra['udp'] = True
    
    return node