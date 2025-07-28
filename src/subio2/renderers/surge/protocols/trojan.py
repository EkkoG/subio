"""Trojan renderer for Surge format."""
from ....models.node import CompositeNode, TrojanProtocol
from .registry import surge_protocol_registry


@surge_protocol_registry.register('trojan')
def render(node: CompositeNode) -> str:
    """Render Trojan node to Surge format."""
    protocol = node.protocol
    if not isinstance(protocol, TrojanProtocol):
        return ""
    
    # Basic format: ProxyName = trojan, server, port, password=
    parts = [
        node.name,
        'trojan',
        node.server,
        str(node.port),
        f'password={protocol.password}'
    ]
    
    # Add SNI if present
    if node.tls and node.tls.sni:
        parts.append(f'sni={node.tls.sni}')
    
    # Add skip-cert-verify if enabled
    if node.tls and node.tls.skip_cert_verify:
        parts.append('skip-cert-verify=true')
    
    return f"{parts[0]} = {', '.join(parts[1:])}"