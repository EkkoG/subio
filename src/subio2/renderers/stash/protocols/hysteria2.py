"""Stash-specific Hysteria2 protocol renderer."""
from typing import Dict, Any
from ....models.node_composite import CompositeNode, Hysteria2Protocol
from ...clash.protocols.registry import clash_protocol_registry


@clash_protocol_registry.register('hysteria2')
def render_hysteria2_stash(node: CompositeNode) -> Dict[str, Any]:
    """Render Hysteria2 node in Stash-specific format.
    
    Stash might have different requirements for Hysteria2 format.
    """
    if not isinstance(node.protocol, Hysteria2Protocol):
        return {}
    
    protocol = node.protocol
    
    # Stash-specific format for Hysteria2
    result = {
        'name': node.name,
        'type': 'hysteria2',
        'server': node.server,
        'port': node.port,
        'password': protocol.password,
    }
    
    # Obfuscation settings
    if protocol.obfs:
        result['obfs'] = protocol.obfs
        if protocol.obfs_password:
            result['obfs-password'] = protocol.obfs_password
    
    # TLS is usually required for Hysteria2
    if node.tls and node.tls.enabled:
        result['sni'] = node.tls.sni or node.server
        result['skip-cert-verify'] = node.tls.skip_cert_verify
        if node.tls.fingerprint:
            result['fingerprint'] = node.tls.fingerprint
    
    # Additional settings
    if hasattr(protocol, 'up') and protocol.up:
        result['up'] = protocol.up
    if hasattr(protocol, 'down') and protocol.down:
        result['down'] = protocol.down
    
    return result