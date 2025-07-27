"""Hysteria protocol renderers for Clash format."""
from typing import Dict, Any
from ....models.node_composite import CompositeNode
from .registry import clash_renderer_registry


@clash_renderer_registry.register('hysteria')
def render_hysteria1(node: CompositeNode) -> Dict[str, Any]:
    """Render Hysteria v1 node to Clash format."""
    result = {
        'name': node.name,
        'type': 'hysteria',
        'server': node.server,
        'port': node.port
    }
    
    # Add Hysteria specific fields
    if hasattr(node.protocol, 'auth_str') and node.protocol.auth_str:
        result['auth-str'] = node.protocol.auth_str
    if hasattr(node.protocol, 'obfs') and node.protocol.obfs:
        result['obfs'] = node.protocol.obfs
    if hasattr(node.protocol, 'up_mbps') and node.protocol.up_mbps:
        result['up'] = node.protocol.up_mbps
    if hasattr(node.protocol, 'down_mbps') and node.protocol.down_mbps:
        result['down'] = node.protocol.down_mbps
    
    # Add TLS settings
    if node.tls:
        if node.tls.sni:
            result['sni'] = node.tls.sni
        result['skip-cert-verify'] = node.tls.skip_cert_verify
        if node.tls.fingerprint:
            result['fingerprint'] = node.tls.fingerprint
    
    return result


@clash_renderer_registry.register('hysteria2')
def render_hysteria2(node: CompositeNode) -> Dict[str, Any]:
    """Render Hysteria v2 node to Clash format."""
    result = {
        'name': node.name,
        'type': 'hysteria2',
        'server': node.server,
        'port': node.port
    }
    
    # Add Hysteria2 specific fields
    if hasattr(node.protocol, 'password') and node.protocol.password:
        result['password'] = node.protocol.password
    if hasattr(node.protocol, 'obfs') and node.protocol.obfs:
        result['obfs'] = node.protocol.obfs
    if hasattr(node.protocol, 'obfs_password') and node.protocol.obfs_password:
        result['obfs-password'] = node.protocol.obfs_password
    if hasattr(node.protocol, 'up_mbps') and node.protocol.up_mbps:
        result['up'] = node.protocol.up_mbps
    if hasattr(node.protocol, 'down_mbps') and node.protocol.down_mbps:
        result['down'] = node.protocol.down_mbps
    
    # Add TLS settings
    if node.tls:
        if node.tls.sni:
            result['sni'] = node.tls.sni
        result['skip-cert-verify'] = node.tls.skip_cert_verify
        if node.tls.fingerprint:
            result['fingerprint'] = node.tls.fingerprint
    
    return result