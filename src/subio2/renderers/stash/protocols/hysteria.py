"""Stash-specific Hysteria protocol renderer."""
from typing import Dict, Any
from ....models.node import Proxy, HysteriaProtocol
from ...clash.protocols.registry import clash_protocol_registry


@clash_protocol_registry.register('hysteria')
def render_hysteria_stash(node: Proxy) -> Dict[str, Any]:
    """Render Hysteria node in Stash-specific format.
    
    Stash has different field names and format for Hysteria compared to Clash.
    """
    if not isinstance(node.protocol, HysteriaProtocol):
        return {}
    
    protocol = node.protocol
    
    # Stash-specific format
    result = {
        'name': node.name,
        'type': 'hysteria',
        'server': node.server,
        'port': node.port,
    }
    
    # Stash uses 'auth-str' instead of 'auth_str'
    if protocol.auth_str:
        result['auth-str'] = protocol.auth_str
    elif protocol.auth:
        result['auth'] = protocol.auth
    
    # Protocol type
    result['protocol'] = protocol.protocol
    
    # Bandwidth
    if protocol.up_mbps:
        result['up'] = f"{protocol.up_mbps} Mbps"
    if protocol.down_mbps:
        result['down'] = f"{protocol.down_mbps} Mbps"
    
    # Obfuscation
    if protocol.obfs:
        result['obfs'] = protocol.obfs
    
    # TLS settings
    if node.tls and node.tls.enabled:
        result['sni'] = node.tls.sni or node.server
        result['skip-cert-verify'] = node.tls.skip_cert_verify
        if node.tls.fingerprint:
            result['fingerprint'] = node.tls.fingerprint
        if node.tls.alpn:
            result['alpn'] = node.tls.alpn
    
    # Additional Stash-specific fields
    if protocol.recv_window_conn:
        result['recv-window-conn'] = protocol.recv_window_conn
    if protocol.recv_window:
        result['recv-window'] = protocol.recv_window
    if protocol.disable_mtu_discovery is not None:
        result['disable-mtu-discovery'] = protocol.disable_mtu_discovery
    
    return result