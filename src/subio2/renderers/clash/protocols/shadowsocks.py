"""Shadowsocks protocol renderer for Clash format."""
from typing import Dict, Any
from ....models.node import Proxy
from .registry import clash_renderer_registry


@clash_renderer_registry.register('shadowsocks')
def render(node: Proxy) -> Dict[str, Any]:
    """Render Shadowsocks node to Clash format."""
    result = {
        'name': node.name,
        'type': 'ss',
        'server': node.server,
        'port': node.port,
        'cipher': node.protocol.method,
        'password': node.protocol.password
    }
    
    # Add plugin if present
    if hasattr(node.protocol, 'plugin') and node.protocol.plugin:
        result['plugin'] = node.protocol.plugin
        if hasattr(node.protocol, 'plugin_opts') and node.protocol.plugin_opts:
            result['plugin-opts'] = node.protocol.plugin_opts
    
    # Add common fields
    result.update({
        'udp': True,
        'skip-cert-verify': node.tls.skip_cert_verify if node.tls else False
    })
    
    return result