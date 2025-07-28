"""Trojan renderer for V2rayN format."""
from urllib.parse import quote, urlencode
from ....models.node import Proxy, TrojanProtocol
from .registry import v2rayn_protocol_registry


@v2rayn_protocol_registry.register('trojan')
def render(node: Proxy) -> str:
    """Render Trojan node to V2rayN URL format."""
    protocol = node.protocol
    if not isinstance(protocol, TrojanProtocol):
        return ""
    
    # Build Trojan URL: trojan://password@server:port?params#name
    url = f"trojan://{quote(protocol.password)}@{node.server}:{node.port}"
    
    # Build query parameters
    params = {}
    
    # Add TLS parameters
    if node.tls and node.tls.enabled:
        if node.tls.sni:
            params['sni'] = node.tls.sni
        if node.tls.skip_cert_verify:
            params['allowInsecure'] = '1'
    
    # Add transport parameters
    if node.transport:
        params['type'] = node.transport.type
        
        if node.transport.type == "ws" and hasattr(node.transport, 'ws') and node.transport.ws:
            ws = node.transport.ws
            params['path'] = ws.path or "/"
            if ws.headers and 'Host' in ws.headers:
                params['host'] = ws.headers['Host']
        elif node.transport.type == "grpc" and hasattr(node.transport, 'grpc') and node.transport.grpc:
            grpc = node.transport.grpc
            params['serviceName'] = grpc.service_name
    
    # Add query string if there are parameters
    if params:
        url += "?" + urlencode(params)
    
    # Add name as fragment
    if node.name:
        url += f"#{quote(node.name)}"
    
    return url