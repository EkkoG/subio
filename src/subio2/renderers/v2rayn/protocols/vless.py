"""VLESS renderer for V2rayN format."""
from urllib.parse import quote, urlencode
from ....models.node_composite import CompositeNode, VlessProtocol
from .registry import v2rayn_protocol_registry


@v2rayn_protocol_registry.register('vless')
def render(node: CompositeNode) -> str:
    """Render VLESS node to V2rayN URL format."""
    protocol = node.protocol
    if not isinstance(protocol, VlessProtocol):
        return ""
    
    # Build VLESS URL: vless://uuid@server:port?params#name
    url = f"vless://{protocol.uuid}@{node.server}:{node.port}"
    
    # Build query parameters
    params = {}
    
    # Add flow if present
    if protocol.flow:
        params['flow'] = protocol.flow
    
    # Add security (TLS)
    if node.tls and node.tls.enabled:
        params['security'] = 'tls'
        if node.tls.sni:
            params['sni'] = node.tls.sni
        if node.tls.skip_cert_verify:
            params['allowInsecure'] = '1'
    else:
        params['security'] = 'none'
    
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
    else:
        params['type'] = 'tcp'
    
    # Add query string
    url += "?" + urlencode(params)
    
    # Add name as fragment
    if node.name:
        url += f"#{quote(node.name)}"
    
    return url