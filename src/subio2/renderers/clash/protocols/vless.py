"""VLESS protocol renderer for Clash format."""
from typing import Dict, Any
from ....models.node_composite import CompositeNode
from .registry import clash_renderer_registry


@clash_renderer_registry.register('vless')
def render(node: CompositeNode) -> Dict[str, Any]:
    """Render VLESS node to Clash format."""
    result = {
        'name': node.name,
        'type': 'vless',
        'server': node.server,
        'port': node.port,
        'uuid': node.protocol.uuid
    }
    
    # Add flow if present
    if hasattr(node.protocol, 'flow') and node.protocol.flow:
        result['flow'] = node.protocol.flow
    
    # Add TLS settings
    if node.tls and node.tls.enabled:
        result['tls'] = True
        if node.tls.sni:
            result['servername'] = node.tls.sni
        result['skip-cert-verify'] = node.tls.skip_cert_verify
    
    # Add transport settings
    if node.transport and node.transport.type != 'tcp':
        result['network'] = node.transport.type
        
        # WebSocket options
        if node.transport.type == 'ws' and node.transport.ws:
            ws_opts = {}
            if node.transport.ws.path:
                ws_opts['path'] = node.transport.ws.path
            if node.transport.ws.headers:
                ws_opts['headers'] = node.transport.ws.headers
            if ws_opts:
                result['ws-opts'] = ws_opts
        
        # gRPC options
        elif node.transport.type == 'grpc' and node.transport.grpc:
            grpc_opts = {}
            if node.transport.grpc.service_name:
                grpc_opts['grpc-service-name'] = node.transport.grpc.service_name
            if grpc_opts:
                result['grpc-opts'] = grpc_opts
    
    # Add common fields
    result.update({
        'udp': True
    })
    
    return result