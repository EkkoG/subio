"""Trojan protocol parser for Clash format."""
from typing import Dict, Any, Optional
from ....models.node_composite import CompositeNode, TrojanProtocol, TLSConfig, Transport, WebSocketTransport, GRPCTransport
from .registry import clash_protocol_registry


@clash_protocol_registry.register('trojan')
def parse(proxy: Dict[str, Any]) -> Optional[CompositeNode]:
    """Parse Trojan proxy from Clash format."""
    try:
        # Extract basic info
        name = proxy.get('name')
        server = proxy.get('server')
        port = proxy.get('port')
        password = proxy.get('password')
        
        if not all([name, server, port, password]):
            return None
        
        # Create protocol config
        protocol = TrojanProtocol(password=password)
        
        # Create node
        node = CompositeNode(
            name=name,
            server=server,
            port=port,
            protocol=protocol
        )
        
        # Handle TLS configuration (Trojan usually uses TLS)
        if proxy.get('tls', True):  # Trojan typically uses TLS by default
            node.tls = TLSConfig(
                enabled=True,
                sni=proxy.get('sni') or proxy.get('servername'),
                skip_cert_verify=proxy.get('skip-cert-verify', False),
                fingerprint=proxy.get('fingerprint'),
                alpn=proxy.get('alpn')
            )
        
        # Handle transport
        network = proxy.get('network', 'tcp')
        if network != 'tcp':
            transport = Transport(type=network)
            
            # WebSocket options
            if network == 'ws' and proxy.get('ws-opts'):
                ws_opts = proxy['ws-opts']
                transport.ws = WebSocketTransport(
                    path=ws_opts.get('path', '/'),
                    headers=ws_opts.get('headers', {})
                )
            
            # gRPC options
            elif network == 'grpc' and proxy.get('grpc-opts'):
                grpc_opts = proxy['grpc-opts']
                transport.grpc = GRPCTransport(
                    service_name=grpc_opts.get('grpc-service-name', '')
                )
            
            node.transport = transport
        
        return node
        
    except Exception as e:
        print(f"Failed to parse Trojan proxy: {e}")
        return None