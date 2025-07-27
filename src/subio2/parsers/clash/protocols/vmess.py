"""VMess protocol parser for Clash format."""
from typing import Dict, Any, Optional
from ....models.node_composite import CompositeNode, VmessProtocol, TLSConfig, Transport, WebSocketTransport, GRPCTransport
from .registry import clash_protocol_registry


@clash_protocol_registry.register('vmess')
def parse(proxy: Dict[str, Any]) -> Optional[CompositeNode]:
    """Parse VMess proxy from Clash format."""
    try:
        # Extract basic info
        name = proxy.get('name')
        server = proxy.get('server')
        port = proxy.get('port')
        uuid = proxy.get('uuid')
        
        if not all([name, server, port, uuid]):
            return None
        
        # Create protocol config
        protocol = VmessProtocol(
            uuid=uuid,
            alter_id=proxy.get('alterId', 0),
            security=proxy.get('cipher', 'auto')  # Clash uses 'cipher', model uses 'security'
        )
        
        # Create node
        node = CompositeNode(
            name=name,
            server=server,
            port=port,
            protocol=protocol
        )
        
        # Handle TLS configuration
        if proxy.get('tls'):
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
                    headers=ws_opts.get('headers', {}),
                    max_early_data=ws_opts.get('max-early-data'),
                    early_data_header_name=ws_opts.get('early-data-header-name')
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
        print(f"Failed to parse VMess proxy: {e}")
        return None