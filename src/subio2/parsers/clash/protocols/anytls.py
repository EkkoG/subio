"""AnyTLS protocol parser for Clash."""
from typing import Dict, Any, Optional
from ....models.node import Proxy, AnyTLSProtocol, TLSConfig
from .registry import register_clash_parser


@register_clash_parser('anytls')
def parse_anytls(data: Dict[str, Any]) -> Optional[Proxy]:
    """Parse AnyTLS proxy configuration."""
    try:
        protocol = AnyTLSProtocol(
            password=data.get('password', ''),
            idle_session_check_interval=data.get('idle-session-check-interval'),
            idle_session_timeout=data.get('idle-session-timeout'),
            min_idle_session=data.get('min-idle-session')
        )
        
        node = Proxy(
            name=data.get('name', 'anytls'),
            server=data.get('server', ''),
            port=data.get('port', 443),
            protocol=protocol
        )
        
        # TLS configuration
        tls_config = TLSConfig(
            enabled=True,
            sni=data.get('sni'),
            skip_cert_verify=data.get('skip-cert-verify', False),
            alpn=data.get('alpn'),
            client_fingerprint=data.get('client-fingerprint', 'chrome')
        )
        node.tls = tls_config
        
        # UDP support
        node.extra['udp'] = data.get('udp', True)
        
        # Validate protocol
        try:
            protocol.validate()
        except ValueError as e:
            print(f"AnyTLS validation error: {e}")
            return None
        
        return node
    except Exception as e:
        print(f"Failed to parse AnyTLS proxy: {e}")
        return None