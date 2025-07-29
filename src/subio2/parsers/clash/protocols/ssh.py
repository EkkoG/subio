"""SSH protocol parser for Clash."""
from typing import Dict, Any, Optional
from ....models.node import Proxy, SSHProtocol
from .registry import register_clash_parser


@register_clash_parser('ssh')
def parse_ssh(data: Dict[str, Any]) -> Optional[Proxy]:
    """Parse SSH proxy configuration."""
    try:
        protocol = SSHProtocol(
            username=data.get('username', 'root'),
            password=data.get('password'),
            private_key=data.get('privateKey') or data.get('private-key'),
            private_key_passphrase=data.get('private-key-passphrase'),
            host_key=data.get('host-key'),
            host_key_algorithms=data.get('host-key-algorithms'),
            client_version=data.get('client-version')
        )
        
        node = Proxy(
            name=data.get('name', 'ssh'),
            server=data.get('server', ''),
            port=data.get('port', 22),
            protocol=protocol
        )
        
        # Validate protocol
        try:
            protocol.validate()
        except ValueError as e:
            print(f"SSH validation error: {e}")
            return None
        
        return node
    except Exception as e:
        print(f"Failed to parse SSH proxy: {e}")
        return None