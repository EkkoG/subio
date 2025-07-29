"""VMess parser for Surge format."""

from typing import List, Optional
from ....models.node import (
    Proxy,
    VmessProtocol,
    TLSConfig,
    Transport,
    WebSocketTransport,
)
from .registry import surge_protocol_registry


@surge_protocol_registry.register("vmess")
def parse(name: str, server: str, port: int, params: List[str]) -> Optional[Proxy]:
    """Parse VMess proxy from Surge format.

    Format: ProxyName = vmess, server, port, username=, [ws=true], [tls=true], [ws-path=/], [ws-headers=...]
    """
    try:
        # Parse parameters
        uuid = None
        ws = False
        tls = False
        ws_path = "/"
        ws_headers = {}

        for param in params:
            if "=" in param:
                key, value = param.split("=", 1)
                key = key.strip()
                value = value.strip()

                if key == "username":
                    uuid = value
                elif key == "ws":
                    ws = value.lower() == "true"
                elif key == "tls":
                    tls = value.lower() == "true"
                elif key == "ws-path":
                    ws_path = value
                elif key == "ws-headers":
                    # Parse headers like "Host:example.com|User-Agent:custom"
                    for header in value.split("|"):
                        if ":" in header:
                            h_key, h_value = header.split(":", 1)
                            ws_headers[h_key.strip()] = h_value.strip()

        if not uuid:
            return None

        # Create protocol config
        protocol = VmessProtocol(
            uuid=uuid,
            alter_id=0,  # Surge doesn't support alterId
            security="auto",
        )

        # Create node
        node = Proxy(name=name, server=server, port=port, protocol=protocol)

        # Add TLS if enabled
        if tls:
            node.tls = TLSConfig(enabled=True)

        # Add WebSocket transport if enabled
        if ws:
            transport = Transport(type="ws")
            transport.ws = WebSocketTransport(
                path=ws_path, headers=ws_headers if ws_headers else None
            )
            node.transport = transport

        return node

    except Exception as e:
        print(f"Failed to parse Surge VMess proxy: {e}")
        return None
