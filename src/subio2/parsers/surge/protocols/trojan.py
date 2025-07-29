"""Trojan parser for Surge format."""

from typing import List, Optional
from ....models.node import Proxy, TrojanProtocol, TLSConfig
from .registry import surge_protocol_registry


@surge_protocol_registry.register("trojan")
def parse(name: str, server: str, port: int, params: List[str]) -> Optional[Proxy]:
    """Parse Trojan proxy from Surge format.

    Format: ProxyName = trojan, server, port, password=, [sni=], [skip-cert-verify=true]
    """
    try:
        # Parse parameters
        password = None
        sni = None
        skip_cert_verify = False

        for param in params:
            if "=" in param:
                key, value = param.split("=", 1)
                key = key.strip()
                value = value.strip()

                if key == "password":
                    password = value
                elif key == "sni":
                    sni = value
                elif key == "skip-cert-verify":
                    skip_cert_verify = value.lower() == "true"

        if not password:
            return None

        # Create protocol config
        protocol = TrojanProtocol(password=password)

        # Create node with TLS (Trojan always uses TLS)
        node = Proxy(
            name=name,
            server=server,
            port=port,
            protocol=protocol,
            tls=TLSConfig(enabled=True, sni=sni, skip_cert_verify=skip_cert_verify),
        )

        return node

    except Exception as e:
        print(f"Failed to parse Surge Trojan proxy: {e}")
        return None
