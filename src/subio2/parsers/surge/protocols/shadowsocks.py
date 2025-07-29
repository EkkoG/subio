"""Shadowsocks parser for Surge format."""

from typing import List, Optional
from ....models.node import Proxy, ShadowsocksProtocol
from .registry import surge_protocol_registry


@surge_protocol_registry.register("ss", "custom")
def parse(name: str, server: str, port: int, params: List[str]) -> Optional[Proxy]:
    """Parse Shadowsocks proxy from Surge format.

    Format: ProxyName = ss, server, port, encrypt-method=, password=, [optional params]
    """
    try:
        # Parse parameters
        method = None
        password = None
        udp_relay = False
        obfs = None
        obfs_host = None

        for param in params:
            if "=" in param:
                key, value = param.split("=", 1)
                key = key.strip()
                value = value.strip()

                if key == "encrypt-method":
                    method = value
                elif key == "password":
                    password = value
                elif key == "udp-relay":
                    udp_relay = value.lower() == "true"
                elif key == "obfs":
                    obfs = value
                elif key == "obfs-host":
                    obfs_host = value

        if not method or not password:
            return None

        # Create protocol config
        protocol = ShadowsocksProtocol(method=method, password=password)

        # Handle obfs plugin
        if obfs:
            protocol.plugin = "obfs-local"
            protocol.plugin_opts = {"mode": obfs}
            if obfs_host:
                protocol.plugin_opts["host"] = obfs_host

        # Create node
        return Proxy(
            name=name,
            server=server,
            port=port,
            protocol=protocol,
            extra={"udp": udp_relay},
        )

    except Exception as e:
        print(f"Failed to parse Surge Shadowsocks proxy: {e}")
        return None
