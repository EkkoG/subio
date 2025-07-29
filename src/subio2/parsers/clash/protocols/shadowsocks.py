"""Shadowsocks protocol parser for Clash format."""

from typing import Dict, Any, Optional
from ....models.node import Proxy, ShadowsocksProtocol, TLSConfig
from .registry import clash_protocol_registry


@clash_protocol_registry.register("ss", "shadowsocks")
def parse(proxy: Dict[str, Any]) -> Optional[Proxy]:
    """Parse Shadowsocks proxy from Clash format."""
    try:
        # Extract basic info
        name = proxy.get("name")
        server = proxy.get("server")
        port = proxy.get("port")

        # Extract Shadowsocks specific info
        cipher = proxy.get("cipher") or proxy.get("method")
        password = proxy.get("password")

        if not all([name, server, port, cipher, password]):
            return None

        # Create protocol config
        protocol = ShadowsocksProtocol(method=cipher, password=password)

        # Handle plugin
        if proxy.get("plugin"):
            protocol.plugin = proxy["plugin"]
            if proxy.get("plugin-opts"):
                protocol.plugin_opts = proxy["plugin-opts"]

        # Create node
        node = Proxy(name=name, server=server, port=port, protocol=protocol)

        # Handle TLS configuration
        if proxy.get("tls"):
            node.tls = TLSConfig(
                enabled=True,
                sni=proxy.get("sni"),
                skip_cert_verify=proxy.get("skip-cert-verify", False),
                fingerprint=proxy.get("fingerprint"),
            )

        return node

    except Exception as e:
        print(f"Failed to parse Shadowsocks proxy: {e}")
        return None
